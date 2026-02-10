//! UDP-QSP session state and replay handling.

use std::future::Future;
use std::io;

use super::{OpenedPacketRef, QspCryptoError, UdpQspKeys};
use crate::types::Cid;

/// Number of packets tracked for replay protection.
pub const PN_REPLAY_WINDOW: usize = 1024;

const WINDOW_WORD_BITS: usize = 64;
const WINDOW_WORDS: usize = PN_REPLAY_WINDOW / WINDOW_WORD_BITS;
const MAX_PACKET_NUMBER: u64 = u32::MAX as u64;

/// UDP-QSP session errors.
#[derive(Debug)]
pub enum QspSessionError {
    /// I/O error from the underlying transport.
    Io(io::Error),
    /// Packet crypto failed.
    Crypto(QspCryptoError),
    /// Packet is a replay.
    Replay,
    /// Packet is too old to fit within the replay window.
    TooOld,
    /// Packet number would overflow.
    PacketNumberOverflow,
}

impl From<io::Error> for QspSessionError {
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}

impl From<QspCryptoError> for QspSessionError {
    fn from(err: QspCryptoError) -> Self {
        Self::Crypto(err)
    }
}

/// Async IO abstraction for UDP-QSP sessions.
pub trait SessionIo {
    /// Send a protected UDP-QSP packet.
    fn send<'a>(&'a mut self, bytes: &'a [u8]) -> impl Future<Output = io::Result<()>> + Send + 'a;
    /// Receive a protected UDP-QSP packet into `buf`, returning the length.
    fn recv<'a>(
        &'a mut self,
        buf: &'a mut [u8],
    ) -> impl Future<Output = io::Result<usize>> + Send + 'a;
}

/// Replay window outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayError {
    /// Packet is a replay of an already-accepted packet.
    Replay,
    /// Packet is older than the replay window.
    TooOld,
}

/// Fixed-size replay window for packet numbers.
#[derive(Debug, Clone)]
pub struct ReplayWindow {
    largest_pn: Option<u64>,
    initial_expected: u64,
    bits: [u64; WINDOW_WORDS],
}

impl ReplayWindow {
    /// Create a replay window with an initial expected packet number.
    #[must_use]
    pub const fn new(initial_expected: u64) -> Self {
        Self {
            largest_pn: None,
            initial_expected,
            bits: [0; WINDOW_WORDS],
        }
    }

    /// Return the highest packet number accepted so far.
    #[must_use]
    pub const fn largest_pn(&self) -> Option<u64> {
        self.largest_pn
    }

    /// Return the expected next packet number.
    #[must_use]
    pub fn expected_pn(&self) -> u64 {
        self.largest_pn
            .map_or(self.initial_expected, |pn| pn.saturating_add(1))
    }

    /// Check and update the replay window for `pn`.
    ///
    /// # Errors
    ///
    /// Returns `ReplayError::TooOld` if `pn` is outside the window, or
    /// `ReplayError::Replay` if the packet number was already seen.
    pub fn check_and_update(&mut self, pn: u64) -> Result<(), ReplayError> {
        match self.largest_pn {
            None => {
                self.bits.fill(0);
                self.largest_pn = Some(pn);
                self.set_bit(pn);
                Ok(())
            }
            Some(largest) if pn > largest => {
                let delta = pn - largest;
                if delta >= PN_REPLAY_WINDOW as u64 {
                    self.bits.fill(0);
                } else {
                    let window = (PN_REPLAY_WINDOW - 1) as u64;
                    let old_start = largest.saturating_sub(window);
                    let new_start = pn.saturating_sub(window);
                    if new_start > old_start {
                        for old_pn in old_start..new_start {
                            self.clear_bit(old_pn);
                        }
                    }
                }
                self.largest_pn = Some(pn);
                self.set_bit(pn);
                Ok(())
            }
            Some(largest) => {
                let delta = largest - pn;
                if delta >= PN_REPLAY_WINDOW as u64 {
                    return Err(ReplayError::TooOld);
                }
                if self.is_set(pn) {
                    return Err(ReplayError::Replay);
                }
                self.set_bit(pn);
                Ok(())
            }
        }
    }

    #[inline]
    const fn is_set(&self, pn: u64) -> bool {
        let (word, mask) = bit_position(pn);
        (self.bits[word] & mask) != 0
    }

    #[inline]
    const fn set_bit(&mut self, pn: u64) {
        let (word, mask) = bit_position(pn);
        self.bits[word] |= mask;
    }

    #[inline]
    const fn clear_bit(&mut self, pn: u64) {
        let (word, mask) = bit_position(pn);
        self.bits[word] &= !mask;
    }
}

#[inline]
#[allow(clippy::cast_possible_truncation)]
const fn bit_position(pn: u64) -> (usize, u64) {
    let idx = (pn % PN_REPLAY_WINDOW as u64) as usize;
    let word = idx / WINDOW_WORD_BITS;
    let bit = idx % WINDOW_WORD_BITS;
    (word, 1u64 << bit)
}

/// UDP-QSP session state with replay protection and packet I/O.
#[derive(Debug)]
pub struct QuicQspSession<I> {
    io: I,
    scid: Cid,
    dcid: Cid,
    keys: UdpQspKeys,
    key_phase: bool,
    next_pn: u64,
    replay_window: ReplayWindow,
    send_buf: Vec<u8>,
    recv_buf: Vec<u8>,
}

impl<I: SessionIo> QuicQspSession<I> {
    /// Create a new UDP-QSP session.
    ///
    /// `send_pn` is the next packet number used for outbound packets.
    /// `recv_expected_pn` is the expected next packet number for inbound
    /// reconstruction (typically the peer's `pn_start`).
    #[must_use]
    pub const fn new(
        io: I,
        scid: Cid,
        dcid: Cid,
        keys: UdpQspKeys,
        send_pn: u64,
        recv_expected_pn: u64,
        key_phase: bool,
    ) -> Self {
        Self {
            io,
            scid,
            dcid,
            keys,
            key_phase,
            next_pn: send_pn,
            replay_window: ReplayWindow::new(recv_expected_pn),
            send_buf: Vec::new(),
            recv_buf: Vec::new(),
        }
    }

    /// Return the source connection ID.
    #[must_use]
    pub const fn scid(&self) -> &Cid {
        &self.scid
    }

    /// Return the destination connection ID.
    #[must_use]
    pub const fn dcid(&self) -> &Cid {
        &self.dcid
    }

    /// Return the next packet number used for outbound packets.
    #[must_use]
    pub const fn next_pn(&self) -> u64 {
        self.next_pn
    }

    /// Return the expected next packet number for inbound packets.
    #[must_use]
    pub fn expected_pn(&self) -> u64 {
        self.replay_window.expected_pn()
    }

    /// Send a payload over UDP-QSP.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the packet number overflows
    /// - the packet number exceeds the wire format bounds
    /// - packet protection fails
    /// - the IO layer fails
    pub async fn send(&mut self, payload: &[u8]) -> Result<(), QspSessionError> {
        let pn = self.next_pn;
        if pn > MAX_PACKET_NUMBER {
            return Err(QspSessionError::PacketNumberOverflow);
        }
        self.next_pn = pn
            .checked_add(1)
            .ok_or(QspSessionError::PacketNumberOverflow)?;
        self.keys.protect_into(
            self.dcid.as_slice(),
            pn,
            self.key_phase,
            payload,
            &mut self.send_buf,
        )?;
        self.io.send(&self.send_buf).await?;
        Ok(())
    }

    /// Receive and decrypt a UDP-QSP packet into the session buffer.
    ///
    /// Returns a reference to the decrypted payload stored in the session.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - IO fails
    /// - header protection / AEAD fails
    /// - the packet is too old or a replay
    pub async fn recv<'a>(
        &'a mut self,
        packet_buf: &mut [u8],
    ) -> Result<OpenedPacketRef<'a>, QspSessionError> {
        let len = self.io.recv(packet_buf).await?;
        self.open_packet(&packet_buf[..len])
    }

    /// Open a protected UDP-QSP packet and update replay state.
    ///
    /// Returns a reference to the decrypted payload stored in the session.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - header protection / AEAD fails
    /// - the packet number exceeds the wire format bounds
    /// - the packet is too old or a replay
    pub fn open_packet<'a>(
        &'a mut self,
        packet: &[u8],
    ) -> Result<OpenedPacketRef<'a>, QspSessionError> {
        let expected_pn = self.replay_window.expected_pn();
        if expected_pn > MAX_PACKET_NUMBER {
            return Err(QspSessionError::PacketNumberOverflow);
        }
        let opened =
            self.keys
                .open_into(self.scid.len(), packet, expected_pn, &mut self.recv_buf)?;
        let pn = opened.pn;
        if pn > MAX_PACKET_NUMBER {
            return Err(QspSessionError::PacketNumberOverflow);
        }
        let pn_len = opened.pn_len;
        let key_phase = opened.key_phase;

        match self.replay_window.check_and_update(pn) {
            Ok(()) => Ok(OpenedPacketRef {
                pn,
                pn_len,
                key_phase,
                payload: self.recv_buf.as_slice(),
            }),
            Err(ReplayError::Replay) => Err(QspSessionError::Replay),
            Err(ReplayError::TooOld) => Err(QspSessionError::TooOld),
        }
    }

    /// Returns a mutable reference to the underlying IO transport.
    #[must_use]
    pub const fn io_mut(&mut self) -> &mut I {
        &mut self.io
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{AEAD_IV_LEN, AEAD_KEY_LEN, CipherSuite, HP_KEY_LEN};

    #[test]
    fn replay_window_rejects_replay() {
        let mut window = ReplayWindow::new(0);
        window.check_and_update(10).unwrap();
        assert_eq!(window.check_and_update(10), Err(ReplayError::Replay));
    }

    #[test]
    fn replay_window_rejects_too_old() {
        let mut window = ReplayWindow::new(0);
        window.check_and_update(2000).unwrap();
        assert_eq!(
            window.check_and_update(2000 - PN_REPLAY_WINDOW as u64),
            Err(ReplayError::TooOld)
        );
    }

    #[test]
    fn replay_window_accepts_out_of_order() {
        let mut window = ReplayWindow::new(0);
        window.check_and_update(100).unwrap();
        window.check_and_update(99).unwrap();
        window.check_and_update(98).unwrap();
        assert_eq!(window.largest_pn(), Some(100));
    }

    #[test]
    fn replay_window_drops_oldest_on_advance() {
        let mut window = ReplayWindow::new(0);
        window.check_and_update(1000).unwrap();
        window.check_and_update(1500).unwrap();
        assert_eq!(window.check_and_update(0), Err(ReplayError::TooOld));
    }

    #[tokio::test]
    async fn session_recv_replay_detection() {
        struct TestIo {
            packet: Vec<u8>,
            sent: Vec<Vec<u8>>,
        }

        impl SessionIo for TestIo {
            async fn send(&mut self, bytes: &[u8]) -> io::Result<()> {
                self.sent.push(bytes.to_vec());
                Ok(())
            }

            async fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                let len = self.packet.len();
                buf[..len].copy_from_slice(&self.packet);
                Ok(len)
            }
        }

        let keys = UdpQspKeys::new(
            CipherSuite::Aes128Gcm,
            [0x11; HP_KEY_LEN],
            [0x11; HP_KEY_LEN],
            [0x33; AEAD_KEY_LEN],
            [0x33; AEAD_KEY_LEN],
            [0x55; AEAD_IV_LEN],
            [0x55; AEAD_IV_LEN],
        )
        .unwrap();
        let dcid = Cid::from([0xAB; 8]);
        let packet = keys.protect(dcid.as_slice(), 7, false, b"hello").unwrap();

        let io = TestIo {
            packet: packet.clone(),
            sent: Vec::new(),
        };
        let mut session = QuicQspSession::new(io, Cid::from([0xCD; 8]), dcid, keys, 0, 7, false);
        let mut buf = vec![0u8; 1500];

        let opened = session.recv(&mut buf).await.unwrap();
        assert_eq!(opened.pn, 7);
        assert_eq!(opened.payload, b"hello");

        assert!(matches!(
            session.recv(&mut buf).await,
            Err(QspSessionError::Replay)
        ));
    }

    #[tokio::test]
    async fn session_send_rejects_packet_number_overflow() {
        struct TestIo;

        impl SessionIo for TestIo {
            async fn send(&mut self, _bytes: &[u8]) -> io::Result<()> {
                Ok(())
            }

            async fn recv(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::new(io::ErrorKind::WouldBlock, "no recv"))
            }
        }

        let keys = UdpQspKeys::new(
            CipherSuite::Aes128Gcm,
            [0x11; HP_KEY_LEN],
            [0x11; HP_KEY_LEN],
            [0x33; AEAD_KEY_LEN],
            [0x33; AEAD_KEY_LEN],
            [0x55; AEAD_IV_LEN],
            [0x55; AEAD_IV_LEN],
        )
        .unwrap();

        let mut session = QuicQspSession::new(
            TestIo,
            Cid::from([0xCD; 8]),
            Cid::from([0xAB; 8]),
            keys,
            u64::from(u32::MAX) + 1,
            0,
            false,
        );

        assert!(matches!(
            session.send(b"hello").await,
            Err(QspSessionError::PacketNumberOverflow)
        ));
    }
}
