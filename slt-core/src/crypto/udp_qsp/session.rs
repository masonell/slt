//! UDP-QSP session state and replay handling.

use std::future::Future;
use std::io;
use std::net::SocketAddr;

use super::{OpenedPacketRef, QspCryptoError, UdpQspKeys};
use crate::types::Cid;

/// Number of packets tracked for replay protection.
pub const PN_REPLAY_WINDOW: usize = 1024;
/// Default packets per key phase before rotating UDP-QSP keys.
pub const KEY_UPDATE_INTERVAL: u64 = 1 << 21;
/// Late packet-number margin where receiver still accepts old keys.
pub const KEY_UPDATE_LATE_MARGIN: u64 = (PN_REPLAY_WINDOW as u64) * 8;

const WINDOW_WORD_BITS: usize = 64;
const WINDOW_WORDS: usize = PN_REPLAY_WINDOW / WINDOW_WORD_BITS;
const DEAD_CHANNEL_FAILURE_THRESHOLD: u32 = 64;

/// UDP-QSP session errors.
#[derive(Debug, thiserror::Error)]
pub enum QspSessionError {
    /// I/O error from the underlying transport.
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    /// Packet crypto failed.
    #[error("crypto error: {0}")]
    Crypto(#[from] QspCryptoError),
    /// Packet is a replay.
    #[error("packet is a replay")]
    Replay,
    /// Packet is too old to fit within the replay window.
    #[error("packet too old")]
    TooOld,
    /// Packet number would overflow.
    #[error("packet number overflow")]
    PacketNumberOverflow,
    /// Too many consecutive decrypt failures; channel is considered dead.
    #[error("channel is dead")]
    DeadChannel,
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
    /// Flush any protected packets buffered by the underlying I/O layer.
    fn flush(&mut self) -> impl Future<Output = io::Result<()>> + Send + '_ {
        async { Ok(()) }
    }
    /// Return whether the underlying I/O layer has buffered packets to flush.
    fn has_pending_flush(&self) -> bool {
        false
    }
}

/// I/O backends that can update their UDP peer address.
pub trait PeerUpdate {
    /// Update the accepted receive peer and outbound transmit destination.
    fn set_peer(&mut self, peer: SocketAddr);
}

/// Replay window outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ReplayError {
    /// Packet is a replay of an already-accepted packet.
    #[error("packet is a replay")]
    Replay,
    /// Packet is older than the replay window.
    #[error("packet older than replay window")]
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

#[derive(Debug, Clone, Copy)]
struct RekeyPolicy {
    interval: u64,
    late_margin: u64,
    dead_failures: u32,
}

impl RekeyPolicy {
    const fn defaults() -> Self {
        Self {
            interval: KEY_UPDATE_INTERVAL,
            late_margin: KEY_UPDATE_LATE_MARGIN,
            dead_failures: DEAD_CHANNEL_FAILURE_THRESHOLD,
        }
    }
}

/// Prior receive key phase, retained so reordered old-phase packets still
/// decrypt after the receiver promotes the next key phase.
///
/// `valid_until_pn` tracks `PN_REPLAY_WINDOW`, not `KEY_UPDATE_LATE_MARGIN`:
/// the replay window is shared across both key phases and rejects any packet
/// more than one window below the largest seen as `TooOld`, so old-phase
/// packets (sent before the threshold) are unreachable past
/// `threshold + PN_REPLAY_WINDOW` regardless of key availability.
/// `KEY_UPDATE_LATE_MARGIN` bounds rotation detection
/// (`should_try_candidate`), a separate concern.
#[derive(Debug)]
struct PreviousRxKeys {
    keys: UdpQspKeys,
    valid_until_pn: u64,
}

/// UDP-QSP session state with replay protection and packet I/O.
#[derive(Debug)]
pub struct QuicQspSession<I> {
    io: I,
    scid: Cid,
    dcid: Cid,
    keys: UdpQspKeys,
    tx_key_phase: bool,
    rx_key_phase: bool,
    next_pn: u64,
    tx_next_rekey_pn: Option<u64>,
    rx_next_rekey_pn: Option<u64>,
    previous_rx: Option<PreviousRxKeys>,
    consecutive_decrypt_failures: u32,
    rekey_policy: RekeyPolicy,
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
            tx_key_phase: key_phase,
            rx_key_phase: key_phase,
            next_pn: send_pn,
            tx_next_rekey_pn: next_rekey_after(send_pn, RekeyPolicy::defaults().interval),
            rx_next_rekey_pn: next_rekey_after(recv_expected_pn, RekeyPolicy::defaults().interval),
            previous_rx: None,
            consecutive_decrypt_failures: 0,
            rekey_policy: RekeyPolicy::defaults(),
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

    /// Return the current transmit key phase bit.
    #[must_use]
    pub const fn tx_key_phase(&self) -> bool {
        self.tx_key_phase
    }

    /// Return the current receive key phase bit.
    #[must_use]
    pub const fn rx_key_phase(&self) -> bool {
        self.rx_key_phase
    }

    /// Send a payload over UDP-QSP.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the packet number overflows
    /// - packet protection fails
    /// - the IO layer fails
    pub async fn send(&mut self, payload: &[u8]) -> Result<(), QspSessionError> {
        let pn = self.next_pn;
        self.maybe_rotate_tx_keys(pn)?;
        self.next_pn = pn
            .checked_add(1)
            .ok_or(QspSessionError::PacketNumberOverflow)?;
        self.keys.protect_into(
            self.dcid.as_slice(),
            pn,
            self.tx_key_phase,
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

    /// Flush any UDP-QSP packets buffered by the underlying I/O layer.
    ///
    /// # Errors
    ///
    /// Returns an error if the IO layer fails.
    pub async fn flush(&mut self) -> io::Result<()> {
        self.io.flush().await
    }

    /// Return whether the underlying I/O layer has buffered packets to flush.
    #[must_use]
    pub fn has_pending_flush(&self) -> bool {
        self.io.has_pending_flush()
    }

    /// Replace the underlying packet I/O backend, preserving all UDP-QSP
    /// cryptographic, packet-number, rekey, and replay state.
    ///
    /// Any send/receive queues owned by the old I/O backend are discarded with
    /// the returned value unless the caller keeps or drains it separately.
    #[must_use]
    pub const fn replace_io(&mut self, new_io: I) -> I {
        std::mem::replace(&mut self.io, new_io)
    }

    /// Return a reference to the underlying I/O backend.
    #[must_use]
    pub const fn io(&self) -> &I {
        &self.io
    }

    /// Update the UDP peer address through the underlying I/O backend.
    pub fn set_peer(&mut self, peer: SocketAddr)
    where
        I: PeerUpdate,
    {
        self.io.set_peer(peer);
    }

    /// Open a protected UDP-QSP packet and update replay state.
    ///
    /// Returns a reference to the decrypted payload stored in the session.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - header protection / AEAD fails
    /// - the packet is too old or a replay
    pub fn open_packet<'a>(
        &'a mut self,
        packet: &[u8],
    ) -> Result<OpenedPacketRef<'a>, QspSessionError> {
        let expected_pn = self.replay_window.expected_pn();
        self.maybe_confirm_previous_rx_keys(expected_pn);
        let current_opened = self
            .keys
            .open_into(self.scid.len(), packet, expected_pn, &mut self.recv_buf)
            .ok()
            .map(|opened| (opened.pn, opened.pn_len, opened.key_phase));
        if let Some((pn, pn_len, key_phase)) = current_opened
            && key_phase == self.rx_key_phase
        {
            return self.accept_opened(pn, pn_len, key_phase);
        }

        if self.can_try_previous(expected_pn)
            && let Some(previous) = &self.previous_rx
            && let Some((pn, pn_len, key_phase)) = previous
                .keys
                .open_into(self.scid.len(), packet, expected_pn, &mut self.recv_buf)
                .ok()
                .map(|opened| (opened.pn, opened.pn_len, opened.key_phase))
            && key_phase != self.rx_key_phase
        {
            return self.accept_opened(pn, pn_len, key_phase);
        }

        if self.should_try_candidate(expected_pn)
            && let Some(candidate_keys) = self.derive_candidate_rx_keys()?
            && let Some((pn, pn_len, key_phase)) = candidate_keys
                .open_into(self.scid.len(), packet, expected_pn, &mut self.recv_buf)
                .ok()
                .map(|opened| (opened.pn, opened.pn_len, opened.key_phase))
            && key_phase != self.rx_key_phase
        {
            self.promote_candidate_rx_keys(candidate_keys)?;
            return self.accept_opened(pn, pn_len, key_phase);
        }

        self.consecutive_decrypt_failures = self.consecutive_decrypt_failures.saturating_add(1);
        if self.consecutive_decrypt_failures >= self.rekey_policy.dead_failures {
            return Err(QspSessionError::DeadChannel);
        }

        Err(QspSessionError::Crypto(QspCryptoError::CryptoFail))
    }

    fn maybe_rotate_tx_keys(&mut self, pn: u64) -> Result<(), QspSessionError> {
        while let Some(threshold) = self.tx_next_rekey_pn {
            if pn < threshold {
                break;
            }

            self.keys = self.keys.with_next_tx_keys()?;
            self.tx_key_phase = !self.tx_key_phase;
            self.tx_next_rekey_pn = next_rekey_after(threshold, self.rekey_policy.interval);
        }
        Ok(())
    }

    fn accept_opened(
        &mut self,
        pn: u64,
        pn_len: usize,
        key_phase: bool,
    ) -> Result<OpenedPacketRef<'_>, QspSessionError> {
        match self.replay_window.check_and_update(pn) {
            Ok(()) => {
                self.consecutive_decrypt_failures = 0;
                Ok(OpenedPacketRef {
                    pn,
                    pn_len,
                    key_phase,
                    payload: self.recv_buf.as_slice(),
                })
            }
            Err(ReplayError::Replay) => Err(QspSessionError::Replay),
            Err(ReplayError::TooOld) => Err(QspSessionError::TooOld),
        }
    }

    fn can_try_previous(&self, expected_pn: u64) -> bool {
        self.previous_rx
            .as_ref()
            .is_some_and(|prev| expected_pn <= prev.valid_until_pn)
    }

    const fn should_try_candidate(&self, expected_pn: u64) -> bool {
        if self.previous_rx.is_some() {
            return false;
        }
        let Some(threshold) = self.rx_next_rekey_pn else {
            return false;
        };
        pn_distance(expected_pn, threshold) <= self.rekey_policy.late_margin
    }

    fn derive_candidate_rx_keys(&self) -> Result<Option<UdpQspKeys>, QspSessionError> {
        if self.rx_next_rekey_pn.is_none() {
            return Ok(None);
        }
        Ok(Some(self.keys.with_next_rx_keys()?))
    }

    fn promote_candidate_rx_keys(&mut self, candidate: UdpQspKeys) -> Result<(), QspSessionError> {
        let threshold = self
            .rx_next_rekey_pn
            .unwrap_or_else(|| self.replay_window.expected_pn());
        // One replay window: by then old-phase packets are `TooOld` in the shared
        // replay window regardless of key availability (see `PreviousRxKeys`).
        let valid_until = threshold.saturating_add(PN_REPLAY_WINDOW as u64);
        self.previous_rx = Some(PreviousRxKeys {
            keys: self.keys.try_clone()?,
            valid_until_pn: valid_until,
        });
        self.keys = candidate;
        self.rx_key_phase = !self.rx_key_phase;
        self.rx_next_rekey_pn = next_rekey_after(threshold, self.rekey_policy.interval);
        Ok(())
    }

    fn maybe_confirm_previous_rx_keys(&mut self, expected_pn: u64) {
        if self
            .previous_rx
            .as_ref()
            .is_some_and(|prev| expected_pn > prev.valid_until_pn)
        {
            self.previous_rx = None;
        }
    }
}

const fn pn_distance(a: u64, b: u64) -> u64 {
    a.abs_diff(b)
}

const fn next_rekey_after(pn: u64, interval: u64) -> Option<u64> {
    if interval == 0 {
        return None;
    }

    let rem = pn % interval;
    let step = if rem == 0 { interval } else { interval - rem };
    pn.checked_add(step)
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    use tokio::sync::mpsc;

    use super::*;
    use crate::proto::{
        AEAD_IV_LEN, AEAD_KEY_LEN, CipherSuite, HP_KEY_LEN, Message, MessageLimits, PingPayload,
        PongPayload, UDP_QSP_TRAFFIC_SECRET_LEN, decode_message, encode_message,
    };

    struct ChanIo {
        tx: mpsc::Sender<Vec<u8>>,
        rx: mpsc::Receiver<Vec<u8>>,
    }

    impl SessionIo for ChanIo {
        async fn send(&mut self, bytes: &[u8]) -> io::Result<()> {
            self.tx
                .send(bytes.to_vec())
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "channel closed"))
        }

        async fn recv<'a>(&'a mut self, buf: &'a mut [u8]) -> io::Result<usize> {
            let packet =
                self.rx.recv().await.ok_or_else(|| {
                    io::Error::new(io::ErrorKind::UnexpectedEof, "channel closed")
                })?;
            if packet.len() > buf.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "packet too large",
                ));
            }
            buf[..packet.len()].copy_from_slice(&packet);
            Ok(packet.len())
        }
    }

    /// In-memory `SessionIo` that buffers sends until `flush`, modeling the
    /// batching contract of the real UDP-QSP socket backend. Used to assert that
    /// `QuicQspSession` proxies `flush`/`has_pending_flush`/`set_peer` to its
    /// underlying I/O layer instead of dropping or short-circuiting them.
    #[derive(Debug)]
    struct BufferingIo {
        state: Arc<Mutex<BufferingIoState>>,
    }

    #[derive(Debug, Default)]
    struct BufferingIoState {
        pending: Vec<Vec<u8>>,
        flushed: Vec<Vec<u8>>,
        last_peer: Option<SocketAddr>,
    }

    impl BufferingIo {
        /// Create a buffering I/O and a shared handle to observe its internal state.
        fn pair() -> (Self, Arc<Mutex<BufferingIoState>>) {
            let state = Arc::new(Mutex::new(BufferingIoState::default()));
            (
                Self {
                    state: state.clone(),
                },
                state,
            )
        }
    }

    impl SessionIo for BufferingIo {
        async fn send(&mut self, bytes: &[u8]) -> io::Result<()> {
            self.state
                .lock()
                .expect("BufferingIo lock")
                .pending
                .push(bytes.to_vec());
            Ok(())
        }

        async fn recv(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "BufferingIo has no recv path",
            ))
        }

        async fn flush(&mut self) -> io::Result<()> {
            {
                let mut state = self.state.lock().expect("BufferingIo lock");
                let pending = std::mem::take(&mut state.pending);
                state.flushed.extend(pending);
            }
            Ok(())
        }

        fn has_pending_flush(&self) -> bool {
            !self
                .state
                .lock()
                .expect("BufferingIo lock")
                .pending
                .is_empty()
        }
    }

    impl PeerUpdate for BufferingIo {
        fn set_peer(&mut self, peer: SocketAddr) {
            self.state.lock().expect("BufferingIo lock").last_peer = Some(peer);
        }
    }

    #[derive(Debug)]
    struct QueueIo {
        sent: Arc<Mutex<Vec<Vec<u8>>>>,
        recv: VecDeque<Vec<u8>>,
    }

    impl QueueIo {
        fn new(recv: Vec<Vec<u8>>) -> (Self, Arc<Mutex<Vec<Vec<u8>>>>) {
            let sent = Arc::new(Mutex::new(Vec::new()));
            (
                Self {
                    sent: sent.clone(),
                    recv: recv.into(),
                },
                sent,
            )
        }
    }

    impl SessionIo for QueueIo {
        async fn send(&mut self, bytes: &[u8]) -> io::Result<()> {
            self.sent
                .lock()
                .expect("QueueIo sent lock")
                .push(bytes.to_vec());
            Ok(())
        }

        async fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let packet = self.recv.pop_front().ok_or_else(|| {
                io::Error::new(io::ErrorKind::UnexpectedEof, "QueueIo receive queue empty")
            })?;
            if packet.len() > buf.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "packet too large",
                ));
            }
            buf[..packet.len()].copy_from_slice(&packet);
            Ok(packet.len())
        }
    }

    fn encode_ping_frame(nonce: u64) -> Vec<u8> {
        let payload = PingPayload { nonce };
        let mut payload_buf = Vec::new();
        payload.encode(&mut payload_buf);

        let mut frame = Vec::new();
        encode_message(
            Message::Ping {
                payload: &payload_buf,
            },
            &mut frame,
        )
        .unwrap();
        frame
    }

    fn encode_pong_frame(nonce: u64) -> Vec<u8> {
        let wire = nonce.to_be_bytes();
        let mut frame = Vec::new();
        encode_message(Message::Pong { payload: &wire }, &mut frame).unwrap();
        frame
    }

    fn decode_one(frame: &[u8], limits: MessageLimits) -> Message<'_> {
        let (message, consumed) = decode_message(frame, limits).unwrap().unwrap();
        assert_eq!(consumed, frame.len());
        message
    }

    fn set_rekey_policy<I: SessionIo>(
        session: &mut QuicQspSession<I>,
        interval: u64,
        late_margin: u64,
        dead_failures: u32,
    ) {
        session.rekey_policy = RekeyPolicy {
            interval,
            late_margin,
            dead_failures,
        };
        session.tx_next_rekey_pn = next_rekey_after(session.next_pn, interval);
        session.rx_next_rekey_pn = next_rekey_after(session.expected_pn(), interval);
        session.previous_rx = None;
        session.consecutive_decrypt_failures = 0;
    }

    fn symmetric_keys() -> UdpQspKeys {
        UdpQspKeys::new(
            CipherSuite::Aes128Gcm,
            [0x11; UDP_QSP_TRAFFIC_SECRET_LEN],
            [0x11; UDP_QSP_TRAFFIC_SECRET_LEN],
        )
        .unwrap()
    }

    #[tokio::test]
    async fn replace_io_preserves_packet_numbers_replay_window_and_rekey_state() {
        let keys = symmetric_keys();
        let scid = Cid::from([0xCD; 20]);
        let dcid = Cid::from([0xAB; 20]);
        let scid_len = scid.len();
        let replayed_packet = keys.protect(dcid.as_slice(), 0, false, b"inbound").unwrap();
        let (io, _old_sent) = QueueIo::new(vec![replayed_packet.clone()]);
        let mut session =
            QuicQspSession::new(io, scid, dcid, keys.try_clone().unwrap(), 1, 0, false);
        set_rekey_policy(
            &mut session,
            2,
            KEY_UPDATE_LATE_MARGIN,
            DEAD_CHANNEL_FAILURE_THRESHOLD,
        );

        let mut packet_buf = vec![0u8; 2048];
        let opened = session.recv(&mut packet_buf).await.unwrap();
        assert_eq!(opened.pn, 0);
        assert_eq!(opened.payload, b"inbound");
        assert_eq!(session.expected_pn(), 1);
        assert_eq!(session.next_pn(), 1);
        assert!(!session.tx_key_phase());

        let (replacement_io, replacement_sent) = QueueIo::new(vec![replayed_packet]);
        let _old_io = session.replace_io(replacement_io);
        assert_eq!(session.expected_pn(), 1);
        assert_eq!(session.next_pn(), 1);
        assert!(!session.tx_key_phase());

        assert!(matches!(
            session.recv(&mut packet_buf).await,
            Err(QspSessionError::Replay)
        ));

        session.send(b"first-after-replace").await.unwrap();
        assert_eq!(session.next_pn(), 2);
        assert!(!session.tx_key_phase());

        let first_sent = {
            let sent = replacement_sent.lock().expect("replacement sent lock");
            assert_eq!(sent.len(), 1);
            sent[0].clone()
        };
        let mut opened_payload = Vec::new();
        let opened = keys
            .open_into(scid_len, &first_sent, 1, &mut opened_payload)
            .unwrap();
        assert_eq!(opened.pn, 1);
        assert_eq!(opened.payload, b"first-after-replace");

        session.send(b"second-after-replace").await.unwrap();
        assert_eq!(session.next_pn(), 3);
        assert!(session.tx_key_phase());
    }

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

        let keys = UdpQspKeys::from_packet_material(
            CipherSuite::Aes128Gcm,
            [0x11; HP_KEY_LEN],
            [0x11; HP_KEY_LEN],
            [0x33; AEAD_KEY_LEN],
            [0x33; AEAD_KEY_LEN],
            [0x55; AEAD_IV_LEN],
            [0x55; AEAD_IV_LEN],
        )
        .unwrap();
        let dcid = Cid::from([0xAB; 20]);
        let packet = keys.protect(dcid.as_slice(), 7, false, b"hello").unwrap();

        let io = TestIo {
            packet: packet.clone(),
            sent: Vec::new(),
        };
        let mut session = QuicQspSession::new(io, Cid::from([0xCD; 20]), dcid, keys, 0, 7, false);
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

        let keys = UdpQspKeys::from_packet_material(
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
            Cid::from([0xCD; 20]),
            Cid::from([0xAB; 20]),
            keys,
            u64::MAX,
            0,
            false,
        );

        assert!(matches!(
            session.send(b"hello").await,
            Err(QspSessionError::PacketNumberOverflow)
        ));
    }

    #[tokio::test]
    async fn session_recv_accepts_packet_number_above_u32_max() {
        struct TestIo {
            packet: Vec<u8>,
        }

        impl SessionIo for TestIo {
            async fn send(&mut self, _bytes: &[u8]) -> io::Result<()> {
                Ok(())
            }

            async fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                let len = self.packet.len();
                buf[..len].copy_from_slice(&self.packet);
                Ok(len)
            }
        }

        let keys = UdpQspKeys::from_packet_material(
            CipherSuite::Aes128Gcm,
            [0x11; HP_KEY_LEN],
            [0x11; HP_KEY_LEN],
            [0x33; AEAD_KEY_LEN],
            [0x33; AEAD_KEY_LEN],
            [0x55; AEAD_IV_LEN],
            [0x55; AEAD_IV_LEN],
        )
        .unwrap();

        let pn = u64::from(u32::MAX) + 7;
        let dcid = Cid::from([0xAB; 20]);
        let packet = keys.protect(dcid.as_slice(), pn, false, b"hello").unwrap();

        let io = TestIo { packet };
        let mut session = QuicQspSession::new(io, Cid::from([0xCD; 20]), dcid, keys, 0, pn, false);
        let mut buf = vec![0u8; 1500];

        let opened = session.recv(&mut buf).await.unwrap();
        assert_eq!(opened.pn, pn);
        assert_eq!(opened.payload, b"hello");
    }

    #[tokio::test]
    async fn session_roundtrip_with_large_packet_number() {
        let (c2s_tx, c2s_rx) = mpsc::channel::<Vec<u8>>(8);
        let (s2c_tx, s2c_rx) = mpsc::channel::<Vec<u8>>(8);

        let hp_c2s = [0x11; HP_KEY_LEN];
        let hp_s2c = [0x22; HP_KEY_LEN];
        let aead_c2s = [0x33; AEAD_KEY_LEN];
        let aead_s2c = [0x44; AEAD_KEY_LEN];
        let iv_c2s = [0x55; AEAD_IV_LEN];
        let iv_s2c = [0x66; AEAD_IV_LEN];

        let keys_client = UdpQspKeys::from_packet_material(
            CipherSuite::Aes128Gcm,
            hp_c2s,
            hp_s2c,
            aead_c2s,
            aead_s2c,
            iv_c2s,
            iv_s2c,
        )
        .unwrap();
        let keys_server = UdpQspKeys::from_packet_material(
            CipherSuite::Aes128Gcm,
            hp_s2c,
            hp_c2s,
            aead_s2c,
            aead_c2s,
            iv_s2c,
            iv_c2s,
        )
        .unwrap();

        let client_scid = Cid::from([0xA1; 20]);
        let server_scid = Cid::from([0xB2; 20]);
        let pn = u64::from(u32::MAX) + 17;

        let mut client = QuicQspSession::new(
            ChanIo {
                tx: c2s_tx,
                rx: s2c_rx,
            },
            client_scid,
            server_scid,
            keys_client,
            pn,
            pn,
            false,
        );
        let mut server = QuicQspSession::new(
            ChanIo {
                tx: s2c_tx,
                rx: c2s_rx,
            },
            server_scid,
            client_scid,
            keys_server,
            pn,
            pn,
            false,
        );

        let limits = MessageLimits::new(2048, 2048);
        let mut packet_buf = vec![0u8; 2048];

        let nonce = 0xCAFE_BABE_DEAD_BEEFu64;
        let frame = encode_ping_frame(nonce);
        client.send(&frame).await.unwrap();
        let opened = server.recv(&mut packet_buf).await.unwrap();
        assert_eq!(opened.pn, pn);
        let Message::Ping { payload } = decode_one(opened.payload, limits) else {
            panic!("expected ping");
        };
        assert_eq!(PingPayload::decode(payload).unwrap().nonce, nonce);

        let frame = encode_pong_frame(nonce);
        server.send(&frame).await.unwrap();
        let opened = client.recv(&mut packet_buf).await.unwrap();
        assert_eq!(opened.pn, pn);
        let Message::Pong { payload } = decode_one(opened.payload, limits) else {
            panic!("expected pong");
        };
        assert_eq!(PongPayload::decode(payload).unwrap().nonce, nonce);
    }

    #[tokio::test]
    async fn session_roundtrips_framed_messages_over_in_memory_io() {
        let (c2s_tx, c2s_rx) = mpsc::channel::<Vec<u8>>(8);
        let (s2c_tx, s2c_rx) = mpsc::channel::<Vec<u8>>(8);

        let hp_c2s = [0x11; HP_KEY_LEN];
        let hp_s2c = [0x22; HP_KEY_LEN];
        let aead_c2s = [0x33; AEAD_KEY_LEN];
        let aead_s2c = [0x44; AEAD_KEY_LEN];
        let iv_c2s = [0x55; AEAD_IV_LEN];
        let iv_s2c = [0x66; AEAD_IV_LEN];

        let keys_client = UdpQspKeys::from_packet_material(
            CipherSuite::Aes128Gcm,
            hp_c2s,
            hp_s2c,
            aead_c2s,
            aead_s2c,
            iv_c2s,
            iv_s2c,
        )
        .unwrap();
        let keys_server = UdpQspKeys::from_packet_material(
            CipherSuite::Aes128Gcm,
            hp_s2c,
            hp_c2s,
            aead_s2c,
            aead_c2s,
            iv_s2c,
            iv_c2s,
        )
        .unwrap();

        let client_scid = Cid::from([0xA1; 20]);
        let server_scid = Cid::from([0xB2; 20]);

        let mut client = QuicQspSession::new(
            ChanIo {
                tx: c2s_tx,
                rx: s2c_rx,
            },
            client_scid,
            server_scid,
            keys_client,
            0,
            0,
            false,
        );
        let mut server = QuicQspSession::new(
            ChanIo {
                tx: s2c_tx,
                rx: c2s_rx,
            },
            server_scid,
            client_scid,
            keys_server,
            0,
            0,
            false,
        );

        let limits = MessageLimits::new(2048, 2048);
        let mut packet_buf = vec![0u8; 2048];

        let nonce = 0x1122_3344_5566_7788_u64;
        let frame = encode_ping_frame(nonce);
        client.send(&frame).await.unwrap();
        let opened = server.recv(&mut packet_buf).await.unwrap();
        assert_eq!(opened.pn, 0);
        let Message::Ping { payload } = decode_one(opened.payload, limits) else {
            panic!("expected ping");
        };
        assert_eq!(PingPayload::decode(payload).unwrap().nonce, nonce);

        let frame = encode_pong_frame(nonce);
        server.send(&frame).await.unwrap();
        let opened = client.recv(&mut packet_buf).await.unwrap();
        assert_eq!(opened.pn, 0);
        let Message::Pong { payload } = decode_one(opened.payload, limits) else {
            panic!("expected pong");
        };
        assert_eq!(PongPayload::decode(payload).unwrap().nonce, nonce);
    }

    #[tokio::test]
    async fn session_rekeys_at_interval_and_accepts_new_phase() {
        struct CaptureIo {
            sent: Vec<Vec<u8>>,
        }

        impl SessionIo for CaptureIo {
            async fn send(&mut self, bytes: &[u8]) -> io::Result<()> {
                self.sent.push(bytes.to_vec());
                Ok(())
            }

            async fn recv(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::new(io::ErrorKind::WouldBlock, "no recv"))
            }
        }

        let keys = UdpQspKeys::from_packet_material(
            CipherSuite::Aes128Gcm,
            [0x11; HP_KEY_LEN],
            [0x11; HP_KEY_LEN],
            [0x33; AEAD_KEY_LEN],
            [0x33; AEAD_KEY_LEN],
            [0x55; AEAD_IV_LEN],
            [0x55; AEAD_IV_LEN],
        )
        .unwrap();
        let dcid = Cid::from([0xAB; 20]);
        let scid = Cid::from([0xCD; 20]);
        let limits = MessageLimits::new(2048, 2048);

        let mut sender = QuicQspSession::new(
            CaptureIo { sent: Vec::new() },
            scid,
            dcid,
            keys.try_clone().unwrap(),
            0,
            0,
            false,
        );
        let mut receiver = QuicQspSession::new(
            CaptureIo { sent: Vec::new() },
            scid,
            dcid,
            keys,
            0,
            0,
            false,
        );
        set_rekey_policy(&mut sender, 8, 16, 4);
        set_rekey_policy(&mut receiver, 8, 16, 4);

        for nonce in 0..=8u64 {
            let frame = encode_ping_frame(nonce);
            sender.send(&frame).await.unwrap();
        }

        for nonce in 0usize..=7usize {
            let opened = receiver.open_packet(&sender.io.sent[nonce]).unwrap();
            assert!(!opened.key_phase);
            let Message::Ping { payload } = decode_one(opened.payload, limits) else {
                panic!("expected ping");
            };
            assert_eq!(PingPayload::decode(payload).unwrap().nonce, nonce as u64);
        }

        let opened = receiver.open_packet(&sender.io.sent[8]).unwrap();
        assert!(opened.key_phase);
        let Message::Ping { payload } = decode_one(opened.payload, limits) else {
            panic!("expected ping");
        };
        assert_eq!(PingPayload::decode(payload).unwrap().nonce, 8);
    }

    #[tokio::test]
    async fn session_accepts_reordered_old_phase_packet_within_grace() {
        struct CaptureIo {
            sent: Vec<Vec<u8>>,
        }

        impl SessionIo for CaptureIo {
            async fn send(&mut self, bytes: &[u8]) -> io::Result<()> {
                self.sent.push(bytes.to_vec());
                Ok(())
            }

            async fn recv(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::new(io::ErrorKind::WouldBlock, "no recv"))
            }
        }

        let keys = UdpQspKeys::from_packet_material(
            CipherSuite::Aes128Gcm,
            [0x11; HP_KEY_LEN],
            [0x11; HP_KEY_LEN],
            [0x33; AEAD_KEY_LEN],
            [0x33; AEAD_KEY_LEN],
            [0x55; AEAD_IV_LEN],
            [0x55; AEAD_IV_LEN],
        )
        .unwrap();
        let dcid = Cid::from([0xAB; 20]);
        let scid = Cid::from([0xCD; 20]);
        let limits = MessageLimits::new(2048, 2048);

        let mut sender = QuicQspSession::new(
            CaptureIo { sent: Vec::new() },
            scid,
            dcid,
            keys.try_clone().unwrap(),
            0,
            0,
            false,
        );
        let mut receiver = QuicQspSession::new(
            CaptureIo { sent: Vec::new() },
            scid,
            dcid,
            keys,
            0,
            0,
            false,
        );
        set_rekey_policy(&mut sender, 8, 16, 4);
        set_rekey_policy(&mut receiver, 8, 16, 4);

        for nonce in 0..=8u64 {
            let frame = encode_ping_frame(nonce);
            sender.send(&frame).await.unwrap();
        }

        for nonce in 0usize..=6usize {
            let opened = receiver.open_packet(&sender.io.sent[nonce]).unwrap();
            assert!(!opened.key_phase);
        }

        let opened = receiver.open_packet(&sender.io.sent[8]).unwrap();
        assert!(opened.key_phase);
        let Message::Ping { payload } = decode_one(opened.payload, limits) else {
            panic!("expected ping");
        };
        assert_eq!(PingPayload::decode(payload).unwrap().nonce, 8);

        let opened = receiver.open_packet(&sender.io.sent[7]).unwrap();
        assert!(!opened.key_phase);
        let Message::Ping { payload } = decode_one(opened.payload, limits) else {
            panic!("expected ping");
        };
        assert_eq!(PingPayload::decode(payload).unwrap().nonce, 7);
    }

    #[test]
    fn session_marks_dead_channel_after_late_crypto_failures() {
        struct TestIo;

        impl SessionIo for TestIo {
            async fn send(&mut self, _bytes: &[u8]) -> io::Result<()> {
                Ok(())
            }

            async fn recv(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::new(io::ErrorKind::WouldBlock, "no recv"))
            }
        }

        let keys_a = UdpQspKeys::from_packet_material(
            CipherSuite::Aes128Gcm,
            [0x11; HP_KEY_LEN],
            [0x11; HP_KEY_LEN],
            [0x33; AEAD_KEY_LEN],
            [0x33; AEAD_KEY_LEN],
            [0x55; AEAD_IV_LEN],
            [0x55; AEAD_IV_LEN],
        )
        .unwrap();
        let keys_b = UdpQspKeys::from_packet_material(
            CipherSuite::Aes128Gcm,
            [0x21; HP_KEY_LEN],
            [0x21; HP_KEY_LEN],
            [0x43; AEAD_KEY_LEN],
            [0x43; AEAD_KEY_LEN],
            [0x65; AEAD_IV_LEN],
            [0x65; AEAD_IV_LEN],
        )
        .unwrap();

        let mut receiver = QuicQspSession::new(
            TestIo,
            Cid::from([0xCD; 20]),
            Cid::from([0xAB; 20]),
            keys_a,
            0,
            100,
            false,
        );
        set_rekey_policy(&mut receiver, 8, 1, 3);
        receiver.rx_next_rekey_pn = Some(90);

        let packet = keys_b
            .protect(receiver.scid().as_slice(), 100, false, b"late-fail")
            .unwrap();

        assert!(matches!(
            receiver.open_packet(&packet),
            Err(QspSessionError::Crypto(QspCryptoError::CryptoFail))
        ));
        assert!(matches!(
            receiver.open_packet(&packet),
            Err(QspSessionError::Crypto(QspCryptoError::CryptoFail))
        ));
        assert!(matches!(
            receiver.open_packet(&packet),
            Err(QspSessionError::DeadChannel)
        ));
    }

    // =========================================================================
    // Edge case tests for pn_distance
    // =========================================================================

    #[test]
    fn pn_distance_handles_wraparound() {
        // Test pn_distance correctness for various value combinations
        assert_eq!(pn_distance(0, 0), 0);
        assert_eq!(pn_distance(100, 50), 50);
        assert_eq!(pn_distance(50, 100), 50);
        assert_eq!(pn_distance(u64::MAX, 0), u64::MAX);
        assert_eq!(pn_distance(0, u64::MAX), u64::MAX);
        assert_eq!(pn_distance(u64::MAX - 1, u64::MAX), 1);
        assert_eq!(pn_distance(u64::MAX, u64::MAX - 1), 1);
        assert_eq!(pn_distance(u64::MAX / 2, u64::MAX / 2 + 100), 100);
    }

    // =========================================================================
    // Edge case tests for ReplayWindow
    // =========================================================================

    #[test]
    fn replay_window_shift_with_various_deltas() {
        // Test window shift with delta smaller than window size
        let mut window = ReplayWindow::new(0);
        window.check_and_update(100).unwrap();
        assert!(window.check_and_update(50).is_ok()); // within window

        // Test window shift with delta equal to window size
        let mut window = ReplayWindow::new(0);
        window.check_and_update(0).unwrap();
        window.check_and_update(PN_REPLAY_WINDOW as u64).unwrap();
        // Now 0 should be TooOld since window shifted completely
        assert_eq!(window.check_and_update(0), Err(ReplayError::TooOld));

        // Test window shift with delta larger than window size (full reset)
        let mut window = ReplayWindow::new(0);
        window.check_and_update(0).unwrap();
        window
            .check_and_update((PN_REPLAY_WINDOW * 2) as u64)
            .unwrap();
        // Window should be completely reset
        assert_eq!(window.largest_pn(), Some((PN_REPLAY_WINDOW * 2) as u64));
    }

    #[test]
    fn replay_window_with_large_packet_numbers() {
        let mut window = ReplayWindow::new(u64::MAX / 2);

        // Accept first packet
        window.check_and_update(u64::MAX / 2).unwrap();
        assert_eq!(window.largest_pn(), Some(u64::MAX / 2));

        // Accept later packet
        window.check_and_update(u64::MAX / 2 + 100).unwrap();
        assert_eq!(window.largest_pn(), Some(u64::MAX / 2 + 100));

        // Accept earlier packet within window
        window.check_and_update(u64::MAX / 2 + 50).unwrap();

        // Reject too old
        let too_old = u64::MAX / 2 - PN_REPLAY_WINDOW as u64 - 1;
        assert_eq!(window.check_and_update(too_old), Err(ReplayError::TooOld));
    }

    // =========================================================================
    // Edge case tests for next_rekey_after
    // =========================================================================

    #[test]
    fn next_rekey_after_handles_zero_interval() {
        // With interval = 0, should return None (no rekeying)
        assert_eq!(next_rekey_after(0, 0), None);
        assert_eq!(next_rekey_after(100, 0), None);
        assert_eq!(next_rekey_after(u64::MAX, 0), None);
    }

    #[test]
    fn next_rekey_after_handles_overflow() {
        // With interval = 10, starting from MAX - 5, the next rekey would overflow
        // MAX - 5 = ...610, which is divisible by 10, so step = 10
        // MAX - 5 + 10 = MAX + 5 which overflows
        assert_eq!(next_rekey_after(u64::MAX - 5, 10), None);

        // With interval = 1 at MAX, should overflow (step = 1, MAX + 1 overflows)
        assert_eq!(next_rekey_after(u64::MAX, 1), None);

        // At MAX - 9, interval 10: rem = 6, step = 4, result = MAX - 9 + 4 = MAX - 5
        assert_eq!(next_rekey_after(u64::MAX - 9, 10), Some(u64::MAX - 5));

        // At MAX - 10, interval 10: rem = 5, step = 5, result = MAX - 10 + 5 = MAX - 5
        assert_eq!(next_rekey_after(u64::MAX - 10, 10), Some(u64::MAX - 5));

        // At MAX - 5, interval 10: rem = 0, step = 10, overflow
        assert_eq!(next_rekey_after(u64::MAX - 5, 10), None);

        // Edge case: exactly at MAX with interval that would overflow
        assert_eq!(next_rekey_after(u64::MAX, 10), None);
    }

    #[test]
    fn next_rekey_after_at_interval_boundaries() {
        // At pn = 0, interval = 100, next rekey at 100
        assert_eq!(next_rekey_after(0, 100), Some(100));

        // At pn = 50, interval = 100, next rekey at 100
        assert_eq!(next_rekey_after(50, 100), Some(100));

        // At pn = 100 (exactly at boundary), next rekey at 200
        assert_eq!(next_rekey_after(100, 100), Some(200));

        // At pn = 99, interval = 100, next rekey at 100
        assert_eq!(next_rekey_after(99, 100), Some(100));
    }

    // =========================================================================
    // Key rotation cycle tests
    // =========================================================================

    #[tokio::test]
    async fn full_key_rotation_cycle_tx_direction() {
        struct CaptureIo {
            sent: Vec<Vec<u8>>,
        }

        impl SessionIo for CaptureIo {
            async fn send(&mut self, bytes: &[u8]) -> io::Result<()> {
                self.sent.push(bytes.to_vec());
                Ok(())
            }

            async fn recv(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::new(io::ErrorKind::WouldBlock, "no recv"))
            }
        }

        let keys = UdpQspKeys::from_packet_material(
            CipherSuite::Aes128Gcm,
            [0x11; HP_KEY_LEN],
            [0x11; HP_KEY_LEN],
            [0x33; AEAD_KEY_LEN],
            [0x33; AEAD_KEY_LEN],
            [0x55; AEAD_IV_LEN],
            [0x55; AEAD_IV_LEN],
        )
        .unwrap();
        let dcid = Cid::from([0xAB; 20]);
        let scid = Cid::from([0xCD; 20]);

        let mut sender = QuicQspSession::new(
            CaptureIo { sent: Vec::new() },
            scid,
            dcid,
            keys.try_clone().unwrap(),
            0,
            0,
            false,
        );
        // Use interval=8 to trigger rotation at packet 8
        set_rekey_policy(&mut sender, 8, 16, 4);

        // Phase 0: packets 0-7 (no rotation yet)
        for _ in 0..8 {
            sender.send(b"test").await.unwrap();
        }
        assert!(
            !sender.tx_key_phase(),
            "after packets 0-7, phase should still be 0"
        );

        // Packet 8 triggers rotation to phase 1
        sender.send(b"test").await.unwrap();
        assert!(
            sender.tx_key_phase(),
            "after packet 8, phase should flip to 1"
        );

        // Phase 1: packets 9-15
        for _ in 0..7 {
            sender.send(b"test").await.unwrap();
        }
        assert!(
            sender.tx_key_phase(),
            "during phase 1 (packets 9-15), phase should remain 1"
        );

        // Verify we have 16 packets total
        assert_eq!(sender.io.sent.len(), 16);
    }

    #[tokio::test]
    async fn full_key_rotation_cycle_rx_direction() {
        struct CaptureIo {
            sent: Vec<Vec<u8>>,
        }

        impl SessionIo for CaptureIo {
            async fn send(&mut self, bytes: &[u8]) -> io::Result<()> {
                self.sent.push(bytes.to_vec());
                Ok(())
            }

            async fn recv(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::new(io::ErrorKind::WouldBlock, "no recv"))
            }
        }

        let keys = UdpQspKeys::from_packet_material(
            CipherSuite::Aes128Gcm,
            [0x11; HP_KEY_LEN],
            [0x11; HP_KEY_LEN],
            [0x33; AEAD_KEY_LEN],
            [0x33; AEAD_KEY_LEN],
            [0x55; AEAD_IV_LEN],
            [0x55; AEAD_IV_LEN],
        )
        .unwrap();
        let dcid = Cid::from([0xAB; 20]);
        let scid = Cid::from([0xCD; 20]);

        let mut sender = QuicQspSession::new(
            CaptureIo { sent: Vec::new() },
            scid,
            dcid,
            keys.try_clone().unwrap(),
            0,
            0,
            false,
        );
        let mut receiver = QuicQspSession::new(
            CaptureIo { sent: Vec::new() },
            scid,
            dcid,
            keys,
            0,
            0,
            false,
        );
        set_rekey_policy(&mut sender, 8, 16, 4);
        set_rekey_policy(&mut receiver, 8, 16, 4);

        // Phase 0: packets 0-7
        for _nonce in 0..8u64 {
            sender.send(b"test").await.unwrap();
        }
        for nonce in 0..8usize {
            let opened = receiver.open_packet(&sender.io.sent[nonce]).unwrap();
            assert!(!opened.key_phase, "packet {nonce} should be phase 0");
        }
        assert!(
            !receiver.rx_key_phase(),
            "receiver phase should still be 0 after packets 0-7"
        );

        // Packet 8 triggers rotation to phase 1
        sender.send(b"test").await.unwrap();
        let opened = receiver.open_packet(&sender.io.sent[8]).unwrap();
        assert!(opened.key_phase, "packet 8 should be phase 1");
        assert!(
            receiver.rx_key_phase(),
            "receiver phase should be 1 after packet 8"
        );

        // Phase 1: packets 9-15 (still in phase 1)
        for _nonce in 9..16u64 {
            sender.send(b"test").await.unwrap();
        }
        for nonce in 9..16usize {
            let opened = receiver.open_packet(&sender.io.sent[nonce]).unwrap();
            assert!(opened.key_phase, "packet {nonce} should be phase 1");
        }
        assert!(
            receiver.rx_key_phase(),
            "receiver phase should still be 1 after packets 9-15"
        );
    }

    #[tokio::test]
    async fn key_phase_transition_at_exact_threshold_boundary() {
        struct CaptureIo {
            sent: Vec<Vec<u8>>,
        }

        impl SessionIo for CaptureIo {
            async fn send(&mut self, bytes: &[u8]) -> io::Result<()> {
                self.sent.push(bytes.to_vec());
                Ok(())
            }

            async fn recv(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::new(io::ErrorKind::WouldBlock, "no recv"))
            }
        }

        let keys = UdpQspKeys::from_packet_material(
            CipherSuite::Aes128Gcm,
            [0x11; HP_KEY_LEN],
            [0x11; HP_KEY_LEN],
            [0x33; AEAD_KEY_LEN],
            [0x33; AEAD_KEY_LEN],
            [0x55; AEAD_IV_LEN],
            [0x55; AEAD_IV_LEN],
        )
        .unwrap();
        let dcid = Cid::from([0xAB; 20]);
        let scid = Cid::from([0xCD; 20]);

        let mut sender = QuicQspSession::new(
            CaptureIo { sent: Vec::new() },
            scid,
            dcid,
            keys.try_clone().unwrap(),
            0,
            0,
            false,
        );
        let mut receiver = QuicQspSession::new(
            CaptureIo { sent: Vec::new() },
            scid,
            dcid,
            keys,
            0,
            0,
            false,
        );
        set_rekey_policy(&mut sender, 8, 16, 4);
        set_rekey_policy(&mut receiver, 8, 16, 4);

        // Send packets 0-6 (phase 0)
        for nonce in 0..7u64 {
            sender.send(b"test").await.unwrap();
            let opened = receiver
                .open_packet(&sender.io.sent[nonce as usize])
                .unwrap();
            assert!(!opened.key_phase, "packet {nonce} should be phase 0");
        }

        // Packet 7 (still phase 0 - boundary is at 8)
        sender.send(b"test").await.unwrap();
        let opened = receiver.open_packet(&sender.io.sent[7]).unwrap();
        assert!(!opened.key_phase, "packet 7 should still be phase 0");

        // Packet 8 (exact boundary - triggers phase 1)
        sender.send(b"test").await.unwrap();
        let opened = receiver.open_packet(&sender.io.sent[8]).unwrap();
        assert!(opened.key_phase, "packet 8 should be phase 1");
    }

    // =========================================================================
    // Failure handling tests
    // =========================================================================

    #[test]
    fn consecutive_decrypt_failures_increment_counter() {
        struct TestIo;

        impl SessionIo for TestIo {
            async fn send(&mut self, _bytes: &[u8]) -> io::Result<()> {
                Ok(())
            }

            async fn recv(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::new(io::ErrorKind::WouldBlock, "no recv"))
            }
        }

        let keys_a = UdpQspKeys::from_packet_material(
            CipherSuite::Aes128Gcm,
            [0x11; HP_KEY_LEN],
            [0x11; HP_KEY_LEN],
            [0x33; AEAD_KEY_LEN],
            [0x33; AEAD_KEY_LEN],
            [0x55; AEAD_IV_LEN],
            [0x55; AEAD_IV_LEN],
        )
        .unwrap();
        let keys_b = UdpQspKeys::from_packet_material(
            CipherSuite::Aes128Gcm,
            [0x21; HP_KEY_LEN],
            [0x21; HP_KEY_LEN],
            [0x43; AEAD_KEY_LEN],
            [0x43; AEAD_KEY_LEN],
            [0x65; AEAD_IV_LEN],
            [0x65; AEAD_IV_LEN],
        )
        .unwrap();

        let mut receiver = QuicQspSession::new(
            TestIo,
            Cid::from([0xCD; 20]),
            Cid::from([0xAB; 20]),
            keys_a,
            0,
            100,
            false,
        );
        // Use high threshold so we can observe increment
        set_rekey_policy(&mut receiver, 8, 1, 100);

        let packet = keys_b
            .protect(receiver.scid().as_slice(), 100, false, b"fail")
            .unwrap();

        assert_eq!(receiver.consecutive_decrypt_failures, 0);
        let _ = receiver.open_packet(&packet);
        assert_eq!(receiver.consecutive_decrypt_failures, 1);
        let _ = receiver.open_packet(&packet);
        assert_eq!(receiver.consecutive_decrypt_failures, 2);
        let _ = receiver.open_packet(&packet);
        assert_eq!(receiver.consecutive_decrypt_failures, 3);
    }

    #[test]
    fn counter_resets_on_successful_decrypt() {
        struct TestIo;

        impl SessionIo for TestIo {
            async fn send(&mut self, _bytes: &[u8]) -> io::Result<()> {
                Ok(())
            }

            async fn recv(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::new(io::ErrorKind::WouldBlock, "no recv"))
            }
        }

        let keys = UdpQspKeys::from_packet_material(
            CipherSuite::Aes128Gcm,
            [0x11; HP_KEY_LEN],
            [0x11; HP_KEY_LEN],
            [0x33; AEAD_KEY_LEN],
            [0x33; AEAD_KEY_LEN],
            [0x55; AEAD_IV_LEN],
            [0x55; AEAD_IV_LEN],
        )
        .unwrap();
        let keys_bad = UdpQspKeys::from_packet_material(
            CipherSuite::Aes128Gcm,
            [0x21; HP_KEY_LEN],
            [0x21; HP_KEY_LEN],
            [0x43; AEAD_KEY_LEN],
            [0x43; AEAD_KEY_LEN],
            [0x65; AEAD_IV_LEN],
            [0x65; AEAD_IV_LEN],
        )
        .unwrap();

        let mut receiver = QuicQspSession::new(
            TestIo,
            Cid::from([0xCD; 20]),
            Cid::from([0xAB; 20]),
            keys.try_clone().unwrap(),
            0,
            100,
            false,
        );
        set_rekey_policy(&mut receiver, 8, 1, 100);

        // Build bad packet to cause failures
        let bad_packet = keys_bad
            .protect(receiver.scid().as_slice(), 100, false, b"fail")
            .unwrap();

        // Cause some failures
        let _ = receiver.open_packet(&bad_packet);
        let _ = receiver.open_packet(&bad_packet);
        assert_eq!(receiver.consecutive_decrypt_failures, 2);

        // Send a valid packet - should reset counter
        let good_packet = keys
            .protect(receiver.scid().as_slice(), 100, false, b"good")
            .unwrap();
        let result = receiver.open_packet(&good_packet);
        assert!(result.is_ok());
        assert_eq!(receiver.consecutive_decrypt_failures, 0);

        // More failures after reset should start from 0
        let _ = receiver.open_packet(&bad_packet);
        assert_eq!(receiver.consecutive_decrypt_failures, 1);
    }

    #[test]
    fn dead_channel_triggered_at_threshold() {
        struct TestIo;

        impl SessionIo for TestIo {
            async fn send(&mut self, _bytes: &[u8]) -> io::Result<()> {
                Ok(())
            }

            async fn recv(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::new(io::ErrorKind::WouldBlock, "no recv"))
            }
        }

        let keys_a = UdpQspKeys::from_packet_material(
            CipherSuite::Aes128Gcm,
            [0x11; HP_KEY_LEN],
            [0x11; HP_KEY_LEN],
            [0x33; AEAD_KEY_LEN],
            [0x33; AEAD_KEY_LEN],
            [0x55; AEAD_IV_LEN],
            [0x55; AEAD_IV_LEN],
        )
        .unwrap();
        let keys_b = UdpQspKeys::from_packet_material(
            CipherSuite::Aes128Gcm,
            [0x21; HP_KEY_LEN],
            [0x21; HP_KEY_LEN],
            [0x43; AEAD_KEY_LEN],
            [0x43; AEAD_KEY_LEN],
            [0x65; AEAD_IV_LEN],
            [0x65; AEAD_IV_LEN],
        )
        .unwrap();

        let mut receiver = QuicQspSession::new(
            TestIo,
            Cid::from([0xCD; 20]),
            Cid::from([0xAB; 20]),
            keys_a,
            0,
            100,
            false,
        );
        // Set threshold to exactly 5
        set_rekey_policy(&mut receiver, 8, 1, 5);

        let packet = keys_b
            .protect(receiver.scid().as_slice(), 100, false, b"fail")
            .unwrap();

        // First 4 failures should return CryptoFail
        for _ in 0..4 {
            assert!(matches!(
                receiver.open_packet(&packet),
                Err(QspSessionError::Crypto(QspCryptoError::CryptoFail))
            ));
        }

        // 5th failure should trigger DeadChannel (counter reaches threshold)
        assert!(matches!(
            receiver.open_packet(&packet),
            Err(QspSessionError::DeadChannel)
        ));
    }

    // =========================================================================
    // Session flush / peer-update proxying contract
    // =========================================================================

    fn buffering_keys() -> UdpQspKeys {
        UdpQspKeys::new(
            CipherSuite::Aes128Gcm,
            [0x11; UDP_QSP_TRAFFIC_SECRET_LEN],
            [0x11; UDP_QSP_TRAFFIC_SECRET_LEN],
        )
        .unwrap()
    }

    #[tokio::test]
    async fn session_proxies_flush_and_pending_flush_state() {
        let (io, state) = BufferingIo::pair();
        let mut session = QuicQspSession::new(
            io,
            Cid::from([0xCD; 20]),
            Cid::from([0xAB; 20]),
            buffering_keys(),
            0,
            0,
            false,
        );

        assert!(!session.has_pending_flush());

        // `send` buffers through the underlying I/O, so a pending flush becomes
        // visible through the session's proxy.
        session.send(b"hello").await.unwrap();
        assert!(session.has_pending_flush());
        assert_eq!(state.lock().expect("state lock").pending.len(), 1);
        assert!(state.lock().expect("state lock").flushed.is_empty());

        // `flush` proxies to the I/O layer and drains the buffered packet.
        session.flush().await.unwrap();
        assert!(!session.has_pending_flush());
        assert!(state.lock().expect("state lock").pending.is_empty());
        assert_eq!(state.lock().expect("state lock").flushed.len(), 1);
    }

    #[tokio::test]
    async fn session_proxies_set_peer_to_io() {
        let (io, state) = BufferingIo::pair();
        let mut session = QuicQspSession::new(
            io,
            Cid::from([0xCD; 20]),
            Cid::from([0xAB; 20]),
            buffering_keys(),
            0,
            0,
            false,
        );

        assert!(state.lock().expect("state lock").last_peer.is_none());

        let peer: SocketAddr = "127.0.0.1:9999".parse().expect("valid addr");
        session.set_peer(peer);

        assert_eq!(state.lock().expect("state lock").last_peer, Some(peer));
    }
}
