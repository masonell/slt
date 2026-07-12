//! UDP-QSP session state and replay handling.

use std::future::Future;
use std::io;
use std::net::SocketAddr;

use super::pn::packet_number_len;
use super::{OpenedPacketRef, QspCryptoError, UdpQspKeys};
use crate::types::Cid;

/// Number of packets tracked for replay protection.
pub const PN_REPLAY_WINDOW: usize = 1024;
/// Default packets per key phase before rotating UDP-QSP keys.
pub const KEY_UPDATE_INTERVAL: u64 = 1 << 21;
/// Late packet-number margin where receiver still accepts old keys.
pub const KEY_UPDATE_LATE_MARGIN: u64 = (PN_REPLAY_WINDOW as u64) * 8;

const MIN_KEY_UPDATE_DETECTION_PN: u64 = KEY_UPDATE_INTERVAL.saturating_sub(KEY_UPDATE_LATE_MARGIN);
const MIN_KEY_UPDATE_DETECTION_PN_LEN: usize = packet_number_len(MIN_KEY_UPDATE_DETECTION_PN);
const MIN_KEY_UPDATE_RECONSTRUCTION_HALF_WINDOW: u64 =
    1u64 << (MIN_KEY_UPDATE_DETECTION_PN_LEN * 8 - 1);

// The receiver starts trying candidate RX keys before the rekey threshold, and
// the first new-phase packet may arrive after it. Keep the full detection span
// inside packet-number reconstruction's half-window for the shortest PN length
// used in that span.
const _: () =
    assert!(KEY_UPDATE_LATE_MARGIN.saturating_mul(2) < MIN_KEY_UPDATE_RECONSTRUCTION_HALF_WINDOW);

const WINDOW_WORD_BITS: usize = 64;
const WINDOW_WORDS: usize = PN_REPLAY_WINDOW / WINDOW_WORD_BITS;

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
    /// Discard protected packets buffered for send and return their count.
    ///
    /// This is a hard egress cutover operation. It must not clear receive
    /// queues, peer state, or UDP-QSP cryptographic and replay state.
    fn discard_pending_send(&mut self) -> usize {
        0
    }
}

/// I/O backends that can update their UDP peer address.
pub trait PeerUpdate {
    /// Update the accepted receive peer and outbound transmit destination.
    ///
    /// Protected packets buffered but not submitted to the socket are sent to
    /// the updated peer when flushed. Packets already submitted to the socket
    /// cannot be redirected.
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
                if pn < self.initial_expected {
                    return Err(ReplayError::TooOld);
                }
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
}

impl RekeyPolicy {
    const fn defaults() -> Self {
        Self {
            interval: KEY_UPDATE_INTERVAL,
            late_margin: KEY_UPDATE_LATE_MARGIN,
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
    /// Returns a reference to the decrypted UDP-QSP plaintext stored in the
    /// session. VPN message packets can include trailing transport padding;
    /// decode them with [`crate::proto::decode_padded_message`] when exact
    /// frame bytes are required.
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

    /// Discard protected packets buffered by the I/O layer for send.
    ///
    /// Packet numbers assigned to discarded packets remain consumed. Receive
    /// queues and all UDP-QSP cryptographic, replay, and key-update state remain
    /// intact so the transport can continue as a receive-only path.
    ///
    /// Returns the number of protected packets discarded.
    pub fn discard_pending_send(&mut self) -> usize {
        self.io.discard_pending_send()
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
    /// Returns a reference to the decrypted UDP-QSP plaintext stored in the
    /// session. VPN message packets can include trailing transport padding;
    /// decode them with [`crate::proto::decode_padded_message`] when exact
    /// frame bytes are required.
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
mod tests;
