use std::io;
use std::net::SocketAddr;
#[cfg(unix)]
use std::os::fd::AsFd;
use std::sync::Arc;

#[cfg(not(unix))]
pub use ClientUdpIo as ClientUdpQspIo;
use slt_core::crypto::udp_qsp::{QspSessionError, QuicQspSession, SessionIo};
use slt_core::proto::{FrameError, MessageError};
#[cfg(unix)]
pub use slt_core::transport::UdpQspIo as ClientUdpQspIo;
use tokio::net::UdpSocket;
use tracing::{info, trace, warn};

use crate::metrics::Metrics;

/// A failure from the UDP-QSP transport.
///
/// The variant is the source of truth — it carries the operation's detail and
/// preserves the original error via `#[source]`/`#[from]`. [`Self::is_recoverable`]
/// is the typed recoverable-vs-fatal decision that replaces the old
/// `map_qsp_error` flattening to `io::ErrorKind` (which then got re-derived back
/// into a policy decision at the session boundary by guessing the kind).
///
/// The slt-core UDP-QSP errors (`QspSessionError`, carrying `QspCryptoError`,
/// `ReplayError`, the dead-channel signal, and the underlying socket `io::Error`)
/// are preserved, not flattened: they flow via `#[from]`. The proto encode
/// errors are likewise preserved (`FrameError` and `MessageError` both via
/// `#[from]`; phase 5 promoted `MessageError` to a real `Error` type, so its
/// own `Display` survives to the terminal).
///
/// Actual socket I/O on the UDP path keeps using raw `io::Error` (preserved here
/// via `Io`): the design note scopes this typed error to the *domain* failures —
/// replay/crypto/dead-channel/proto — not to legitimate `send_to`/`recv_from`
/// I/O, which stays `io::Error`.
#[derive(Debug, thiserror::Error)]
pub enum UdpQspError {
    /// Recv-side network-level I/O error from the underlying UDP socket
    /// (`recv_from`). Preserved, not stringified. Only **transient** kinds are
    /// recoverable (see [`Self::is_recoverable`]): one failed datagram recv is
    /// not evidence the UDP path is dead, so the session drops it and keeps the
    /// UDP path alive (the idle-timeout backstops a persistently-failing path).
    /// This is a *deliberate improvement* over the old kind-based behaviour,
    /// which routed a transient recv `io::Error` (`WouldBlock`, `TimedOut`,
    /// `ConnectionRefused`) to TCP fallback / close. Send-side I/O from
    /// `session.send` uses [`Self::SendIo`] (never recoverable); flush-time
    /// send I/O reaches the session separately as a non-recoverable
    /// `SessionError::Io`, so it falls back to TCP the same way.
    #[error(transparent)]
    Io(#[from] io::Error),

    /// Send-side network-level I/O error from `session.send` (`send_to` / GSO
    /// flush). **Never recoverable**: a send failure is not droppable — dropping
    /// it would lose the outbound packet and leave the session sending over a
    /// path that just failed, so it propagates to TCP fallback (or close if TCP
    /// is dead), matching the pre-refactor behaviour. Constructed only by
    /// `UdpQspTransport::write_message`, which re-wraps `QspSessionError::Io` from
    /// `session.send` here so the send-vs-recv distinction survives.
    #[error("udp-qsp send io error: {source}")]
    SendIo {
        /// Preserved underlying socket I/O error from the send.
        #[source]
        source: io::Error,
    },

    /// UDP-QSP session failure: a replayed/too-old packet number, a packet
    /// number overflow, a crypto (header-protection/AEAD) failure, or the
    /// dead-channel signal after too many consecutive decrypt failures.
    ///
    /// Preserved from `slt_core` via `#[from]`; [`Self::is_recoverable`]
    /// classifies the inner variant so the recoverable packet-level failures
    /// (replay, too-old, single crypto failure) can be dropped while the
    /// dead-channel signal and packet-number overflow propagate.
    #[error(transparent)]
    Qsp(#[from] QspSessionError),

    /// Protocol framing error from `encode_message`, preserved from `slt_core`.
    /// Fatal: a version mismatch / corruption that retry won't fix.
    #[error(transparent)]
    Frame(#[from] FrameError),

    /// Protocol message encode/decode error, preserved from `slt_core` via
    /// `#[from]`. Fatal: a version mismatch / corruption that retry won't fix.
    /// `MessageError` is now a real `std::error::Error` in `slt-core` (phase 5
    /// promoted it), so its own `Display` survives to the terminal.
    #[error(transparent)]
    Message(#[from] MessageError),

    /// Received a UDP-QSP packet whose decrypted payload did not contain a
    /// complete framed message. The session dropped the partial packet.
    /// Recoverable: a transient decode outcome, not a fatal session condition.
    #[error("udp-qsp message incomplete")]
    IncompleteMessage,
}

impl UdpQspError {
    /// Recoverable-vs-fatal policy for the UDP-QSP transport.
    ///
    /// Recoverable failures are *droppable* (drop & continue): the session drops
    /// the offending packet and keeps the UDP path alive. Fatal failures must
    /// propagate out of the UDP-QSP transport so the session can take a
    /// session-level decision (TCP fallback when TCP is alive, or session close
    /// otherwise) — they are never silently dropped.
    ///
    /// # Policy
    ///
    /// Recoverable (drop & continue):
    /// - [`Self::Qsp`] with inner `Replay` / `TooOld` / `Crypto(_)` — a single
    ///   bad/garbage/replayed packet. The old `map_qsp_error` flattened these to
    ///   `io::ErrorKind::InvalidData`, which `handle_udp_error` /
    ///   `should_drop_refresh_*` dropped; this path preserves that behaviour.
    /// - [`Self::Qsp`] with inner `QspSessionError::Io(_)` and standalone
    ///   [`Self::Io`] — a UDP socket send/recv failure. Only **transient**
    ///   kinds (`WouldBlock`, `TimedOut`, `ConnectionRefused`,
    ///   `ConnectionReset`) are dropped: one failed datagram is not evidence
    ///   the path is dead, and dropping it is a deliberate improvement over the
    ///   old kind-based path (which routed every non-`InvalidData`/
    ///   non-`ConnectionAborted` `io::Error` to TCP fallback and so tore down
    ///   the UDP path on a single transient recv failure). A **real socket
    ///   failure** (`PermissionDenied`, `NetworkUnreachable`, `HostUnreachable`,
    ///   `BrokenPipe`, `NotConnected`, …) is NOT droppable — it propagates to
    ///   TCP fallback / close / reconnect so the session fails fast instead of
    ///   spinning on a persistent I/O error (and the refresh probe doesn't
    ///   retry until its timeout on an immediate permanent failure).
    /// - [`Self::Frame`] / [`Self::Message`] / [`Self::IncompleteMessage`] — a
    ///   malformed/garbage/partial packet from the peer. Dropped, session
    ///   continues.
    ///
    /// Fatal (propagate out of the UDP-QSP transport):
    /// - [`Self::Qsp`] with inner `DeadChannel` — too many consecutive decrypt
    ///   failures; the peer's keys have diverged beyond recovery. The old code
    ///   flattened this to `ConnectionAborted`, which the session treated as
    ///   fatal; preserved.
    /// - [`Self::Qsp`] with inner `PacketNumberOverflow` — the TX packet-number
    ///   space is exhausted; the session cannot send again on this UDP path.
    ///   Marking this fatal preserves the *old runtime routing*: the old
    ///   `map_qsp_error` flattened it to `io::ErrorKind::QuotaExceeded`, which
    ///   `handle_udp_error` (which only dropped `InvalidData`) routed to TCP
    ///   fallback (or close if TCP was dead) — NOT a drop. The initial phase-3
    ///   recoverable-classification would have *dropped* overflow, diverging
    ///   from that old behaviour and silently losing packets on a session that
    ///   can no longer send; classifying it as fatal here restores the old
    ///   TCP-fallback routing. The session reconnects for a fresh
    ///   packet-number space only once it re-establishes (via the runtime's
    ///   reconnect policy), not as an immediate consequence of the overflow.
    ///
    /// The grouping of arms by policy is deliberate so a reviewer can audit
    /// each variant against the policy above. Pinned by
    /// `recoverable_policy_pins_each_shape` and `is_dead_channel_only_matches_dead_channel`.
    #[allow(clippy::match_same_arms)]
    #[must_use]
    pub fn is_recoverable(&self) -> bool {
        match self {
            // Send-side socket I/O: never droppable — a send failure must
            // propagate to TCP fallback / close (dropping it would lose the
            // outbound packet). See [`Self::SendIo`].
            Self::SendIo { .. } => false,
            // Recv-side socket I/O: only transient kinds (a single failed
            // datagram) are droppable; a real socket failure (PermissionDenied,
            // NetworkUnreachable, BrokenPipe, ...) propagates. See doc above.
            Self::Io(source) | Self::Qsp(QspSessionError::Io(source)) => matches!(
                source.kind(),
                io::ErrorKind::WouldBlock
                    | io::ErrorKind::TimedOut
                    | io::ErrorKind::ConnectionRefused
                    | io::ErrorKind::ConnectionReset
            ),
            // Recoverable: a single bad/replayed/garbage packet is dropped.
            Self::Qsp(QspSessionError::Crypto(_)) => true,
            Self::Qsp(QspSessionError::Replay) => true,
            Self::Qsp(QspSessionError::TooOld) => true,
            // Fatal: dead channel (peer keys diverged beyond recovery).
            Self::Qsp(QspSessionError::DeadChannel) => false,
            // Fatal: TX packet-number space exhausted — session cannot send
            // again on this UDP path. Propagate to restore the old TCP-fallback
            // routing (a recoverable classification here would silently drop
            // packets on a session that can no longer send). See doc above.
            Self::Qsp(QspSessionError::PacketNumberOverflow) => false,
            // Recoverable: malformed/garbage/partial packet from the peer.
            Self::Frame(_) | Self::Message(_) | Self::IncompleteMessage => true,
        }
    }

    /// Whether this is the UDP-QSP dead-channel signal — the signal that the
    /// peer's keys have diverged beyond recovery (too many consecutive decrypt
    /// failures), distinct from a single crypto failure on one packet.
    ///
    /// Convenience for the session layer, which previously matched
    /// `io::ErrorKind::ConnectionAborted` to detect this; the typed error now
    /// carries the classification directly. The session must fall back to TCP
    /// or reconnect.
    #[must_use]
    pub const fn is_dead_channel(&self) -> bool {
        matches!(self, Self::Qsp(QspSessionError::DeadChannel))
    }
}

/// Client-side UDP-QSP socket I/O backed by a `tokio::net::UdpSocket`.
#[cfg(any(test, not(unix)))]
pub struct ClientUdpIo {
    socket: Arc<UdpSocket>,
    peer: SocketAddr,
}

#[cfg(any(test, not(unix)))]
impl ClientUdpIo {
    /// Create a new UDP-QSP I/O wrapper for traffic to/from `peer`.
    #[must_use]
    pub const fn new(socket: Arc<UdpSocket>, peer: SocketAddr) -> Self {
        Self { socket, peer }
    }

    #[cfg(not(unix))]
    /// Return the accepted receive peer and outbound transmit destination.
    #[must_use]
    pub const fn peer(&self) -> SocketAddr {
        self.peer
    }
}

#[cfg(unix)]
pub fn client_udp_qsp_io(socket: &Arc<UdpSocket>, peer: SocketAddr) -> io::Result<ClientUdpQspIo> {
    let fd = socket.as_fd().try_clone_to_owned()?;
    let socket = std::net::UdpSocket::from(fd);
    socket.set_nonblocking(true)?;
    ClientUdpQspIo::new(socket, peer)
}

#[cfg(not(unix))]
pub fn client_udp_qsp_io(socket: &Arc<UdpSocket>, peer: SocketAddr) -> io::Result<ClientUdpQspIo> {
    Ok(ClientUdpQspIo::new(socket.clone(), peer))
}

#[cfg(any(test, not(unix)))]
impl SessionIo for ClientUdpIo {
    async fn send<'a>(&'a mut self, bytes: &'a [u8]) -> io::Result<()> {
        let _ = self.socket.send_to(bytes, self.peer).await?;
        Ok(())
    }

    async fn recv<'a>(&'a mut self, buf: &'a mut [u8]) -> io::Result<usize> {
        loop {
            let (len, from) = self.socket.recv_from(buf).await?;
            if from == self.peer {
                return Ok(len);
            }
        }
    }
}

/// UDP-QSP transport wrapper for VPN protocol messages.
pub struct UdpQspTransport<I> {
    session: QuicQspSession<I>,
    write_buf: Vec<u8>,
    packet_buf: Vec<u8>,
    metrics: Arc<Metrics>,
}

/// Production UDP-QSP transport with real socket I/O.
pub type ClientTransport = UdpQspTransport<ClientUdpQspIo>;

impl<I: SessionIo> UdpQspTransport<I> {
    /// Create a new UDP-QSP transport around an established session.
    #[must_use]
    pub fn new(session: QuicQspSession<I>, metrics: Arc<Metrics>) -> Self {
        Self {
            session,
            write_buf: Vec::new(),
            packet_buf: vec![0u8; 2048],
            metrics,
        }
    }

    /// Flush protected packets buffered by the underlying I/O layer.
    ///
    /// # Errors
    ///
    /// Returns any I/O error reported by the socket backend.
    pub async fn flush(&mut self) -> io::Result<()> {
        self.session.flush().await
    }

    /// Returns whether the underlying I/O layer has packets waiting for flush.
    #[must_use]
    pub fn has_pending_flush(&self) -> bool {
        self.session.has_pending_flush()
    }

    /// Replace the underlying UDP-QSP I/O backend after a best-effort flush.
    ///
    /// Flush failures during network handoff are logged and ignored: any packet
    /// already assigned a packet number may be lost, but the session's packet
    /// number, replay, and key-phase state remain monotonic.
    pub async fn replace_io(&mut self, new_io: I) -> I {
        if self.session.has_pending_flush()
            && let Err(err) = self.session.flush().await
        {
            warn!(error = %err, "failed to flush udp-qsp packets before io replacement");
        }
        self.session.replace_io(new_io)
    }

    /// Encode and send a VPN protocol message over UDP-QSP.
    ///
    /// Frames the message using the SLT wire protocol, encrypts it with UDP-QSP
    /// packet protection, and sends it to the peer. Tracks TX key phase transitions
    /// in metrics.
    ///
    /// # Errors
    ///
    /// Returns a typed [`UdpQspError`] if:
    /// - Message encoding fails ([`UdpQspError::Frame`] / [`UdpQspError::Message`])
    /// - UDP-QSP session send fails: replay/too-old/overflow/crypto failure
    ///   ([`UdpQspError::Qsp`]), dead-channel signal
    ///   ([`UdpQspError::is_dead_channel`]), or socket I/O ([`UdpQspError::Io`]).
    ///   Use [`UdpQspError::is_recoverable`] to classify drop-vs-propagate.
    pub async fn write_message(
        &mut self,
        message: slt_core::proto::Message<'_>,
    ) -> Result<(), UdpQspError> {
        self.write_buf.clear();
        // FrameError and MessageError both flow via `#[from]`.
        slt_core::proto::encode_message(message, &mut self.write_buf)?;

        let tx_phase_before = self.session.tx_key_phase();
        match self.session.send(&self.write_buf).await {
            Ok(()) => {
                if self.session.tx_key_phase() != tx_phase_before {
                    self.metrics.inc_udp_qsp_tx_key_phase_transition();
                    info!(
                        key_phase = self.session.tx_key_phase(),
                        "UDP-QSP TX key phase transitioned"
                    );
                }
                Ok(())
            }
            Err(QspSessionError::DeadChannel) => {
                self.metrics.inc_udp_qsp_dead_channel();
                warn!("UDP-QSP channel marked dead");
                Err(UdpQspError::Qsp(QspSessionError::DeadChannel))
            }
            // QspSessionError (other variants) flows via `#[from]`, except
            // send-side I/O, which is re-wrapped as `SendIo` (never
            // recoverable) so a send failure falls back to TCP rather than
            // being dropped like a recv-side transient.
            Err(err) => Err(match err {
                QspSessionError::Io(source) => UdpQspError::SendIo { source },
                other => UdpQspError::Qsp(other),
            }),
        }
    }

    /// Receive and decode a single VPN protocol message from UDP-QSP.
    ///
    /// Receives a UDP-QSP protected packet, decrypts and validates it, then
    /// decodes the framed message payload. Tracks RX key phase transitions in
    /// metrics and ignores trailing bytes after the first message per protocol spec.
    ///
    /// # Errors
    ///
    /// Returns a typed [`UdpQspError`] if:
    /// - Packet decryption fails (replay, too old, crypto, packet-number
    ///   overflow) or the channel is marked dead ([`UdpQspError::Qsp`]).
    /// - Socket recv fails ([`UdpQspError::Io`]).
    /// - Message decoding fails ([`UdpQspError::Message`]).
    /// - The decrypted payload does not contain a complete framed message
    ///   ([`UdpQspError::IncompleteMessage`]).
    ///
    /// Recoverable failures (see [`UdpQspError::is_recoverable`]) are typically
    /// dropped by the caller; the dead-channel signal propagates.
    pub async fn read_next_message(
        &mut self,
        limits: slt_core::proto::MessageLimits,
    ) -> Result<slt_core::proto::OwnedMessageBuf, UdpQspError> {
        let rx_phase_before = self.session.rx_key_phase();
        let decode_result = {
            let opened = match self.session.recv(&mut self.packet_buf).await {
                Ok(opened) => opened,
                Err(err) => {
                    // Update metrics for the recoverable-class decrypt failures
                    // and surface the typed error. The caller decides drop-vs-
                    // propagate via `UdpQspError::is_recoverable`.
                    self.note_recv_error(&err);
                    return Err(err.into());
                }
            };

            match slt_core::proto::decode_message(opened.payload, limits) {
                Ok(Some((message, consumed))) => {
                    // Per protocol.md Section 4.4: receivers MUST ignore any trailing bytes
                    // after decoding the first framed message (may be padding for HP sample).
                    Ok((message.ty(), opened.payload[..consumed].to_vec()))
                }
                Ok(None) => Err(UdpQspError::IncompleteMessage),
                // MessageError flows via `#[from]`.
                Err(err) => Err(err.into()),
            }
        };
        // Check for key phase transition by comparing session state before/after recv
        let rx_phase_after = self.session.rx_key_phase();
        if rx_phase_after != rx_phase_before {
            self.metrics.inc_udp_qsp_rx_key_phase_transition();
            info!(
                key_phase = rx_phase_after,
                "UDP-QSP RX key phase transitioned"
            );
        }
        let (message_ty, frame) = decode_result?;
        Ok(slt_core::proto::OwnedMessageBuf::new(message_ty, frame))
    }

    /// Update metrics counters for a UDP-QSP receive failure.
    ///
    /// This is the metrics side of what the old `handle_recv_error` did (the
    /// error itself is now returned typed to the caller rather than flattened
    /// to an `io::ErrorKind` here). Each counter corresponds to a
    /// `QspSessionError` variant; the dead-channel counter is also bumped here
    /// so callers that drop a recoverable error still get the metric.
    fn note_recv_error(&self, err: &QspSessionError) {
        match err {
            QspSessionError::Replay => {
                self.metrics.inc_udp_qsp_decrypt_fail_replay();
                trace!(reason = "replay", "UDP-QSP packet dropped: decrypt failure");
            }
            QspSessionError::TooOld => {
                self.metrics.inc_udp_qsp_decrypt_fail_too_old();
                trace!(
                    reason = "too_old",
                    "UDP-QSP packet dropped: decrypt failure"
                );
            }
            QspSessionError::DeadChannel => {
                self.metrics.inc_udp_qsp_dead_channel();
                warn!("UDP-QSP channel marked dead");
            }
            QspSessionError::Crypto(crypto_err) => {
                self.metrics.inc_udp_qsp_decrypt_fail_crypto();
                trace!(
                    reason = "crypto",
                    error = ?crypto_err,
                    "UDP-QSP packet dropped: decrypt failure"
                );
            }
            QspSessionError::Io(_) => {}
            QspSessionError::PacketNumberOverflow => {
                self.metrics.inc_udp_qsp_decrypt_fail_other();
                trace!(
                    reason = "packet_number_overflow",
                    "UDP-QSP packet dropped: decrypt failure"
                );
            }
        }
    }
}

impl UdpQspTransport<ClientUdpQspIo> {
    /// Return the current UDP peer address for client-side socket recreation.
    #[must_use]
    pub const fn peer(&self) -> SocketAddr {
        self.session.io().peer()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use slt_core::crypto::udp_qsp::{QspCryptoError, QspSessionError, QuicQspSession};
    use slt_core::proto::{HEADER_LEN, Message, MessageLimits, PingPayload, PongPayload};
    use slt_core::types::Cid;
    use tokio::sync::mpsc;

    use super::*;
    use crate::metrics::MetricsSnapshot;
    use crate::test_support::{ChanIo, encode_ping, encode_pong, make_server_keys, make_test_keys};

    // Keep in sync with slt-core::crypto::udp_qsp::session::KEY_UPDATE_INTERVAL.
    const KEY_UPDATE_INTERVAL: u64 = 1 << 21;

    fn make_session(io: ChanIo) -> QuicQspSession<ChanIo> {
        make_session_with_pn(io, 0, 0)
    }

    fn make_session_with_pn(
        io: ChanIo,
        send_pn: u64,
        recv_expected_pn: u64,
    ) -> QuicQspSession<ChanIo> {
        let scid = Cid::from([0xA1; 20]);
        let dcid = Cid::from([0xB2; 20]);
        QuicQspSession::new(
            io,
            scid,
            dcid,
            make_test_keys(),
            send_pn,
            recv_expected_pn,
            false,
        )
    }

    fn make_transport(session: QuicQspSession<ChanIo>) -> UdpQspTransport<ChanIo> {
        let metrics = Arc::new(Metrics::default());
        UdpQspTransport::new(session, metrics)
    }

    fn snapshot(transport: &UdpQspTransport<ChanIo>) -> MetricsSnapshot {
        transport.metrics.snapshot()
    }

    #[tokio::test]
    async fn write_message_encodes_and_sends_framed_message() {
        let (c2s_tx, c2s_rx) = mpsc::channel::<Vec<u8>>(8);
        let (s2c_tx, s2c_rx) = mpsc::channel::<Vec<u8>>(8);

        let scid = Cid::from([0xA1; 20]);
        let dcid = Cid::from([0xB2; 20]);

        let client_io = ChanIo {
            tx: c2s_tx,
            rx: s2c_rx,
        };
        let client_session =
            QuicQspSession::new(client_io, scid, dcid, make_test_keys(), 0, 0, false);
        let mut transport = make_transport(client_session);

        let server_io = ChanIo {
            tx: s2c_tx,
            rx: c2s_rx,
        };
        let mut server_session =
            QuicQspSession::new(server_io, dcid, scid, make_server_keys(), 0, 0, false);

        let frame = encode_ping(0x1234_5678);
        transport
            .write_message(Message::Ping {
                payload: &frame[HEADER_LEN..],
            })
            .await
            .unwrap();

        let mut packet_buf = [0u8; 2048];
        let opened = server_session.recv(&mut packet_buf).await.unwrap();
        assert_eq!(opened.payload, frame.as_slice());
    }

    #[tokio::test]
    async fn read_next_message_decodes_framed_message() {
        let (c2s_tx, c2s_rx) = mpsc::channel::<Vec<u8>>(8);
        let (s2c_tx, s2c_rx) = mpsc::channel::<Vec<u8>>(8);

        let server_io = ChanIo {
            tx: s2c_tx,
            rx: c2s_rx,
        };
        let client_io = ChanIo {
            tx: c2s_tx,
            rx: s2c_rx,
        };

        let scid = Cid::from([0xA1; 20]);
        let dcid = Cid::from([0xB2; 20]);

        let mut server_session =
            QuicQspSession::new(server_io, dcid, scid, make_server_keys(), 0, 0, false);
        let client_session =
            QuicQspSession::new(client_io, scid, dcid, make_test_keys(), 0, 0, false);

        let mut client_transport = make_transport(client_session);

        let nonce = 0xABCD_EF12_3456_7890u64;
        let frame = encode_ping(nonce);
        server_session.send(&frame).await.unwrap();

        let limits = MessageLimits::new(2048, 2048);
        let msg = client_transport.read_next_message(limits).await.unwrap();

        // Use message() to get the decoded message
        match msg.message() {
            Message::Ping { payload } => {
                assert_eq!(PingPayload::decode(payload).unwrap().nonce, nonce);
            }
            _ => panic!("expected ping"),
        }
    }

    #[tokio::test]
    async fn full_roundtrip_write_recv_read_returns_original_message() {
        let (c2s_tx, c2s_rx) = mpsc::channel::<Vec<u8>>(8);
        let (s2c_tx, s2c_rx) = mpsc::channel::<Vec<u8>>(8);

        let scid = Cid::from([0xA1; 20]);
        let dcid = Cid::from([0xB2; 20]);

        // Client transport
        let client_io = ChanIo {
            tx: c2s_tx,
            rx: s2c_rx,
        };
        let client_session =
            QuicQspSession::new(client_io, scid, dcid, make_test_keys(), 0, 0, false);
        let mut client = make_transport(client_session);

        // Server transport
        let server_io = ChanIo {
            tx: s2c_tx,
            rx: c2s_rx,
        };
        let server_session =
            QuicQspSession::new(server_io, dcid, scid, make_server_keys(), 0, 0, false);
        let mut server = make_transport(server_session);

        let limits = MessageLimits::new(2048, 2048);
        let nonce = 0xDEAD_BEEF_CAFE_BABEu64;

        // Client sends ping
        let request_frame = encode_ping(nonce);
        client
            .write_message(Message::Ping {
                payload: &request_frame[HEADER_LEN..],
            })
            .await
            .unwrap();

        // Server receives and decodes
        let msg = server.read_next_message(limits).await.unwrap();
        match msg.message() {
            Message::Ping { payload } => {
                assert_eq!(PingPayload::decode(payload).unwrap().nonce, nonce);
            }
            _ => panic!("expected ping"),
        }

        // Server sends pong
        let response_frame = encode_pong(nonce);
        server
            .write_message(Message::Pong {
                payload: &response_frame[HEADER_LEN..],
            })
            .await
            .unwrap();

        // Client receives pong
        let msg = client.read_next_message(limits).await.unwrap();
        match msg.message() {
            Message::Pong { payload } => {
                assert_eq!(PongPayload::decode(payload).unwrap().nonce, nonce);
            }
            _ => panic!("expected pong"),
        }
    }

    #[test]
    fn dead_channel_preserves_qsp_shape_and_is_fatal() {
        // DeadChannel is the one fatal non-I/O UDP-QSP condition (peer keys
        // diverged beyond recovery). The typed `is_dead_channel` /
        // `is_recoverable` API replaces the old `map_qsp_error` ->
        // `io::ErrorKind::ConnectionAborted` flattening.
        let err: UdpQspError = QspSessionError::DeadChannel.into();
        assert!(matches!(
            err,
            UdpQspError::Qsp(QspSessionError::DeadChannel)
        ));
        assert!(err.is_dead_channel());
        assert!(!err.is_recoverable());
    }

    #[test]
    fn qsp_io_preserves_shape_and_is_recoverable() {
        // Socket I/O is preserved via `#[from]`, not flattened. Transient recv
        // I/O is recoverable under the new policy (deliberate improvement; see
        // `is_recoverable` doc) — one failed datagram does not kill the path.
        let io_err = io::Error::new(io::ErrorKind::TimedOut, "timeout");
        let err: UdpQspError = QspSessionError::Io(io_err).into();
        assert!(matches!(err, UdpQspError::Qsp(QspSessionError::Io(_))));
        assert!(err.is_recoverable());
        assert!(!err.is_dead_channel());
    }

    #[test]
    fn persistent_socket_io_errors_propagate_not_dropped() {
        // Real socket failures are NOT droppable: PermissionDenied (firewall/
        // policy), NetworkUnreachable/HostUnreachable (no route), BrokenPipe,
        // or NotConnected must propagate to TCP fallback / close / reconnect
        // rather than be silently dropped (which would let the session spin on
        // a permanent I/O error and the refresh probe retry until its timeout).
        // Only transient kinds (WouldBlock/TimedOut/ConnectionRefused/
        // ConnectionReset) are recoverable.
        for kind in [
            io::ErrorKind::PermissionDenied,
            io::ErrorKind::NetworkUnreachable,
            io::ErrorKind::HostUnreachable,
            io::ErrorKind::BrokenPipe,
            io::ErrorKind::NotConnected,
        ] {
            let direct: UdpQspError = io::Error::from(kind).into();
            assert!(
                !direct.is_recoverable(),
                "{kind:?}: direct UdpQspError::Io should propagate, not drop"
            );
            let wrapped: UdpQspError = QspSessionError::Io(io::Error::from(kind)).into();
            assert!(
                !wrapped.is_recoverable(),
                "{kind:?}: Qsp(Io(_)) should propagate, not drop"
            );
            assert!(!direct.is_dead_channel());
        }
    }

    #[test]
    fn send_io_errors_are_never_recoverable() {
        // Send-side socket I/O (from `session.send` / send_to / GSO flush) is
        // NEVER recoverable, even for kinds that are transient on the recv path:
        // a send failure must fall back to TCP (or close if TCP is dead), not be
        // silently dropped — dropping it would lose the outbound packet and leave
        // the active transport on UDP while the send path is failing.
        for kind in [
            io::ErrorKind::WouldBlock,
            io::ErrorKind::TimedOut,
            io::ErrorKind::ConnectionRefused,
            io::ErrorKind::ConnectionReset,
            io::ErrorKind::PermissionDenied,
            io::ErrorKind::NetworkUnreachable,
            io::ErrorKind::BrokenPipe,
        ] {
            let err = UdpQspError::SendIo {
                source: io::Error::from(kind),
            };
            assert!(
                !err.is_recoverable(),
                "{kind:?}: SendIo must propagate to TCP fallback, not drop"
            );
            assert!(!err.is_dead_channel());
        }
    }

    #[test]
    fn packet_number_overflow_preserves_shape_and_is_fatal() {
        // Packet-number overflow is FATAL: the TX pn space is exhausted, so the
        // session cannot send again on this UDP path. The runtime routing is
        // unchanged from old: the old `map_qsp_error` mapped this to
        // `QuotaExceeded`, which `handle_udp_error` routed to TCP fallback (or
        // close) — NOT a drop — and the typed fatal classification here routes
        // identically. The initial phase-3 recoverable-classification would
        // have *dropped* overflow and lost packets; fatal restores the old
        // routing. The session reconnects for a fresh pn space only once it
        // re-establishes, not as an immediate consequence of the overflow.
        let err: UdpQspError = QspSessionError::PacketNumberOverflow.into();
        assert!(matches!(
            err,
            UdpQspError::Qsp(QspSessionError::PacketNumberOverflow)
        ));
        assert!(!err.is_recoverable());
        assert!(!err.is_dead_channel());
        let rendered = format!("{err:#}");
        assert!(rendered.contains("overflow"), "{rendered:?}");
    }

    #[test]
    fn crypto_failure_preserves_qsp_shape_and_is_recoverable() {
        let err: UdpQspError = QspSessionError::Crypto(QspCryptoError::CryptoFail).into();
        assert!(matches!(
            err,
            UdpQspError::Qsp(QspSessionError::Crypto(QspCryptoError::CryptoFail))
        ));
        // A single crypto (decrypt) failure is recoverable — distinct from the
        // DeadChannel signal, which is many consecutive failures.
        assert!(err.is_recoverable());
        assert!(!err.is_dead_channel());
    }

    #[test]
    fn replay_preserves_qsp_shape_and_is_recoverable() {
        let err: UdpQspError = QspSessionError::Replay.into();
        assert!(matches!(err, UdpQspError::Qsp(QspSessionError::Replay)));
        assert!(err.is_recoverable());
    }

    #[test]
    fn too_old_preserves_qsp_shape_and_is_recoverable() {
        let err: UdpQspError = QspSessionError::TooOld.into();
        assert!(matches!(err, UdpQspError::Qsp(QspSessionError::TooOld)));
        assert!(err.is_recoverable());
    }

    #[tokio::test]
    async fn rx_key_phase_transition_increments_metric() {
        let (c2s_tx, c2s_rx) = mpsc::channel::<Vec<u8>>(8);
        let (s2c_tx, s2c_rx) = mpsc::channel::<Vec<u8>>(8);

        let scid = Cid::from([0xA1; 20]);
        let dcid = Cid::from([0xB2; 20]);

        let client_io = ChanIo {
            tx: c2s_tx,
            rx: s2c_rx,
        };
        let client_session = QuicQspSession::new(
            client_io,
            scid,
            dcid,
            make_test_keys(),
            0,
            KEY_UPDATE_INTERVAL - 1,
            false,
        );
        let mut client = make_transport(client_session);

        let server_io = ChanIo {
            tx: s2c_tx,
            rx: c2s_rx,
        };
        let mut server_session = QuicQspSession::new(
            server_io,
            dcid,
            scid,
            make_server_keys(),
            KEY_UPDATE_INTERVAL - 1,
            0,
            false,
        );

        let limits = MessageLimits::new(2048, 2048);

        assert_eq!(snapshot(&client).udp_qsp_rx_key_phase_transitions, 0);

        let first_ping = encode_ping(1);
        server_session.send(&first_ping).await.unwrap();
        client.read_next_message(limits).await.unwrap();
        assert_eq!(snapshot(&client).udp_qsp_rx_key_phase_transitions, 0);

        // Second packet crosses the sender rekey threshold and flips key phase.
        let second_ping = encode_ping(2);
        server_session.send(&second_ping).await.unwrap();
        client.read_next_message(limits).await.unwrap();

        assert_eq!(snapshot(&client).udp_qsp_rx_key_phase_transitions, 1);
    }

    #[tokio::test]
    async fn tx_key_phase_transition_increments_metric() {
        let (tx, _rx) = mpsc::channel::<Vec<u8>>(8);
        let io = ChanIo {
            tx,
            rx: mpsc::channel(1).1,
        };
        let session = make_session_with_pn(io, KEY_UPDATE_INTERVAL - 1, 0);
        let mut transport = make_transport(session);

        assert_eq!(snapshot(&transport).udp_qsp_tx_key_phase_transitions, 0);

        let first_frame = encode_ping(1);
        transport
            .write_message(Message::Ping {
                payload: &first_frame[HEADER_LEN..],
            })
            .await
            .unwrap();
        assert_eq!(snapshot(&transport).udp_qsp_tx_key_phase_transitions, 0);

        // Second packet crosses the sender rekey threshold and flips key phase.
        let second_frame = encode_ping(2);
        transport
            .write_message(Message::Ping {
                payload: &second_frame[HEADER_LEN..],
            })
            .await
            .unwrap();

        assert_eq!(snapshot(&transport).udp_qsp_tx_key_phase_transitions, 1);
    }

    #[tokio::test]
    async fn trailing_padding_bytes_ignored_after_message_decode() {
        let (c2s_tx, c2s_rx) = mpsc::channel::<Vec<u8>>(8);
        let (s2c_tx, s2c_rx) = mpsc::channel::<Vec<u8>>(8);

        let scid = Cid::from([0xA1; 20]);
        let dcid = Cid::from([0xB2; 20]);

        let client_io = ChanIo {
            tx: c2s_tx,
            rx: s2c_rx,
        };
        let client_session =
            QuicQspSession::new(client_io, scid, dcid, make_test_keys(), 0, 0, false);
        let mut client = make_transport(client_session);

        let server_io = ChanIo {
            tx: s2c_tx,
            rx: c2s_rx,
        };
        let mut server_session =
            QuicQspSession::new(server_io, dcid, scid, make_server_keys(), 0, 0, false);

        // Send a ping frame with explicit trailing bytes.
        let nonce = 0u64;
        let mut ping_with_padding = encode_ping(nonce);
        ping_with_padding.extend_from_slice(&[0x00, 0x00, 0xFF, 0xEE]);
        server_session.send(&ping_with_padding).await.unwrap();

        let limits = MessageLimits::new(2048, 2048);
        let msg = client.read_next_message(limits).await.unwrap();

        // The decoded message payload excludes trailing bytes.
        match msg.message() {
            Message::Ping { payload } => {
                assert_eq!(payload.len(), std::mem::size_of::<u64>());
                assert_eq!(PingPayload::decode(payload).unwrap().nonce, nonce);
            }
            _ => panic!("expected ping"),
        }
    }

    #[tokio::test]
    async fn note_recv_error_replay_increments_metric_and_is_recoverable() {
        let (tx, _rx) = mpsc::channel::<Vec<u8>>(8);
        let io = ChanIo {
            tx,
            rx: mpsc::channel(1).1,
        };
        let session = make_session(io);
        let transport = make_transport(session);

        assert_eq!(snapshot(&transport).udp_qsp_decrypt_fail_replay, 0);

        let qsp_err = QspSessionError::Replay;
        transport.note_recv_error(&qsp_err);
        assert_eq!(snapshot(&transport).udp_qsp_decrypt_fail_replay, 1);

        // The typed UdpQspError classifies the recoverable decision.
        let err: UdpQspError = qsp_err.into();
        assert!(err.is_recoverable());
        assert!(!err.is_dead_channel());
    }

    #[tokio::test]
    async fn note_recv_error_too_old_increments_metric_and_is_recoverable() {
        let (tx, _rx) = mpsc::channel::<Vec<u8>>(8);
        let io = ChanIo {
            tx,
            rx: mpsc::channel(1).1,
        };
        let session = make_session(io);
        let transport = make_transport(session);

        assert_eq!(snapshot(&transport).udp_qsp_decrypt_fail_too_old, 0);

        let qsp_err = QspSessionError::TooOld;
        transport.note_recv_error(&qsp_err);
        assert_eq!(snapshot(&transport).udp_qsp_decrypt_fail_too_old, 1);

        let err: UdpQspError = qsp_err.into();
        assert!(err.is_recoverable());
    }

    #[tokio::test]
    async fn note_recv_error_dead_channel_increments_metric_and_is_fatal() {
        let (tx, _rx) = mpsc::channel::<Vec<u8>>(8);
        let io = ChanIo {
            tx,
            rx: mpsc::channel(1).1,
        };
        let session = make_session(io);
        let transport = make_transport(session);

        assert_eq!(snapshot(&transport).udp_qsp_dead_channel, 0);

        let qsp_err = QspSessionError::DeadChannel;
        transport.note_recv_error(&qsp_err);
        assert_eq!(snapshot(&transport).udp_qsp_dead_channel, 1);

        let err: UdpQspError = qsp_err.into();
        assert!(!err.is_recoverable());
        assert!(err.is_dead_channel());
    }

    #[tokio::test]
    async fn note_recv_error_crypto_increments_metric_and_is_recoverable() {
        let (tx, _rx) = mpsc::channel::<Vec<u8>>(8);
        let io = ChanIo {
            tx,
            rx: mpsc::channel(1).1,
        };
        let session = make_session(io);
        let transport = make_transport(session);

        assert_eq!(snapshot(&transport).udp_qsp_decrypt_fail_crypto, 0);

        let qsp_err = QspSessionError::Crypto(QspCryptoError::CryptoFail);
        transport.note_recv_error(&qsp_err);
        assert_eq!(snapshot(&transport).udp_qsp_decrypt_fail_crypto, 1);

        let err: UdpQspError = qsp_err.into();
        assert!(err.is_recoverable());
    }

    #[tokio::test]
    async fn note_recv_error_io_does_not_bump_decrypt_metrics() {
        let (tx, _rx) = mpsc::channel::<Vec<u8>>(8);
        let io = ChanIo {
            tx,
            rx: mpsc::channel(1).1,
        };
        let session = make_session(io);
        let transport = make_transport(session);

        let before = snapshot(&transport);
        let qsp_err = QspSessionError::Io(io::Error::new(io::ErrorKind::TimedOut, "timeout"));
        transport.note_recv_error(&qsp_err);
        let after = snapshot(&transport);
        // Socket I/O bumps no decrypt-fail counter; it is preserved as a typed
        // UdpQspError::Qsp(QspSessionError::Io(_)) for the caller.
        assert_eq!(before, after);

        let err: UdpQspError = qsp_err.into();
        assert!(err.is_recoverable());
    }

    #[tokio::test]
    async fn note_recv_error_packet_number_overflow_increments_metric_and_is_fatal() {
        let (tx, _rx) = mpsc::channel::<Vec<u8>>(8);
        let io = ChanIo {
            tx,
            rx: mpsc::channel(1).1,
        };
        let session = make_session(io);
        let transport = make_transport(session);

        assert_eq!(snapshot(&transport).udp_qsp_decrypt_fail_other, 0);

        let qsp_err = QspSessionError::PacketNumberOverflow;
        transport.note_recv_error(&qsp_err);
        assert_eq!(snapshot(&transport).udp_qsp_decrypt_fail_other, 1);

        // Overflow is FATAL (the TX pn space is exhausted): propagate ->
        // reconnect. See `is_recoverable` doc for the behaviour-fix rationale.
        let err: UdpQspError = qsp_err.into();
        assert!(!err.is_recoverable());
    }

    /// The typed `UdpQspError::is_recoverable` policy, pinned per shape. This
    /// is NOT a blanket "matches old behaviour" claim: one shape is a deliberate
    /// improvement over the old `map_qsp_error` + `ErrorKind` path, called out
    /// below; the rest preserve the old runtime routing (drop, or
    /// TCP-fallback/close) through the typed path.
    #[test]
    fn recoverable_policy_pins_each_shape() {
        // === Fatal (propagate out of the UDP-QSP transport -> TCP fallback /
        // session close at the session layer) ===
        // DeadChannel: preserved parity. Old = `ConnectionAborted` -> propagate.
        assert!(!UdpQspError::from(QspSessionError::DeadChannel).is_recoverable());
        // PacketNumberOverflow: restores the old runtime routing. The old path
        // flattened this to `QuotaExceeded`, which `handle_udp_error` routed to
        // TCP fallback (or close) — NOT a drop. The initial phase-3
        // recoverable-classification would have *dropped* overflow, diverging
        // from that old behaviour and silently losing packets on a session that
        // can no longer send; classifying it fatal here keeps the runtime
        // routing identical to old (TCP fallback). See `is_recoverable` doc.
        assert!(!UdpQspError::from(QspSessionError::PacketNumberOverflow).is_recoverable());

        // === Recoverable: preserved parity with old `InvalidData` drop path ===
        // These were flattened to `InvalidData` and dropped by `handle_udp_error` /
        // `should_drop_refresh_*`; the typed path preserves that.
        assert!(UdpQspError::from(QspSessionError::Replay).is_recoverable());
        assert!(UdpQspError::from(QspSessionError::TooOld).is_recoverable());
        assert!(
            UdpQspError::from(QspSessionError::Crypto(QspCryptoError::CryptoFail)).is_recoverable()
        );
        assert!(UdpQspError::from(FrameError::UnknownType(0xFF)).is_recoverable());
        assert!(UdpQspError::from(MessageError::DataTooLarge { len: 10, max: 5 }).is_recoverable());
        assert!(UdpQspError::IncompleteMessage.is_recoverable());

        // === Recoverable: DELIBERATE IMPROVEMENT (transient datagram I/O) ===
        // The old path routed non-`InvalidData`/non-`ConnectionAborted`
        // `io::Error` to TCP fallback / close, so a single transient recv
        // failure tore down the UDP path. Dropping it is correct for UDP; the
        // idle-timeout backstops persistent failure. Pinned for both the
        // wrapped and standalone io::Error shapes, using a transient kind
        // (`TimedOut`); a non-transient kind (PermissionDenied/
        // NetworkUnreachable/BrokenPipe/...) propagates — see
        // `persistent_socket_io_errors_propagate_not_dropped`.
        let transient = io::ErrorKind::TimedOut;
        assert!(
            UdpQspError::from(QspSessionError::Io(io::Error::from(transient))).is_recoverable()
        );
        assert!(UdpQspError::from(io::Error::from(transient)).is_recoverable());
    }

    /// A transient recv socket I/O failure (`WouldBlock`, `TimedOut`,
    /// `ConnectionRefused`, ...) must be DROPPED (not propagated, not routed to
    /// TCP fallback) under the new typed policy. This is the guardrail for the
    /// deliberate-improvement change documented on `UdpQspError::Io` and
    /// `is_recoverable`: a single failed datagram recv is not evidence the UDP
    /// path is dead.
    #[test]
    fn transient_recv_io_is_dropped_not_propagated() {
        for kind in [
            io::ErrorKind::WouldBlock,
            io::ErrorKind::TimedOut,
            io::ErrorKind::ConnectionRefused,
            io::ErrorKind::ConnectionReset,
        ] {
            let err = UdpQspError::from(io::Error::new(kind, "transient recv"));
            assert!(
                err.is_recoverable(),
                "transient recv {kind:?} must be recoverable (dropped), got fatal"
            );
            assert!(
                !err.is_dead_channel(),
                "transient recv {kind:?} must not look like the dead-channel signal"
            );
        }
    }

    /// `is_dead_channel` is the typed replacement for the session's old
    /// `io::ErrorKind::ConnectionAborted` check on the UDP path.
    #[test]
    fn is_dead_channel_only_matches_dead_channel() {
        assert!(UdpQspError::from(QspSessionError::DeadChannel).is_dead_channel());
        // Every other variant — including a real ConnectionAborted io::Error —
        // must NOT be reported as the dead-channel signal, since the session
        // treats dead-channel as a UDP-key-divergence condition distinct from
        // socket I/O.
        assert!(!UdpQspError::from(QspSessionError::Replay).is_dead_channel());
        assert!(
            !UdpQspError::from(io::Error::new(io::ErrorKind::ConnectionAborted, "x"))
                .is_dead_channel()
        );
        assert!(!UdpQspError::IncompleteMessage.is_dead_channel());
    }
}

/// Tests for `ClientUdpIo` peer filtering behavior using real UDP sockets.
#[cfg(test)]
mod peer_filtering_tests {
    use std::time::Duration;

    use tokio::time::timeout;

    use super::*;
    use crate::test_support::{encode_ping, udp_pair};

    #[tokio::test]
    async fn client_udp_io_accepts_packets_from_peer() {
        let (socket_a, socket_b) = udp_pair().await;

        // Create ClientUdpIo with socket_a, expecting packets from socket_b
        let peer_addr = socket_b.local_addr().unwrap();
        let mut io = ClientUdpIo::new(socket_a.clone(), peer_addr);

        // Send a packet from the peer (socket_b)
        let ping_frame = encode_ping(0x1234);
        socket_b.send(&ping_frame).await.unwrap();

        // Receive should succeed
        let mut buf = [0u8; 2048];
        let len = io.recv(&mut buf).await.unwrap();
        assert_eq!(&buf[..len], ping_frame.as_slice());
    }

    #[tokio::test]
    async fn client_udp_io_ignores_packets_from_non_peer() {
        let (socket_a, socket_b) = udp_pair().await;

        // Create a third socket that is NOT the peer
        let socket_c = Arc::new(
            tokio::net::UdpSocket::bind("127.0.0.1:0")
                .await
                .expect("failed to bind socket C"),
        );

        // Create ClientUdpIo with socket_a, expecting packets from socket_b
        let peer_addr = socket_b.local_addr().unwrap();
        let mut io = ClientUdpIo::new(socket_a.clone(), peer_addr);

        // Send a packet from non-peer (socket_c) to socket_a
        let junk_packet = b"junk from non-peer";
        socket_c
            .send_to(junk_packet, socket_a.local_addr().unwrap())
            .await
            .unwrap();

        // Give the packet time to arrive
        tokio::time::sleep(Duration::from_millis(10)).await;

        // Now send the real packet from the peer
        let ping_frame = encode_ping(0x5678);
        socket_b.send(&ping_frame).await.unwrap();

        // Receive should return the peer's packet, skipping the non-peer's
        let mut buf = [0u8; 2048];
        let len = io.recv(&mut buf).await.unwrap();
        assert_eq!(&buf[..len], ping_frame.as_slice());
        // Verify we got the ping, not the junk
        assert_ne!(&buf[..len.min(junk_packet.len())], junk_packet);
    }

    #[tokio::test]
    async fn client_udp_io_send_delivers_to_peer() {
        let (socket_a, socket_b) = udp_pair().await;

        // Create ClientUdpIo with socket_a, sending to socket_b
        let peer_addr = socket_b.local_addr().unwrap();
        let mut io = ClientUdpIo::new(socket_a.clone(), peer_addr);

        // Send a packet
        let ping_frame = encode_ping(0xABCD);
        io.send(&ping_frame).await.unwrap();

        // Socket_b should receive it
        let mut buf = [0u8; 2048];
        let (len, from) = socket_b.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..len], ping_frame.as_slice());
        assert_eq!(from, socket_a.local_addr().unwrap());
    }

    #[tokio::test]
    async fn client_udp_io_multiple_packets_in_order() {
        let (socket_a, socket_b) = udp_pair().await;

        let peer_addr = socket_b.local_addr().unwrap();
        let mut io = ClientUdpIo::new(socket_a.clone(), peer_addr);

        // Send multiple packets from peer
        for nonce in 0u64..5 {
            let ping_frame = encode_ping(nonce);
            socket_b.send(&ping_frame).await.unwrap();
        }

        // Receive them in order
        let mut buf = [0u8; 2048];
        for expected_nonce in 0u64..5 {
            let len = io.recv(&mut buf).await.unwrap();
            let expected = encode_ping(expected_nonce);
            assert_eq!(&buf[..len], expected.as_slice());
        }
    }

    #[tokio::test]
    async fn client_udp_io_recv_timeout_when_no_peer_packet() {
        let (socket_a, socket_b) = udp_pair().await;

        // Create a third socket that is NOT the peer
        let socket_c = Arc::new(
            tokio::net::UdpSocket::bind("127.0.0.1:0")
                .await
                .expect("failed to bind socket C"),
        );

        let peer_addr = socket_b.local_addr().unwrap();
        let mut io = ClientUdpIo::new(socket_a.clone(), peer_addr);

        // Send junk from non-peer
        let junk_packet = b"junk from non-peer";
        socket_c
            .send_to(junk_packet, socket_a.local_addr().unwrap())
            .await
            .unwrap();

        // Recv should block waiting for a packet from the actual peer
        // Use a short timeout to verify it doesn't return the non-peer packet
        let mut buf = [0u8; 2048];
        let result = timeout(Duration::from_millis(50), io.recv(&mut buf)).await;
        assert!(
            result.is_err(),
            "recv should timeout since no peer packet arrived"
        );
    }
}

/// Real socket integration tests for UDP-QSP transport.
#[cfg(test)]
mod real_socket_tests {
    use slt_core::crypto::udp_qsp::QuicQspSession;
    use slt_core::proto::{
        CloseCode, HEADER_LEN, Message, MessageLimits, PingPayload, PongPayload,
    };
    use slt_core::types::Cid;

    use super::*;
    use crate::test_support::{
        encode_close, encode_data, encode_ping, encode_pong, make_server_keys, make_test_keys,
        udp_pair,
    };

    /// Create a paired client/server UDP-QSP transport for integration testing.
    async fn udp_qsp_transport_pair() -> (UdpQspTransport<ClientUdpIo>, UdpQspTransport<ClientUdpIo>)
    {
        let (client_socket, server_socket) = udp_pair().await;
        let client_addr = client_socket.local_addr().unwrap();
        let server_addr = server_socket.local_addr().unwrap();

        let scid = Cid::from([0xA1; 20]);
        let dcid = Cid::from([0xB2; 20]);

        let client_io = ClientUdpIo::new(client_socket, server_addr);
        let client_session =
            QuicQspSession::new(client_io, scid, dcid, make_test_keys(), 0, 0, false);
        let client_metrics = Arc::new(Metrics::default());
        let client = UdpQspTransport::new(client_session, client_metrics);

        let server_io = ClientUdpIo::new(server_socket, client_addr);
        let server_session =
            QuicQspSession::new(server_io, dcid, scid, make_server_keys(), 0, 0, false);
        let server_metrics = Arc::new(Metrics::default());
        let server = UdpQspTransport::new(server_session, server_metrics);

        (client, server)
    }

    #[tokio::test]
    async fn full_roundtrip_over_real_udp_sockets() {
        let (mut client, mut server) = udp_qsp_transport_pair().await;

        let limits = MessageLimits::new(2048, 2048);
        let nonce = 0x1234_5678_9ABC_DEF0u64;

        // Client sends ping
        let ping_frame = encode_ping(nonce);
        client
            .write_message(Message::Ping {
                payload: &ping_frame[HEADER_LEN..],
            })
            .await
            .unwrap();

        // Server receives and decodes
        let msg = server.read_next_message(limits).await.unwrap();
        match msg.message() {
            Message::Ping { payload } => {
                assert_eq!(PingPayload::decode(payload).unwrap().nonce, nonce);
            }
            _ => panic!("expected ping"),
        }
    }

    #[tokio::test]
    async fn bidirectional_message_exchange_over_real_udp() {
        let (mut client, mut server) = udp_qsp_transport_pair().await;

        let limits = MessageLimits::new(2048, 2048);
        let nonce = 0xDEAD_BEEF_CAFE_BABEu64;

        // Client sends ping
        let ping_frame = encode_ping(nonce);
        client
            .write_message(Message::Ping {
                payload: &ping_frame[HEADER_LEN..],
            })
            .await
            .unwrap();

        // Server receives ping
        let msg = server.read_next_message(limits).await.unwrap();
        match msg.message() {
            Message::Ping { payload } => {
                assert_eq!(PingPayload::decode(payload).unwrap().nonce, nonce);
            }
            _ => panic!("expected ping"),
        }

        // Server sends pong
        let pong_frame = encode_pong(nonce);
        server
            .write_message(Message::Pong {
                payload: &pong_frame[HEADER_LEN..],
            })
            .await
            .unwrap();

        // Client receives pong
        let msg = client.read_next_message(limits).await.unwrap();
        match msg.message() {
            Message::Pong { payload } => {
                assert_eq!(PongPayload::decode(payload).unwrap().nonce, nonce);
            }
            _ => panic!("expected pong"),
        }
    }

    #[tokio::test]
    async fn multiple_packets_in_sequence_over_real_udp() {
        let (mut client, mut server) = udp_qsp_transport_pair().await;

        let limits = MessageLimits::new(2048, 2048);

        // Send multiple pings in sequence
        for nonce in 0u64..5 {
            let ping_frame = encode_ping(nonce);
            client
                .write_message(Message::Ping {
                    payload: &ping_frame[HEADER_LEN..],
                })
                .await
                .unwrap();

            let msg = server.read_next_message(limits).await.unwrap();
            match msg.message() {
                Message::Ping { payload } => {
                    assert_eq!(PingPayload::decode(payload).unwrap().nonce, nonce);
                }
                _ => panic!("expected ping for nonce {nonce}"),
            }
        }
    }

    #[tokio::test]
    async fn data_message_roundtrip_over_real_udp() {
        let (mut client, mut server) = udp_qsp_transport_pair().await;

        let limits = MessageLimits::new(2048, 2048);
        let packet_data = b"hello world vpn packet";

        let data_frame = encode_data(packet_data);
        client
            .write_message(Message::Data {
                packet: &data_frame[HEADER_LEN..],
            })
            .await
            .unwrap();

        let msg = server.read_next_message(limits).await.unwrap();
        match msg.message() {
            Message::Data { packet } => {
                assert_eq!(packet, &data_frame[HEADER_LEN..]);
            }
            _ => panic!("expected data"),
        }
    }

    #[tokio::test]
    async fn close_message_roundtrip_over_real_udp() {
        let (mut client, mut server) = udp_qsp_transport_pair().await;

        let limits = MessageLimits::new(2048, 2048);
        let close_code = CloseCode::Normal;

        let close_frame = encode_close(close_code);
        client
            .write_message(Message::Close {
                payload: &close_frame[HEADER_LEN..],
            })
            .await
            .unwrap();

        let msg = server.read_next_message(limits).await.unwrap();
        match msg.message() {
            Message::Close { payload } => {
                use slt_core::proto::ClosePayload;
                assert_eq!(ClosePayload::decode(payload).unwrap().code, close_code);
            }
            _ => panic!("expected close"),
        }
    }

    #[tokio::test]
    async fn server_to_client_message_over_real_udp() {
        let (mut client, mut server) = udp_qsp_transport_pair().await;

        let limits = MessageLimits::new(2048, 2048);
        let nonce = 0xF00D_FACEu64;

        // Server sends ping to client
        let ping_frame = encode_ping(nonce);
        server
            .write_message(Message::Ping {
                payload: &ping_frame[HEADER_LEN..],
            })
            .await
            .unwrap();

        // Client receives it
        let msg = client.read_next_message(limits).await.unwrap();
        match msg.message() {
            Message::Ping { payload } => {
                assert_eq!(PingPayload::decode(payload).unwrap().nonce, nonce);
            }
            _ => panic!("expected ping"),
        }
    }

    /// On Unix the client transport wraps the GSO `UdpQspIo` backend, so a data
    /// write buffers into the send slab and is only transmitted once `flush` runs.
    #[cfg(unix)]
    #[tokio::test]
    async fn write_message_buffers_until_flush_over_gso_backend() {
        use std::time::Duration;

        use tokio::time::timeout;

        let (client_socket, server_socket) = udp_pair().await;
        let client_addr = client_socket.local_addr().unwrap();
        let server_addr = server_socket.local_addr().unwrap();

        let scid = Cid::from([0xA1; 20]);
        let dcid = Cid::from([0xB2; 20]);

        let client_io = client_udp_qsp_io(&client_socket, server_addr).unwrap();
        let client_session =
            QuicQspSession::new(client_io, scid, dcid, make_test_keys(), 0, 0, false);
        let mut client = UdpQspTransport::new(client_session, Arc::new(Metrics::default()));

        let server_io = client_udp_qsp_io(&server_socket, client_addr).unwrap();
        let server_session =
            QuicQspSession::new(server_io, dcid, scid, make_server_keys(), 0, 0, false);
        let mut server = UdpQspTransport::new(server_session, Arc::new(Metrics::default()));

        let limits = MessageLimits::new(2048, 2048);
        let ping_frame = encode_ping(0xBEEF);

        // Writing buffers into the GSO send slab; nothing is transmitted yet.
        client
            .write_message(Message::Ping {
                payload: &ping_frame[HEADER_LEN..],
            })
            .await
            .unwrap();
        assert!(
            client.has_pending_flush(),
            "write_message must leave a pending flush"
        );
        assert!(
            timeout(Duration::from_millis(80), server.read_next_message(limits))
                .await
                .is_err(),
            "buffered packet must not be delivered until flush"
        );

        // Flushing transmits the slab and clears the pending flag.
        client.flush().await.unwrap();
        assert!(!client.has_pending_flush());

        let msg = server.read_next_message(limits).await.unwrap();
        match msg.message() {
            Message::Ping { payload } => {
                assert_eq!(PingPayload::decode(payload).unwrap().nonce, 0xBEEF);
            }
            _ => panic!("expected ping"),
        }
    }
}
