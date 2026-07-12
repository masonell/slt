use std::io;
use std::net::SocketAddr;
#[cfg(any(target_os = "android", target_os = "linux"))]
use std::os::fd::AsFd;
use std::sync::Arc;

#[cfg(not(any(target_os = "android", target_os = "linux")))]
pub use ClientUdpIo as ClientUdpQspIo;
use slt_core::crypto::udp_qsp::{QspSessionError, QuicQspSession, SessionIo};
use slt_core::proto::{FrameError, MessageError};
#[cfg(target_os = "android")]
pub use slt_core::transport::PlainUdpQspIo as ClientUdpQspIo;
#[cfg(target_os = "linux")]
pub use slt_core::transport::UdpQspIo as ClientUdpQspIo;
use tokio::net::UdpSocket;
use tracing::{info, trace, warn};

use crate::metrics::Metrics;

/// A failure from the UDP-QSP transport.
///
/// [`Self::is_recoverable`] is the typed recoverable-vs-fatal decision; the
/// UDP-QSP and proto encode errors from `slt_core` are carried as-is.
///
/// Actual socket I/O on the UDP path keeps using raw `io::Error` (carried here
/// via `Io`): this typed error is scoped to the *domain* failures —
/// replay/crypto/proto — not to legitimate `send_to`/`recv_from`
/// I/O, which stays `io::Error`.
#[derive(Debug, thiserror::Error)]
pub enum UdpQspError {
    /// Recv-side network-level I/O error from the underlying UDP socket
    /// (`recv_from`). Only **transient** kinds are recoverable (see
    /// [`Self::is_recoverable`]): one failed datagram recv is not evidence the
    /// UDP path is dead, so the session drops it and keeps the UDP path alive
    /// (the idle-timeout backstops a persistently-failing path). Send-side I/O
    /// from `session.send` uses [`Self::SendIo`] (never recoverable);
    /// flush-time send I/O reaches the session separately as a non-recoverable
    /// `SessionError::Io`, so it falls back to TCP the same way.
    #[error(transparent)]
    Io(#[from] io::Error),

    /// Send-side network-level I/O error from `session.send` (`send_to` / GSO
    /// flush). **Never recoverable**: a send failure is not droppable — dropping
    /// it would lose the outbound packet and leave the session sending over a
    /// path that just failed, so it propagates to TCP fallback (or close if TCP
    /// is dead). Constructed only by `UdpQspTransport::write_message`, which
    /// re-wraps `QspSessionError::Io` from `session.send` here so the
    /// send-vs-recv distinction survives.
    #[error("udp-qsp send io error: {source}")]
    SendIo {
        /// Underlying socket I/O error from the send.
        #[source]
        source: io::Error,
    },

    /// UDP-QSP session failure: a replayed/too-old packet number, a packet
    /// number overflow, or a crypto (header-protection/AEAD) failure.
    ///
    /// [`Self::is_recoverable`] classifies the inner variant so the recoverable
    /// packet-level failures (replay, too-old, crypto failure) can be dropped
    /// while packet-number overflow propagates.
    #[error(transparent)]
    Qsp(#[from] QspSessionError),

    /// Protocol framing error from `encode_message`. Fatal: a version mismatch
    /// / corruption that retry won't fix.
    #[error(transparent)]
    Frame(#[from] FrameError),

    /// Protocol message encode/decode error. Fatal: a version mismatch /
    /// corruption that retry won't fix.
    #[error(transparent)]
    Message(#[from] MessageError),

    /// Received a UDP-QSP packet whose authenticated payload did not contain a
    /// complete framed message. Fatal: UDP datagrams are atomic, so a later
    /// datagram cannot complete this message.
    #[error("udp-qsp message incomplete")]
    IncompleteMessage,
}

impl UdpQspError {
    /// Recoverable-vs-fatal policy for the UDP-QSP transport.
    ///
    /// Recoverable failures are *droppable* (drop & continue): the session drops
    /// the offending packet and keeps the UDP path alive. Other failures must
    /// propagate so the session can distinguish path failure from an
    /// authenticated protocol violation.
    ///
    /// # Policy
    ///
    /// Recoverable (drop & continue):
    /// - [`Self::Qsp`] with inner `Replay` / `TooOld` / `Crypto(_)` — a single
    ///   bad/garbage/replayed packet. Dropped by the session, which keeps the
    ///   UDP path alive.
    /// - [`Self::Qsp`] with inner `QspSessionError::Io(_)` and standalone
    ///   [`Self::Io`] — a UDP socket send/recv failure. Only **transient**
    ///   kinds (`WouldBlock`, `TimedOut`, `ConnectionRefused`,
    ///   `ConnectionReset`) are dropped: one failed datagram is not evidence
    ///   the path is dead. A **real socket failure** (`PermissionDenied`,
    ///   `NetworkUnreachable`, `HostUnreachable`, `BrokenPipe`,
    ///   `NotConnected`, …) is NOT droppable — it propagates to TCP fallback /
    ///   close / reconnect so the session fails fast instead of spinning on a
    ///   persistent I/O error (and the refresh probe doesn't retry until its
    ///   timeout on an immediate permanent failure).
    ///
    /// Non-recoverable (propagate out of the UDP-QSP transport):
    /// - [`Self::Qsp`] with inner `PacketNumberOverflow` — the TX packet-number
    ///   space is exhausted; the session cannot send again on this UDP path.
    ///   Dropping overflow would silently lose packets on a session that can no
    ///   longer send, so it is classified fatal to keep the TCP-fallback
    ///   routing (or close if TCP is dead) — NOT a drop. The session reconnects
    ///   for a fresh packet-number space only once it re-establishes (via the
    ///   runtime's reconnect policy), not as an immediate consequence of the
    ///   overflow.
    /// - [`Self::Frame`] — a local message-encoding failure.
    /// - [`Self::Message`] / [`Self::IncompleteMessage`] — an authenticated
    ///   framing violation, invalid message, or incomplete atomic datagram.
    ///   These protocol failures terminate the session with `ProtocolError`.
    ///
    /// Arms are grouped by policy for reviewability. Pinned by
    /// `recoverable_policy_pins_each_shape`.
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
            // Fatal: TX packet-number space exhausted — session cannot send
            // again on this UDP path. Propagate to TCP fallback (a recoverable
            // classification here would silently drop packets on a session that
            // can no longer send). See doc above.
            Self::Qsp(QspSessionError::PacketNumberOverflow) => false,
            // Protocol encode/decode failures terminate the session.
            Self::Frame(_) | Self::Message(_) | Self::IncompleteMessage => false,
        }
    }
}

/// Client-side UDP-QSP socket I/O backed by a `tokio::net::UdpSocket`.
#[cfg(any(test, not(any(target_os = "android", target_os = "linux"))))]
pub struct ClientUdpIo {
    socket: Arc<UdpSocket>,
    peer: SocketAddr,
}

#[cfg(any(test, not(any(target_os = "android", target_os = "linux"))))]
impl ClientUdpIo {
    /// Create a new UDP-QSP I/O wrapper for traffic to/from `peer`.
    #[must_use]
    pub const fn new(socket: Arc<UdpSocket>, peer: SocketAddr) -> Self {
        Self { socket, peer }
    }

    #[cfg(not(any(target_os = "android", target_os = "linux")))]
    /// Return the accepted receive peer and outbound transmit destination.
    #[must_use]
    pub const fn peer(&self) -> SocketAddr {
        self.peer
    }
}

#[cfg(any(target_os = "android", target_os = "linux"))]
pub fn client_udp_qsp_io(socket: &Arc<UdpSocket>, peer: SocketAddr) -> io::Result<ClientUdpQspIo> {
    let fd = socket.as_fd().try_clone_to_owned()?;
    let socket = std::net::UdpSocket::from(fd);
    socket.set_nonblocking(true)?;
    ClientUdpQspIo::new(socket, peer)
}

#[cfg(not(any(target_os = "android", target_os = "linux")))]
pub fn client_udp_qsp_io(socket: &Arc<UdpSocket>, peer: SocketAddr) -> io::Result<ClientUdpQspIo> {
    Ok(ClientUdpQspIo::new(socket.clone(), peer))
}

#[cfg(any(test, not(any(target_os = "android", target_os = "linux"))))]
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

    /// Discard protected packets buffered for send while preserving receive and
    /// UDP-QSP cryptographic state. Returns the number of packets discarded.
    pub fn discard_pending_send(&mut self) -> usize {
        self.session.discard_pending_send()
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
    ///   ([`UdpQspError::Qsp`]) or socket I/O ([`UdpQspError::Io`]).
    ///   Use [`UdpQspError::is_recoverable`] to classify drop-vs-propagate.
    pub async fn write_message(
        &mut self,
        message: slt_core::proto::Message<'_>,
    ) -> Result<(), UdpQspError> {
        self.write_buf.clear();
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
            // Send-side I/O is re-wrapped as `SendIo` (never recoverable) so a
            // send failure falls back to TCP rather than being dropped like a
            // recv-side transient.
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
    ///   overflow) ([`UdpQspError::Qsp`]).
    /// - Socket recv fails ([`UdpQspError::Io`]).
    /// - Message decoding fails ([`UdpQspError::Message`]).
    /// - The decrypted payload does not contain a complete framed message
    ///   ([`UdpQspError::IncompleteMessage`]).
    ///
    /// Recoverable failures (see [`UdpQspError::is_recoverable`]) are typically
    /// dropped by the caller.
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

            match slt_core::proto::decode_padded_message(opened.payload, limits) {
                Ok(Some((message, frame_bytes))) => Ok((message.ty(), frame_bytes.to_vec())),
                Ok(None) => Err(UdpQspError::IncompleteMessage),
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
    /// The error itself is returned typed to the caller; this method bumps the
    /// per-variant metric.
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
mod tests;
