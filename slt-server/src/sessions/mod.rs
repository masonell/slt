//! Client session tracking and lifecycle helpers.

mod error;
mod lifecycle;
mod register;
mod tcp;
mod types;
mod udp;
mod udp_io;
mod upgrade;

use std::collections::VecDeque;
use std::future::{Future, poll_fn};
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::task::Poll;
use std::time::{Duration, Instant};

use slt_core::crypto::udp_qsp::{QspSessionError, QuicQspSession};
use slt_core::proto::{
    CloseCode, ClosePayload, Message, MessageLimits, PingPayload, encode_message,
};
use slt_core::transport::UdpQspIo;
use slt_core::types::ServerUdpQspConfig;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::time;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, trace, warn};
use tun_rs::AsyncDevice;

pub use self::error::{SessionError, UdpQspError};
use self::types::SessionControl;
pub use self::types::{
    ActiveTransport, SessionEvent, SessionKeyUpdater, SessionRx, SessionTcpChannel,
    SessionTimeouts, SessionTx,
};
pub(crate) use self::udp_io::ServerUdpQspIoFactory;
#[cfg(test)]
pub(crate) use self::udp_io::{UdpIoFactory, UdpSocketIo};
pub use self::udp_io::{UdpSessionIo, UdpSessionIoFactory};
use super::metrics::Metrics;
use super::registry::SessionRegistry;
use super::router::PacketRouter;
use super::{AssignedIp, ClientId};
use crate::tun::{TunDeviceIo, TunPacketSendOutcome};

const BEST_EFFORT_IO_TIMEOUT: Duration = Duration::from_secs(1);

#[derive(Debug, Clone, Copy)]
enum UdpFailureRecovery {
    RetryMessageOnTcp,
    SignalTcpWithPing,
    RetireOnly,
}

#[derive(Debug, Clone, Default)]
struct UdpUpgradeState {
    upgrade_id: Option<u64>,
    probe_seen: bool,
    ready_seen: bool,
    switch_to_udp_sent: bool,
    stale_upgrade_ids: VecDeque<u64>,
}

/// Core session structure for an authenticated VPN client.
///
/// Manages the client's connection state, active transport (TCP or UDP-QSP),
/// message routing between TUN device and network transports, and session lifecycle.
/// The session is generic over the TUN device implementation, TCP stream type,
/// and UDP-QSP I/O backend to support testing and flexibility.
///
/// # Type Parameters
///
/// * `T` - TUN device I/O implementation (must implement [`TunDeviceIo`])
/// * `S` - TCP stream type (defaults to [`TcpStream`], must be async read/write)
/// * `I` - UDP-QSP session I/O backend (defaults to production [`UdpQspIo`])
pub struct ClientSessionBase<
    T: TunDeviceIo,
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static = TcpStream,
    I: UdpSessionIo = UdpQspIo,
> {
    /// Client identifier.
    pub client_id: ClientId,
    /// Assigned VPN IPv4 address.
    pub assigned_ipv4: AssignedIp,
    /// Session creation timestamp.
    pub created_at: Instant,
    /// Last activity timestamp.
    pub last_activity: Instant,
    /// Active data transport.
    pub active_transport: ActiveTransport,
    session_id: u64,
    registry: Arc<SessionRegistry>,
    metrics: Arc<Metrics>,
    tx: SessionTx,
    shutdown: CancellationToken,
    tcp: SessionTcpChannel<S>,
    tun: Arc<T>,
    udp_io_factory: Arc<dyn UdpSessionIoFactory<I>>,
    /// UDP-QSP session for encrypted UDP traffic. The session's peer address is
    /// updated on every incoming UDP packet from `handle_udp_claim`. This is
    /// safe because `send_udp_message` is only called when either:
    /// - `active_transport == UdpQsp` (meaning we've received at least one UDP packet)
    /// - We're inside `handle_udp_claim` processing an incoming UDP packet
    ///
    /// In both cases, the peer has already been set on the session.
    udp_session: Option<QuicQspSession<I>>,
    udp_upgrade: UdpUpgradeState,
    rx: SessionRx,
    limits: MessageLimits,
    timeouts: SessionTimeouts,
    udp_qsp_config: ServerUdpQspConfig,
    udp_write_buf: Vec<u8>,
    udp_opened_payload_buf: Vec<u8>,
    /// Whether the TCP connection is still usable. Set to false when TCP closes
    /// while UDP-QSP is active, allowing the session to continue on UDP alone.
    tcp_alive: bool,
}

/// Default client session type using the async TUN device.
///
/// This is the primary session type used in production, combining
/// `ClientSessionBase` with the runtime `AsyncDevice` implementation.
pub type ClientSession = ClientSessionBase<AsyncDevice>;

impl<T: TunDeviceIo, S: AsyncRead + AsyncWrite + Unpin + Send + 'static, I: UdpSessionIo>
    ClientSessionBase<T, S, I>
{
    /// Create a new client session with TCP active.
    #[must_use]
    // All constructor inputs are required session wiring dependencies, and we
    // keep them explicit at call sites instead of hiding them behind a builder.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        session_id: u64,
        client_id: ClientId,
        assigned_ipv4: AssignedIp,
        tcp: SessionTcpChannel<S>,
        tun: Arc<T>,
        udp_io_factory: Arc<dyn UdpSessionIoFactory<I>>,
        registry: Arc<SessionRegistry>,
        metrics: Arc<Metrics>,
        tx: SessionTx,
        rx: SessionRx,
        shutdown: CancellationToken,
        limits: MessageLimits,
        timeouts: SessionTimeouts,
        udp_qsp_config: ServerUdpQspConfig,
    ) -> Self {
        let now = Instant::now();
        Self {
            client_id,
            assigned_ipv4,
            created_at: now,
            last_activity: now,
            active_transport: ActiveTransport::Tcp,
            session_id,
            registry,
            metrics,
            tx,
            shutdown,
            tcp,
            tun,
            udp_io_factory,
            udp_session: None,
            udp_upgrade: UdpUpgradeState::default(),
            rx,
            limits,
            timeouts,
            udp_qsp_config,
            udp_write_buf: Vec::new(),
            udp_opened_payload_buf: Vec::new(),
            tcp_alive: true,
        }
    }

    async fn handle_tun_packet(&mut self, packet: Vec<u8>) -> Result<SessionControl, SessionError> {
        if packet.len() > self.limits.max_data_len {
            trace!(
                session_id = self.session_id,
                client_id = %self.client_id,
                packet_len = packet.len(),
                max_len = self.limits.max_data_len,
                "TUN packet dropped: size limit exceeded"
            );
            return Ok(SessionControl::Continue);
        }

        match self.active_transport {
            ActiveTransport::Tcp => {
                self.send_tcp_message(Message::Data {
                    packet: packet.as_slice(),
                })
                .await?;
            }
            ActiveTransport::UdpQsp => {
                self.send_udp_message(
                    Message::Data {
                        packet: packet.as_slice(),
                    },
                    UdpFailureRecovery::RetryMessageOnTcp,
                )
                .await?;
            }
        }
        Ok(SessionControl::Continue)
    }

    fn should_forward_packet_to_tun(&self, packet: &[u8]) -> bool {
        PacketRouter::validate_packet_src(self, packet)
    }

    fn handle_tun_packet_send_outcome(
        &self,
        outcome: TunPacketSendOutcome,
    ) -> Result<(), SessionError> {
        match outcome {
            TunPacketSendOutcome::Accepted => Ok(()),
            TunPacketSendOutcome::Dropped { bytes } => {
                trace!(
                    session_id = self.session_id,
                    client_id = %self.client_id,
                    bytes,
                    "TUN packet dropped by delivery path"
                );
                Ok(())
            }
            TunPacketSendOutcome::Closed => {
                Err(io::Error::new(io::ErrorKind::BrokenPipe, "TUN delivery path closed").into())
            }
        }
    }

    fn pong_payload_for_ping(payload: &[u8]) -> Result<[u8; 8], SessionError> {
        let ping = PingPayload::decode(payload)?;
        Ok(ping.nonce.to_be_bytes())
    }

    fn peer_close_control(&self, increment_disconnect_close: bool) -> SessionControl {
        if increment_disconnect_close {
            self.metrics.inc_disconnect_close();
        }
        SessionControl::Close
    }

    /// Update the UDP session's peer address.
    fn update_udp_peer(&mut self, peer: SocketAddr) {
        if let Some(session) = self.udp_session.as_mut() {
            session.set_peer(peer);
        }
    }

    fn set_active_transport(&mut self, transport: ActiveTransport) {
        if self.active_transport == transport {
            return;
        }
        match (self.active_transport, transport) {
            (ActiveTransport::Tcp, ActiveTransport::UdpQsp) => {
                self.metrics.inc_transport_tcp_to_udp();
                info!(
                    session_id = self.session_id,
                    client_id = %self.client_id,
                    from = "tcp",
                    to = "udp",
                    "transport switched"
                );
            }
            (ActiveTransport::UdpQsp, ActiveTransport::Tcp) => {
                self.metrics.inc_transport_udp_to_tcp();
                debug!(
                    session_id = self.session_id,
                    client_id = %self.client_id,
                    from = "udp",
                    to = "tcp",
                    "transport switched"
                );
            }
            _ => {}
        }
        self.active_transport = transport;
    }

    async fn send_message(&mut self, message: Message<'_>) -> Result<(), SessionError> {
        match self.active_transport {
            ActiveTransport::Tcp => self.send_tcp_message(message).await,
            ActiveTransport::UdpQsp => {
                self.send_udp_message_and_flush(message, UdpFailureRecovery::RetryMessageOnTcp)
                    .await
            }
        }
    }

    async fn send_tcp_message(&mut self, message: Message<'_>) -> Result<(), SessionError> {
        let timeout = self.timeouts.tcp_write_timeout;
        let write = self.tcp.write_message(message);
        tokio::pin!(write);

        // Most writes complete on their first poll. Only register a Tokio timer
        // after socket/TLS backpressure actually makes the write pending.
        let first_poll = poll_fn(|cx| Poll::Ready(write.as_mut().poll(cx))).await;
        let result = match first_poll {
            Poll::Ready(result) => result,
            Poll::Pending => {
                let Ok(result) = time::timeout(timeout, write.as_mut()).await else {
                    warn!(
                        session_id = self.session_id,
                        client_id = %self.client_id,
                        timeout_ms = timeout.as_millis(),
                        "tcp message write timed out"
                    );
                    return Err(SessionError::Connection {
                        source: io::Error::new(
                            io::ErrorKind::TimedOut,
                            "tcp message write timed out",
                        ),
                    });
                };
                result
            }
        };

        result.map_err(|err| match err {
            slt_core::transport::tcp::TcpWriteError::Frame(frame) => SessionError::Frame(frame),
            slt_core::transport::tcp::TcpWriteError::Io(source) => {
                SessionError::Connection { source }
            }
        })
    }

    /// Send a message via UDP-QSP.
    ///
    /// This method is only called when either:
    /// - `active_transport == UdpQsp` (meaning we've switched to UDP after receiving a packet)
    /// - We're inside `handle_udp_claim` responding to an incoming UDP message
    ///
    /// In both cases, the session's peer has already been set by `handle_udp_claim`,
    /// so we can safely send without checking for a valid peer address.
    async fn queue_udp_message(&mut self, message: Message<'_>) -> Result<(), UdpQspError> {
        let Some(session) = self.udp_session.as_mut() else {
            return Ok(());
        };

        self.udp_write_buf.clear();
        encode_message(message, &mut self.udp_write_buf)?;
        let tx_phase_before = session.tx_key_phase();
        match session.send(&self.udp_write_buf).await {
            Ok(()) => {
                if session.tx_key_phase() != tx_phase_before {
                    self.metrics.inc_udp_qsp_tx_key_phase_transition();
                    info!(
                        session_id = self.session_id,
                        client_id = %self.client_id,
                        key_phase = session.tx_key_phase(),
                        "UDP-QSP TX key phase transitioned"
                    );
                }
                Ok(())
            }
            Err(QspSessionError::DeadChannel) => {
                self.metrics.inc_udp_qsp_dead_channel();
                Err(UdpQspError::Qsp(QspSessionError::DeadChannel))
            }
            Err(err) => Err(UdpQspError::Qsp(err)),
        }
    }

    async fn send_udp_message(
        &mut self,
        message: Message<'_>,
        recovery: UdpFailureRecovery,
    ) -> Result<(), SessionError> {
        match self.queue_udp_message(message).await {
            Ok(()) => Ok(()),
            Err(err) => {
                self.recover_from_udp_send_error(message, recovery, err)
                    .await
            }
        }
    }

    async fn send_udp_message_and_flush(
        &mut self,
        message: Message<'_>,
        recovery: UdpFailureRecovery,
    ) -> Result<(), SessionError> {
        self.send_udp_message(message, recovery).await?;
        match self.flush_udp_session().await {
            Ok(()) => Ok(()),
            Err(source) => {
                self.recover_from_udp_flush_error(Some(message), recovery, source)
                    .await
            }
        }
    }

    async fn flush_udp_session(&mut self) -> io::Result<()> {
        if let Some(session) = self.udp_session.as_mut() {
            session.flush().await?;
        }
        Ok(())
    }

    async fn recover_from_udp_send_error(
        &mut self,
        message: Message<'_>,
        recovery: UdpFailureRecovery,
        err: UdpQspError,
    ) -> Result<(), SessionError> {
        if !matches!(err, UdpQspError::Qsp(_) | UdpQspError::Io(_)) {
            return Err(err.into());
        }

        warn!(
            session_id = self.session_id,
            client_id = %self.client_id,
            error = %err,
            "UDP-QSP send failed; clearing udp state"
        );
        self.retire_udp_transport();
        self.apply_udp_failure_recovery(Some(message), recovery, err.into())
            .await
    }

    async fn recover_from_udp_flush_error(
        &mut self,
        message: Option<Message<'_>>,
        recovery: UdpFailureRecovery,
        source: io::Error,
    ) -> Result<(), SessionError> {
        warn!(
            session_id = self.session_id,
            client_id = %self.client_id,
            error = %source,
            "UDP-QSP flush failed; clearing udp state"
        );
        self.retire_udp_transport();
        self.apply_udp_failure_recovery(
            message,
            recovery,
            SessionError::UdpQsp(UdpQspError::Io(source)),
        )
        .await
    }

    async fn apply_udp_failure_recovery(
        &mut self,
        message: Option<Message<'_>>,
        recovery: UdpFailureRecovery,
        fallback_error: SessionError,
    ) -> Result<(), SessionError> {
        if !self.tcp_alive {
            return Err(fallback_error);
        }

        self.set_active_transport(ActiveTransport::Tcp);
        match recovery {
            UdpFailureRecovery::RetryMessageOnTcp => {
                let Some(message) = message else {
                    return self.send_tcp_ping_after_udp_fallback().await;
                };
                self.send_tcp_message(message).await
            }
            UdpFailureRecovery::SignalTcpWithPing => self.send_tcp_ping_after_udp_fallback().await,
            UdpFailureRecovery::RetireOnly => Ok(()),
        }
    }

    async fn send_tcp_ping_after_udp_fallback(&mut self) -> Result<(), SessionError> {
        let nonce = fastrand::u64(..);
        let ping = PingPayload { nonce };
        let mut buf = Vec::with_capacity(8);
        ping.encode(&mut buf);
        debug!(
            session_id = self.session_id,
            client_id = %self.client_id,
            "sent immediate tcp ping after udp-qsp fallback"
        );
        self.send_tcp_message(Message::Ping { payload: &buf }).await
    }

    fn retire_udp_transport(&mut self) {
        self.registry.remove_cids_for_session(self.session_id);
        self.udp_session = None;
        self.reset_udp_upgrade_state();
    }

    async fn flush_pending_udp_session_best_effort(&mut self) {
        let Some(session) = self.udp_session.as_mut() else {
            return;
        };
        if !session.has_pending_flush() {
            return;
        }
        match time::timeout(BEST_EFFORT_IO_TIMEOUT, session.flush()).await {
            Ok(Ok(())) => {}
            Ok(Err(err)) => {
                debug!(
                    session_id = self.session_id,
                    client_id = %self.client_id,
                    error = %err,
                    "failed to flush pending udp-qsp packets during shutdown"
                );
            }
            Err(_) => {
                debug!(
                    session_id = self.session_id,
                    client_id = %self.client_id,
                    timeout_ms = BEST_EFFORT_IO_TIMEOUT.as_millis(),
                    "timed out flushing pending udp-qsp packets during shutdown"
                );
            }
        }
    }

    fn has_pending_udp_flush(&self) -> bool {
        self.active_transport == ActiveTransport::UdpQsp
            && self
                .udp_session
                .as_ref()
                .is_some_and(QuicQspSession::has_pending_flush)
    }

    async fn send_close(&mut self, code: CloseCode) -> Result<(), SessionError> {
        let payload = ClosePayload { code };
        let mut buf = Vec::with_capacity(1);
        payload.encode(&mut buf);
        // Prefer TCP for close messages to maximize delivery reliability.
        // Only use UDP when TCP is no longer available.
        if self.tcp_alive {
            self.send_tcp_message(Message::Close { payload: &buf })
                .await
        } else {
            self.send_udp_message_and_flush(
                Message::Close { payload: &buf },
                UdpFailureRecovery::RetryMessageOnTcp,
            )
            .await
        }
    }

    fn cleanup(&self) {
        self.registry
            .remove_session(self.session_id, self.client_id, self.assigned_ipv4);
    }
}

#[cfg(test)]
mod tests;
