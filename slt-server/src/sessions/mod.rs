//! Client session tracking and lifecycle helpers.

mod egress;
mod error;
mod lifecycle;
mod register;
mod tcp;
mod types;
mod udp;
mod udp_io;
mod upgrade;

use std::collections::VecDeque;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use slt_core::crypto::udp_qsp::QuicQspSession;
use slt_core::proto::{Message, MessageLimits, PingPayload};
use slt_core::transport::UdpQspIo;
use slt_core::types::ServerUdpQspConfig;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::oneshot;
use tracing::{debug, info, trace};
use tun_rs::AsyncDevice;

use self::egress::UdpFailureRecovery;
pub use self::error::{SessionError, UdpQspError};
use self::types::SessionControl;
pub(crate) use self::types::SessionShutdownReason;
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
/// Manages the client's connection state, preferred transport (TCP or UDP-QSP),
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
    /// Receipt time of the latest accepted message on either live transport.
    pub last_activity: Instant,
    /// Preferred outbound data transport.
    pub active_transport: ActiveTransport,
    session_id: u64,
    registry: Arc<SessionRegistry>,
    metrics: Arc<Metrics>,
    tx: SessionTx,
    shutdown: Option<oneshot::Receiver<SessionShutdownReason>>,
    tcp: SessionTcpChannel<S>,
    tun: Arc<T>,
    udp_io_factory: Arc<dyn UdpSessionIoFactory<I>>,
    /// UDP-QSP session for encrypted UDP traffic. The session's peer address is
    /// updated only after packet authentication succeeds in `handle_udp_claim`.
    /// This is safe because `send_udp_message` is only called when either:
    /// - `active_transport == UdpQsp` (meaning we've authenticated UDP traffic)
    /// - We're inside `handle_udp_claim` processing an incoming UDP packet
    ///
    /// In both cases, the peer has already been set on the session.
    udp_session: Option<QuicQspSession<I>>,
    /// Highest authenticated client-to-server packet number allowed to select
    /// the UDP reply peer. Lower unseen packets remain valid replay-window
    /// traffic but cannot roll the peer back to an older path.
    udp_peer_packet_number: Option<u64>,
    /// Last packet that authenticated under this session's UDP-QSP receive keys.
    last_authenticated_udp_activity: Option<Instant>,
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
    /// A TCP write was interrupted by the managed-shutdown select. A new frame
    /// cannot safely be appended because the prior frame may be partially sent.
    tcp_write_interrupted: bool,
    /// Locally initiated TCP fallback awaiting its peer acknowledgement.
    pending_tcp_fallback: Option<u64>,
    /// Peer fallback identifier retained for session-long duplicate suppression.
    last_peer_fallback_id: Option<u64>,
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
    pub(crate) fn new(
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
        shutdown: oneshot::Receiver<SessionShutdownReason>,
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
            shutdown: Some(shutdown),
            tcp,
            tun,
            udp_io_factory,
            udp_session: None,
            udp_peer_packet_number: None,
            last_authenticated_udp_activity: None,
            udp_upgrade: UdpUpgradeState::default(),
            rx,
            limits,
            timeouts,
            udp_qsp_config,
            udp_write_buf: Vec::new(),
            udp_opened_payload_buf: Vec::new(),
            tcp_alive: true,
            tcp_write_interrupted: false,
            pending_tcp_fallback: None,
            last_peer_fallback_id: None,
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

    /// Record accepted authenticated UDP ingress for idle and path-liveness accounting.
    const fn note_authenticated_udp_activity(&mut self, received_at: Instant) {
        self.last_activity = received_at;
        self.last_authenticated_udp_activity = Some(received_at);
    }

    /// Adopt `peer` only when `packet_number` advances the receive path.
    fn adopt_udp_peer_if_newer(&mut self, peer: SocketAddr, packet_number: u64) {
        if matches!(
            self.udp_peer_packet_number,
            Some(current) if packet_number <= current
        ) {
            return;
        }

        if let Some(session) = self.udp_session.as_mut() {
            session.set_peer(peer);
            self.udp_peer_packet_number = Some(packet_number);
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
                // TCP fallback is a hard egress cutover. Discard only protected
                // packets still buffered for UDP send; keep the session's socket,
                // receive queue, crypto, and replay state for in-flight ingress.
                let discarded_packets = self
                    .udp_session
                    .as_mut()
                    .map_or(0, QuicQspSession::discard_pending_send);
                self.metrics.inc_transport_udp_to_tcp();
                debug!(
                    session_id = self.session_id,
                    client_id = %self.client_id,
                    from = "udp",
                    to = "tcp",
                    discarded_packets,
                    "transport switched"
                );
            }
            _ => {}
        }
        self.active_transport = transport;
    }

    fn cleanup(&self) {
        self.registry
            .remove_session(self.session_id, self.client_id, self.assigned_ipv4);
    }
}

#[cfg(test)]
mod tests;
