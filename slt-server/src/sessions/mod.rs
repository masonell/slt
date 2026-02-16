//! Client session tracking and lifecycle helpers.

mod lifecycle;
mod register;
mod tcp;
mod types;
mod udp;
mod udp_io;

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use slt_core::crypto::udp_qsp::{QspSessionError, QuicQspSession};
use slt_core::proto::{
    CloseCode, ClosePayload, FrameError, Message, MessageError, MessageLimits, PayloadError,
    PingPayload, encode_message,
};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpStream, UdpSocket};
use tracing::{debug, info, trace};
use tun_rs::AsyncDevice;

use self::types::SessionControl;
pub use self::types::{
    ActiveTransport, SessionEvent, SessionKeyUpdater, SessionRx, SessionTcpChannel,
    SessionTimeouts, SessionTx,
};
use self::udp_io::UdpIo;
pub use self::udp_io::UdpSocketIo;
use super::metrics::Metrics;
use super::registry::SessionRegistry;
use super::router::PacketRouter;
use super::{AssignedIp, ClientId};
use crate::tun::TunDeviceIo;

/// A single authenticated client session.
pub struct ClientSessionBase<
    T: TunDeviceIo,
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static = TcpStream,
    U: UdpSocketIo = UdpSocket,
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
    tcp: SessionTcpChannel<S>,
    tun: Arc<T>,
    udp_socket: Arc<U>,
    /// UDP-QSP session for encrypted UDP traffic. The session's peer address is
    /// updated on every incoming UDP packet from `handle_udp_claim`. This is
    /// safe because `send_udp_message` is only called when either:
    /// - `active_transport == UdpQsp` (meaning we've received at least one UDP packet)
    /// - We're inside `handle_udp_claim` processing an incoming UDP packet
    ///
    /// In both cases, the peer has already been set on the session.
    udp_session: Option<QuicQspSession<UdpIo<U>>>,
    rx: SessionRx,
    limits: MessageLimits,
    timeouts: SessionTimeouts,
    udp_write_buf: Vec<u8>,
    /// Whether the TCP connection is still usable. Set to false when TCP closes
    /// while UDP-QSP is active, allowing the session to continue on UDP alone.
    tcp_alive: bool,
}

/// Default client session using a real TUN device.
pub type ClientSession = ClientSessionBase<AsyncDevice>;

impl<T: TunDeviceIo, S: AsyncRead + AsyncWrite + Unpin + Send + 'static, U: UdpSocketIo>
    ClientSessionBase<T, S, U>
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
        udp_socket: Arc<U>,
        registry: Arc<SessionRegistry>,
        metrics: Arc<Metrics>,
        tx: SessionTx,
        rx: SessionRx,
        limits: MessageLimits,
        timeouts: SessionTimeouts,
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
            tcp,
            tun,
            udp_socket,
            udp_session: None,
            rx,
            limits,
            timeouts,
            udp_write_buf: Vec::new(),
            tcp_alive: true,
        }
    }

    async fn handle_tun_packet(&mut self, packet: Vec<u8>) -> io::Result<SessionControl> {
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
                self.send_udp_message(Message::Data {
                    packet: packet.as_slice(),
                })
                .await?;
            }
        }
        Ok(SessionControl::Continue)
    }

    fn should_forward_packet_to_tun(&self, packet: &[u8]) -> bool {
        PacketRouter::validate_packet_src(self, packet)
    }

    fn pong_payload_for_ping(payload: &[u8]) -> io::Result<[u8; 8]> {
        let ping = PingPayload::decode(payload).map_err(map_payload_error)?;
        Ok(ping.nonce.to_be_bytes())
    }

    fn peer_close_control(&self, increment_disconnect_close: bool) -> SessionControl {
        if increment_disconnect_close {
            self.metrics.inc_disconnect_close();
        }
        SessionControl::Close
    }

    /// Update the UDP session's peer address.
    const fn update_udp_peer(&mut self, peer: SocketAddr) {
        if let Some(session) = self.udp_session.as_mut() {
            session.io_mut().set_peer(peer);
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

    async fn send_message(&mut self, message: Message<'_>) -> io::Result<()> {
        match self.active_transport {
            ActiveTransport::Tcp => self.send_tcp_message(message).await,
            ActiveTransport::UdpQsp => self.send_udp_message(message).await,
        }
    }

    async fn send_tcp_message(&mut self, message: Message<'_>) -> io::Result<()> {
        self.tcp.write_message(message).await
    }

    /// Send a message via UDP-QSP.
    ///
    /// This method is only called when either:
    /// - `active_transport == UdpQsp` (meaning we've switched to UDP after receiving a packet)
    /// - We're inside `handle_udp_claim` responding to an incoming UDP message
    ///
    /// In both cases, the session's peer has already been set by `handle_udp_claim`,
    /// so we can safely send without checking for a valid peer address.
    async fn send_udp_message(&mut self, message: Message<'_>) -> io::Result<()> {
        let Some(session) = self.udp_session.as_mut() else {
            return Ok(());
        };

        self.udp_write_buf.clear();
        encode_message(message, &mut self.udp_write_buf).map_err(map_frame_error)?;
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
            Err(QspSessionError::Io(err)) => Err(err),
            Err(QspSessionError::DeadChannel) => {
                self.metrics.inc_udp_qsp_dead_channel();
                Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "udp-qsp channel dead",
                ))
            }
            Err(err) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("udp-qsp send failed: {err:?}"),
            )),
        }
    }

    async fn send_close(&mut self, code: CloseCode) -> io::Result<()> {
        let payload = ClosePayload { code };
        let mut buf = Vec::with_capacity(1);
        payload.encode(&mut buf);
        // Prefer TCP for close messages to maximize delivery reliability.
        // Only use UDP when TCP is no longer available.
        if self.tcp_alive {
            self.send_tcp_message(Message::Close { payload: &buf })
                .await
        } else {
            self.send_udp_message(Message::Close { payload: &buf })
                .await
        }
    }

    fn cleanup(&self) {
        self.registry
            .remove_session(self.session_id, self.client_id, self.assigned_ipv4);
    }
}

fn map_message_error(err: MessageError) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("message error: {err:?}"),
    )
}

fn map_frame_error(err: FrameError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("frame error: {err:?}"))
}

fn map_payload_error(err: PayloadError) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("payload error: {err:?}"),
    )
}

#[cfg(test)]
mod tests;
