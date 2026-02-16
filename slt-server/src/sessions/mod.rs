//! Client session tracking and lifecycle helpers.

mod register;
mod types;
mod udp_io;

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use fastrand;
use slt_core::crypto::udp_qsp::{QspSessionError, QuicQspSession};
use slt_core::proto::{
    CloseCode, ClosePayload, FrameError, Message, MessageError, MessageLimits, PayloadError,
    PingPayload, PongPayload, decode_message, encode_message,
};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time;
use tracing::{debug, error, info, trace, warn};
use tun_rs::AsyncDevice;

use self::types::SessionControl;
pub use self::types::{
    ActiveTransport, SessionEvent, SessionKeyUpdater, SessionRx, SessionTcpChannel,
    SessionTimeouts, SessionTx,
};
use self::udp_io::UdpIo;
pub use self::udp_io::UdpSocketIo;
use super::metrics::Metrics;
use super::quic::UdpClaim;
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

    /// Run the session event loop until shutdown.
    ///
    /// # Errors
    ///
    /// Returns an error if the TCP stream or TUN device fails.
    pub async fn run(mut self) -> io::Result<()> {
        info!(
            session_id = self.session_id,
            client_id = %self.client_id,
            assigned_ip = %self.assigned_ipv4,
            "session created"
        );
        let result = self.run_inner().await;
        if result.is_err() {
            self.metrics.inc_disconnect_error();
            error!(
                session_id = self.session_id,
                client_id = %self.client_id,
                error = ?result.as_ref().err(),
                "session terminated with error"
            );
        } else {
            debug!(
                session_id = self.session_id,
                client_id = %self.client_id,
                "session terminated normally"
            );
        }
        self.cleanup();
        result
    }

    async fn run_inner(&mut self) -> io::Result<()> {
        let mut next_ping_at = self.schedule_next_ping();

        loop {
            if self.tcp_alive
                && self.tcp.has_buffered_input()
                && self.handle_tcp_read().await? == SessionControl::Close
            {
                return Ok(());
            }

            let idle_deadline = self.last_activity + self.timeouts.idle_timeout;

            tokio::select! {
                res = self.tcp.read_more(), if self.tcp_alive => {
                    let n = res?;
                    if n == 0 {
                        if self.active_transport == ActiveTransport::UdpQsp {
                            info!(
                                session_id = self.session_id,
                                client_id = %self.client_id,
                                "tcp connection closed; continuing on udp"
                            );
                            self.tcp_alive = false;
                            continue;
                        }
                        self.metrics.inc_disconnect_close();
                        info!(
                            session_id = self.session_id,
                            client_id = %self.client_id,
                            reason = "tcp_close",
                            "session disconnect"
                        );
                        return Ok(());
                    }
                    self.note_activity();
                    if self.handle_tcp_read().await? == SessionControl::Close {
                        return Ok(());
                    }
                }
                Some(event) = self.rx.recv() => {
                    if self.handle_event(event).await? == SessionControl::Close {
                        return Ok(());
                    }
                }
                () = time::sleep_until(next_ping_at.into()) => {
                    self.handle_ping_tick().await?;
                    next_ping_at = self.schedule_next_ping();
                }
                () = time::sleep_until(idle_deadline.into()) => {
                    self.metrics.inc_disconnect_idle_timeout();
                    info!(
                        session_id = self.session_id,
                        client_id = %self.client_id,
                        reason = "idle_timeout",
                        "session disconnect"
                    );
                    let _ = self.send_close(CloseCode::IdleTimeout).await;
                    return Ok(());
                }
            }
        }
    }

    async fn handle_tcp_read(&mut self) -> io::Result<SessionControl> {
        loop {
            let Some(msg_buf) = self
                .tcp
                .try_pop_message(self.limits)
                .map_err(map_message_error)?
            else {
                return Ok(SessionControl::Continue);
            };

            if self.handle_tcp_message(msg_buf.message()).await? == SessionControl::Close {
                return Ok(SessionControl::Close);
            }
        }
    }

    async fn handle_tcp_message(&mut self, message: Message<'_>) -> io::Result<SessionControl> {
        match message {
            Message::Auth { .. }
            | Message::AuthOk { .. }
            | Message::AuthFail { .. }
            | Message::RegisterOk { .. }
            | Message::RegisterFail { .. } => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unexpected control message on established session",
            )),
            Message::Data { packet } => {
                if self.active_transport != ActiveTransport::Tcp {
                    trace!(
                        session_id = self.session_id,
                        client_id = %self.client_id,
                        "TCP data dropped: not active transport"
                    );
                    return Ok(SessionControl::Continue);
                }
                if PacketRouter::validate_packet_src(self, packet) {
                    self.tun.send(packet).await?;
                }
                Ok(SessionControl::Continue)
            }
            Message::Ping { payload } => {
                let ping_in = PingPayload::decode(payload).map_err(map_payload_error)?;
                let pong_out = PongPayload {
                    nonce: ping_in.nonce,
                };
                let payload = pong_out.nonce.to_be_bytes();
                self.send_tcp_message(Message::Pong { payload: &payload })
                    .await?;
                Ok(SessionControl::Continue)
            }
            Message::Pong { .. } => Ok(SessionControl::Continue),
            Message::Close { .. } => {
                self.metrics.inc_disconnect_close();
                Ok(SessionControl::Close)
            }
            Message::RegisterCid { payload } => self.handle_register_cid(payload).await,
        }
    }

    async fn handle_event(&mut self, event: SessionEvent) -> io::Result<SessionControl> {
        self.note_activity();
        match event {
            SessionEvent::TunPacket(packet) => self.handle_tun_packet(packet).await,
            SessionEvent::Udp(claim) => self.handle_udp_claim(claim).await,
            SessionEvent::Shutdown => {
                self.metrics.inc_disconnect_shutdown();
                info!(
                    session_id = self.session_id,
                    client_id = %self.client_id,
                    reason = "shutdown_request",
                    "session disconnect"
                );
                Ok(SessionControl::Close)
            }
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

    async fn handle_udp_claim(&mut self, claim: UdpClaim) -> io::Result<SessionControl> {
        let peer = claim.peer;

        trace!(
            session_id = self.session_id,
            client_id = %self.client_id,
            peer = %peer,
            dcid_prefix = ?claim.dcid_prefix,
            "UDP claim received"
        );

        let Some(opened) = self.open_udp_packet(&claim.payload) else {
            return Ok(SessionControl::Continue);
        };

        self.update_udp_peer(peer);

        let Some(message) = self.decode_udp_message(&opened)? else {
            return Ok(SessionControl::Continue);
        };

        self.maybe_activate_udp(&message);

        self.dispatch_udp_message(message).await
    }

    /// Decrypt and validate a UDP-QSP packet.
    ///
    /// Returns `Some(payload)` on success, or `None` if the packet should be dropped.
    /// Handles dead channel fallback internally.
    fn open_udp_packet(&mut self, payload: &[u8]) -> Option<Vec<u8>> {
        let session = self.udp_session.as_mut()?;
        let rx_phase_before = session.rx_key_phase();

        let payload_vec = match session.open_packet(payload) {
            Ok(opened) => opened.payload.to_vec(),
            Err(QspSessionError::Replay) => {
                self.metrics.inc_udp_qsp_decrypt_fail_replay();
                trace!(
                    session_id = self.session_id,
                    client_id = %self.client_id,
                    reason = "replay",
                    "UDP packet dropped: decrypt failure"
                );
                return None;
            }
            Err(QspSessionError::TooOld) => {
                self.metrics.inc_udp_qsp_decrypt_fail_too_old();
                trace!(
                    session_id = self.session_id,
                    client_id = %self.client_id,
                    reason = "too_old",
                    "UDP packet dropped: decrypt failure"
                );
                return None;
            }
            Err(QspSessionError::DeadChannel) => {
                self.metrics.inc_udp_qsp_dead_channel();
                warn!(
                    session_id = self.session_id,
                    client_id = %self.client_id,
                    "UDP-QSP channel marked dead; falling back to tcp"
                );
                self.registry.remove_cids_for_session(self.session_id);
                self.udp_session = None;
                self.set_active_transport(ActiveTransport::Tcp);
                return None;
            }
            Err(QspSessionError::Crypto(err)) => {
                self.metrics.inc_udp_qsp_decrypt_fail_crypto();
                trace!(
                    session_id = self.session_id,
                    client_id = %self.client_id,
                    reason = "crypto",
                    error = ?err,
                    "UDP packet dropped: decrypt failure"
                );
                return None;
            }
            Err(err) => {
                self.metrics.inc_udp_qsp_decrypt_fail_other();
                trace!(
                    session_id = self.session_id,
                    client_id = %self.client_id,
                    reason = "other",
                    error = ?err,
                    "UDP packet dropped: decrypt failure"
                );
                return None;
            }
        };

        // Check for key phase transition after the match to avoid borrow conflicts.
        if let Some(session) = self.udp_session.as_ref()
            && session.rx_key_phase() != rx_phase_before
        {
            self.metrics.inc_udp_qsp_rx_key_phase_transition();
            info!(
                session_id = self.session_id,
                client_id = %self.client_id,
                key_phase = session.rx_key_phase(),
                "UDP-QSP RX key phase transitioned"
            );
        }

        Some(payload_vec)
    }

    /// Update the UDP session's peer address.
    const fn update_udp_peer(&mut self, peer: SocketAddr) {
        if let Some(session) = self.udp_session.as_mut() {
            session.io_mut().set_peer(peer);
        }
    }

    /// Decode a message from the decrypted UDP payload.
    ///
    /// Returns `Some(message)` on success, or `None` if the message
    /// is malformed or has trailing data.
    fn decode_udp_message<'a>(&self, payload: &'a [u8]) -> io::Result<Option<Message<'a>>> {
        let decoded = decode_message(payload, self.limits).map_err(map_message_error)?;
        let Some((message, consumed)) = decoded else {
            return Ok(None);
        };
        if consumed != payload.len() {
            return Ok(None);
        }
        Ok(Some(message))
    }

    /// Activate UDP transport if the message warrants it.
    fn maybe_activate_udp(&mut self, message: &Message<'_>) {
        let should_activate = matches!(
            message,
            Message::Ping { .. }
                | Message::Pong { .. }
                | Message::Data { .. }
                | Message::Close { .. }
                | Message::RegisterCid { .. }
        );
        if should_activate {
            self.set_active_transport(ActiveTransport::UdpQsp);
        }
    }

    /// Dispatch a decrypted UDP message to the appropriate handler.
    async fn dispatch_udp_message(&mut self, message: Message<'_>) -> io::Result<SessionControl> {
        match message {
            Message::Ping { payload } => {
                let ping_in = PingPayload::decode(payload).map_err(map_payload_error)?;
                let pong_out = PongPayload {
                    nonce: ping_in.nonce,
                };
                let payload = pong_out.nonce.to_be_bytes();
                self.send_udp_message(Message::Pong { payload: &payload })
                    .await?;
                Ok(SessionControl::Continue)
            }
            Message::Pong { payload } => {
                let pong_in = PongPayload::decode(payload).map_err(map_payload_error)?;
                trace!(
                    session_id = self.session_id,
                    client_id = %self.client_id,
                    nonce = pong_in.nonce,
                    "received udp pong"
                );
                Ok(SessionControl::Continue)
            }
            Message::Data { packet } => {
                if PacketRouter::validate_packet_src(self, packet) {
                    self.tun.send(packet).await?;
                }
                Ok(SessionControl::Continue)
            }
            Message::Close { .. } => Ok(SessionControl::Close),
            Message::RegisterCid { payload } => self.handle_register_cid(payload).await,
            Message::Auth { .. }
            | Message::AuthOk { .. }
            | Message::AuthFail { .. }
            | Message::RegisterOk { .. }
            | Message::RegisterFail { .. } => Ok(SessionControl::Continue),
        }
    }

    async fn handle_ping_tick(&mut self) -> io::Result<()> {
        let nonce = fastrand::u64(..);
        let ping = PingPayload { nonce };
        let mut buf = Vec::new();
        ping.encode(&mut buf);
        match self.active_transport {
            ActiveTransport::Tcp => self.send_tcp_message(Message::Ping { payload: &buf }).await,
            ActiveTransport::UdpQsp => self.send_udp_message(Message::Ping { payload: &buf }).await,
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

    fn schedule_next_ping(&self) -> Instant {
        let min = self.timeouts.ping_min;
        let max = self.timeouts.ping_max;

        // Config validation ensures timeouts <= 1 hour (fits in u64) and min <= max.
        #[allow(clippy::cast_possible_truncation, clippy::unchecked_time_subtraction)]
        let range_ms = (max - min).as_millis() as u64;
        let jitter = if range_ms > 0 {
            Duration::from_millis(fastrand::u64(0..=range_ms))
        } else {
            Duration::ZERO
        };

        Instant::now() + min + jitter
    }

    fn note_activity(&mut self) {
        self.last_activity = Instant::now();
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
