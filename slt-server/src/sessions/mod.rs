//! Client session tracking and lifecycle helpers.

mod udp_io;

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use boring::ssl::SslRef;
use fastrand;
use slt_core::crypto::udp_qsp::{QspSessionError, QuicQspSession, UdpQspKeys};
use slt_core::proto::{
    CloseCode, ClosePayload, FrameError, Message, MessageError, MessageLimits, PayloadError,
    PingPayload, PongPayload, RegisterCidPayload, RegisterFailCode, RegisterFailPayload,
    RegisterOkPayload, decode_message, encode_message,
};
use slt_core::transport::tcp::{
    IntervalKeyUpdater, KeyUpdater, TcpChannel, default_interval_key_updater,
};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tokio::time;
use tracing::{debug, error, info, trace, warn};
use tun_rs::AsyncDevice;

use self::udp_io::UdpIo;
pub use self::udp_io::UdpSocketIo;
use super::metrics::Metrics;
use super::quic::UdpClaim;
use super::registry::{CidInsertError, SessionRegistry};
use super::router::PacketRouter;
use super::{AssignedIp, ClientId};
use crate::tun::TunDeviceIo;

/// Active transport for a client session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActiveTransport {
    /// TLS-over-TCP transport.
    Tcp,
    /// UDP-QSP transport.
    UdpQsp,
}

/// Inbound events delivered to a `ClientSession`.
#[derive(Debug)]
pub enum SessionEvent {
    /// Claimed UDP-QSP datagram destined for this session.
    Udp(UdpClaim),
    /// IP packet read from TUN destined for the client.
    TunPacket(Vec<u8>),
    /// Request that the session shut down.
    Shutdown,
}

/// Sender for delivering events to a session.
pub type SessionTx = mpsc::Sender<SessionEvent>;
/// Receiver for session events.
pub type SessionRx = mpsc::Receiver<SessionEvent>;
/// Metrics-aware TLS key updater used by server session channels.
#[derive(Debug, Clone)]
pub struct SessionKeyUpdater {
    inner: IntervalKeyUpdater,
    metrics: Arc<Metrics>,
}

impl SessionKeyUpdater {
    /// Create a metrics-aware key updater with default interval policy.
    #[must_use]
    pub const fn new(metrics: Arc<Metrics>) -> Self {
        Self {
            inner: default_interval_key_updater(),
            metrics,
        }
    }
}

impl KeyUpdater for SessionKeyUpdater {
    fn maybe_request_key_update(&mut self, ssl: &mut SslRef) -> io::Result<()> {
        let will_update = self.inner.messages_until_update() == 1;
        let request_peer_update = self.inner.requests_peer_update();
        if will_update {
            self.metrics.inc_tls_key_update_requested();
        }
        self.inner.maybe_request_key_update(ssl)?;
        if will_update {
            self.metrics.inc_tls_key_update_applied();
            trace!(
                request_peer_update,
                "server TCP TLS key update applied before outbound message"
            );
        }
        Ok(())
    }
}

/// Session TCP channel with interval-based TLS key updates.
pub type SessionTcpChannel<S = TcpStream> = TcpChannel<S, SessionKeyUpdater>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SessionControl {
    Continue,
    Close,
}

#[derive(Debug, Clone, Copy)]
pub struct SessionTimeouts {
    /// Minimum interval between keepalive pings.
    pub ping_min: Duration,
    /// Maximum interval between keepalive pings.
    pub ping_max: Duration,
    /// Idle timeout for the session.
    pub idle_timeout: Duration,
}

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

    #[allow(clippy::too_many_lines)]
    async fn handle_udp_claim(&mut self, claim: UdpClaim) -> io::Result<SessionControl> {
        let peer = claim.peer;

        trace!(
            session_id = self.session_id,
            client_id = %self.client_id,
            peer = %peer,
            dcid_prefix = ?claim.dcid_prefix,
            "UDP claim received"
        );

        let opened_payload = {
            let Some(session) = self.udp_session.as_mut() else {
                return Ok(SessionControl::Continue);
            };

            let rx_phase_before = session.rx_key_phase();
            match session.open_packet(&claim.payload) {
                Ok(opened) => {
                    let payload = opened.payload.to_vec();
                    if session.rx_key_phase() != rx_phase_before {
                        self.metrics.inc_udp_qsp_rx_key_phase_transition();
                        info!(
                            session_id = self.session_id,
                            client_id = %self.client_id,
                            key_phase = session.rx_key_phase(),
                            "UDP-QSP RX key phase transitioned"
                        );
                    }
                    payload
                }
                Err(QspSessionError::Replay) => {
                    self.metrics.inc_udp_qsp_decrypt_fail_replay();
                    trace!(
                        session_id = self.session_id,
                        client_id = %self.client_id,
                        reason = "replay",
                        "UDP packet dropped: decrypt failure"
                    );
                    return Ok(SessionControl::Continue);
                }
                Err(QspSessionError::TooOld) => {
                    self.metrics.inc_udp_qsp_decrypt_fail_too_old();
                    trace!(
                        session_id = self.session_id,
                        client_id = %self.client_id,
                        reason = "too_old",
                        "UDP packet dropped: decrypt failure"
                    );
                    return Ok(SessionControl::Continue);
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
                    return Ok(SessionControl::Continue);
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
                    return Ok(SessionControl::Continue);
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
                    return Ok(SessionControl::Continue);
                }
            }
        };

        // Update the session's peer address on every incoming UDP packet.
        // The peer address comes from the UDP packet's source, which may change
        // if the client's NAT mapping changes.
        if let Some(session) = self.udp_session.as_mut() {
            session.io_mut().set_peer(peer);
        }

        let decoded = decode_message(&opened_payload, self.limits).map_err(map_message_error)?;
        let Some((message, consumed)) = decoded else {
            return Ok(SessionControl::Continue);
        };
        if consumed != opened_payload.len() {
            return Ok(SessionControl::Continue);
        }

        let should_activate_udp = matches!(
            &message,
            Message::Ping { .. }
                | Message::Pong { .. }
                | Message::Data { .. }
                | Message::Close { .. }
                | Message::RegisterCid { .. }
        );
        if should_activate_udp {
            self.set_active_transport(ActiveTransport::UdpQsp);
        }

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

    #[allow(clippy::too_many_lines)]
    async fn handle_register_cid(&mut self, payload: &[u8]) -> io::Result<SessionControl> {
        let Ok(register) = RegisterCidPayload::decode(payload) else {
            warn!(
                session_id = self.session_id,
                client_id = %self.client_id,
                active_transport = ?self.active_transport,
                reason = "decode_failed",
                "register_cid rejected"
            );
            self.send_register_fail(RegisterFailCode::InvalidCid)
                .await?;
            return Ok(SessionControl::Continue);
        };

        let Ok(keys) = UdpQspKeys::from_register(&register) else {
            warn!(
                session_id = self.session_id,
                client_id = %self.client_id,
                active_transport = ?self.active_transport,
                reason = "invalid_keys",
                "register_cid rejected"
            );
            self.send_register_fail(RegisterFailCode::InvalidKeys)
                .await?;
            return Ok(SessionControl::Continue);
        };

        if let Err(CidInsertError::PrefixCollision(_)) =
            self.registry
                .insert_cid(self.session_id, register.dcid.prefix(), self.tx.clone())
        {
            warn!(
                session_id = self.session_id,
                client_id = %self.client_id,
                active_transport = ?self.active_transport,
                dcid_prefix = ?register.dcid.prefix(),
                reason = "prefix_collision",
                "register_cid rejected"
            );
            self.send_register_fail(RegisterFailCode::InvalidCid)
                .await?;
            return Ok(SessionControl::Continue);
        }

        self.registry
            .remove_cids_for_session_except(self.session_id, register.dcid.prefix());

        // Create the UDP session with a placeholder peer address. The actual peer
        // is set by `handle_udp_claim` when the first UDP packet arrives.
        // This is safe because:
        // 1. We don't switch `active_transport` to UDP until after the first valid UDP claim
        // 2. `send_udp_message` is only called when `active_transport == UdpQsp`
        // 3. Therefore, we never send to this placeholder address
        let placeholder_peer = SocketAddr::from(([0, 0, 0, 0], 0));
        let io = UdpIo::new(self.udp_socket.clone(), placeholder_peer);
        let udp = QuicQspSession::new(
            io,
            register.scid,
            register.dcid,
            keys,
            register.pn_start,
            register.pn_start_rx,
            register.key_phase,
        );

        self.udp_session = Some(udp);
        // Do not switch transport until the first valid UDP claim arrives.
        // This ensures the session's peer address is set before we send any data.

        debug!(
            session_id = self.session_id,
            client_id = %self.client_id,
            active_transport = ?self.active_transport,
            dcid_prefix = ?register.dcid.prefix(),
            scid = ?register.scid,
            "register_cid accepted"
        );

        let ok = RegisterOkPayload {
            dcid: register.dcid,
        };
        let mut ok_buf = Vec::new();
        ok.encode(&mut ok_buf).map_err(map_payload_error)?;
        self.send_message(Message::RegisterOk { payload: &ok_buf })
            .await?;

        Ok(SessionControl::Continue)
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

    async fn send_register_fail(&mut self, code: RegisterFailCode) -> io::Result<()> {
        let payload = RegisterFailPayload { code };
        let mut buf = Vec::with_capacity(1);
        payload.encode(&mut buf);
        self.send_message(Message::RegisterFail { payload: &buf })
            .await
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
mod tests {
    use std::net::Ipv4Addr;
    use std::path::PathBuf;
    use std::sync::Arc;

    use boring::ssl::{SslAcceptor, SslConnector, SslFiletype, SslMethod, SslVerifyMode};
    use slt_core::proto::{
        AEAD_IV_LEN, AEAD_KEY_LEN, CipherSuite, CloseCode, ClosePayload, HP_KEY_LEN,
        RegisterFailCode, RegisterFailPayload,
    };
    use slt_core::types::{Cid, QUIC_DCID_PREFIX_LEN};
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
    use tokio::sync::mpsc;
    use tokio::time::{Duration, timeout};

    use super::*;

    #[derive(Clone)]
    struct TestTun {
        tx: mpsc::Sender<Vec<u8>>,
    }

    impl TunDeviceIo for TestTun {
        fn send<'a>(
            &'a self,
            buf: &'a [u8],
        ) -> impl std::future::Future<Output = io::Result<usize>> + Send + 'a {
            let tx = self.tx.clone();
            async move {
                let _ = tx.send(buf.to_vec()).await;
                Ok(buf.len())
            }
        }
    }

    struct TestUdpSocket {
        tx: mpsc::Sender<Vec<u8>>,
    }

    impl UdpSocketIo for TestUdpSocket {
        fn send_to<'a>(
            &'a self,
            buf: &'a [u8],
            _peer: SocketAddr,
        ) -> impl std::future::Future<Output = io::Result<usize>> + Send + 'a {
            let tx = self.tx.clone();
            async move {
                let _ = tx.send(buf.to_vec()).await;
                Ok(buf.len())
            }
        }
    }

    fn cert_paths() -> (PathBuf, PathBuf) {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        (
            root.join("../vendor/boring/test/cert.pem"),
            root.join("../vendor/boring/test/key.pem"),
        )
    }

    fn tls_acceptor() -> SslAcceptor {
        let (cert, key) = cert_paths();
        let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
        builder.set_certificate_chain_file(cert).unwrap();
        builder.set_private_key_file(key, SslFiletype::PEM).unwrap();
        builder.check_private_key().unwrap();
        builder.build()
    }

    fn tls_connector() -> SslConnector {
        let mut builder = SslConnector::builder(SslMethod::tls()).unwrap();
        builder.set_verify(SslVerifyMode::NONE);
        builder.build()
    }

    async fn tls_pair() -> (
        tokio_boring::SslStream<DuplexStream>,
        tokio_boring::SslStream<DuplexStream>,
    ) {
        let acceptor = tls_acceptor();
        let connector = tls_connector();
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let server = tokio_boring::accept(&acceptor, server_io);
        let client = tokio_boring::connect(connector.configure().unwrap(), "localhost", client_io);
        let (server_tls, client_tls) = tokio::try_join!(server, client).unwrap();
        (server_tls, client_tls)
    }

    fn default_timeouts() -> SessionTimeouts {
        SessionTimeouts {
            ping_min: Duration::from_secs(3600),
            ping_max: Duration::from_secs(3600),
            idle_timeout: Duration::from_secs(3600),
        }
    }

    async fn spawn_session() -> (
        tokio::task::JoinHandle<io::Result<()>>,
        tokio_boring::SslStream<DuplexStream>,
        SessionTx,
        mpsc::Receiver<Vec<u8>>,
        mpsc::Receiver<Vec<u8>>,
        MessageLimits,
        AssignedIp,
        Arc<SessionRegistry>,
    ) {
        spawn_session_with_timeouts(default_timeouts()).await
    }

    async fn spawn_session_with_timeouts(
        timeouts: SessionTimeouts,
    ) -> (
        tokio::task::JoinHandle<io::Result<()>>,
        tokio_boring::SslStream<DuplexStream>,
        SessionTx,
        mpsc::Receiver<Vec<u8>>,
        mpsc::Receiver<Vec<u8>>,
        MessageLimits,
        AssignedIp,
        Arc<SessionRegistry>,
    ) {
        let (server_tls, client_tls) = tls_pair().await;
        let (tun_tx, tun_rx) = mpsc::channel(8);
        let (udp_tx, udp_rx) = mpsc::channel(16);
        let tun = Arc::new(TestTun { tx: tun_tx });
        let registry = Arc::new(SessionRegistry::new());
        let metrics = Arc::new(Metrics::default());
        let (tx, rx) = mpsc::channel(8);
        let client_id = ClientId([0xA5; 16]);
        let assigned = AssignedIp(Ipv4Addr::new(10, 0, 0, 9));
        let (handle, _old) = registry.register_session(client_id, assigned, tx.clone());
        let limits = MessageLimits::from_mtu(1500);
        let session = ClientSessionBase::<TestTun, DuplexStream, TestUdpSocket>::new(
            handle.session_id,
            client_id,
            assigned,
            TcpChannel::with_key_updater(server_tls, SessionKeyUpdater::new(metrics.clone())),
            tun,
            Arc::new(TestUdpSocket { tx: udp_tx }),
            registry.clone(),
            metrics,
            tx.clone(),
            rx,
            limits,
            timeouts,
        );
        let join = tokio::spawn(async move { session.run().await });
        (
            join, client_tls, tx, tun_rx, udp_rx, limits, assigned, registry,
        )
    }

    async fn read_message_bytes(
        stream: &mut tokio_boring::SslStream<DuplexStream>,
        limits: MessageLimits,
    ) -> io::Result<Vec<u8>> {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            let n = stream.read(&mut chunk).await?;
            if n == 0 {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "tls closed"));
            }
            buf.extend_from_slice(&chunk[..n]);
            match decode_message(&buf, limits) {
                Ok(Some((_msg, _))) => return Ok(buf),
                Ok(None) => {}
                Err(err) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("message error: {err:?}"),
                    ));
                }
            }
        }
    }

    fn ipv4_packet(src: Ipv4Addr, dst: Ipv4Addr, payload_len: usize) -> Vec<u8> {
        let total_len = 20 + payload_len;
        let total_len_u16 = u16::try_from(total_len).expect("payload too large for IPv4 packet");
        let mut packet = vec![0u8; total_len];
        packet[0] = 0x45;
        let [hi, lo] = total_len_u16.to_be_bytes();
        packet[2] = hi;
        packet[3] = lo;
        packet[8] = 64;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&src.octets());
        packet[16..20].copy_from_slice(&dst.octets());
        if payload_len > 0 {
            packet[20] = 0xAA;
        }
        packet
    }

    fn make_register_payload(dcid: Cid, scid: Cid, cipher: CipherSuite) -> RegisterCidPayload {
        RegisterCidPayload {
            dcid,
            scid,
            cipher,
            hp_tx: [0x11; HP_KEY_LEN],
            hp_rx: [0x11; HP_KEY_LEN],
            aead_tx: [0x22; AEAD_KEY_LEN],
            aead_rx: [0x22; AEAD_KEY_LEN],
            iv_tx: [0x33; AEAD_IV_LEN],
            iv_rx: [0x33; AEAD_IV_LEN],
            pn_start: 0,
            pn_start_rx: 0,
            key_phase: false,
        }
    }

    #[tokio::test]
    async fn session_responds_to_tcp_ping() {
        let (join, mut client, tx, _tun_rx, _udp_rx, limits, _assigned, _registry) =
            spawn_session().await;
        let nonce = 0xA1B2_C3D4_E5F6_0708;
        let ping_payload = PingPayload { nonce };
        let mut ping_payload_bytes = Vec::new();
        ping_payload.encode(&mut ping_payload_bytes);
        let mut frame = Vec::new();
        encode_message(
            Message::Ping {
                payload: &ping_payload_bytes,
            },
            &mut frame,
        )
        .unwrap();
        client.write_all(&frame).await.unwrap();

        let buf = timeout(
            Duration::from_secs(1),
            read_message_bytes(&mut client, limits),
        )
        .await
        .unwrap()
        .unwrap();
        let (message, _) = decode_message(&buf, limits).unwrap().unwrap();
        match message {
            Message::Pong { payload } => {
                let response_payload = PongPayload::decode(payload).unwrap();
                assert_eq!(response_payload.nonce, nonce);
            }
            _ => panic!("expected pong"),
        }

        let _ = tx.send(SessionEvent::Shutdown).await;
        let _ = join.await.unwrap();
    }

    #[tokio::test]
    async fn session_forwards_tcp_data_to_tun() {
        let (join, mut client, tx, mut tun_rx, _udp_rx, _limits, assigned, _registry) =
            spawn_session().await;
        let packet = ipv4_packet(assigned.addr(), Ipv4Addr::new(192, 0, 2, 1), 8);
        let mut frame = Vec::new();
        encode_message(Message::Data { packet: &packet }, &mut frame).unwrap();
        client.write_all(&frame).await.unwrap();

        let received = timeout(Duration::from_secs(1), tun_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received, packet);

        let _ = tx.send(SessionEvent::Shutdown).await;
        let _ = join.await.unwrap();
    }

    #[tokio::test]
    async fn session_drops_spoofed_tcp_data() {
        let (join, mut client, tx, mut tun_rx, _udp_rx, _limits, _assigned, _registry) =
            spawn_session().await;
        let packet = ipv4_packet(Ipv4Addr::new(10, 0, 0, 99), Ipv4Addr::new(192, 0, 2, 1), 8);
        let mut frame = Vec::new();
        encode_message(Message::Data { packet: &packet }, &mut frame).unwrap();
        client.write_all(&frame).await.unwrap();

        match timeout(Duration::from_millis(200), tun_rx.recv()).await {
            Ok(Some(_)) => panic!("unexpected tunneled packet"),
            Ok(None) => panic!("tun channel closed unexpectedly"),
            Err(_) => {}
        }

        let _ = tx.send(SessionEvent::Shutdown).await;
        let _ = join.await.unwrap();
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn session_registers_udp_and_forwards_data() {
        let (join, mut client, tx, _tun_rx, mut udp_rx, limits, assigned, _registry) =
            spawn_session().await;

        let dcid = Cid::from([0xAA; QUIC_DCID_PREFIX_LEN]);
        let scid = Cid::from([0xBB; QUIC_DCID_PREFIX_LEN]);
        let register = make_register_payload(dcid, scid, CipherSuite::Aes128Gcm);

        let mut reg_buf = Vec::new();
        register.encode(&mut reg_buf).unwrap();
        let mut frame = Vec::new();
        encode_message(Message::RegisterCid { payload: &reg_buf }, &mut frame).unwrap();
        client.write_all(&frame).await.unwrap();

        let buf = timeout(
            Duration::from_secs(1),
            read_message_bytes(&mut client, limits),
        )
        .await
        .unwrap()
        .unwrap();
        let (message, _) = decode_message(&buf, limits).unwrap().unwrap();
        assert!(matches!(message, Message::RegisterOk { .. }));

        // Before first UDP claim, downlink traffic must stay on TCP.
        let tcp_packet = ipv4_packet(assigned.addr(), Ipv4Addr::new(192, 0, 2, 2), 12);
        tx.send(SessionEvent::TunPacket(tcp_packet.clone()))
            .await
            .unwrap();

        let buf = timeout(
            Duration::from_secs(1),
            read_message_bytes(&mut client, limits),
        )
        .await
        .unwrap()
        .unwrap();
        let (message, _) = decode_message(&buf, limits).unwrap().unwrap();
        match message {
            Message::Data { packet } => assert_eq!(packet, tcp_packet.as_slice()),
            _ => panic!("expected tcp data before first udp claim"),
        }
        assert!(
            timeout(Duration::from_millis(200), udp_rx.recv())
                .await
                .is_err(),
            "unexpected udp datagram before first udp claim"
        );

        let keys = UdpQspKeys::from_register(&register).unwrap();
        let peer = SocketAddr::from(([127, 0, 0, 1], 55555));

        // Send a UDP PING to establish the peer address.
        // Server switches to UDP after this first valid claim.
        let probe_nonce = 0xA1B2_C3D4_E5F6_0708;
        let probe = PingPayload { nonce: probe_nonce };
        let mut probe_payload = Vec::new();
        probe.encode(&mut probe_payload);
        let mut probe_frame = Vec::new();
        encode_message(
            Message::Ping {
                payload: &probe_payload,
            },
            &mut probe_frame,
        )
        .unwrap();
        let packet = keys
            .protect(
                register.dcid.as_slice(),
                0,
                register.key_phase,
                &probe_frame,
            )
            .unwrap();
        let claim = UdpClaim {
            peer,
            dcid_prefix: register.dcid.prefix(),
            payload: packet,
        };
        tx.send(SessionEvent::Udp(claim)).await.unwrap();

        // Wait for PONG response (establishes peer and verifies UDP works)
        let mut server_expected_pn = register.pn_start;
        let packet = timeout(Duration::from_secs(1), udp_rx.recv())
            .await
            .unwrap()
            .unwrap();
        let opened = keys
            .open(register.dcid.len(), &packet, server_expected_pn)
            .unwrap();
        server_expected_pn = opened.pn + 1;
        let (message, consumed) = decode_message(&opened.payload, limits).unwrap().unwrap();
        assert_eq!(consumed, opened.payload.len());
        assert!(
            matches!(message, Message::Pong { .. }),
            "expected pong response"
        );

        // Now send a TUN packet and verify it's forwarded via UDP.
        let data_packet = ipv4_packet(assigned.addr(), Ipv4Addr::new(192, 0, 2, 3), 12);
        tx.send(SessionEvent::TunPacket(data_packet.clone()))
            .await
            .unwrap();

        let packet = timeout(Duration::from_millis(200), udp_rx.recv())
            .await
            .unwrap()
            .unwrap();
        let opened = keys
            .open(register.dcid.len(), &packet, server_expected_pn)
            .unwrap();
        let (message, consumed) = decode_message(&opened.payload, limits).unwrap().unwrap();
        assert_eq!(consumed, opened.payload.len());
        if let Message::Data { packet } = message {
            assert_eq!(packet, data_packet.as_slice());
        } else {
            panic!("expected data message");
        }

        let _ = tx.send(SessionEvent::Shutdown).await;
        let _ = join.await.unwrap();
    }

    #[tokio::test]
    async fn session_switches_to_udp_after_first_valid_data_claim() {
        let (join, mut client, tx, mut tun_rx, mut udp_rx, limits, assigned, _registry) =
            spawn_session().await;

        let dcid = Cid::from([0xCC; QUIC_DCID_PREFIX_LEN]);
        let scid = Cid::from([0xDD; QUIC_DCID_PREFIX_LEN]);
        let register = make_register_payload(dcid, scid, CipherSuite::Aes128Gcm);

        let mut reg_buf = Vec::new();
        register.encode(&mut reg_buf).unwrap();
        let mut frame = Vec::new();
        encode_message(Message::RegisterCid { payload: &reg_buf }, &mut frame).unwrap();
        client.write_all(&frame).await.unwrap();

        let buf = timeout(
            Duration::from_secs(1),
            read_message_bytes(&mut client, limits),
        )
        .await
        .unwrap()
        .unwrap();
        let (message, _) = decode_message(&buf, limits).unwrap().unwrap();
        assert!(matches!(message, Message::RegisterOk { .. }));

        let keys = UdpQspKeys::from_register(&register).unwrap();
        let peer = SocketAddr::from(([127, 0, 0, 1], 44444));

        // First valid UDP claim is DATA; this should switch active transport to UDP.
        let uplink_packet = ipv4_packet(assigned.addr(), Ipv4Addr::new(192, 0, 2, 44), 12);
        let mut data_frame = Vec::new();
        encode_message(
            Message::Data {
                packet: &uplink_packet,
            },
            &mut data_frame,
        )
        .unwrap();
        let udp_packet = keys
            .protect(register.dcid.as_slice(), 0, register.key_phase, &data_frame)
            .unwrap();
        let claim = UdpClaim {
            peer,
            dcid_prefix: register.dcid.prefix(),
            payload: udp_packet,
        };
        tx.send(SessionEvent::Udp(claim)).await.unwrap();

        let received = timeout(Duration::from_secs(1), tun_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received, uplink_packet);

        let downlink_packet = ipv4_packet(assigned.addr(), Ipv4Addr::new(192, 0, 2, 45), 12);
        tx.send(SessionEvent::TunPacket(downlink_packet.clone()))
            .await
            .unwrap();

        let packet = timeout(Duration::from_secs(1), udp_rx.recv())
            .await
            .unwrap()
            .unwrap();
        let opened = keys
            .open(register.dcid.len(), &packet, register.pn_start)
            .unwrap();
        let (message, consumed) = decode_message(&opened.payload, limits).unwrap().unwrap();
        assert_eq!(consumed, opened.payload.len());
        match message {
            Message::Data { packet } => assert_eq!(packet, downlink_packet.as_slice()),
            _ => panic!("expected udp data after first valid udp claim"),
        }

        let _ = tx.send(SessionEvent::Shutdown).await;
        let _ = join.await.unwrap();
    }

    #[tokio::test]
    async fn session_register_rejects_invalid_cid() {
        let (join, mut client, tx, _tun_rx, _udp_rx, limits, _assigned, _registry) =
            spawn_session().await;

        let payload = vec![1, 0xAA, 0x00];
        let mut frame = Vec::new();
        encode_message(Message::RegisterCid { payload: &payload }, &mut frame).unwrap();
        client.write_all(&frame).await.unwrap();

        let buf = timeout(
            Duration::from_secs(1),
            read_message_bytes(&mut client, limits),
        )
        .await
        .unwrap()
        .unwrap();
        let (message, _) = decode_message(&buf, limits).unwrap().unwrap();
        match message {
            Message::RegisterFail { payload } => {
                let fail = RegisterFailPayload::decode(payload).unwrap();
                assert_eq!(fail.code, RegisterFailCode::InvalidCid);
            }
            _ => panic!("expected register fail"),
        }

        let _ = tx.send(SessionEvent::Shutdown).await;
        let _ = join.await.unwrap();
    }

    #[tokio::test]
    async fn session_register_rejects_invalid_keys() {
        let (join, mut client, tx, _tun_rx, _udp_rx, limits, _assigned, _registry) =
            spawn_session().await;

        let dcid = Cid::from([0xAB; QUIC_DCID_PREFIX_LEN]);
        let scid = Cid::from([0xBC; QUIC_DCID_PREFIX_LEN]);
        let register = make_register_payload(dcid, scid, CipherSuite::ChaCha20Poly1305);
        let mut reg_buf = Vec::new();
        register.encode(&mut reg_buf).unwrap();
        let mut frame = Vec::new();
        encode_message(Message::RegisterCid { payload: &reg_buf }, &mut frame).unwrap();
        client.write_all(&frame).await.unwrap();

        let buf = timeout(
            Duration::from_secs(1),
            read_message_bytes(&mut client, limits),
        )
        .await
        .unwrap()
        .unwrap();
        let (message, _) = decode_message(&buf, limits).unwrap().unwrap();
        match message {
            Message::RegisterFail { payload } => {
                let fail = RegisterFailPayload::decode(payload).unwrap();
                assert_eq!(fail.code, RegisterFailCode::InvalidKeys);
            }
            _ => panic!("expected register fail"),
        }

        let _ = tx.send(SessionEvent::Shutdown).await;
        let _ = join.await.unwrap();
    }

    #[tokio::test]
    async fn session_register_rejects_prefix_collision() {
        let (join, mut client, tx, _tun_rx, _udp_rx, limits, _assigned, registry) =
            spawn_session().await;

        let dcid = Cid::from([0xCD; QUIC_DCID_PREFIX_LEN]);
        let scid = Cid::from([0xDE; QUIC_DCID_PREFIX_LEN]);
        let (dummy_tx, _dummy_rx) = mpsc::channel(1);
        registry.insert_cid(999, dcid.prefix(), dummy_tx).unwrap();

        let register = make_register_payload(dcid, scid, CipherSuite::Aes128Gcm);
        let mut reg_buf = Vec::new();
        register.encode(&mut reg_buf).unwrap();
        let mut frame = Vec::new();
        encode_message(Message::RegisterCid { payload: &reg_buf }, &mut frame).unwrap();
        client.write_all(&frame).await.unwrap();

        let buf = timeout(
            Duration::from_secs(1),
            read_message_bytes(&mut client, limits),
        )
        .await
        .unwrap()
        .unwrap();
        let (message, _) = decode_message(&buf, limits).unwrap().unwrap();
        match message {
            Message::RegisterFail { payload } => {
                let fail = RegisterFailPayload::decode(payload).unwrap();
                assert_eq!(fail.code, RegisterFailCode::InvalidCid);
            }
            _ => panic!("expected register fail"),
        }

        let _ = tx.send(SessionEvent::Shutdown).await;
        let _ = join.await.unwrap();
    }

    #[tokio::test]
    async fn session_idle_timeout_sends_close() {
        let mut timeouts = default_timeouts();
        timeouts.idle_timeout = Duration::from_millis(50);
        timeouts.ping_min = Duration::from_secs(5);
        timeouts.ping_max = Duration::from_secs(5);

        let (join, mut client, _tx, _tun_rx, _udp_rx, limits, _assigned, _registry) =
            spawn_session_with_timeouts(timeouts).await;

        tokio::time::sleep(Duration::from_millis(80)).await;

        let buf = timeout(
            Duration::from_secs(1),
            read_message_bytes(&mut client, limits),
        )
        .await
        .unwrap()
        .unwrap();
        let (message, _) = decode_message(&buf, limits).unwrap().unwrap();
        match message {
            Message::Close { payload } => {
                let close = ClosePayload::decode(payload).unwrap();
                assert_eq!(close.code, CloseCode::IdleTimeout);
            }
            _ => panic!("expected close"),
        }

        let result = timeout(Duration::from_secs(1), join)
            .await
            .unwrap()
            .unwrap();
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn session_handles_close_message() {
        let (join, mut client, _tx, _tun_rx, _udp_rx, _limits, _assigned, _registry) =
            spawn_session().await;

        let close = ClosePayload {
            code: CloseCode::ProtocolError,
        };
        let mut payload = Vec::new();
        close.encode(&mut payload);
        let mut frame = Vec::new();
        encode_message(Message::Close { payload: &payload }, &mut frame).unwrap();
        client.write_all(&frame).await.unwrap();

        let result = timeout(Duration::from_secs(1), join)
            .await
            .unwrap()
            .unwrap();
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn session_rejects_unexpected_control_message() {
        let (join, mut client, _tx, _tun_rx, _udp_rx, _limits, _assigned, _registry) =
            spawn_session().await;

        let mut frame = Vec::new();
        encode_message(Message::AuthOk { payload: &[] }, &mut frame).unwrap();
        client.write_all(&frame).await.unwrap();

        let result = timeout(Duration::from_secs(1), join)
            .await
            .unwrap()
            .unwrap();
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn session_sends_tcp_ping_on_schedule() {
        let mut timeouts = default_timeouts();
        timeouts.ping_min = Duration::from_millis(50);
        timeouts.ping_max = Duration::from_millis(50);
        timeouts.idle_timeout = Duration::from_secs(5);

        let (join, mut client, tx, _tun_rx, _udp_rx, limits, _assigned, _registry) =
            spawn_session_with_timeouts(timeouts).await;

        tokio::time::sleep(Duration::from_millis(80)).await;

        let buf = timeout(
            Duration::from_secs(1),
            read_message_bytes(&mut client, limits),
        )
        .await
        .unwrap()
        .unwrap();
        let (message, _) = decode_message(&buf, limits).unwrap().unwrap();
        assert!(matches!(message, Message::Ping { .. }));

        let _ = tx.send(SessionEvent::Shutdown).await;
        let _ = join.await.unwrap();
    }

    #[tokio::test]
    async fn session_sends_udp_ping_on_schedule() {
        let mut timeouts = default_timeouts();
        timeouts.ping_min = Duration::from_millis(200);
        timeouts.ping_max = Duration::from_millis(200);
        timeouts.idle_timeout = Duration::from_secs(5);

        let (join, mut client, tx, _tun_rx, mut udp_rx, limits, _assigned, _registry) =
            spawn_session_with_timeouts(timeouts).await;

        let dcid = Cid::from([0x41; QUIC_DCID_PREFIX_LEN]);
        let scid = Cid::from([0x42; QUIC_DCID_PREFIX_LEN]);
        let register = make_register_payload(dcid, scid, CipherSuite::Aes128Gcm);
        let mut reg_buf = Vec::new();
        register.encode(&mut reg_buf).unwrap();
        let mut frame = Vec::new();
        encode_message(Message::RegisterCid { payload: &reg_buf }, &mut frame).unwrap();
        client.write_all(&frame).await.unwrap();

        let buf = timeout(
            Duration::from_secs(1),
            read_message_bytes(&mut client, limits),
        )
        .await
        .unwrap()
        .unwrap();
        let (message, _) = decode_message(&buf, limits).unwrap().unwrap();
        assert!(matches!(message, Message::RegisterOk { .. }));

        let keys = UdpQspKeys::from_register(&register).unwrap();
        let peer = SocketAddr::from(([127, 0, 0, 1], 33333));

        let packet = ipv4_packet(Ipv4Addr::new(10, 0, 0, 9), Ipv4Addr::new(192, 0, 2, 4), 8);
        let mut data_frame = Vec::new();
        encode_message(Message::Data { packet: &packet }, &mut data_frame).unwrap();
        let packet = keys
            .protect(register.dcid.as_slice(), 0, register.key_phase, &data_frame)
            .unwrap();
        let claim = UdpClaim {
            peer,
            dcid_prefix: register.dcid.prefix(),
            payload: packet,
        };
        tx.send(SessionEvent::Udp(claim)).await.unwrap();

        let packet = timeout(Duration::from_secs(1), udp_rx.recv())
            .await
            .unwrap()
            .unwrap();
        let opened = keys
            .open(register.dcid.len(), &packet, register.pn_start)
            .unwrap();
        let (message, consumed) = decode_message(&opened.payload, limits).unwrap().unwrap();
        assert_eq!(consumed, opened.payload.len());
        let verify_nonce = match message {
            Message::Ping { payload } => PingPayload::decode(payload).unwrap().nonce,
            _ => panic!("expected verify ping"),
        };
        let server_expected_pn = opened.pn + 1;

        let pong = PongPayload {
            nonce: verify_nonce,
        };
        let mut pong_payload = Vec::new();
        pong.encode(&mut pong_payload);
        let mut pong_frame = Vec::new();
        encode_message(
            Message::Pong {
                payload: &pong_payload,
            },
            &mut pong_frame,
        )
        .unwrap();
        let packet = keys
            .protect(register.dcid.as_slice(), 1, register.key_phase, &pong_frame)
            .unwrap();
        let claim = UdpClaim {
            peer,
            dcid_prefix: register.dcid.prefix(),
            payload: packet,
        };
        tx.send(SessionEvent::Udp(claim)).await.unwrap();

        tokio::time::sleep(Duration::from_millis(250)).await;

        let packet = timeout(Duration::from_secs(1), udp_rx.recv())
            .await
            .unwrap()
            .unwrap();
        let opened = keys
            .open(register.dcid.len(), &packet, server_expected_pn)
            .unwrap();
        let (message, consumed) = decode_message(&opened.payload, limits).unwrap().unwrap();
        assert_eq!(consumed, opened.payload.len());
        assert!(matches!(message, Message::Ping { .. }));

        let _ = tx.send(SessionEvent::Shutdown).await;
        let _ = join.await.unwrap();
    }

    #[tokio::test]
    async fn session_cleans_registry_on_shutdown() {
        let (join, mut client, tx, _tun_rx, _udp_rx, limits, assigned, registry) =
            spawn_session().await;

        let dcid = Cid::from([0x51; QUIC_DCID_PREFIX_LEN]);
        let scid = Cid::from([0x52; QUIC_DCID_PREFIX_LEN]);
        let register = make_register_payload(dcid, scid, CipherSuite::Aes128Gcm);
        let mut reg_buf = Vec::new();
        register.encode(&mut reg_buf).unwrap();
        let mut frame = Vec::new();
        encode_message(Message::RegisterCid { payload: &reg_buf }, &mut frame).unwrap();
        client.write_all(&frame).await.unwrap();

        let buf = timeout(
            Duration::from_secs(1),
            read_message_bytes(&mut client, limits),
        )
        .await
        .unwrap()
        .unwrap();
        let (message, _) = decode_message(&buf, limits).unwrap().unwrap();
        assert!(matches!(message, Message::RegisterOk { .. }));
        assert!(registry.has_cid(register.dcid.prefix()));
        assert!(registry.lookup_ip(assigned.addr()).is_some());

        let _ = tx.send(SessionEvent::Shutdown).await;
        let _ = join.await.unwrap();

        assert!(registry.lookup_ip(assigned.addr()).is_none());
        assert!(!registry.has_cid(register.dcid.prefix()));
    }

    #[tokio::test]
    async fn session_continues_on_udp_after_tcp_close() {
        let (join, mut client, tx, mut tun_rx, _udp_rx, limits, assigned, _registry) =
            spawn_session().await;

        // Register UDP
        let dcid = Cid::from([0x61; QUIC_DCID_PREFIX_LEN]);
        let scid = Cid::from([0x62; QUIC_DCID_PREFIX_LEN]);
        let register = make_register_payload(dcid, scid, CipherSuite::Aes128Gcm);
        let mut reg_buf = Vec::new();
        register.encode(&mut reg_buf).unwrap();
        let mut frame = Vec::new();
        encode_message(Message::RegisterCid { payload: &reg_buf }, &mut frame).unwrap();
        client.write_all(&frame).await.unwrap();

        let buf = timeout(
            Duration::from_secs(1),
            read_message_bytes(&mut client, limits),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(matches!(
            decode_message(&buf, limits).unwrap().unwrap().0,
            Message::RegisterOk { .. }
        ));

        // Activate UDP with a data packet
        let keys = UdpQspKeys::from_register(&register).unwrap();
        let peer = SocketAddr::from(([127, 0, 0, 1], 22222));
        let uplink_packet = ipv4_packet(assigned.addr(), Ipv4Addr::new(192, 0, 2, 10), 8);
        let mut data_frame = Vec::new();
        encode_message(
            Message::Data {
                packet: &uplink_packet,
            },
            &mut data_frame,
        )
        .unwrap();
        let udp_packet = keys
            .protect(register.dcid.as_slice(), 0, register.key_phase, &data_frame)
            .unwrap();
        tx.send(SessionEvent::Udp(UdpClaim {
            peer,
            dcid_prefix: register.dcid.prefix(),
            payload: udp_packet,
        }))
        .await
        .unwrap();

        let received = timeout(Duration::from_secs(1), tun_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received, uplink_packet);

        // Close TCP connection
        drop(client);

        // Session should still handle UDP traffic
        let uplink_packet2 = ipv4_packet(assigned.addr(), Ipv4Addr::new(192, 0, 2, 11), 8);
        let mut data_frame2 = Vec::new();
        encode_message(
            Message::Data {
                packet: &uplink_packet2,
            },
            &mut data_frame2,
        )
        .unwrap();
        let udp_packet2 = keys
            .protect(
                register.dcid.as_slice(),
                1,
                register.key_phase,
                &data_frame2,
            )
            .unwrap();
        tx.send(SessionEvent::Udp(UdpClaim {
            peer,
            dcid_prefix: register.dcid.prefix(),
            payload: udp_packet2,
        }))
        .await
        .unwrap();

        let received2 = timeout(Duration::from_secs(1), tun_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received2, uplink_packet2);

        // Clean shutdown
        let _ = tx.send(SessionEvent::Shutdown).await;
        let _ = join.await.unwrap();
    }

    #[tokio::test]
    async fn session_drops_oversized_tun_packet() {
        let (join, mut client, tx, _tun_rx, _udp_rx, limits, assigned, _registry) =
            spawn_session().await;

        // Create a packet larger than max_data_len
        let max_payload = limits.max_data_len - 20; // IPv4 header is 20 bytes
        let oversized_packet = ipv4_packet(
            assigned.addr(),
            Ipv4Addr::new(192, 0, 2, 1),
            max_payload + 100,
        );

        tx.send(SessionEvent::TunPacket(oversized_packet))
            .await
            .unwrap();

        // Should not forward anything to client via TCP
        match timeout(
            Duration::from_millis(200),
            read_message_bytes(&mut client, limits),
        )
        .await
        {
            Ok(Ok(_)) => panic!("oversized packet should not be forwarded to client"),
            Ok(Err(_)) | Err(_) => {}
        }

        let _ = tx.send(SessionEvent::Shutdown).await;
        let _ = join.await.unwrap();
    }

    #[tokio::test]
    async fn session_drops_tcp_data_when_udp_active() {
        let (join, mut client, tx, mut tun_rx, _udp_rx, limits, assigned, _registry) =
            spawn_session().await;

        // Register and activate UDP
        let dcid = Cid::from([0x71; QUIC_DCID_PREFIX_LEN]);
        let scid = Cid::from([0x72; QUIC_DCID_PREFIX_LEN]);
        let register = make_register_payload(dcid, scid, CipherSuite::Aes128Gcm);
        let mut reg_buf = Vec::new();
        register.encode(&mut reg_buf).unwrap();
        let mut frame = Vec::new();
        encode_message(Message::RegisterCid { payload: &reg_buf }, &mut frame).unwrap();
        client.write_all(&frame).await.unwrap();

        let buf = timeout(
            Duration::from_secs(1),
            read_message_bytes(&mut client, limits),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(matches!(
            decode_message(&buf, limits).unwrap().unwrap().0,
            Message::RegisterOk { .. }
        ));

        let keys = UdpQspKeys::from_register(&register).unwrap();
        let peer = SocketAddr::from(([127, 0, 0, 1], 33333));
        let udp_data = ipv4_packet(assigned.addr(), Ipv4Addr::new(192, 0, 2, 20), 8);
        let mut udp_frame = Vec::new();
        encode_message(Message::Data { packet: &udp_data }, &mut udp_frame).unwrap();
        let udp_packet = keys
            .protect(register.dcid.as_slice(), 0, register.key_phase, &udp_frame)
            .unwrap();
        tx.send(SessionEvent::Udp(UdpClaim {
            peer,
            dcid_prefix: register.dcid.prefix(),
            payload: udp_packet,
        }))
        .await
        .unwrap();
        let _ = timeout(Duration::from_secs(1), tun_rx.recv())
            .await
            .unwrap()
            .unwrap();

        // Now send data via TCP - should be dropped since UDP is active
        let tcp_data = ipv4_packet(assigned.addr(), Ipv4Addr::new(192, 0, 2, 21), 8);
        let mut tcp_frame = Vec::new();
        encode_message(Message::Data { packet: &tcp_data }, &mut tcp_frame).unwrap();
        client.write_all(&tcp_frame).await.unwrap();

        // Should NOT appear on TUN (dropped because TCP is not active transport)
        match timeout(Duration::from_millis(200), tun_rx.recv()).await {
            Ok(Some(_)) => panic!("TCP data should be dropped when UDP is active"),
            Ok(None) | Err(_) => {}
        }

        let _ = tx.send(SessionEvent::Shutdown).await;
        let _ = join.await.unwrap();
    }

    #[tokio::test]
    async fn session_drops_udp_message_with_trailing_data() {
        let (join, mut client, tx, mut tun_rx, _udp_rx, limits, assigned, _registry) =
            spawn_session().await;

        // Register UDP
        let dcid = Cid::from([0x81; QUIC_DCID_PREFIX_LEN]);
        let scid = Cid::from([0x82; QUIC_DCID_PREFIX_LEN]);
        let register = make_register_payload(dcid, scid, CipherSuite::Aes128Gcm);
        let mut reg_buf = Vec::new();
        register.encode(&mut reg_buf).unwrap();
        let mut frame = Vec::new();
        encode_message(Message::RegisterCid { payload: &reg_buf }, &mut frame).unwrap();
        client.write_all(&frame).await.unwrap();

        let buf = timeout(
            Duration::from_secs(1),
            read_message_bytes(&mut client, limits),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(matches!(
            decode_message(&buf, limits).unwrap().unwrap().0,
            Message::RegisterOk { .. }
        ));

        let keys = UdpQspKeys::from_register(&register).unwrap();
        let peer = SocketAddr::from(([127, 0, 0, 1], 44444));

        // Create a valid data frame then append garbage
        let uplink_packet = ipv4_packet(assigned.addr(), Ipv4Addr::new(192, 0, 2, 30), 8);
        let mut data_frame = Vec::new();
        encode_message(
            Message::Data {
                packet: &uplink_packet,
            },
            &mut data_frame,
        )
        .unwrap();
        data_frame.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]); // trailing garbage

        let udp_packet = keys
            .protect(register.dcid.as_slice(), 0, register.key_phase, &data_frame)
            .unwrap();
        tx.send(SessionEvent::Udp(UdpClaim {
            peer,
            dcid_prefix: register.dcid.prefix(),
            payload: udp_packet,
        }))
        .await
        .unwrap();

        // Should NOT forward to TUN (dropped due to trailing data)
        match timeout(Duration::from_millis(200), tun_rx.recv()).await {
            Ok(Some(_)) => panic!("UDP message with trailing data should be dropped"),
            Ok(None) | Err(_) => {}
        }

        let _ = tx.send(SessionEvent::Shutdown).await;
        let _ = join.await.unwrap();
    }
}
