//! Client session tracking and lifecycle helpers.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use fastrand;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tokio::time;
use tokio_boring::SslStream;
use tun_rs::AsyncDevice;

use super::quic::UdpClaim;
use super::registry::{CidInsertError, SessionRegistry};
use super::router::PacketRouter;
use super::{AssignedIp, ClientId};
use crate::crypto::udp_qsp::{QspSessionError, QuicQspSession, SessionIo, UdpQspKeys};
use crate::proto::{
    AEAD_IV_LEN, AEAD_KEY_LEN, AUTH_PAYLOAD_LEN, CloseCode, ClosePayload, FrameError, HP_KEY_LEN,
    Message, MessageError, MessageLimits, PayloadError, PingPayload, PongPayload,
    RegisterCidPayload, RegisterFailCode, RegisterFailPayload, RegisterOkPayload, decode_message,
    encode_message,
};
use crate::types::MAX_DCID_LEN;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SessionControl {
    Continue,
    Close,
}

#[derive(Debug, Clone, Copy)]
struct UdpVerify {
    nonce: u64,
    deadline: Instant,
    sent: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct SessionTimeouts {
    /// Minimum interval between keepalive pings.
    pub ping_min: Duration,
    /// Maximum interval between keepalive pings.
    pub ping_max: Duration,
    /// Idle timeout for the session.
    pub idle_timeout: Duration,
    /// Timeout for UDP-QSP verification.
    pub udp_verify_timeout: Duration,
}

struct UdpIo {
    socket: Arc<UdpSocket>,
    peer: SocketAddr,
}

impl UdpIo {
    const fn new(socket: Arc<UdpSocket>, peer: SocketAddr) -> Self {
        Self { socket, peer }
    }

    const fn set_peer(&mut self, peer: SocketAddr) {
        self.peer = peer;
    }
}

impl SessionIo for UdpIo {
    async fn send<'a>(&'a mut self, bytes: &'a [u8]) -> io::Result<()> {
        let _ = self.socket.send_to(bytes, self.peer).await?;
        Ok(())
    }

    async fn recv<'a>(&'a mut self, _buf: &'a mut [u8]) -> io::Result<usize> {
        Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "direct recv not supported",
        ))
    }
}

/// A single authenticated client session.
pub struct ClientSession {
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
    /// Whether UDP-QSP is verified for this session.
    pub udp_verified: bool,
    session_id: u64,
    registry: Arc<SessionRegistry>,
    tx: SessionTx,
    tcp: SslStream<TcpStream>,
    tun: Arc<AsyncDevice>,
    udp_socket: Arc<UdpSocket>,
    udp_peer: Option<SocketAddr>,
    udp_session: Option<QuicQspSession<UdpIo>>,
    udp_verify: Option<UdpVerify>,
    rx: SessionRx,
    limits: MessageLimits,
    timeouts: SessionTimeouts,
    tcp_read_buf: Vec<u8>,
    tcp_write_buf: Vec<u8>,
}

impl ClientSession {
    /// Create a new client session with TCP active.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        session_id: u64,
        client_id: ClientId,
        assigned_ipv4: AssignedIp,
        tcp: SslStream<TcpStream>,
        tun: Arc<AsyncDevice>,
        udp_socket: Arc<UdpSocket>,
        registry: Arc<SessionRegistry>,
        tx: SessionTx,
        rx: SessionRx,
        limits: MessageLimits,
        timeouts: SessionTimeouts,
        initial_tcp_buf: Vec<u8>,
    ) -> Self {
        let now = Instant::now();
        Self {
            client_id,
            assigned_ipv4,
            created_at: now,
            last_activity: now,
            active_transport: ActiveTransport::Tcp,
            udp_verified: false,
            session_id,
            registry,
            tx,
            tcp,
            tun,
            udp_socket,
            udp_peer: None,
            udp_session: None,
            udp_verify: None,
            rx,
            limits,
            timeouts,
            tcp_read_buf: initial_tcp_buf,
            tcp_write_buf: Vec::new(),
        }
    }

    /// Run the session event loop until shutdown.
    ///
    /// # Errors
    ///
    /// Returns an error if the TCP stream or TUN device fails.
    pub async fn run(mut self) -> io::Result<()> {
        let result = self.run_inner().await;
        self.cleanup();
        result
    }

    async fn run_inner(&mut self) -> io::Result<()> {
        let mut next_ping_at = self.schedule_next_ping();

        loop {
            if !self.tcp_read_buf.is_empty() {
                let decoded =
                    decode_message(&self.tcp_read_buf, self.limits).map_err(map_message_error)?;
                if decoded.is_some() && self.handle_tcp_read().await? == SessionControl::Close {
                    return Ok(());
                }
            }

            let idle_deadline = self.last_activity + self.timeouts.idle_timeout;
            let verify_deadline = self.udp_verify.map(|v| v.deadline);

            if let Some(verify_deadline) = verify_deadline {
                tokio::select! {
                    res = self.tcp.read_buf(&mut self.tcp_read_buf) => {
                    let n = res?;
                    if n == 0 {
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
                        let _ = self.send_close(CloseCode::IdleTimeout).await;
                        return Ok(());
                    }
                    () = time::sleep_until(verify_deadline.into()) => {
                        self.handle_udp_verify_timeout();
                    }
                }
            } else {
                tokio::select! {
                    res = self.tcp.read_buf(&mut self.tcp_read_buf) => {
                    let n = res?;
                    if n == 0 {
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
                        let _ = self.send_close(CloseCode::IdleTimeout).await;
                        return Ok(());
                    }
                }
            }
        }
    }

    async fn handle_tcp_read(&mut self) -> io::Result<SessionControl> {
        loop {
            let decoded =
                decode_message(&self.tcp_read_buf, self.limits).map_err(map_message_error)?;
            let Some((_, consumed)) = decoded else {
                return Ok(SessionControl::Continue);
            };

            let rest = self.tcp_read_buf.split_off(consumed);
            let frame_buf = std::mem::replace(&mut self.tcp_read_buf, rest);
            let decoded = decode_message(&frame_buf, self.limits).map_err(map_message_error)?;
            let Some((message, _)) = decoded else {
                return Ok(SessionControl::Continue);
            };

            if self.handle_tcp_message(message).await? == SessionControl::Close {
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
            Message::Close { .. } => Ok(SessionControl::Close),
            Message::RegisterCid { payload } => {
                self.handle_register_cid(payload, Transport::Tcp).await
            }
        }
    }

    async fn handle_event(&mut self, event: SessionEvent) -> io::Result<SessionControl> {
        self.note_activity();
        match event {
            SessionEvent::TunPacket(packet) => self.handle_tun_packet(packet).await,
            SessionEvent::Udp(claim) => self.handle_udp_claim(claim).await,
            SessionEvent::Shutdown => Ok(SessionControl::Close),
        }
    }

    async fn handle_tun_packet(&mut self, packet: Vec<u8>) -> io::Result<SessionControl> {
        if packet.len() > self.limits.max_data_len {
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
        let send_verify_nonce = if let Some(verify) = self.udp_verify
            && !verify.sent
        {
            Some(verify.nonce)
        } else {
            None
        };

        let opened_payload = {
            let Some(session) = self.udp_session.as_mut() else {
                return Ok(SessionControl::Continue);
            };

            let opened = match session.open_packet(&claim.payload) {
                Ok(opened) => opened,
                Err(QspSessionError::Replay | QspSessionError::TooOld) => {
                    return Ok(SessionControl::Continue);
                }
                Err(_) => return Ok(SessionControl::Continue),
            };

            opened.payload.to_vec()
        };

        if self.udp_peer != Some(peer) {
            self.udp_peer = Some(peer);
            if let Some(session) = self.udp_session.as_mut() {
                session.io_mut().set_peer(peer);
            }
        }

        if let Some(nonce) = send_verify_nonce {
            self.send_udp_verify_ping(nonce).await?;
            if let Some(verify) = self.udp_verify
                && verify.nonce == nonce
                && !verify.sent
            {
                self.udp_verify = Some(UdpVerify {
                    sent: true,
                    ..verify
                });
            }
        }

        let decoded = decode_message(&opened_payload, self.limits).map_err(map_message_error)?;
        let Some((message, consumed)) = decoded else {
            return Ok(SessionControl::Continue);
        };
        if consumed != opened_payload.len() {
            return Ok(SessionControl::Continue);
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
                if self
                    .udp_verify
                    .is_some_and(|verify| verify.nonce == pong_in.nonce)
                {
                    self.udp_verified = true;
                    self.active_transport = ActiveTransport::UdpQsp;
                    self.udp_verify = None;
                }
                Ok(SessionControl::Continue)
            }
            Message::Data { packet } => {
                if !self.udp_verified {
                    return Ok(SessionControl::Continue);
                }
                if PacketRouter::validate_packet_src(self, packet) {
                    self.tun.send(packet).await?;
                }
                Ok(SessionControl::Continue)
            }
            Message::Close { .. } => Ok(SessionControl::Close),
            Message::RegisterCid { payload } => {
                if !self.udp_verified {
                    return Ok(SessionControl::Continue);
                }
                self.handle_register_cid(payload, Transport::Udp).await
            }
            Message::Auth { .. }
            | Message::AuthOk { .. }
            | Message::AuthFail { .. }
            | Message::RegisterOk { .. }
            | Message::RegisterFail { .. } => Ok(SessionControl::Continue),
        }
    }

    async fn handle_register_cid(
        &mut self,
        payload: &[u8],
        transport: Transport,
    ) -> io::Result<SessionControl> {
        let Ok(register) = RegisterCidPayload::decode(payload) else {
            self.send_register_fail(RegisterFailCode::InvalidCid, transport)
                .await?;
            return Ok(SessionControl::Continue);
        };

        if register.pn_start > u64::from(u32::MAX) || register.pn_start_rx > u64::from(u32::MAX) {
            self.send_register_fail(RegisterFailCode::InvalidCid, transport)
                .await?;
            return Ok(SessionControl::Continue);
        }

        let Ok(keys) = UdpQspKeys::from_register(&register) else {
            self.send_register_fail(RegisterFailCode::InvalidKeys, transport)
                .await?;
            return Ok(SessionControl::Continue);
        };

        if let Err(CidInsertError::PrefixCollision(_)) =
            self.registry
                .insert_cid(self.session_id, register.dcid.prefix(), self.tx.clone())
        {
            self.send_register_fail(RegisterFailCode::InvalidCid, transport)
                .await?;
            return Ok(SessionControl::Continue);
        }

        self.registry
            .remove_cids_for_session_except(self.session_id, register.dcid.prefix());

        let peer = self
            .udp_peer
            .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0)));
        let io = UdpIo::new(self.udp_socket.clone(), peer);
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
        self.udp_verified = false;
        self.active_transport = ActiveTransport::Tcp;
        self.udp_verify = Some(UdpVerify {
            nonce: fastrand::u64(..),
            deadline: Instant::now() + self.timeouts.udp_verify_timeout,
            sent: false,
        });

        let ok = RegisterOkPayload {
            dcid: register.dcid,
        };
        let mut ok_buf = Vec::new();
        ok.encode(&mut ok_buf).map_err(map_payload_error)?;
        self.send_message(Message::RegisterOk { payload: &ok_buf }, transport)
            .await?;

        if self.udp_peer.is_some()
            && let Some(verify) = self.udp_verify
            && !verify.sent
        {
            self.send_udp_verify_ping(verify.nonce).await?;
            self.udp_verify = Some(UdpVerify {
                sent: true,
                ..verify
            });
        }

        Ok(SessionControl::Continue)
    }

    async fn send_udp_verify_ping(&mut self, nonce: u64) -> io::Result<()> {
        let ping = PingPayload { nonce };
        let mut buf = Vec::new();
        ping.encode(&mut buf);
        self.send_udp_message(Message::Ping { payload: &buf }).await
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

    fn handle_udp_verify_timeout(&mut self) {
        let Some(verify) = self.udp_verify else {
            return;
        };
        if Instant::now() < verify.deadline {
            return;
        }
        self.registry.remove_cids_for_session(self.session_id);
        self.udp_session = None;
        self.udp_peer = None;
        self.udp_verify = None;
        self.udp_verified = false;
        self.active_transport = ActiveTransport::Tcp;
    }

    async fn send_message(&mut self, message: Message<'_>, transport: Transport) -> io::Result<()> {
        match transport {
            Transport::Tcp => self.send_tcp_message(message).await,
            Transport::Udp => self.send_udp_message(message).await,
        }
    }

    async fn send_tcp_message(&mut self, message: Message<'_>) -> io::Result<()> {
        self.tcp_write_buf.clear();
        encode_message(message, &mut self.tcp_write_buf).map_err(map_frame_error)?;
        self.tcp.write_all(&self.tcp_write_buf).await
    }

    async fn send_udp_message(&mut self, message: Message<'_>) -> io::Result<()> {
        let Some(session) = self.udp_session.as_mut() else {
            return Ok(());
        };
        if self.udp_peer.is_none() {
            return Ok(());
        }

        self.tcp_write_buf.clear();
        encode_message(message, &mut self.tcp_write_buf).map_err(map_frame_error)?;
        session
            .send(&self.tcp_write_buf)
            .await
            .map_err(|err| match err {
                QspSessionError::Io(err) => err,
                _ => io::Error::new(io::ErrorKind::InvalidData, "udp-qsp send failed"),
            })
    }

    async fn send_register_fail(
        &mut self,
        code: RegisterFailCode,
        transport: Transport,
    ) -> io::Result<()> {
        let payload = RegisterFailPayload { code };
        let mut buf = Vec::with_capacity(1);
        payload.encode(&mut buf);
        self.send_message(Message::RegisterFail { payload: &buf }, transport)
            .await
    }

    async fn send_close(&mut self, code: CloseCode) -> io::Result<()> {
        let payload = ClosePayload { code };
        let mut buf = Vec::with_capacity(1);
        payload.encode(&mut buf);
        self.send_tcp_message(Message::Close { payload: &buf })
            .await
    }

    fn schedule_next_ping(&self) -> Instant {
        let min_ms = u64::try_from(self.timeouts.ping_min.as_millis()).unwrap_or(u64::MAX);
        let max_ms = u64::try_from(self.timeouts.ping_max.as_millis()).unwrap_or(u64::MAX);
        let jitter_ms = if max_ms > min_ms {
            fastrand::u64(0..=(max_ms - min_ms))
        } else {
            0
        };
        Instant::now() + Duration::from_millis(min_ms + jitter_ms)
    }

    fn note_activity(&mut self) {
        self.last_activity = Instant::now();
    }

    fn cleanup(&self) {
        self.registry
            .remove_session(self.session_id, self.client_id, self.assigned_ipv4);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Transport {
    Tcp,
    Udp,
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

/// Compute message size limits based on TUN MTU.
#[must_use]
pub fn message_limits_from_mtu(mtu: u16) -> MessageLimits {
    let max_data_len = mtu as usize;
    let max_register_len = 1
        + MAX_DCID_LEN
        + 1
        + MAX_DCID_LEN
        + 1
        + (HP_KEY_LEN * 2)
        + (AEAD_KEY_LEN * 2)
        + (AEAD_IV_LEN * 2)
        + 8
        + 8
        + 1;
    let max_frame_len = max_data_len.max(max_register_len).max(AUTH_PAYLOAD_LEN);
    MessageLimits::new(max_frame_len, max_data_len)
}
