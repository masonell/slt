//! Client session tracking and lifecycle helpers.

mod limits;
mod udp_io;

pub use self::limits::message_limits_from_mtu;
pub use self::udp_io::UdpSocketIo;

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use self::udp_io::UdpIo;
use fastrand;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tokio::time;
use tokio_boring::SslStream;
use tun_rs::AsyncDevice;

use super::quic::UdpClaim;
use super::registry::{CidInsertError, SessionRegistry};
use super::router::PacketRouter;
use super::tun::TunDeviceIo;
use super::{AssignedIp, ClientId};
use crate::crypto::udp_qsp::{QspSessionError, QuicQspSession, UdpQspKeys};
use crate::proto::{
    CloseCode, ClosePayload, FrameError, Message, MessageError, MessageLimits, PayloadError,
    PingPayload, PongPayload, RegisterCidPayload, RegisterFailCode, RegisterFailPayload,
    RegisterOkPayload, decode_message, encode_message,
};

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
    /// Whether UDP-QSP is verified for this session.
    pub udp_verified: bool,
    session_id: u64,
    registry: Arc<SessionRegistry>,
    tx: SessionTx,
    tcp: SslStream<S>,
    tun: Arc<T>,
    udp_socket: Arc<U>,
    udp_peer: Option<SocketAddr>,
    udp_session: Option<QuicQspSession<UdpIo<U>>>,
    udp_verify: Option<UdpVerify>,
    rx: SessionRx,
    limits: MessageLimits,
    timeouts: SessionTimeouts,
    tcp_read_buf: Vec<u8>,
    tcp_write_buf: Vec<u8>,
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
        tcp: SslStream<S>,
        tun: Arc<T>,
        udp_socket: Arc<U>,
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

#[cfg(test)]
mod tests {
    use super::*;
    use boring::ssl::{SslAcceptor, SslConnector, SslFiletype, SslMethod, SslVerifyMode};
    use std::net::Ipv4Addr;
    use std::path::PathBuf;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
    use tokio::sync::mpsc;
    use tokio::time::{Duration, timeout};

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

    struct TestUdpSocket;

    impl UdpSocketIo for TestUdpSocket {
        fn send_to<'a>(
            &'a self,
            buf: &'a [u8],
            _peer: SocketAddr,
        ) -> impl std::future::Future<Output = io::Result<usize>> + Send + 'a {
            async move { Ok(buf.len()) }
        }
    }

    fn cert_paths() -> (PathBuf, PathBuf) {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        (
            root.join("vendor/boring/test/cert.pem"),
            root.join("vendor/boring/test/key.pem"),
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

    fn session_timeouts() -> SessionTimeouts {
        SessionTimeouts {
            ping_min: Duration::from_secs(3600),
            ping_max: Duration::from_secs(3600),
            idle_timeout: Duration::from_secs(3600),
            udp_verify_timeout: Duration::from_secs(3600),
        }
    }

    async fn spawn_session() -> (
        tokio::task::JoinHandle<io::Result<()>>,
        tokio_boring::SslStream<DuplexStream>,
        SessionTx,
        mpsc::Receiver<Vec<u8>>,
        MessageLimits,
        AssignedIp,
    ) {
        let (server_tls, client_tls) = tls_pair().await;
        let (tun_tx, tun_rx) = mpsc::channel(8);
        let tun = Arc::new(TestTun { tx: tun_tx });
        let registry = Arc::new(SessionRegistry::new());
        let (tx, rx) = mpsc::channel(8);
        let client_id = ClientId([0xA5; 16]);
        let assigned = AssignedIp(Ipv4Addr::new(10, 0, 0, 9));
        let (handle, _old) = registry.register_session(client_id, assigned, tx.clone());
        let limits = message_limits_from_mtu(1500);
        let session = ClientSessionBase::<TestTun, DuplexStream, TestUdpSocket>::new(
            handle.session_id,
            client_id,
            assigned,
            server_tls,
            tun,
            Arc::new(TestUdpSocket),
            registry,
            tx.clone(),
            rx,
            limits,
            session_timeouts(),
            Vec::new(),
        );
        let join = tokio::spawn(async move { session.run().await });
        (join, client_tls, tx, tun_rx, limits, assigned)
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
                Ok(None) => continue,
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
        let mut packet = vec![0u8; total_len];
        packet[0] = 0x45;
        packet[2] = ((total_len >> 8) & 0xff) as u8;
        packet[3] = (total_len & 0xff) as u8;
        packet[8] = 64;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&src.octets());
        packet[16..20].copy_from_slice(&dst.octets());
        if payload_len > 0 {
            packet[20] = 0xAA;
        }
        packet
    }

    #[tokio::test]
    async fn session_responds_to_tcp_ping() {
        let (join, mut client, tx, _tun_rx, limits, _assigned) = spawn_session().await;
        let nonce = 0xA1B2_C3D4_E5F6_0708;
        let ping = PingPayload { nonce };
        let mut payload = Vec::new();
        ping.encode(&mut payload);
        let mut frame = Vec::new();
        encode_message(Message::Ping { payload: &payload }, &mut frame).unwrap();
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
                let pong = PongPayload::decode(payload).unwrap();
                assert_eq!(pong.nonce, nonce);
            }
            _ => panic!("expected pong"),
        }

        let _ = tx.send(SessionEvent::Shutdown).await;
        let _ = join.await.unwrap();
    }

    #[tokio::test]
    async fn session_forwards_tcp_data_to_tun() {
        let (join, mut client, tx, mut tun_rx, _limits, assigned) = spawn_session().await;
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
        let (join, mut client, tx, mut tun_rx, _limits, _assigned) = spawn_session().await;
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
}
