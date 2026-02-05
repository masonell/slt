use crate::{auth, quic, tcp, tun};
use boring::rand::rand_bytes;
use slt_core::config::ClientConfig;
use slt_core::crypto::udp_qsp::{QuicQspSession, SessionIo, UdpQspKeys};
use slt_core::proto::{
    AEAD_IV_LEN, AEAD_KEY_LEN, AUTH_PAYLOAD_LEN, CipherSuite, CloseCode, ClosePayload, FrameError,
    HP_KEY_LEN, MAX_DCID_LEN, Message, MessageError, MessageLimits, PayloadError, PingPayload,
    PongPayload, RegisterCidPayload, RegisterFailPayload, RegisterOkPayload, decode_message,
    encode_message,
};
use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tokio::time;
use tokio_boring::SslStream;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, trace, warn};
use tun_rs::DeviceBuilder;

const PING_MIN: Duration = Duration::from_secs(10);
const PING_MAX: Duration = Duration::from_secs(20);
const IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const REGISTER_TIMEOUT: Duration = Duration::from_secs(10);

/// Run the client runtime until shutdown.
pub async fn run_client(
    config: ClientConfig,
    cancel: CancellationToken,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut tcp = tcp::connect(&config).await?;
    info!(peer = ?tcp.peer, sni = ?tcp.sni, "tcp handshake complete");
    let auth_outcome = auth::authenticate(&mut tcp.stream, &config).await?;
    tcp.read_buf = auth_outcome.leftover;
    if !tcp.read_buf.is_empty() {
        debug!(len = tcp.read_buf.len(), "preserved auth leftovers");
    }

    let quic_ids = if config.upgrade.is_some() {
        match Box::pin(quic::discover_quic_ids(&config, &cancel, tcp.peer)).await {
            Ok(ids) => {
                info!(
                    dcid_len = ids.dcid.len(),
                    scid_len = ids.scid.len(),
                    "quic dcid discovery succeeded"
                );
                Some(ids)
            }
            Err(err) => {
                warn!(error = %err, "quic dcid discovery failed");
                None
            }
        }
    } else {
        debug!("upgrade disabled; skipping quic dcid discovery");
        None
    };

    let tun = Arc::new(
        DeviceBuilder::new()
            .name(&config.tun_name)
            .mtu(config.tun_mtu)
            .build_async()?,
    );

    let mut tun_handles = tun::spawn(tun, config.assigned_ipv4, cancel.clone(), config.tun_mtu);
    let limits = message_limits_from_mtu(config.tun_mtu);

    let (to_session_rx, to_tun_tx) = tun_handles.take_channels();

    let udp_session = if let Some(ids) = &quic_ids {
        match Box::pin(register_udp_qsp(
            &mut tcp.stream,
            &mut tcp.read_buf,
            limits,
            &to_tun_tx,
            ids,
        ))
        .await
        {
            Ok(session) => {
                info!(
                    dcid_len = ids.dcid.len(),
                    scid_len = ids.scid.len(),
                    peer = %ids.peer,
                    "register_cid accepted"
                );
                Some(session)
            }
            Err(err) => {
                warn!(error = %err, "register_cid failed");
                None
            }
        }
    } else {
        None
    };
    let mut session = ClientSession::new(
        tcp.stream,
        tcp.read_buf,
        to_session_rx,
        to_tun_tx,
        cancel.clone(),
        limits,
        PING_MIN,
        PING_MAX,
        IDLE_TIMEOUT,
        quic_ids,
        udp_session,
    );

    let result = session.run().await;
    cancel.cancel();
    tun_handles.shutdown().await;

    if let Err(err) = result {
        warn!(error = %err, "client session exited with error");
        return Err(err.into());
    }

    info!("client shutdown complete");
    Ok(())
}

struct ClientSession {
    stream: SslStream<TcpStream>,
    read_buf: Vec<u8>,
    write_buf: Vec<u8>,
    to_session_rx: mpsc::Receiver<Vec<u8>>,
    to_tun_tx: mpsc::Sender<Vec<u8>>,
    cancel: CancellationToken,
    limits: MessageLimits,
    last_activity: Instant,
    ping_min: Duration,
    ping_max: Duration,
    idle_timeout: Duration,
    quic_ids: Option<quic::QuicIds>,
    udp_session: Option<QuicQspSession<ClientUdpIo>>,
}

impl ClientSession {
    #[allow(clippy::too_many_arguments)]
    fn new(
        stream: SslStream<TcpStream>,
        read_buf: Vec<u8>,
        to_session_rx: mpsc::Receiver<Vec<u8>>,
        to_tun_tx: mpsc::Sender<Vec<u8>>,
        cancel: CancellationToken,
        limits: MessageLimits,
        ping_min: Duration,
        ping_max: Duration,
        idle_timeout: Duration,
        quic_ids: Option<quic::QuicIds>,
        udp_session: Option<QuicQspSession<ClientUdpIo>>,
    ) -> Self {
        Self {
            stream,
            read_buf,
            write_buf: Vec::new(),
            to_session_rx,
            to_tun_tx,
            cancel,
            limits,
            last_activity: Instant::now(),
            ping_min,
            ping_max,
            idle_timeout,
            quic_ids,
            udp_session,
        }
    }

    async fn run(&mut self) -> io::Result<()> {
        if let Some(ids) = &self.quic_ids {
            debug!(
                dcid_len = ids.dcid.len(),
                scid_len = ids.scid.len(),
                "quic ids ready for registration"
            );
        }
        if let Some(session) = &self.udp_session {
            debug!(
                dcid_len = session.dcid().len(),
                scid_len = session.scid().len(),
                "udp-qsp session initialized"
            );
        }
        let mut next_ping_at = self.schedule_next_ping();

        loop {
            if !self.read_buf.is_empty() && self.handle_tcp_read().await? == SessionControl::Close {
                return Ok(());
            }

            let idle_deadline = self.last_activity + self.idle_timeout;

            tokio::select! {
                () = self.cancel.cancelled() => {
                    info!("shutdown requested");
                    if let Err(err) = self.send_close(CloseCode::Normal).await {
                        debug!(error = %err, "failed to send close on shutdown");
                    }
                    return Ok(());
                }
                res = self.stream.read_buf(&mut self.read_buf) => {
                    let n = res?;
                    if n == 0 {
                        info!("tcp connection closed");
                        return Ok(());
                    }
                    self.note_activity();
                    if self.handle_tcp_read().await? == SessionControl::Close {
                        return Ok(());
                    }
                }
                maybe = self.to_session_rx.recv() => {
                    let Some(packet) = maybe else {
                        info!("tun channel closed");
                        if let Err(err) = self.send_close(CloseCode::Normal).await {
                            debug!(error = %err, "failed to send close after tun shutdown");
                        }
                        return Ok(());
                    };
                    if self.handle_tun_packet(packet).await? == SessionControl::Close {
                        return Ok(());
                    }
                }
                () = time::sleep_until(next_ping_at.into()) => {
                    self.handle_ping_tick().await?;
                    next_ping_at = self.schedule_next_ping();
                }
                () = time::sleep_until(idle_deadline.into()) => {
                    info!("idle timeout reached");
                    if let Err(err) = self.send_close(CloseCode::IdleTimeout).await {
                        debug!(error = %err, "failed to send idle close");
                    }
                    return Ok(());
                }
            }
        }
    }

    async fn handle_tcp_read(&mut self) -> io::Result<SessionControl> {
        loop {
            let decoded = decode_message(&self.read_buf, self.limits).map_err(map_message_error)?;
            let Some((_, consumed)) = decoded else {
                return Ok(SessionControl::Continue);
            };

            let rest = self.read_buf.split_off(consumed);
            let frame_buf = std::mem::replace(&mut self.read_buf, rest);
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
        self.note_activity();
        match message {
            Message::Data { packet } => {
                if self.to_tun_tx.send(packet.to_vec()).await.is_err() {
                    return Ok(SessionControl::Close);
                }
                Ok(SessionControl::Continue)
            }
            Message::Ping { payload } => {
                let ping_in = PingPayload::decode(payload).map_err(map_payload_error)?;
                let pong_out = PongPayload {
                    nonce: ping_in.nonce,
                };
                let mut pong_buf = Vec::with_capacity(8);
                pong_out.encode(&mut pong_buf);
                self.send_tcp_message(Message::Pong { payload: &pong_buf })
                    .await?;
                Ok(SessionControl::Continue)
            }
            Message::Pong { payload } => {
                let pong_in = PongPayload::decode(payload).map_err(map_payload_error)?;
                trace!(nonce = pong_in.nonce, "received pong");
                Ok(SessionControl::Continue)
            }
            Message::Close { payload } => {
                let close = ClosePayload::decode(payload).map_err(map_payload_error)?;
                info!(code = ?close.code, "received close");
                Ok(SessionControl::Close)
            }
            Message::RegisterCid { .. }
            | Message::RegisterOk { .. }
            | Message::RegisterFail { .. }
            | Message::Auth { .. }
            | Message::AuthOk { .. }
            | Message::AuthFail { .. } => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unexpected control message on established session",
            )),
        }
    }

    async fn handle_tun_packet(&mut self, packet: Vec<u8>) -> io::Result<SessionControl> {
        if packet.is_empty() {
            return Ok(SessionControl::Continue);
        }
        if packet.len() > self.limits.max_data_len {
            trace!(
                packet_len = packet.len(),
                max_len = self.limits.max_data_len,
                "dropping tun packet: size limit exceeded"
            );
            return Ok(SessionControl::Continue);
        }

        self.send_tcp_message(Message::Data {
            packet: packet.as_slice(),
        })
        .await?;
        Ok(SessionControl::Continue)
    }

    async fn handle_ping_tick(&mut self) -> io::Result<()> {
        let nonce = fastrand::u64(..);
        let ping = PingPayload { nonce };
        let mut buf = Vec::with_capacity(8);
        ping.encode(&mut buf);
        trace!(nonce, "sending ping");
        self.send_tcp_message(Message::Ping { payload: &buf }).await
    }

    async fn send_close(&mut self, code: CloseCode) -> io::Result<()> {
        let payload = ClosePayload { code };
        let mut buf = Vec::with_capacity(1);
        payload.encode(&mut buf);
        self.send_tcp_message(Message::Close { payload: &buf })
            .await
    }

    async fn send_tcp_message(&mut self, message: Message<'_>) -> io::Result<()> {
        self.write_buf.clear();
        encode_message(message, &mut self.write_buf).map_err(map_frame_error)?;
        self.stream.write_all(&self.write_buf).await
    }

    fn schedule_next_ping(&self) -> Instant {
        let min_ms = u64::try_from(self.ping_min.as_millis()).unwrap_or(u64::MAX);
        let max_ms = u64::try_from(self.ping_max.as_millis()).unwrap_or(u64::MAX);
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SessionControl {
    Continue,
    Close,
}

struct RegisterContext<'a> {
    to_tun_tx: &'a mpsc::Sender<Vec<u8>>,
    ids: &'a quic::QuicIds,
    payload: &'a RegisterCidPayload,
    cipher: CipherSuite,
    pn_start_c2s: u64,
    pn_start_s2c: u64,
}

struct ClientUdpIo {
    socket: Arc<UdpSocket>,
    peer: std::net::SocketAddr,
}

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

async fn register_udp_qsp(
    stream: &mut SslStream<TcpStream>,
    read_buf: &mut Vec<u8>,
    limits: MessageLimits,
    to_tun_tx: &mpsc::Sender<Vec<u8>>,
    ids: &quic::QuicIds,
) -> io::Result<QuicQspSession<ClientUdpIo>> {
    let cipher = CipherSuite::Aes128Gcm;
    let hp_c2s = random_array::<HP_KEY_LEN>()?;
    let hp_s2c = random_array::<HP_KEY_LEN>()?;
    let aead_c2s = random_array::<AEAD_KEY_LEN>()?;
    let aead_s2c = random_array::<AEAD_KEY_LEN>()?;
    let iv_c2s = random_array::<AEAD_IV_LEN>()?;
    let iv_s2c = random_array::<AEAD_IV_LEN>()?;
    let pn_start_s2c = u64::from(fastrand::u32(..));
    let pn_start_c2s = u64::from(fastrand::u32(..));
    let key_phase = false;

    let payload = RegisterCidPayload {
        dcid: ids.dcid,
        scid: ids.scid,
        cipher,
        hp_tx: hp_s2c,
        hp_rx: hp_c2s,
        aead_tx: aead_s2c,
        aead_rx: aead_c2s,
        iv_tx: iv_s2c,
        iv_rx: iv_c2s,
        pn_start: pn_start_s2c,
        pn_start_rx: pn_start_c2s,
        key_phase,
    };

    let mut payload_buf = Vec::new();
    payload
        .encode(&mut payload_buf)
        .map_err(map_payload_error)?;
    send_tcp_message(
        stream,
        Message::RegisterCid {
            payload: &payload_buf,
        },
    )
    .await?;

    let ctx = RegisterContext {
        to_tun_tx,
        ids,
        payload: &payload,
        cipher,
        pn_start_c2s,
        pn_start_s2c,
    };

    let deadline = Instant::now() + REGISTER_TIMEOUT;
    loop {
        if !read_buf.is_empty()
            && let Some(session) = handle_register_read(stream, read_buf, limits, &ctx).await?
        {
            return Ok(session);
        }

        let timeout = time::sleep_until(deadline.into());
        tokio::select! {
            () = timeout => {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "register_cid timed out"));
            }
            res = stream.read_buf(read_buf) => {
                let n = res?;
                if n == 0 {
                    return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "register_cid connection closed"));
                }
            }
        }
    }
}

async fn handle_register_read(
    stream: &mut SslStream<TcpStream>,
    read_buf: &mut Vec<u8>,
    limits: MessageLimits,
    ctx: &RegisterContext<'_>,
) -> io::Result<Option<QuicQspSession<ClientUdpIo>>> {
    loop {
        let decoded = decode_message(read_buf, limits).map_err(map_message_error)?;
        let Some((_, consumed)) = decoded else {
            return Ok(None);
        };

        let rest = read_buf.split_off(consumed);
        let frame_buf = std::mem::replace(read_buf, rest);
        let decoded = decode_message(&frame_buf, limits).map_err(map_message_error)?;
        let Some((message, _)) = decoded else {
            return Ok(None);
        };

        let result = handle_register_message(stream, message, ctx).await?;
        if let Some(session) = result {
            return Ok(Some(session));
        }
    }
}

async fn handle_register_message(
    stream: &mut SslStream<TcpStream>,
    message: Message<'_>,
    ctx: &RegisterContext<'_>,
) -> io::Result<Option<QuicQspSession<ClientUdpIo>>> {
    match message {
        Message::RegisterOk {
            payload: ok_payload,
        } => {
            let ok = RegisterOkPayload::decode(ok_payload).map_err(map_payload_error)?;
            if ok.dcid != ctx.ids.dcid {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "register_ok dcid mismatch",
                ));
            }
            let keys = UdpQspKeys::new(
                ctx.cipher,
                ctx.payload.hp_rx,
                ctx.payload.hp_tx,
                ctx.payload.aead_rx,
                ctx.payload.aead_tx,
                ctx.payload.iv_rx,
                ctx.payload.iv_tx,
            )
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "udp-qsp keys invalid"))?;
            let io = ClientUdpIo {
                socket: ctx.ids.socket.clone(),
                peer: ctx.ids.peer,
            };
            let session = QuicQspSession::new(
                io,
                ctx.ids.scid,
                ctx.ids.dcid,
                keys,
                ctx.pn_start_c2s,
                ctx.pn_start_s2c,
                ctx.payload.key_phase,
            );
            Ok(Some(session))
        }
        Message::RegisterFail {
            payload: fail_payload,
        } => {
            let fail = RegisterFailPayload::decode(fail_payload).map_err(map_payload_error)?;
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("register_cid rejected: {:?}", fail.code),
            ))
        }
        Message::Ping { payload } => {
            let ping_in = PingPayload::decode(payload).map_err(map_payload_error)?;
            let pong_out = PongPayload {
                nonce: ping_in.nonce,
            };
            let mut pong_buf = Vec::with_capacity(8);
            pong_out.encode(&mut pong_buf);
            send_tcp_message(stream, Message::Pong { payload: &pong_buf }).await?;
            Ok(None)
        }
        Message::Pong { .. } => Ok(None),
        Message::Close { payload } => {
            let close = ClosePayload::decode(payload).map_err(map_payload_error)?;
            Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                format!("register_cid closed: {:?}", close.code),
            ))
        }
        Message::Data { packet } => {
            if ctx.to_tun_tx.send(packet.to_vec()).await.is_err() {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "tun channel closed during register",
                ));
            }
            Ok(None)
        }
        Message::Auth { .. }
        | Message::AuthOk { .. }
        | Message::AuthFail { .. }
        | Message::RegisterCid { .. } => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected control message during register_cid",
        )),
    }
}

fn random_array<const N: usize>() -> io::Result<[u8; N]> {
    let mut bytes = [0u8; N];
    rand_bytes(&mut bytes).map_err(|err| io::Error::other(format!("{err:?}")))?;
    Ok(bytes)
}

async fn send_tcp_message(
    stream: &mut SslStream<TcpStream>,
    message: Message<'_>,
) -> io::Result<()> {
    let mut buf = Vec::new();
    encode_message(message, &mut buf).map_err(map_frame_error)?;
    stream.write_all(&buf).await
}

fn message_limits_from_mtu(mtu: u16) -> MessageLimits {
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

fn map_frame_error(err: FrameError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("frame error: {err:?}"))
}

fn map_message_error(err: MessageError) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("message error: {err:?}"),
    )
}

fn map_payload_error(err: PayloadError) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("payload error: {err:?}"),
    )
}
