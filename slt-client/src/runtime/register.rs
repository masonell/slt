use crate::transport::quic_discovery as quic;
use boring::rand::rand_bytes;
use slt_core::crypto::udp_qsp::{QuicQspSession, SessionIo, UdpQspKeys};
use slt_core::proto::{
    AEAD_IV_LEN, AEAD_KEY_LEN, AUTH_PAYLOAD_LEN, CipherSuite, ClosePayload, HP_KEY_LEN,
    MAX_DCID_LEN, Message, MessageLimits, PingPayload, PongPayload, RegisterCidPayload,
    RegisterFailPayload, RegisterOkPayload, encode_message,
};
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tokio::time;
use tokio_boring::SslStream;

const REGISTER_TIMEOUT: Duration = Duration::from_secs(10);

struct RegisterContext<'a> {
    to_tun_tx: &'a mpsc::Sender<Vec<u8>>,
    ids: &'a quic::QuicIds,
    payload: &'a RegisterCidPayload,
    cipher: CipherSuite,
    pn_start_c2s: u64,
    pn_start_s2c: u64,
}

pub(super) struct ClientUdpIo {
    socket: Arc<UdpSocket>,
    peer: SocketAddr,
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

pub(super) async fn register_udp_qsp(
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
        .map_err(super::map_payload_error)?;
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
        let Some(msg_buf) =
            crate::wire::pop_message_buf(read_buf, limits).map_err(super::map_message_error)?
        else {
            return Ok(None);
        };

        let result = handle_register_message(stream, msg_buf.message(), ctx).await?;
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
            let ok = RegisterOkPayload::decode(ok_payload).map_err(super::map_payload_error)?;
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
            let fail =
                RegisterFailPayload::decode(fail_payload).map_err(super::map_payload_error)?;
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("register_cid rejected: {:?}", fail.code),
            ))
        }
        Message::Ping { payload } => {
            let ping_in = PingPayload::decode(payload).map_err(super::map_payload_error)?;
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
            let close = ClosePayload::decode(payload).map_err(super::map_payload_error)?;
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
    encode_message(message, &mut buf).map_err(super::map_frame_error)?;
    stream.write_all(&buf).await
}

pub(super) fn message_limits_from_mtu(mtu: u16) -> MessageLimits {
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
