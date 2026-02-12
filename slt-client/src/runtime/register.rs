use crate::transport::quic_discovery as quic;
use crate::transport::tcp::TcpTransport;
use crate::transport::udp_qsp::{ClientUdpIo, UdpQspTransport};
use boring::rand::rand_bytes;
use slt_core::crypto::udp_qsp::{QuicQspSession, UdpQspKeys};
use slt_core::proto::{
    AEAD_IV_LEN, AEAD_KEY_LEN, CipherSuite, ClosePayload, HP_KEY_LEN, Message, MessageLimits,
    PingPayload, PongPayload, RegisterCidPayload, RegisterFailPayload, RegisterOkPayload,
};
use std::io;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tokio::time;
use tokio_util::sync::CancellationToken;

const REGISTER_TIMEOUT: Duration = Duration::from_secs(10);

/// Prepared state for a UDP-QSP `REGISTER_CID` exchange.
///
/// This bundles the encoded `RegisterCidPayload` to send to the server together
/// with a locally-constructed `UdpQspTransport` that matches the generated
/// keys/packet-number starts. The transport is stored in an `Option` so it can
/// be moved out exactly once (via `take()`) when the server replies
/// `REGISTER_OK`.
pub(super) struct PreparedUdpQspRegistration {
    /// Encoded `RegisterCidPayload` bytes (used as the `Message::RegisterCid` payload).
    pub(super) payload_buf: Vec<u8>,
    /// Matching UDP-QSP transport to install once registration succeeds.
    pub(super) udp: Option<UdpQspTransport>,
}

/// Build a `REGISTER_CID` payload and a matching UDP-QSP transport.
///
/// The payload is expressed in the server's `(tx, rx)` terms; the returned
/// transport uses the reversed directions for the client.
pub(super) fn prepare_udp_qsp_registration(
    ids: &quic::QuicIds,
) -> io::Result<PreparedUdpQspRegistration> {
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
        .map_err(crate::wire::map_payload_error)?;

    // Reverse key directions: the payload is expressed in the server's (tx/rx) terms.
    let keys = UdpQspKeys::new(
        cipher,
        payload.hp_rx,
        payload.hp_tx,
        payload.aead_rx,
        payload.aead_tx,
        payload.iv_rx,
        payload.iv_tx,
    )
    .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "udp-qsp keys invalid"))?;

    let io = ClientUdpIo::new(ids.socket.clone(), ids.peer);
    let session = QuicQspSession::new(
        io,
        ids.scid,
        ids.dcid,
        keys,
        pn_start_c2s,
        pn_start_s2c,
        key_phase,
    );

    Ok(PreparedUdpQspRegistration {
        payload_buf,
        udp: Some(UdpQspTransport::new(session)),
    })
}

pub(super) async fn register_udp_qsp(
    tcp: &mut TcpTransport,
    limits: MessageLimits,
    to_tun_tx: &mpsc::Sender<Vec<u8>>,
    ids: &quic::QuicIds,
    cancel: &CancellationToken,
) -> io::Result<UdpQspTransport> {
    let mut prepared = prepare_udp_qsp_registration(ids)?;
    tcp.write_message(Message::RegisterCid {
        payload: &prepared.payload_buf,
    })
    .await?;

    let deadline = Instant::now() + REGISTER_TIMEOUT;
    loop {
        if let Some(session) =
            handle_register_read(tcp, limits, to_tun_tx, ids, &mut prepared).await?
        {
            return Ok(session);
        }

        let timeout = time::sleep_until(deadline.into());
        tokio::select! {
            () = timeout => {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "register_cid timed out"));
            }
            res = tcp.read_more() => {
                let n = res?;
                if n == 0 {
                    return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "register_cid connection closed"));
                }
            }
            () = cancel.cancelled() => {
                return Err(io::Error::new(io::ErrorKind::Interrupted, "register_cid cancelled"));
            }
        }
    }
}

async fn handle_register_read(
    tcp: &mut TcpTransport,
    limits: MessageLimits,
    to_tun_tx: &mpsc::Sender<Vec<u8>>,
    ids: &quic::QuicIds,
    prepared: &mut PreparedUdpQspRegistration,
) -> io::Result<Option<UdpQspTransport>> {
    loop {
        let Some(msg_buf) = tcp
            .try_pop_message(limits)
            .map_err(crate::wire::map_message_error)?
        else {
            return Ok(None);
        };

        let result =
            handle_register_message(tcp, msg_buf.message(), to_tun_tx, ids, prepared).await?;
        if result.is_some() {
            return Ok(result);
        }
    }
}

async fn handle_register_message(
    tcp: &mut TcpTransport,
    message: Message<'_>,
    to_tun_tx: &mpsc::Sender<Vec<u8>>,
    ids: &quic::QuicIds,
    prepared: &mut PreparedUdpQspRegistration,
) -> io::Result<Option<UdpQspTransport>> {
    match message {
        Message::RegisterOk {
            payload: ok_payload,
        } => {
            let ok =
                RegisterOkPayload::decode(ok_payload).map_err(crate::wire::map_payload_error)?;
            if ok.dcid != ids.dcid {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "register_ok dcid mismatch",
                ));
            }
            let session = prepared.udp.take().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "udp-qsp session missing")
            })?;
            Ok(Some(session))
        }
        Message::RegisterFail {
            payload: fail_payload,
        } => {
            let fail = RegisterFailPayload::decode(fail_payload)
                .map_err(crate::wire::map_payload_error)?;
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("register_cid rejected: {:?}", fail.code),
            ))
        }
        Message::Ping { payload } => {
            let ping_in = PingPayload::decode(payload).map_err(crate::wire::map_payload_error)?;
            let pong_out = PongPayload {
                nonce: ping_in.nonce,
            };
            let mut pong_buf = Vec::with_capacity(8);
            pong_out.encode(&mut pong_buf);
            tcp.write_message(Message::Pong { payload: &pong_buf })
                .await?;
            Ok(None)
        }
        Message::Pong { .. } => Ok(None),
        Message::Close { payload } => {
            let close = ClosePayload::decode(payload).map_err(crate::wire::map_payload_error)?;
            Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                format!("register_cid closed: {:?}", close.code),
            ))
        }
        Message::Data { packet } => {
            if to_tun_tx.send(packet.to_vec()).await.is_err() {
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
