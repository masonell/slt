use std::io;

use boring::rand::rand_bytes;
use slt_core::crypto::udp_qsp::{QuicQspSession, UdpQspKeys};
use slt_core::proto::{
    AEAD_IV_LEN, AEAD_KEY_LEN, CipherSuite, HP_KEY_LEN, Message, RegisterCidPayload,
};

use crate::transport::quic_discovery as quic;
use crate::transport::tcp::TcpTransport;
use crate::transport::udp_qsp::ClientUdpIo;

/// Prepared state for a UDP-QSP `REGISTER_CID` exchange.
///
/// This bundles the encoded `RegisterCidPayload` to send to the server together
/// with a locally-constructed `QuicQspSession` that matches the generated
/// keys/packet-number starts. The session is stored in an `Option` so it can
/// be moved out exactly once (via `take()`) when the server replies
/// `REGISTER_OK`.
pub(super) struct PreparedUdpQspRegistration {
    /// Encoded `RegisterCidPayload` bytes (used as the `Message::RegisterCid` payload).
    pub(super) payload_buf: Vec<u8>,
    /// Matching UDP-QSP session to install once registration succeeds.
    pub(super) session: Option<QuicQspSession<ClientUdpIo>>,
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
        session: Some(session),
    })
}

/// Start a UDP-QSP `REGISTER_CID` exchange by sending a prepared payload.
///
/// Response handling is owned by the main session loop so TCP activity
/// accounting and idle tracking remain centralized.
pub(super) async fn start_udp_qsp_registration(
    tcp: &mut TcpTransport,
    ids: &quic::QuicIds,
) -> io::Result<PreparedUdpQspRegistration> {
    let prepared = prepare_udp_qsp_registration(ids)?;
    tcp.write_message(Message::RegisterCid {
        payload: &prepared.payload_buf,
    })
    .await?;
    Ok(prepared)
}

fn random_array<const N: usize>() -> io::Result<[u8; N]> {
    let mut bytes = [0u8; N];
    rand_bytes(&mut bytes).map_err(|err| io::Error::other(format!("{err:?}")))?;
    Ok(bytes)
}
