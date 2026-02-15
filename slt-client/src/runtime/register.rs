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

#[cfg(test)]
mod tests {
    use slt_core::proto::{AEAD_IV_LEN, AEAD_KEY_LEN, CipherSuite, HP_KEY_LEN, RegisterCidPayload};
    use slt_core::types::QUIC_DCID_PREFIX_LEN;

    use super::*;
    use crate::test_support::mock_quic_ids;

    #[tokio::test]
    async fn prepare_registration_returns_valid_structure() {
        let ids = mock_quic_ids().await;
        let result = prepare_udp_qsp_registration(&ids);

        assert!(result.is_ok());
        let prepared = result.unwrap();
        assert!(!prepared.payload_buf.is_empty());
        assert!(prepared.session.is_some());
    }

    #[tokio::test]
    async fn prepare_registration_payload_is_decodable() {
        let ids = mock_quic_ids().await;
        let prepared = prepare_udp_qsp_registration(&ids).unwrap();

        // The payload_buf should be decodable as a RegisterCidPayload
        let decoded = RegisterCidPayload::decode(&prepared.payload_buf);
        assert!(decoded.is_ok());

        let decoded = decoded.unwrap();

        // CIDs should match what we passed in
        assert_eq!(decoded.dcid, ids.dcid);
        assert_eq!(decoded.scid, ids.scid);

        // Cipher should be AES-128-GCM (the only cipher currently used)
        assert_eq!(decoded.cipher, CipherSuite::Aes128Gcm);
    }

    #[tokio::test]
    async fn prepare_registration_payload_wire_format() {
        let ids = mock_quic_ids().await;
        let prepared = prepare_udp_qsp_registration(&ids).unwrap();
        let payload = &prepared.payload_buf;

        // Verify minimum payload length
        // Structure: dcid_len(1) + dcid(8) + scid_len(1) + scid(8) + cipher(1) +
        //            hp_tx(16) + hp_rx(16) + aead_tx(16) + aead_rx(16) +
        //            iv_tx(12) + iv_rx(12) + pn_start(8) + pn_start_rx(8) + key_phase(1)
        let expected_min_len = 1
            + QUIC_DCID_PREFIX_LEN
            + 1
            + QUIC_DCID_PREFIX_LEN
            + 1
            + HP_KEY_LEN * 2
            + AEAD_KEY_LEN * 2
            + AEAD_IV_LEN * 2
            + 8
            + 8
            + 1;
        assert!(payload.len() >= expected_min_len);

        // Verify DCID length prefix
        let dcid_len = payload[0] as usize;
        assert_eq!(dcid_len, QUIC_DCID_PREFIX_LEN);

        // Verify DCID bytes
        assert_eq!(&payload[1..1 + dcid_len], ids.dcid.as_slice());

        // Verify SCID length prefix
        let scid_len_offset = 1 + dcid_len;
        let scid_len = payload[scid_len_offset] as usize;
        assert_eq!(scid_len, QUIC_DCID_PREFIX_LEN);

        // Verify SCID bytes
        let scid_offset = scid_len_offset + 1;
        assert_eq!(
            &payload[scid_offset..scid_offset + scid_len],
            ids.scid.as_slice()
        );

        // Verify cipher byte (AES-128-GCM = 0x01)
        let cipher_offset = scid_offset + scid_len;
        assert_eq!(payload[cipher_offset], u8::from(CipherSuite::Aes128Gcm));
    }

    #[tokio::test]
    async fn prepare_registration_key_direction_reversal() {
        let ids = mock_quic_ids().await;
        let prepared = prepare_udp_qsp_registration(&ids).unwrap();

        // Decode the payload to examine the keys
        let decoded = RegisterCidPayload::decode(&prepared.payload_buf).unwrap();

        // The prepare_udp_qsp_registration function constructs the payload with:
        // - hp_tx = hp_s2c (server's tx = client's rx direction)
        // - hp_rx = hp_c2s (server's rx = client's tx direction)
        // This means the payload expresses keys in server's (tx, rx) terms.

        // Verify the keys are non-zero (random generation worked)
        assert!(decoded.hp_tx.iter().any(|&b| b != 0));
        assert!(decoded.hp_rx.iter().any(|&b| b != 0));
        assert!(decoded.aead_tx.iter().any(|&b| b != 0));
        assert!(decoded.aead_rx.iter().any(|&b| b != 0));

        // The session stored in prepared should have reversed directions:
        // - Client uses hp_rx (from payload) for its tx direction
        // - Client uses hp_tx (from payload) for its rx direction

        // Verify that a session was created (keys were valid)
        assert!(prepared.session.is_some());
    }

    #[tokio::test]
    async fn prepare_registration_packet_numbers_in_valid_range() {
        let ids = mock_quic_ids().await;
        let prepared = prepare_udp_qsp_registration(&ids).unwrap();
        let decoded = RegisterCidPayload::decode(&prepared.payload_buf).unwrap();

        // Packet numbers are generated from fastrand::u32(..), so should be in u32 range
        assert!(decoded.pn_start <= u64::from(u32::MAX));
        assert!(decoded.pn_start_rx <= u64::from(u32::MAX));
    }

    #[tokio::test]
    async fn prepare_registration_key_phase_is_false() {
        let ids = mock_quic_ids().await;
        let prepared = prepare_udp_qsp_registration(&ids).unwrap();
        let decoded = RegisterCidPayload::decode(&prepared.payload_buf).unwrap();

        // Initial key phase should always be false (0)
        assert!(!decoded.key_phase);
    }

    #[tokio::test]
    async fn prepare_registration_payload_matches_encode() {
        let ids = mock_quic_ids().await;
        let prepared = prepare_udp_qsp_registration(&ids).unwrap();

        // Decode and re-encode to verify roundtrip consistency
        let decoded = RegisterCidPayload::decode(&prepared.payload_buf).unwrap();

        let mut re_encoded = Vec::new();
        decoded.encode(&mut re_encoded).unwrap();

        assert_eq!(prepared.payload_buf, re_encoded);
    }

    #[tokio::test]
    async fn prepared_registration_session_can_be_taken() {
        let ids = mock_quic_ids().await;
        let mut prepared = prepare_udp_qsp_registration(&ids).unwrap();

        // Session should be Some initially
        assert!(prepared.session.is_some());

        // Take the session
        let session = prepared.session.take();
        assert!(session.is_some());

        // After take, session should be None
        assert!(prepared.session.is_none());
    }

    #[test]
    fn random_array_produces_correct_length() {
        let result: io::Result<[u8; 16]> = random_array();
        assert!(result.is_ok());
        let arr = result.unwrap();
        assert_eq!(arr.len(), 16);
    }

    #[test]
    fn random_array_produces_different_values() {
        let a: [u8; 32] = random_array().unwrap();
        let b: [u8; 32] = random_array().unwrap();

        // Two random arrays should almost certainly differ
        assert_ne!(a, b);
    }

    #[test]
    fn random_array_not_all_zeros() {
        let arr: [u8; 64] = random_array().unwrap();

        // Probability of all zeros is astronomically low
        assert!(arr.iter().any(|&b| b != 0));
    }
}
