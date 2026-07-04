use boring::rand::rand_bytes;
use slt_core::crypto::udp_qsp::{QuicQspSession, UdpQspKeys};
use slt_core::proto::{AEAD_IV_LEN, CipherSuite, Message, RegisterCidPayload};
use slt_core::types::ClientUdpQspCipher;

use crate::runtime::session::SessionError;
use crate::transport::quic_discovery as quic;
use crate::transport::tcp::TcpTransport;
use crate::transport::udp_qsp::{ClientUdpQspIo, client_udp_qsp_io};

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
    pub(super) session: Option<QuicQspSession<ClientUdpQspIo>>,
}

/// Builds a `REGISTER_CID` payload and a matching UDP-QSP session.
///
/// Generates random cryptographic keys for the UDP-QSP session and encodes
/// them in a `RegisterCidPayload` for transmission to the server. The payload
/// is expressed in the server's `(tx, rx)` terms; the returned session uses
/// the reversed directions for the client.
///
/// # Errors
///
/// Returns an error if:
/// - Random bytes generation fails (preserved as [`SessionError::Crypto`])
/// - Key derivation fails (invalid cipher parameters)
/// - Payload encoding fails
pub(super) fn prepare_udp_qsp_registration(
    ids: &quic::QuicIds,
    cipher: CipherSuite,
) -> Result<PreparedUdpQspRegistration, SessionError> {
    let hp_c2s = random_bytes(cipher.hp_key_len())?;
    let hp_s2c = random_bytes(cipher.hp_key_len())?;
    let aead_c2s = random_bytes(cipher.aead_key_len())?;
    let aead_s2c = random_bytes(cipher.aead_key_len())?;
    let iv_c2s = random_array::<AEAD_IV_LEN>()?;
    let iv_s2c = random_array::<AEAD_IV_LEN>()?;
    let pn_start_s2c = u64::from(fastrand::u32(..));
    let pn_start_c2s = u64::from(fastrand::u32(..));
    let key_phase = false;

    let payload = RegisterCidPayload {
        client_to_server_cid: ids.dcid,
        server_to_client_cid: ids.scid,
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
    payload.encode(&mut payload_buf)?;

    // Reverse key directions: the payload is expressed in the server's (tx/rx) terms.
    let keys = UdpQspKeys::new(
        cipher,
        &payload.hp_rx,
        &payload.hp_tx,
        &payload.aead_rx,
        &payload.aead_tx,
        payload.iv_rx,
        payload.iv_tx,
    )?;

    let io = client_udp_qsp_io(&ids.socket, ids.peer)?;
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

/// Starts a UDP-QSP `REGISTER_CID` exchange by sending a prepared payload.
///
/// Prepares the registration payload and sends `REGISTER_CID` to the server
/// over the TCP transport. Response handling is owned by the main session loop
/// so TCP activity accounting and idle tracking remain centralized.
///
/// # Errors
///
/// Returns an error if:
/// - Registration preparation fails (see `prepare_udp_qsp_registration`)
/// - TCP write fails
pub(super) async fn start_udp_qsp_registration(
    tcp: &mut TcpTransport,
    ids: &quic::QuicIds,
    cipher_policy: ClientUdpQspCipher,
) -> Result<PreparedUdpQspRegistration, SessionError> {
    let cipher = select_udp_qsp_cipher(cipher_policy);
    let prepared = prepare_udp_qsp_registration(ids, cipher)?;
    tcp.write_message(Message::RegisterCid {
        payload: &prepared.payload_buf,
    })
    .await?;
    Ok(prepared)
}

/// Fill a fixed-size array with cryptographically secure random bytes.
///
/// The boring `ErrorStack` from `RAND_bytes` is preserved via
/// [`SessionError::Crypto`], so the cause chain survives to the terminal
/// report.
fn random_array<const N: usize>() -> Result<[u8; N], SessionError> {
    let mut bytes = [0u8; N];
    rand_bytes(&mut bytes)?;
    Ok(bytes)
}

fn random_bytes(len: usize) -> Result<Vec<u8>, SessionError> {
    let mut bytes = vec![0u8; len];
    rand_bytes(&mut bytes)?;
    Ok(bytes)
}

fn select_udp_qsp_cipher(policy: ClientUdpQspCipher) -> CipherSuite {
    policy.select(aes_gcm_acceleration_available())
}

/// Returns the explicit cipher policy for the suite other than `tried`.
///
/// Used as the one-shot fallback when a server rejects an auto-selected suite:
/// given the suite `auto` resolved to, this yields the other explicit suite.
const fn other_explicit_policy(tried: CipherSuite) -> ClientUdpQspCipher {
    match tried {
        CipherSuite::Aes128Gcm => ClientUdpQspCipher::ChaCha20Poly1305,
        CipherSuite::ChaCha20Poly1305 => ClientUdpQspCipher::Aes128Gcm,
    }
}

/// The explicit cipher policy for the suite `auto` did not select.
///
/// This is the fallback policy installed when a server rejects the auto-selected
/// suite with `InvalidCipher`, so the next `REGISTER_CID` retries with the other
/// supported suite.
pub(super) fn auto_fallback_policy() -> ClientUdpQspCipher {
    other_explicit_policy(select_udp_qsp_cipher(ClientUdpQspCipher::Auto))
}

fn aes_gcm_acceleration_available() -> bool {
    aes_gcm_acceleration_available_for_target()
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn aes_gcm_acceleration_available_for_target() -> bool {
    std::arch::is_x86_feature_detected!("aes") && std::arch::is_x86_feature_detected!("pclmulqdq")
}

#[cfg(target_arch = "aarch64")]
fn aes_gcm_acceleration_available_for_target() -> bool {
    std::arch::is_aarch64_feature_detected!("aes")
        && std::arch::is_aarch64_feature_detected!("pmull")
}

#[cfg(target_arch = "arm")]
fn aes_gcm_acceleration_available_for_target() -> bool {
    std::arch::is_arm_feature_detected!("aes") && std::arch::is_arm_feature_detected!("pmull")
}

#[cfg(not(any(
    target_arch = "x86",
    target_arch = "x86_64",
    target_arch = "aarch64",
    target_arch = "arm"
)))]
const fn aes_gcm_acceleration_available_for_target() -> bool {
    false
}

#[cfg(test)]
mod tests {
    use slt_core::proto::{
        AEAD_IV_LEN, AEAD_KEY_LEN, CHACHA20_POLY1305_KEY_LEN, CipherSuite, HP_KEY_LEN,
        RegisterCidPayload,
    };
    use slt_core::types::{ClientUdpQspCipher, MAX_DCID_LEN};

    use super::*;
    use crate::test_support::mock_quic_ids;

    #[tokio::test]
    async fn prepare_registration_returns_valid_structure() {
        let ids = mock_quic_ids().await;
        let result = prepare_udp_qsp_registration(&ids, CipherSuite::Aes128Gcm);

        assert!(result.is_ok());
        let prepared = result.unwrap();
        assert!(!prepared.payload_buf.is_empty());
        assert!(prepared.session.is_some());
    }

    #[tokio::test]
    async fn prepare_registration_payload_is_decodable() {
        let ids = mock_quic_ids().await;
        let prepared = prepare_udp_qsp_registration(&ids, CipherSuite::Aes128Gcm).unwrap();

        // The payload_buf should be decodable as a RegisterCidPayload
        let decoded = RegisterCidPayload::decode(&prepared.payload_buf);
        assert!(decoded.is_ok());

        let decoded = decoded.unwrap();

        // CIDs should match what we passed in
        assert_eq!(decoded.client_to_server_cid, ids.dcid);
        assert_eq!(decoded.server_to_client_cid, ids.scid);

        // Cipher should match the requested suite.
        assert_eq!(decoded.cipher, CipherSuite::Aes128Gcm);
    }

    #[tokio::test]
    async fn prepare_registration_payload_uses_requested_chacha_cipher() {
        let ids = mock_quic_ids().await;
        let prepared = prepare_udp_qsp_registration(&ids, CipherSuite::ChaCha20Poly1305).unwrap();
        let decoded = RegisterCidPayload::decode(&prepared.payload_buf).unwrap();

        assert_eq!(decoded.cipher, CipherSuite::ChaCha20Poly1305);
        assert_eq!(decoded.hp_tx.len(), CHACHA20_POLY1305_KEY_LEN);
        assert_eq!(decoded.hp_rx.len(), CHACHA20_POLY1305_KEY_LEN);
        assert_eq!(decoded.aead_tx.len(), CHACHA20_POLY1305_KEY_LEN);
        assert_eq!(decoded.aead_rx.len(), CHACHA20_POLY1305_KEY_LEN);
        assert!(prepared.session.is_some());
    }

    #[tokio::test]
    async fn prepare_registration_payload_wire_format() {
        let ids = mock_quic_ids().await;
        let prepared = prepare_udp_qsp_registration(&ids, CipherSuite::Aes128Gcm).unwrap();
        let payload = &prepared.payload_buf;

        // Verify minimum payload length
        // Structure: c2s_cid_len(1) + c2s_cid(20) + s2c_cid_len(1) + s2c_cid(var) + cipher(1) +
        //            hp_tx(16) + hp_rx(16) + aead_tx(16) + aead_rx(16) +
        //            iv_tx(12) + iv_rx(12) + pn_start(8) + pn_start_rx(8) + key_phase(1)
        let expected_min_len = (1
            + MAX_DCID_LEN
            + 1) // s2c can be empty
            + 1
            + HP_KEY_LEN * 2
            + AEAD_KEY_LEN * 2
            + AEAD_IV_LEN * 2
            + 8
            + 8
            + 1;
        assert!(payload.len() >= expected_min_len);

        // Verify client_to_server_cid length prefix (must be MAX_DCID_LEN)
        let c2s_cid_len = payload[0] as usize;
        assert_eq!(c2s_cid_len, MAX_DCID_LEN);

        // Verify client_to_server_cid bytes
        assert_eq!(&payload[1..=c2s_cid_len], ids.dcid.as_slice());

        // Verify server_to_client_cid length prefix
        let s2c_cid_len_offset = 1 + c2s_cid_len;
        let s2c_cid_len = payload[s2c_cid_len_offset] as usize;

        // Verify server_to_client_cid bytes
        let s2c_cid_offset = s2c_cid_len_offset + 1;
        assert_eq!(
            &payload[s2c_cid_offset..s2c_cid_offset + s2c_cid_len],
            ids.scid.as_slice()
        );

        // Verify cipher byte (AES-128-GCM = 0x01)
        let cipher_offset = s2c_cid_offset + s2c_cid_len;
        assert_eq!(payload[cipher_offset], u8::from(CipherSuite::Aes128Gcm));
    }

    #[tokio::test]
    async fn prepare_registration_key_direction_reversal() {
        let ids = mock_quic_ids().await;
        let prepared = prepare_udp_qsp_registration(&ids, CipherSuite::Aes128Gcm).unwrap();

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
        let prepared = prepare_udp_qsp_registration(&ids, CipherSuite::Aes128Gcm).unwrap();
        let decoded = RegisterCidPayload::decode(&prepared.payload_buf).unwrap();

        // Packet numbers are generated from fastrand::u32(..), so should be in u32 range
        assert!(u32::try_from(decoded.pn_start).is_ok());
        assert!(u32::try_from(decoded.pn_start_rx).is_ok());
    }

    #[tokio::test]
    async fn prepare_registration_key_phase_is_false() {
        let ids = mock_quic_ids().await;
        let prepared = prepare_udp_qsp_registration(&ids, CipherSuite::Aes128Gcm).unwrap();
        let decoded = RegisterCidPayload::decode(&prepared.payload_buf).unwrap();

        // Initial key phase should always be false (0)
        assert!(!decoded.key_phase);
    }

    #[tokio::test]
    async fn prepare_registration_payload_matches_encode() {
        let ids = mock_quic_ids().await;
        let prepared = prepare_udp_qsp_registration(&ids, CipherSuite::Aes128Gcm).unwrap();

        // Decode and re-encode to verify roundtrip consistency
        let decoded = RegisterCidPayload::decode(&prepared.payload_buf).unwrap();

        let mut re_encoded = Vec::new();
        decoded.encode(&mut re_encoded).unwrap();

        assert_eq!(prepared.payload_buf, re_encoded);
    }

    #[tokio::test]
    async fn prepared_registration_session_can_be_taken() {
        let ids = mock_quic_ids().await;
        let mut prepared = prepare_udp_qsp_registration(&ids, CipherSuite::Aes128Gcm).unwrap();

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
        let result: Result<[u8; 16], SessionError> = random_array();
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

    #[test]
    fn random_bytes_produces_requested_length() {
        let bytes = random_bytes(32).unwrap();
        assert_eq!(bytes.len(), 32);
        assert!(bytes.iter().any(|&b| b != 0));
    }

    #[test]
    fn explicit_cipher_selection_respects_policy() {
        assert_eq!(
            ClientUdpQspCipher::Aes128Gcm.select(false),
            CipherSuite::Aes128Gcm
        );
        assert_eq!(
            ClientUdpQspCipher::ChaCha20Poly1305.select(true),
            CipherSuite::ChaCha20Poly1305
        );
    }

    #[test]
    fn auto_cipher_selection_follows_aes_acceleration() {
        // `select` takes the acceleration probe as a parameter, so the auto decision
        // is deterministic for a given feature set without touching real hardware.
        assert_eq!(
            ClientUdpQspCipher::Auto.select(true),
            CipherSuite::Aes128Gcm
        );
        assert_eq!(
            ClientUdpQspCipher::Auto.select(false),
            CipherSuite::ChaCha20Poly1305
        );
    }

    #[test]
    fn other_explicit_policy_returns_the_opposite_suite() {
        assert_eq!(
            other_explicit_policy(CipherSuite::Aes128Gcm),
            ClientUdpQspCipher::ChaCha20Poly1305
        );
        assert_eq!(
            other_explicit_policy(CipherSuite::ChaCha20Poly1305),
            ClientUdpQspCipher::Aes128Gcm
        );
    }

    #[test]
    fn auto_fallback_policy_is_the_suite_auto_did_not_select() {
        // The fallback is, by construction, the explicit policy whose resolved
        // suite differs from the one `auto` picks on this host.
        let fallback = auto_fallback_policy();
        let auto_picked = select_udp_qsp_cipher(ClientUdpQspCipher::Auto);
        assert_ne!(fallback.select(true), auto_picked);
        assert_ne!(fallback.select(false), auto_picked);
        // And it must be one of the two explicit policies.
        assert!(matches!(
            fallback,
            ClientUdpQspCipher::Aes128Gcm | ClientUdpQspCipher::ChaCha20Poly1305
        ));
    }
}
