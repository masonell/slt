//! TLS 1.3 HKDF expansion and UDP-QSP packet-key derivation.

use boring::hash::hmac_sha256;

use super::super::QspCryptoError;
use crate::proto::UDP_QSP_TRAFFIC_SECRET_LEN;

const TLS13_LABEL_PREFIX: &[u8] = b"tls13 ";
const QUIC_KEY_LABEL: &[u8] = b"quic key";
const QUIC_IV_LABEL: &[u8] = b"quic iv";
const QUIC_HP_LABEL: &[u8] = b"quic hp";
const QUIC_KU_LABEL: &[u8] = b"quic ku";

pub(super) struct PacketMaterial {
    pub(super) key: Vec<u8>,
    pub(super) iv: Vec<u8>,
}

pub(super) fn derive_header_protection_key(
    secret: &[u8; UDP_QSP_TRAFFIC_SECRET_LEN],
    key_len: usize,
) -> Result<Vec<u8>, QspCryptoError> {
    hkdf_expand_label_sha256(secret, QUIC_HP_LABEL, b"", key_len)
}

pub(super) fn derive_packet_material(
    secret: &[u8; UDP_QSP_TRAFFIC_SECRET_LEN],
    key_len: usize,
    iv_len: usize,
) -> Result<PacketMaterial, QspCryptoError> {
    Ok(PacketMaterial {
        key: hkdf_expand_label_sha256(secret, QUIC_KEY_LABEL, b"", key_len)?,
        iv: hkdf_expand_label_sha256(secret, QUIC_IV_LABEL, b"", iv_len)?,
    })
}

pub(super) fn derive_next_secret(
    secret: &[u8; UDP_QSP_TRAFFIC_SECRET_LEN],
) -> Result<[u8; UDP_QSP_TRAFFIC_SECRET_LEN], QspCryptoError> {
    hkdf_expand_label_sha256(secret, QUIC_KU_LABEL, b"", UDP_QSP_TRAFFIC_SECRET_LEN)?
        .try_into()
        .map_err(|_| QspCryptoError::CryptoFail)
}

#[cfg(test)]
fn hkdf_extract_sha256(salt: &[u8], ikm: &[u8]) -> Result<[u8; 32], QspCryptoError> {
    hmac_sha256(salt, ikm).map_err(|_| QspCryptoError::CryptoFail)
}

fn hkdf_expand_label_sha256(
    secret: &[u8; UDP_QSP_TRAFFIC_SECRET_LEN],
    label: &[u8],
    context: &[u8],
    len: usize,
) -> Result<Vec<u8>, QspCryptoError> {
    let output_len = u16::try_from(len).map_err(|_| QspCryptoError::CryptoFail)?;
    let full_label_len = TLS13_LABEL_PREFIX.len() + label.len();
    let full_label_len = u8::try_from(full_label_len).map_err(|_| QspCryptoError::CryptoFail)?;
    let context_len = u8::try_from(context.len()).map_err(|_| QspCryptoError::CryptoFail)?;

    let mut info = Vec::with_capacity(2 + 1 + usize::from(full_label_len) + 1 + context.len());
    info.extend_from_slice(&output_len.to_be_bytes());
    info.push(full_label_len);
    info.extend_from_slice(TLS13_LABEL_PREFIX);
    info.extend_from_slice(label);
    info.push(context_len);
    info.extend_from_slice(context);

    hkdf_expand_sha256_vec(secret, &info, len)
}

fn hkdf_expand_sha256_vec(
    prk: &[u8; 32],
    info: &[u8],
    len: usize,
) -> Result<Vec<u8>, QspCryptoError> {
    if len == 0 {
        return Ok(Vec::new());
    }

    let mut out = Vec::with_capacity(len);
    let mut prev = [0u8; 32];
    let mut prev_len = 0usize;
    let mut counter = 1u8;

    while out.len() < len {
        let mut input = Vec::with_capacity(prev_len + info.len() + 1);
        if prev_len != 0 {
            input.extend_from_slice(&prev[..prev_len]);
        }
        input.extend_from_slice(info);
        input.push(counter);

        prev = hmac_sha256(prk, &input).map_err(|_| QspCryptoError::CryptoFail)?;
        prev_len = prev.len();

        let remaining = len - out.len();
        let take = remaining.min(prev_len);
        out.extend_from_slice(&prev[..take]);

        counter = counter.checked_add(1).ok_or(QspCryptoError::CryptoFail)?;
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{AEAD_IV_LEN, AEAD_KEY_LEN, HP_KEY_LEN};

    #[test]
    fn hkdf_expand_produces_expected_length() {
        let prk = [0x42u8; 32];
        let info = b"test info";

        let out16 = hkdf_expand_sha256_vec(&prk, info, 16).unwrap();
        assert_eq!(out16.len(), 16);

        let out32 = hkdf_expand_sha256_vec(&prk, info, 32).unwrap();
        assert_eq!(out32.len(), 32);

        let out64 = hkdf_expand_sha256_vec(&prk, info, 64).unwrap();
        assert_eq!(out64.len(), 64);
    }

    #[test]
    fn hkdf_expand_deterministic() {
        let prk = [0x42u8; 32];
        let info = b"test info";

        let out1 = hkdf_expand_sha256_vec(&prk, info, 32).unwrap();
        let out2 = hkdf_expand_sha256_vec(&prk, info, 32).unwrap();

        assert_eq!(out1, out2, "HKDF expand should be deterministic");
    }

    #[test]
    fn hkdf_expand_different_info_produces_different_output() {
        let prk = [0x42u8; 32];

        let out1 = hkdf_expand_sha256_vec(&prk, b"info 1", 32).unwrap();
        let out2 = hkdf_expand_sha256_vec(&prk, b"info 2", 32).unwrap();

        assert_ne!(out1, out2, "different info should produce different output");
    }

    #[test]
    fn hkdf_expand_different_prk_produces_different_output() {
        let prk1 = [0x42u8; 32];
        let prk2 = [0x24u8; 32];
        let info = b"test info";

        let out1 = hkdf_expand_sha256_vec(&prk1, info, 32).unwrap();
        let out2 = hkdf_expand_sha256_vec(&prk2, info, 32).unwrap();

        assert_ne!(out1, out2, "different PRK should produce different output");
    }

    #[test]
    fn hkdf_expand_label_matches_rfc9001_client_initial_vectors() {
        let secret: [u8; UDP_QSP_TRAFFIC_SECRET_LEN] =
            hex::decode("c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea")
                .unwrap()
                .try_into()
                .unwrap();

        let key = hkdf_expand_label_sha256(&secret, QUIC_KEY_LABEL, b"", AEAD_KEY_LEN).unwrap();
        let iv = hkdf_expand_label_sha256(&secret, QUIC_IV_LABEL, b"", AEAD_IV_LEN).unwrap();
        let hp = hkdf_expand_label_sha256(&secret, QUIC_HP_LABEL, b"", HP_KEY_LEN).unwrap();

        assert_eq!(hex::encode(key), "1f369613dd76d5467730efcbe3b1a22d");
        assert_eq!(hex::encode(iv), "fa044b2f42a3fd3b46fb255c");
        assert_eq!(hex::encode(hp), "9f50449e04a0e810283a1e9933adedd2");
    }

    #[test]
    fn hkdf_expand_label_quic_ku_vector_is_stable() {
        let secret = [0x42; UDP_QSP_TRAFFIC_SECRET_LEN];
        let next = derive_next_secret(&secret).unwrap();

        assert_eq!(
            hex::encode(next),
            "f8f868f38fc89d88af15ab693b940f391dee2dee6ec57aa4321581de7a45960d"
        );
    }

    #[test]
    fn hkdf_extract_produces_32_bytes() {
        let salt = [0x01u8; 12];
        let ikm = b"input key material";

        let prk = hkdf_extract_sha256(&salt, ikm);
        assert!(prk.is_ok());
        assert_eq!(prk.unwrap().len(), 32);
    }

    #[test]
    fn hkdf_extract_deterministic() {
        let salt = [0x01u8; 12];
        let ikm = b"input key material";

        let prk1 = hkdf_extract_sha256(&salt, ikm).unwrap();
        let prk2 = hkdf_extract_sha256(&salt, ikm).unwrap();

        assert_eq!(prk1, prk2, "HKDF extract should be deterministic");
    }

    #[test]
    fn hkdf_extract_different_salt_different_output() {
        let salt1 = [0x01u8; 12];
        let salt2 = [0x02u8; 12];
        let ikm = b"input key material";

        let prk1 = hkdf_extract_sha256(&salt1, ikm).unwrap();
        let prk2 = hkdf_extract_sha256(&salt2, ikm).unwrap();

        assert_ne!(prk1, prk2, "different salt should produce different PRK");
    }
}
