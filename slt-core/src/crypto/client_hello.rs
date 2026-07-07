use boring::error::ErrorStack;
use boring::hash::hmac_sha256;
use boring::ssl::SslRef;

use crate::types::SharedSecret;

/// TLS `HandshakeType` value for `ClientHello`.
pub const HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 0x01;
/// Expected `legacy_session_id` length used by the classifier.
pub const LEGACY_SESSION_ID_LEN: usize = 32;
/// Truncated HMAC length per part.
pub const PART_LEN: usize = 16;
/// Prefix length of `ClientHello` random used for the first HMAC.
pub const RANDOM_PREFIX_LEN: usize = 16;
/// Extension type for `key_share`.
pub const EXT_KEY_SHARE: u16 = 0x0033;
/// `NamedGroup` for `X25519`.
pub const GROUP_X25519: u16 = 0x001d;

/// Errors from `ClientHello` session ID generation.
#[derive(Debug, Clone, thiserror::Error)]
pub enum ClientHelloError {
    /// The `session_id` buffer has wrong length.
    #[error("session_id buffer has wrong length: expected {expected}, got {actual}")]
    InvalidSessionIdLength {
        /// Expected buffer length.
        expected: usize,
        /// Actual buffer length.
        actual: usize,
    },
    /// The `ClientHello` is malformed or missing required extensions.
    #[error("malformed ClientHello: {0}")]
    MalformedClientHello(&'static str),
    /// HMAC computation failed.
    #[error("HMAC computation failed: {0}")]
    HmacFailed(#[source] ErrorStack),
}

impl From<ClientHelloError> for ErrorStack {
    fn from(err: ClientHelloError) -> Self {
        match err {
            // Preserve the original OpenSSL stack from crypto operations.
            ClientHelloError::HmacFailed(err) => err,
            other => Self::internal_error(other),
        }
    }
}

/// Parse a serialized `ClientHello` (including handshake header) and extract
/// the legacy random and `X25519` `key_share`.
///
/// Returns `None` if the buffer is malformed or does not contain an `X25519`
/// `key_share`.
///
/// Selection contract: selects the first `key_share` entry whose group is
/// `X25519` with a 32-byte key. The server-side streaming classifier
/// ([`crate::classifier::classify_tcp_client_hello`]) applies the same rule so
/// the HMAC-derived session id round-trips across the wire.
#[must_use]
pub fn parse_client_hello(client_hello: &[u8]) -> Option<([u8; 32], [u8; 32])> {
    if client_hello.len() < 4 {
        return None;
    }

    if client_hello[0] != HANDSHAKE_TYPE_CLIENT_HELLO {
        return None;
    }

    let hs_len = ((client_hello[1] as usize) << 16)
        | ((client_hello[2] as usize) << 8)
        | (client_hello[3] as usize);
    if client_hello.len() < 4 + hs_len {
        return None;
    }

    let mut pos = 4;
    if pos + 2 + 32 + 1 > 4 + hs_len {
        return None;
    }

    pos += 2; // legacy_version

    let mut random = [0u8; 32];
    random.copy_from_slice(&client_hello[pos..pos + 32]);
    pos += 32;

    let session_id_len = client_hello[pos] as usize;
    pos += 1;
    if pos + session_id_len > 4 + hs_len {
        return None;
    }
    pos += session_id_len;

    if pos + 2 > 4 + hs_len {
        return None;
    }
    let cipher_suites_len = u16::from_be_bytes([client_hello[pos], client_hello[pos + 1]]) as usize;
    pos += 2;
    if pos + cipher_suites_len > 4 + hs_len {
        return None;
    }
    pos += cipher_suites_len;

    if pos + 1 > 4 + hs_len {
        return None;
    }
    let compression_len = client_hello[pos] as usize;
    pos += 1;
    if pos + compression_len > 4 + hs_len {
        return None;
    }
    pos += compression_len;

    if pos + 2 > 4 + hs_len {
        return None;
    }
    let extensions_len = u16::from_be_bytes([client_hello[pos], client_hello[pos + 1]]) as usize;
    pos += 2;
    if pos + extensions_len > 4 + hs_len {
        return None;
    }

    let mut ext_pos = pos;
    let ext_end = pos + extensions_len;
    while ext_pos + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([client_hello[ext_pos], client_hello[ext_pos + 1]]);
        let ext_len =
            u16::from_be_bytes([client_hello[ext_pos + 2], client_hello[ext_pos + 3]]) as usize;
        ext_pos += 4;
        if ext_pos + ext_len > ext_end {
            return None;
        }

        if ext_type == EXT_KEY_SHARE {
            if ext_len < 2 {
                return None;
            }
            let list_len =
                u16::from_be_bytes([client_hello[ext_pos], client_hello[ext_pos + 1]]) as usize;
            let mut list_pos = ext_pos + 2;
            let list_end = ext_pos + 2 + list_len;
            if list_end > ext_pos + ext_len {
                return None;
            }

            while list_pos + 4 <= list_end {
                let group =
                    u16::from_be_bytes([client_hello[list_pos], client_hello[list_pos + 1]]);
                let ks_len =
                    u16::from_be_bytes([client_hello[list_pos + 2], client_hello[list_pos + 3]])
                        as usize;
                list_pos += 4;
                if list_pos + ks_len > list_end {
                    return None;
                }

                if group == GROUP_X25519 && ks_len == 32 {
                    let mut key_share = [0u8; 32];
                    key_share.copy_from_slice(&client_hello[list_pos..list_pos + 32]);
                    return Some((random, key_share));
                }

                list_pos += ks_len;
            }
        }

        ext_pos += ext_len;
    }

    None
}

/// Fill the `legacy_session_id` based on `ClientHello` random and `key_share`.
///
/// This computes two truncated HMAC-SHA256 parts and writes them into the
/// provided `session_id` buffer.
///
/// # Errors
///
/// Returns an error if:
/// - The `session_id` buffer length is not exactly `LEGACY_SESSION_ID_LEN`
/// - The `client_hello` is malformed or missing required extensions
/// - HMAC computation fails
pub fn fill_legacy_session_id(
    client_hello: &[u8],
    session_id: &mut [u8],
    secret: &SharedSecret,
) -> Result<(), ClientHelloError> {
    if session_id.len() != LEGACY_SESSION_ID_LEN {
        return Err(ClientHelloError::InvalidSessionIdLength {
            expected: LEGACY_SESSION_ID_LEN,
            actual: session_id.len(),
        });
    }

    let Some((random, key_share)) = parse_client_hello(client_hello) else {
        return Err(ClientHelloError::MalformedClientHello(
            "missing X25519 key_share or invalid structure",
        ));
    };

    let part1 = hmac_sha256(secret.as_bytes(), &random[..RANDOM_PREFIX_LEN])
        .map_err(ClientHelloError::HmacFailed)?;
    let part2 = hmac_sha256(secret.as_bytes(), &key_share).map_err(ClientHelloError::HmacFailed)?;

    session_id[..PART_LEN].copy_from_slice(&part1[..PART_LEN]);
    session_id[PART_LEN..].copy_from_slice(&part2[..PART_LEN]);

    Ok(())
}

/// Helper to build a `BoringSSL` callback that overwrites `legacy_session_id`.
///
/// The callback uses `secret` to fill the `session_id` based on `ClientHello`
/// random and `X25519` `key_share`.
pub fn client_hello_session_id_callback(
    secret: SharedSecret,
) -> impl Fn(&mut SslRef, &[u8], &mut [u8]) -> Result<(), ErrorStack> + Sync + Send + 'static {
    move |_ssl, client_hello, session_id| {
        fill_legacy_session_id(client_hello, session_id, &secret).map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use boring::symm::{Cipher, encrypt};

    use super::*;

    #[test]
    fn fill_legacy_session_id_rejects_wrong_session_id_len() {
        let secret = SharedSecret([0x11; 32]);
        let mut session_id = [0u8; LEGACY_SESSION_ID_LEN - 1];

        let err = fill_legacy_session_id(&[], &mut session_id, &secret).unwrap_err();

        match err {
            ClientHelloError::InvalidSessionIdLength { expected, actual } => {
                assert_eq!(expected, LEGACY_SESSION_ID_LEN);
                assert_eq!(actual, LEGACY_SESSION_ID_LEN - 1);
            }
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[test]
    fn fill_legacy_session_id_rejects_malformed_client_hello() {
        let secret = SharedSecret([0x22; 32]);
        let mut session_id = [0u8; LEGACY_SESSION_ID_LEN];

        let err = fill_legacy_session_id(&[], &mut session_id, &secret).unwrap_err();

        assert!(matches!(err, ClientHelloError::MalformedClientHello(_)));
    }

    #[test]
    fn client_hello_error_stack_uses_internal_error_for_structural_failures() {
        let err = ClientHelloError::MalformedClientHello("test malformed hello");
        let stack: ErrorStack = err.into();

        assert!(!stack.errors().is_empty());
        assert!(stack.to_string().contains("malformed ClientHello"));
    }

    #[test]
    fn client_hello_error_stack_preserves_crypto_error_stack() {
        let crypto_err = encrypt(Cipher::aes_128_cbc(), &[], None, &[]).unwrap_err();
        let mapped: ErrorStack = ClientHelloError::HmacFailed(crypto_err.clone()).into();

        assert_eq!(mapped.errors().len(), crypto_err.errors().len());
        assert_eq!(mapped.to_string(), crypto_err.to_string());
    }

    use crate::test_support::generate_client_hello_handshake;

    #[test]
    fn parse_client_hello_extracts_x25519_public_key() {
        let secret = SharedSecret([0x42; 32]);
        let handshake = generate_client_hello_handshake(secret);

        let result = parse_client_hello(&handshake);
        assert!(result.is_some(), "should parse valid ClientHello");

        let (random, key_share) = result.unwrap();
        assert_eq!(random.len(), 32, "random should be 32 bytes");
        assert_eq!(key_share.len(), 32, "key_share should be 32 bytes");
        // Key share should not be all zeros (BoringSSL generates real keys)
        assert_ne!(key_share, [0u8; 32], "key_share should be non-zero");
    }

    #[test]
    fn parse_client_hello_rejects_empty_buffer() {
        assert_eq!(parse_client_hello(&[]), None);
    }

    #[test]
    fn parse_client_hello_rejects_incomplete_header() {
        // Need at least 4 bytes for handshake type + length
        assert_eq!(parse_client_hello(&[0x01]), None);
        assert_eq!(parse_client_hello(&[0x01, 0x00]), None);
        assert_eq!(parse_client_hello(&[0x01, 0x00, 0x00]), None);
    }

    #[test]
    fn parse_client_hello_rejects_wrong_content_type() {
        // 0x02 is ServerHello, not ClientHello (0x01)
        let buf = [0x02, 0x00, 0x00, 0x10];
        assert_eq!(parse_client_hello(&buf), None);
    }

    #[test]
    fn parse_client_hello_rejects_truncated_body() {
        // Declares 16 bytes but only provides 4
        let buf = [0x01, 0x00, 0x00, 0x10, 0x03, 0x03];
        assert_eq!(parse_client_hello(&buf), None);
    }

    /// Build a minimal `ClientHello` handshake message with custom extensions.
    fn build_minimal_client_hello(random: &[u8; 32], extensions: &[u8]) -> Vec<u8> {
        let session_id: &[u8] = &[];
        let cipher_suites: &[u8] = &[0x00, 0x02, 0x13, 0x01]; // len + TLS_AES_128_GCM_SHA256
        let compression: &[u8] = &[0x01, 0x00]; // len + null

        let body_len = 2 // legacy_version
            + 32 // random
            + 1 + session_id.len() // session_id_len + session_id
            + cipher_suites.len()
            + compression.len()
            + 2 + extensions.len(); // extensions_len + extensions

        let mut buf = Vec::with_capacity(4 + body_len);
        buf.push(HANDSHAKE_TYPE_CLIENT_HELLO);
        buf.extend_from_slice(&(body_len as u32).to_be_bytes()[1..]); // u24 length
        buf.extend_from_slice(&[0x03, 0x03]); // legacy_version TLS 1.2
        buf.extend_from_slice(random);
        buf.push(session_id.len() as u8);
        buf.extend_from_slice(session_id);
        buf.extend_from_slice(cipher_suites);
        buf.extend_from_slice(compression);
        buf.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        buf.extend_from_slice(extensions);
        buf
    }

    #[test]
    fn parse_client_hello_rejects_missing_key_share() {
        let random = [0xAB; 32];
        let extensions: &[u8] = &[]; // no extensions
        let buf = build_minimal_client_hello(&random, extensions);

        assert_eq!(parse_client_hello(&buf), None);
    }

    #[test]
    fn parse_client_hello_rejects_non_x25519_key_share() {
        let random = [0xCD; 32];

        // Build key_share extension with secp256r1 (0x0017) instead of X25519 (0x001d)
        let key_share_data = [
            0x00, 0x04, // list_len = 4 bytes
            0x00, 0x17, // group = secp256r1
            0x00, 0x20, // key_exchange_len = 32
        ];
        let key: [u8; 32] = [0x11; 32];

        let mut ext = vec![];
        ext.extend_from_slice(&EXT_KEY_SHARE.to_be_bytes());
        ext.extend_from_slice(&((key_share_data.len() + key.len()) as u16).to_be_bytes());
        ext.extend_from_slice(&key_share_data);
        ext.extend_from_slice(&key);

        let buf = build_minimal_client_hello(&random, &ext);
        assert_eq!(parse_client_hello(&buf), None);
    }

    #[test]
    fn parse_client_hello_extracts_specific_random() {
        let random = [0xAB; 32];
        let key_share = [0x55; 32];

        // Build key_share extension with X25519
        let key_share_data = [
            0x00,
            0x24, // list_len = 36 bytes (4 header + 32 key)
            0x00,
            GROUP_X25519 as u8, // group = X25519 (0x001d)
            0x00,
            0x20, // key_exchange_len = 32
        ];

        let mut ext = vec![];
        ext.extend_from_slice(&EXT_KEY_SHARE.to_be_bytes());
        ext.extend_from_slice(&((key_share_data.len() + key_share.len()) as u16).to_be_bytes());
        ext.extend_from_slice(&key_share_data);
        ext.extend_from_slice(&key_share);

        let buf = build_minimal_client_hello(&random, &ext);
        let result = parse_client_hello(&buf);

        assert!(result.is_some());
        let (extracted_random, extracted_key) = result.unwrap();
        assert_eq!(extracted_random, random);
        assert_eq!(extracted_key, key_share);
    }
}
