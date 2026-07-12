use boring::error::ErrorStack;
use boring::hash::hmac_sha256;
use boring::memcmp;
use boring::ssl::SslRef;

use crate::types::SharedSecret;

/// TLS `HandshakeType` value for `ClientHello`.
pub const HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 0x01;
/// Required `legacy_session_id` length for an SLT TCP claim token.
pub const LEGACY_SESSION_ID_LEN: usize = 32;
/// Length of each half of the TCP claim token.
pub const TOKEN_PART_LEN: usize = LEGACY_SESSION_ID_LEN / 2;
/// Prefix length of `ClientHello.random` used by the early candidate tag.
pub const RANDOM_PREFIX_LEN: usize = 16;
/// Maximum TLS-framed TCP prefix through the end of an SLT `ClientHello1`.
///
/// A claim-bearing `ClientHello1` that does not finish within this many stream
/// bytes is ordinary traffic and is passed to the HTTPS upstream.
pub const MAX_TCP_CLIENT_HELLO_WIRE_LEN: usize = 8 * 1024;

const CANDIDATE_LABEL: &[u8] = b"slt-tcp-candidate-v2";
const CLAIM_LABEL: &[u8] = b"slt-tcp-claim-v2";
const CANDIDATE_INPUT_LEN: usize = CANDIDATE_LABEL.len() + RANDOM_PREFIX_LEN;
const ZERO_SESSION_ID: [u8; LEGACY_SESSION_ID_LEN] = [0; LEGACY_SESSION_ID_LEN];

/// Errors from `ClientHello` session ID generation and verification.
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
    /// The `ClientHello` is malformed or lacks the required session ID shape.
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

#[derive(Debug, Clone, Copy)]
struct ClientHelloLayout {
    random: [u8; 32],
    session_id_start: usize,
}

/// Derive the early candidate half of an SLT TCP claim token.
///
/// This tag lets the front door pass ordinary TLS traffic without waiting for
/// the complete `ClientHello`. A matching candidate is not sufficient to claim
/// the connection; [`verify_legacy_session_id`] verifies the complete-message
/// tag before TLS termination.
///
/// # Errors
///
/// Returns the underlying [`ErrorStack`] if HMAC computation fails.
pub fn candidate_session_id_tag(
    random: &[u8; 32],
    secret: &SharedSecret,
) -> Result<[u8; TOKEN_PART_LEN], ErrorStack> {
    let mut input = [0u8; CANDIDATE_INPUT_LEN];
    input[..CANDIDATE_LABEL.len()].copy_from_slice(CANDIDATE_LABEL);
    input[CANDIDATE_LABEL.len()..].copy_from_slice(&random[..RANDOM_PREFIX_LEN]);

    let mac = hmac_sha256(secret.as_bytes(), &input)?;
    let mut tag = [0u8; TOKEN_PART_LEN];
    tag.copy_from_slice(&mac[..TOKEN_PART_LEN]);
    Ok(tag)
}

/// Verify both halves of an SLT TCP claim token in a complete `ClientHello`.
///
/// The second token half authenticates every byte of the serialized handshake
/// message except the `legacy_session_id` bytes themselves. This keeps the
/// token stable while preventing an observer from modifying an otherwise
/// captured `ClientHello` and retaining a valid claim.
///
/// # Errors
///
/// Returns an error if `client_hello` is not exactly one well-framed
/// `ClientHello` handshake message or if HMAC computation fails.
pub fn verify_legacy_session_id(
    client_hello: &[u8],
    secret: &SharedSecret,
) -> Result<bool, ClientHelloError> {
    let layout = client_hello_layout(client_hello)?;
    let session_id =
        &client_hello[layout.session_id_start..layout.session_id_start + LEGACY_SESSION_ID_LEN];
    let candidate =
        candidate_session_id_tag(&layout.random, secret).map_err(ClientHelloError::HmacFailed)?;
    let claim = complete_claim_tag(client_hello, layout, secret)?;

    Ok(memcmp::eq(&session_id[..TOKEN_PART_LEN], &candidate)
        && memcmp::eq(&session_id[TOKEN_PART_LEN..], &claim))
}

/// Fill `legacy_session_id` with an SLT TCP claim token.
///
/// The first 16 bytes are an early candidate MAC over `random[0..16]`. The
/// remaining 16 bytes are a MAC over the complete serialized `ClientHello`
/// after replacing its 32 `legacy_session_id` bytes with zeroes.
///
/// # Errors
///
/// Returns an error if:
///
/// - `session_id` is not exactly [`LEGACY_SESSION_ID_LEN`] bytes
/// - `client_hello` is not exactly one well-framed `ClientHello` handshake
///   message with a 32-byte `legacy_session_id`
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

    let layout = client_hello_layout(client_hello)?;
    let candidate =
        candidate_session_id_tag(&layout.random, secret).map_err(ClientHelloError::HmacFailed)?;

    // TLS 1.3 requires ClientHello2 to retain ClientHello1's legacy session ID.
    // BoringSSL serializes the retained token before invoking this callback again.
    if memcmp::eq(&session_id[..TOKEN_PART_LEN], &candidate) {
        return Ok(());
    }

    let claim = complete_claim_tag(client_hello, layout, secret)?;

    session_id[..TOKEN_PART_LEN].copy_from_slice(&candidate);
    session_id[TOKEN_PART_LEN..].copy_from_slice(&claim);

    Ok(())
}

/// Helper to build a `BoringSSL` callback that overwrites `legacy_session_id`.
///
/// The callback seals the complete serialized `ClientHello` with a two-stage
/// token. Its first half allows a fast ordinary-traffic rejection; its second
/// half authenticates the full message before a connection can be claimed.
pub fn client_hello_session_id_callback(
    secret: SharedSecret,
) -> impl Fn(&mut SslRef, &[u8], &mut [u8]) -> Result<(), ErrorStack> + Sync + Send + 'static {
    move |_ssl, client_hello, session_id| {
        fill_legacy_session_id(client_hello, session_id, &secret).map_err(Into::into)
    }
}

fn client_hello_layout(client_hello: &[u8]) -> Result<ClientHelloLayout, ClientHelloError> {
    let Some(header) = client_hello.get(..4) else {
        return Err(ClientHelloError::MalformedClientHello(
            "missing handshake header",
        ));
    };

    if header[0] != HANDSHAKE_TYPE_CLIENT_HELLO {
        return Err(ClientHelloError::MalformedClientHello(
            "not a ClientHello handshake",
        ));
    }

    let body_len = ((header[1] as usize) << 16) | ((header[2] as usize) << 8) | header[3] as usize;
    let message_len =
        4usize
            .checked_add(body_len)
            .ok_or(ClientHelloError::MalformedClientHello(
                "handshake length overflows",
            ))?;
    if client_hello.len() != message_len {
        return Err(ClientHelloError::MalformedClientHello(
            "handshake length does not match buffer",
        ));
    }

    let random_start = 4 + 2;
    let random_end = random_start + 32;
    let Some(random_bytes) = client_hello.get(random_start..random_end) else {
        return Err(ClientHelloError::MalformedClientHello(
            "missing ClientHello random",
        ));
    };
    let Some(&session_id_len) = client_hello.get(random_end) else {
        return Err(ClientHelloError::MalformedClientHello(
            "missing legacy_session_id length",
        ));
    };
    if usize::from(session_id_len) != LEGACY_SESSION_ID_LEN {
        return Err(ClientHelloError::MalformedClientHello(
            "legacy_session_id is not 32 bytes",
        ));
    }

    let session_id_start = random_end + 1;
    let session_id_end = session_id_start + LEGACY_SESSION_ID_LEN;
    if client_hello.get(session_id_start..session_id_end).is_none() {
        return Err(ClientHelloError::MalformedClientHello(
            "truncated legacy_session_id",
        ));
    }

    let mut random = [0u8; 32];
    random.copy_from_slice(random_bytes);
    Ok(ClientHelloLayout {
        random,
        session_id_start,
    })
}

fn complete_claim_tag(
    client_hello: &[u8],
    layout: ClientHelloLayout,
    secret: &SharedSecret,
) -> Result<[u8; TOKEN_PART_LEN], ClientHelloError> {
    let session_id_end = layout.session_id_start + LEGACY_SESSION_ID_LEN;
    truncated_hmac(
        secret,
        CLAIM_LABEL,
        &[
            &client_hello[..layout.session_id_start],
            &ZERO_SESSION_ID,
            &client_hello[session_id_end..],
        ],
    )
    .map_err(ClientHelloError::HmacFailed)
}

fn truncated_hmac(
    secret: &SharedSecret,
    label: &[u8],
    parts: &[&[u8]],
) -> Result<[u8; TOKEN_PART_LEN], ErrorStack> {
    let input_len = label.len() + parts.iter().map(|part| part.len()).sum::<usize>();
    let mut input = Vec::with_capacity(input_len);
    input.extend_from_slice(label);
    for part in parts {
        input.extend_from_slice(part);
    }

    let mac = hmac_sha256(secret.as_bytes(), &input)?;
    let mut tag = [0u8; TOKEN_PART_LEN];
    tag.copy_from_slice(&mac[..TOKEN_PART_LEN]);
    Ok(tag)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};

    use boring::ssl::{
        SslAcceptor, SslConnector, SslFiletype, SslMethod, SslOptions, SslVerifyMode, SslVersion,
    };
    use boring::symm::{Cipher, encrypt};

    use super::*;
    use crate::test_support::generate_client_hello_handshake;

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

    #[test]
    fn generated_client_hello_verifies_full_claim_token() {
        let secret = SharedSecret([0x42; 32]);
        let handshake = generate_client_hello_handshake(secret);

        assert!(verify_legacy_session_id(&handshake, &secret).unwrap());
    }

    #[test]
    fn complete_claim_tag_normalizes_the_session_id() {
        let secret = SharedSecret([0x42; 32]);
        let mut handshake = generate_client_hello_handshake(secret);
        let layout = client_hello_layout(&handshake).unwrap();
        let original_tag = complete_claim_tag(&handshake, layout, &secret).unwrap();

        handshake[layout.session_id_start..layout.session_id_start + LEGACY_SESSION_ID_LEN]
            .fill(0xA5);

        assert_eq!(
            complete_claim_tag(&handshake, layout, &secret).unwrap(),
            original_tag
        );
    }

    #[test]
    fn complete_claim_tag_binds_bytes_after_the_session_id() {
        let secret = SharedSecret([0x42; 32]);
        let mut handshake = generate_client_hello_handshake(secret);
        let layout = client_hello_layout(&handshake).unwrap();

        let original_tag = complete_claim_tag(&handshake, layout, &secret).unwrap();
        let last = handshake.last_mut().unwrap();
        *last ^= 0x01;

        assert_ne!(
            complete_claim_tag(&handshake, layout, &secret).unwrap(),
            original_tag
        );
        assert!(!verify_legacy_session_id(&handshake, &secret).unwrap());
    }

    #[test]
    fn fill_preserves_existing_token_when_retry_changes_client_hello() {
        let secret = SharedSecret([0x42; 32]);
        let mut second_client_hello = generate_client_hello_handshake(secret);
        let layout = client_hello_layout(&second_client_hello).unwrap();
        let original_token: [u8; LEGACY_SESSION_ID_LEN] = second_client_hello
            [layout.session_id_start..layout.session_id_start + LEGACY_SESSION_ID_LEN]
            .try_into()
            .unwrap();

        *second_client_hello.last_mut().unwrap() ^= 0x01;
        assert!(!verify_legacy_session_id(&second_client_hello, &secret).unwrap());

        let mut retry_token = original_token;
        fill_legacy_session_id(&second_client_hello, &mut retry_token, &secret).unwrap();

        assert_eq!(retry_token, original_token);
    }

    #[tokio::test]
    async fn client_hello_token_survives_key_share_retry() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let cert = root.join("../vendor/boring/test/cert.pem");
        let key = root.join("../vendor/boring/test/key.pem");

        let mut acceptor = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
        acceptor.set_certificate_chain_file(cert).unwrap();
        acceptor
            .set_private_key_file(key, SslFiletype::PEM)
            .unwrap();
        acceptor.check_private_key().unwrap();
        acceptor
            .set_min_proto_version(Some(SslVersion::TLS1_3))
            .unwrap();
        acceptor
            .set_max_proto_version(Some(SslVersion::TLS1_3))
            .unwrap();
        acceptor.set_options(SslOptions::CIPHER_SERVER_PREFERENCE);
        acceptor.set_curves_list("P-256:X25519").unwrap();
        let acceptor = acceptor.build();

        let secret = SharedSecret([0x42; 32]);
        let observed_tokens = Arc::new(Mutex::new(Vec::<[u8; LEGACY_SESSION_ID_LEN]>::new()));
        let observed_tokens_for_callback = observed_tokens.clone();
        let fill_token = client_hello_session_id_callback(secret);
        let mut connector = SslConnector::builder(SslMethod::tls()).unwrap();
        connector.set_verify(SslVerifyMode::NONE);
        connector
            .set_min_proto_version(Some(SslVersion::TLS1_3))
            .unwrap();
        connector
            .set_max_proto_version(Some(SslVersion::TLS1_3))
            .unwrap();
        connector.set_curves_list("X25519:P-256").unwrap();
        connector.set_client_hello_session_id_callback(move |ssl, client_hello, session_id| {
            fill_token(ssl, client_hello, session_id)?;
            observed_tokens_for_callback
                .lock()
                .unwrap()
                .push(session_id.try_into().unwrap());
            Ok(())
        });
        let connector = connector.build();

        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let server = tokio_boring::accept(&acceptor, server_io);
        let client = tokio_boring::connect(connector.configure().unwrap(), "localhost", client_io);
        let (_server_tls, client_tls) = tokio::try_join!(server, client).unwrap();

        assert!(client_tls.ssl().used_hello_retry_request());
        let observed_tokens = observed_tokens.lock().unwrap();
        assert_eq!(observed_tokens.len(), 2);
        assert_eq!(observed_tokens[0], observed_tokens[1]);
    }

    #[test]
    fn verify_legacy_session_id_rejects_truncated_handshake() {
        let secret = SharedSecret([0x42; 32]);
        let mut handshake = generate_client_hello_handshake(secret);
        handshake.pop();

        let err = verify_legacy_session_id(&handshake, &secret).unwrap_err();
        assert!(matches!(err, ClientHelloError::MalformedClientHello(_)));
    }
}
