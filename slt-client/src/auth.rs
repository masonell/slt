use std::io;
use std::time::Instant;

use ed25519_dalek::{Signer, SigningKey};
use slt_core::config::ClientConfig;
use slt_core::proto::{
    AUTH_CHALLENGE_LEN, AuthFailPayload, AuthOkPayload, AuthPayload, Message, MessageLimits,
    PingPayload, PongPayload,
};
use slt_core::transport::tcp::{KeyUpdater, TcpChannel};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time;
use tracing::{debug, info, trace, warn};

use crate::metrics::Metrics;

const AUTH_MAX_FRAME: usize = 16 * 1024;

/// Perform TLS exporter auth and wait for [`AUTH_OK`](slt_core::proto::Message::AuthOk).
pub async fn authenticate(
    tcp: &mut crate::transport::tcp::TcpTransport,
    config: &ClientConfig,
    metrics: &Metrics,
) -> io::Result<()> {
    authenticate_with_channel_impl(tcp, config, metrics).await
}

/// Generic auth implementation that works with any `TcpChannel`.
async fn authenticate_with_channel_impl<S, K>(
    tcp: &mut TcpChannel<S, K>,
    config: &ClientConfig,
    metrics: &Metrics,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
    K: KeyUpdater,
{
    let challenge = export_challenge(tcp)?;
    let payload = build_auth_payload(config, challenge);
    send_auth(tcp, &payload).await?;

    let limits = MessageLimits::new(AUTH_MAX_FRAME, AUTH_MAX_FRAME);
    let deadline = Instant::now() + config.timing.auth_timeout;

    loop {
        let timeout = time::sleep_until(deadline.into());
        tokio::select! {
            () = timeout => {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "auth timed out"));
            }
            res = tcp.read_more() => {
                let n = res?;
                if n == 0 {
                    return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "auth connection closed"));
                }
                trace!(bytes_read = n, "received auth data");
            }
        }

        while let Some(msg_buf) = tcp
            .try_pop_message(limits)
            .map_err(crate::wire::map_message_error)?
        {
            match handle_auth_message(tcp, msg_buf.message()).await? {
                AuthResult::Continue => {}
                AuthResult::Accepted => {
                    metrics.inc_auth_successes();
                    return Ok(());
                }
                AuthResult::Rejected => {
                    metrics.inc_auth_failures();
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "auth failed",
                    ));
                }
                AuthResult::Disconnected => {
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionReset,
                        "server closed during auth",
                    ));
                }
            }
        }
    }
}

/// Test-only authentication function that works with any `TcpChannel`.
///
/// This is a variant of `authenticate` exposed for testing purposes,
/// allowing authentication to be tested with mock TCP channels.
///
/// # Arguments
///
/// * `tcp` - TCP channel for communication
/// * `config` - Client configuration containing identity and credentials
/// * `metrics` - Metrics collector for tracking auth results
///
/// # Errors
///
/// Returns an error if:
/// - TLS key export fails
/// - Connection times out during authentication
/// - Server rejects authentication
/// - Connection is closed unexpectedly
#[cfg(test)]
pub async fn authenticate_with_channel<S, K>(
    tcp: &mut TcpChannel<S, K>,
    config: &ClientConfig,
    metrics: &Metrics,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
    K: KeyUpdater,
{
    authenticate_with_channel_impl(tcp, config, metrics).await
}

fn export_challenge<S, K>(tcp: &TcpChannel<S, K>) -> io::Result<[u8; AUTH_CHALLENGE_LEN]>
where
    S: AsyncRead + AsyncWrite + Unpin,
    K: KeyUpdater,
{
    let mut challenge = [0u8; AUTH_CHALLENGE_LEN];
    tcp.ssl()
        .export_keying_material(&mut challenge, "slt-auth-challenge", None)
        .map_err(|err| io::Error::other(format!("tls key export failed: {err}")))?;
    Ok(challenge)
}

/// Build an authentication payload from client config and TLS challenge.
///
/// Creates an Ed25519 signature over the challenge combined with client identity
/// information (client ID, assigned IPv4, and protocol version string).
///
/// # Arguments
///
/// * `config` - Client configuration containing identity and private key
/// * `challenge` - 32-byte challenge from TLS key material export
///
/// # Returns
///
/// A signed `AuthPayload` containing the client's credentials and signature.
pub fn build_auth_payload(
    config: &ClientConfig,
    challenge: [u8; AUTH_CHALLENGE_LEN],
) -> AuthPayload {
    let mut context = Vec::with_capacity(11 + 16 + 4 + challenge.len());
    context.extend_from_slice(b"slt-auth-v1");
    context.extend_from_slice(config.identity.client_id.as_bytes());
    context.extend_from_slice(&config.identity.assigned_ipv4.octets());
    context.extend_from_slice(&challenge);

    let signing_key = SigningKey::from_bytes(config.identity.privkey_ed25519.as_bytes());
    let signature = signing_key.sign(&context).to_bytes();

    AuthPayload {
        client_id: config.identity.client_id,
        assigned_ipv4: config.identity.assigned_ipv4,
        challenge,
        signature,
    }
}

async fn send_auth<S, K>(tcp: &mut TcpChannel<S, K>, payload: &AuthPayload) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
    K: KeyUpdater,
{
    let mut payload_buf = Vec::with_capacity(slt_core::proto::AUTH_PAYLOAD_LEN);
    payload.encode(&mut payload_buf);
    tcp.write_message(Message::Auth {
        payload: &payload_buf,
    })
    .await
}

async fn handle_auth_message<S, K>(
    tcp: &mut TcpChannel<S, K>,
    message: Message<'_>,
) -> io::Result<AuthResult>
where
    S: AsyncRead + AsyncWrite + Unpin,
    K: KeyUpdater,
{
    match message {
        Message::AuthOk { payload } => {
            AuthOkPayload::decode(payload).map_err(crate::wire::map_payload_error)?;
            info!("authentication accepted");
            Ok(AuthResult::Accepted)
        }
        Message::AuthFail { payload } => {
            let fail = AuthFailPayload::decode(payload).map_err(crate::wire::map_payload_error)?;
            warn!(code = ?fail.code, "authentication rejected");
            Ok(AuthResult::Rejected)
        }
        Message::Ping { payload } => {
            let ping = PingPayload::decode(payload).map_err(crate::wire::map_payload_error)?;
            debug!(nonce = ping.nonce, "received ping during auth");
            let pong_payload = PongPayload { nonce: ping.nonce };
            let mut pong_buf = Vec::with_capacity(8);
            pong_payload.encode(&mut pong_buf);
            tcp.write_message(Message::Pong { payload: &pong_buf })
                .await?;
            Ok(AuthResult::Continue)
        }
        Message::Close { .. } => {
            warn!("received close during auth");
            Ok(AuthResult::Disconnected)
        }
        other => {
            warn!(message = ?other, "unexpected message during auth");
            Ok(AuthResult::Rejected)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuthResult {
    Continue,
    Accepted,
    Rejected,
    Disconnected,
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use ed25519_dalek::{Signature, Verifier};
    use slt_core::types::{ClientId, PrivKeyEd25519};

    use super::*;
    use crate::test_support::test_config_with_identity;

    fn verify_signature(
        payload: &AuthPayload,
        challenge: [u8; AUTH_CHALLENGE_LEN],
        verifying_key: &ed25519_dalek::VerifyingKey,
    ) -> Result<(), ed25519_dalek::SignatureError> {
        let mut context = Vec::with_capacity(11 + 16 + 4 + challenge.len());
        context.extend_from_slice(b"slt-auth-v1");
        context.extend_from_slice(payload.client_id.as_bytes());
        context.extend_from_slice(&payload.assigned_ipv4.octets());
        context.extend_from_slice(&challenge);
        let signature = Signature::from_bytes(&payload.signature);
        verifying_key.verify(&context, &signature)
    }

    #[test]
    fn auth_payload_roundtrip_and_signature_verifies() {
        let config = test_config_with_identity(
            ClientId([0x11; 16]),
            Ipv4Addr::new(10, 10, 0, 2),
            PrivKeyEd25519([0x33; 32]),
        );

        let challenge = [0x44; AUTH_CHALLENGE_LEN];
        let payload = build_auth_payload(&config, challenge);

        let mut buf = Vec::new();
        payload.encode(&mut buf);

        let decoded = AuthPayload::decode(&buf).unwrap();
        assert_eq!(decoded, payload);

        let signing_key = SigningKey::from_bytes(config.identity.privkey_ed25519.as_bytes());
        let verifying_key = signing_key.verifying_key();
        verify_signature(&payload, challenge, &verifying_key).unwrap();
    }

    #[test]
    fn auth_payload_various_client_ids() {
        let test_cases = [
            (ClientId([0x00; 16]), "all zeros"),
            (ClientId([0xFF; 16]), "all ones"),
            (
                ClientId([
                    0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76,
                    0x54, 0x32, 0x10,
                ]),
                "mixed",
            ),
        ];

        for (client_id, desc) in test_cases {
            let config = test_config_with_identity(
                client_id,
                Ipv4Addr::new(10, 10, 0, 2),
                PrivKeyEd25519([0x33; 32]),
            );
            let challenge = [0x44; AUTH_CHALLENGE_LEN];
            let payload = build_auth_payload(&config, challenge);

            assert_eq!(payload.client_id, client_id, "{desc}");

            let signing_key = SigningKey::from_bytes(config.identity.privkey_ed25519.as_bytes());
            verify_signature(&payload, challenge, &signing_key.verifying_key())
                .expect("{desc}: signature should verify");
        }
    }

    #[test]
    fn auth_payload_various_ipv4_addresses() {
        let test_cases = [
            (Ipv4Addr::UNSPECIFIED, "zero"),
            (Ipv4Addr::new(10, 0, 0, 1), "private 10.x"),
            (Ipv4Addr::new(192, 168, 1, 100), "private 192.168.x"),
            (Ipv4Addr::new(172, 16, 0, 1), "private 172.16.x"),
            (Ipv4Addr::BROADCAST, "broadcast"),
        ];

        for (ipv4, desc) in test_cases {
            let config =
                test_config_with_identity(ClientId([0x11; 16]), ipv4, PrivKeyEd25519([0x33; 32]));
            let challenge = [0x44; AUTH_CHALLENGE_LEN];
            let payload = build_auth_payload(&config, challenge);

            assert_eq!(payload.assigned_ipv4, ipv4, "{desc}");

            let signing_key = SigningKey::from_bytes(config.identity.privkey_ed25519.as_bytes());
            verify_signature(&payload, challenge, &signing_key.verifying_key())
                .expect("{desc}: signature should verify");
        }
    }

    #[test]
    fn auth_payload_various_challenges() {
        let test_cases = [
            ([0x00; AUTH_CHALLENGE_LEN], "all zeros"),
            ([0xFF; AUTH_CHALLENGE_LEN], "all ones"),
            ([0x01; AUTH_CHALLENGE_LEN], "repeated byte"),
        ];

        for (challenge, desc) in test_cases {
            let config = test_config_with_identity(
                ClientId([0x11; 16]),
                Ipv4Addr::new(10, 10, 0, 2),
                PrivKeyEd25519([0x33; 32]),
            );
            let payload = build_auth_payload(&config, challenge);

            assert_eq!(payload.challenge, challenge, "{desc}");

            let signing_key = SigningKey::from_bytes(config.identity.privkey_ed25519.as_bytes());
            verify_signature(&payload, challenge, &signing_key.verifying_key())
                .expect("{desc}: signature should verify");
        }
    }

    #[test]
    fn auth_payload_signature_fails_with_wrong_verifying_key() {
        let config = test_config_with_identity(
            ClientId([0x11; 16]),
            Ipv4Addr::new(10, 10, 0, 2),
            PrivKeyEd25519([0x33; 32]),
        );
        let challenge = [0x44; AUTH_CHALLENGE_LEN];
        let payload = build_auth_payload(&config, challenge);

        // Generate a different key pair
        let wrong_signing_key = SigningKey::from_bytes(&[0x99; 32]);
        let wrong_verifying_key = wrong_signing_key.verifying_key();

        // Signature should NOT verify with wrong key
        let result = verify_signature(&payload, challenge, &wrong_verifying_key);
        assert!(
            result.is_err(),
            "signature should not verify with wrong key"
        );
    }

    #[test]
    fn auth_payload_signature_fails_with_tampered_signature() {
        let config = test_config_with_identity(
            ClientId([0x11; 16]),
            Ipv4Addr::new(10, 10, 0, 2),
            PrivKeyEd25519([0x33; 32]),
        );
        let challenge = [0x44; AUTH_CHALLENGE_LEN];
        let mut payload = build_auth_payload(&config, challenge);

        // Tamper with the signature
        payload.signature[0] ^= 0xFF;

        let signing_key = SigningKey::from_bytes(config.identity.privkey_ed25519.as_bytes());
        let result = verify_signature(&payload, challenge, &signing_key.verifying_key());
        assert!(result.is_err(), "tampered signature should not verify");
    }

    #[test]
    fn auth_payload_signature_fails_with_tampered_challenge() {
        let config = test_config_with_identity(
            ClientId([0x11; 16]),
            Ipv4Addr::new(10, 10, 0, 2),
            PrivKeyEd25519([0x33; 32]),
        );
        let challenge = [0x44; AUTH_CHALLENGE_LEN];
        let payload = build_auth_payload(&config, challenge);

        // Verify with a different challenge
        let wrong_challenge = [0x55; AUTH_CHALLENGE_LEN];
        let signing_key = SigningKey::from_bytes(config.identity.privkey_ed25519.as_bytes());
        let result = verify_signature(&payload, wrong_challenge, &signing_key.verifying_key());
        assert!(
            result.is_err(),
            "signature should not verify with different challenge"
        );
    }

    #[test]
    fn auth_payload_signature_fails_with_tampered_client_id() {
        let config = test_config_with_identity(
            ClientId([0x11; 16]),
            Ipv4Addr::new(10, 10, 0, 2),
            PrivKeyEd25519([0x33; 32]),
        );
        let challenge = [0x44; AUTH_CHALLENGE_LEN];
        let mut payload = build_auth_payload(&config, challenge);

        // Tamper with client_id
        payload.client_id.0[0] ^= 0xFF;

        let signing_key = SigningKey::from_bytes(config.identity.privkey_ed25519.as_bytes());
        let result = verify_signature(&payload, challenge, &signing_key.verifying_key());
        assert!(
            result.is_err(),
            "signature should not verify with tampered client_id"
        );
    }

    #[test]
    fn auth_payload_signature_fails_with_tampered_ipv4() {
        let config = test_config_with_identity(
            ClientId([0x11; 16]),
            Ipv4Addr::new(10, 10, 0, 2),
            PrivKeyEd25519([0x33; 32]),
        );
        let challenge = [0x44; AUTH_CHALLENGE_LEN];
        let mut payload = build_auth_payload(&config, challenge);

        // Tamper with IPv4
        payload.assigned_ipv4 = Ipv4Addr::new(10, 10, 0, 3);

        let signing_key = SigningKey::from_bytes(config.identity.privkey_ed25519.as_bytes());
        let result = verify_signature(&payload, challenge, &signing_key.verifying_key());
        assert!(
            result.is_err(),
            "signature should not verify with tampered ipv4"
        );
    }

    #[test]
    fn auth_result_variants_are_debug_clone_copy() {
        // Test Debug trait
        assert_eq!(format!("{:?}", AuthResult::Continue), "Continue");
        assert_eq!(format!("{:?}", AuthResult::Accepted), "Accepted");
        assert_eq!(format!("{:?}", AuthResult::Rejected), "Rejected");
        assert_eq!(format!("{:?}", AuthResult::Disconnected), "Disconnected");

        // Test Clone trait
        let original = AuthResult::Accepted;
        let cloned = original;
        assert!(matches!(cloned, AuthResult::Accepted));

        // Test Copy trait
        let original = AuthResult::Rejected;
        let copied = original;
        assert!(matches!(original, AuthResult::Rejected)); // still valid due to Copy
        assert!(matches!(copied, AuthResult::Rejected));
    }

    #[test]
    fn auth_result_variant_equality() {
        assert_eq!(AuthResult::Continue, AuthResult::Continue);
        assert_eq!(AuthResult::Accepted, AuthResult::Accepted);
        assert_ne!(AuthResult::Continue, AuthResult::Accepted);
        assert_ne!(AuthResult::Rejected, AuthResult::Disconnected);
    }
}

/// Integration tests requiring a mock TLS server.
#[cfg(test)]
mod integration_tests {
    use std::sync::Arc;

    use slt_core::proto::AuthFailCode;
    use slt_core::transport::tcp::TcpChannel;
    use tokio::io::DuplexStream;

    use super::*;
    use crate::test_support::{MockTlsServer, test_config, tls_server_pair};

    /// Create a mock TCP transport pair for testing.
    /// Returns (`client_transport`, `server_stream`).
    async fn mock_transport_pair() -> (
        TcpChannel<DuplexStream, crate::transport::tcp::ClientKeyUpdater>,
        tokio_boring::SslStream<DuplexStream>,
    ) {
        let (client_stream, server_stream) = tls_server_pair().await;
        let metrics = Arc::new(crate::metrics::Metrics::default());
        let updater = crate::transport::tcp::ClientKeyUpdater::new(metrics);
        let client = TcpChannel::with_key_updater(client_stream, updater);
        (client, server_stream)
    }

    #[tokio::test]
    async fn full_auth_flow_success() {
        let config = test_config();
        let (mut client, server) = mock_transport_pair().await;
        let mut server = MockTlsServer::new(server);
        let metrics = Arc::new(crate::metrics::Metrics::default());

        // Run authenticate and server concurrently
        let client_fut = authenticate_with_channel(&mut client, &config, &metrics);
        let server_fut = server.recv_auth_and_send_ok(&config);

        let (client_result, server_result) = tokio::join!(client_fut, server_fut);
        server_result.expect("server should complete without error");
        client_result.expect("client auth should succeed");
    }

    #[tokio::test]
    async fn auth_failure_handling() {
        let config = test_config();
        let (mut client, server) = mock_transport_pair().await;
        let mut server = MockTlsServer::new(server);
        let metrics = Arc::new(crate::metrics::Metrics::default());

        // Run authenticate and server concurrently
        let client_fut = authenticate_with_channel(&mut client, &config, &metrics);
        let server_fut = server.recv_auth_and_send_fail(&config, AuthFailCode::BadSignature);

        let (client_result, server_result) = tokio::join!(client_fut, server_fut);
        server_result.expect("server should complete without error");

        let err = client_result.expect_err("client auth should fail");
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
    }

    #[tokio::test]
    async fn auth_timeout_handling() {
        let mut config = test_config();
        // Set a very short timeout
        config.timing.auth_timeout = std::time::Duration::from_millis(10);

        let (mut client, server) = mock_transport_pair().await;
        let _server = MockTlsServer::new(server); // Server doesn't respond
        let metrics = Arc::new(crate::metrics::Metrics::default());

        let result = authenticate_with_channel(&mut client, &config, &metrics).await;
        let err = result.expect_err("client auth should timeout");
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
    }

    #[tokio::test]
    async fn auth_handles_ping_during_auth() {
        let config = test_config();
        let (mut client, server) = mock_transport_pair().await;
        let mut server = MockTlsServer::new(server);
        let metrics = Arc::new(crate::metrics::Metrics::default());

        // Server will receive AUTH first (client sends it immediately), then send PING,
        // wait for PONG, and finally send AUTH_OK
        let server_fut = async {
            // Receive AUTH first
            server.recv_auth_verify(&config).await?;
            // Send PING (client should respond with PONG)
            server.send_ping(0xABCDEF00).await?;
            // Receive PONG (client's auth loop handles it)
            let nonce = server.recv_pong().await?;
            assert_eq!(nonce, 0xABCDEF00);
            // Now send AUTH_OK
            server
                .write_message(slt_core::proto::Message::AuthOk { payload: &[] })
                .await
        };

        let client_fut = authenticate_with_channel(&mut client, &config, &metrics);

        let (client_result, server_result) = tokio::join!(client_fut, server_fut);
        server_result.expect("server should complete without error");
        client_result.expect("client auth should succeed despite PING");
    }

    #[tokio::test]
    async fn auth_handles_close_during_auth() {
        let config = test_config();
        let (mut client, server) = mock_transport_pair().await;
        let mut server = MockTlsServer::new(server);
        let metrics = Arc::new(crate::metrics::Metrics::default());

        // Server sends CLOSE instead of AUTH_OK
        let server_fut = async {
            // Wait for AUTH message first
            server.recv_auth_verify(&config).await?;
            // Send CLOSE
            server.send_close(slt_core::proto::CloseCode::Normal).await
        };

        let client_fut = authenticate_with_channel(&mut client, &config, &metrics);

        let (client_result, server_result) = tokio::join!(client_fut, server_fut);
        server_result.expect("server should complete without error");

        let err = client_result.expect_err("client auth should fail on CLOSE");
        assert_eq!(err.kind(), std::io::ErrorKind::ConnectionReset);
    }
}
