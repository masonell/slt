use std::time::{Duration, Instant};

use slt_core::config::ClientConfig;
use slt_core::proto::{
    AUTH_CHALLENGE_LEN, AuthFailPayload, AuthOkPayload, AuthPayload, CloseCode, ClosePayload,
    Message, MessageContext, MessageLimits, MessageSender, MessageTransport, PingPayload,
    PongPayload, ProtocolPhase, validate_message,
};
use slt_core::transport::tcp::{KeyUpdater, TcpChannel, TcpWriteError};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time;
use tracing::{debug, info, trace, warn};

use crate::error::ConnectError;
use crate::metrics::Metrics;
use crate::transport::tcp::write_message_with_timeout;

const AUTH_MAX_FRAME: usize = 16 * 1024;

/// Perform TLS exporter auth and wait for [`AUTH_OK`](slt_core::proto::Message::AuthOk).
///
/// # Errors
///
/// Returns a [`ConnectError`] describing the auth failure:
/// - [`ConnectError::AuthRejected`] carries the server's [`slt_core::proto::AuthFailCode`],
///   the client id, and the assigned IPv4.
/// - [`ConnectError::AuthTimeout`] if `AUTH_OK`/`AUTH_FAIL` does not arrive in time.
/// - [`ConnectError::AuthDisconnected`] if the server closes the connection.
/// - [`ConnectError::AuthProtocolError`] if the server reports a protocol violation.
/// - [`ConnectError::AuthTlsExport`] if the TLS keying-material export fails.
/// - Protocol decode errors surface as their typed variant.
pub async fn authenticate(
    tcp: &mut crate::transport::tcp::TcpTransport,
    config: &ClientConfig,
    metrics: &Metrics,
) -> Result<(), ConnectError> {
    authenticate_with_channel_impl(tcp, config, metrics).await
}

/// Generic auth implementation that works with any `TcpChannel`.
async fn authenticate_with_channel_impl<S, K>(
    tcp: &mut TcpChannel<S, K>,
    config: &ClientConfig,
    metrics: &Metrics,
) -> Result<(), ConnectError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    K: KeyUpdater,
{
    let deadline = Instant::now() + config.timing.auth_timeout;
    time::timeout_at(
        deadline.into(),
        run_auth_flow(tcp, config, metrics, config.timing.tcp_write_timeout),
    )
    .await
    .unwrap_or(Err(ConnectError::AuthTimeout))
}

async fn run_auth_flow<S, K>(
    tcp: &mut TcpChannel<S, K>,
    config: &ClientConfig,
    metrics: &Metrics,
    tcp_write_timeout: Duration,
) -> Result<(), ConnectError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    K: KeyUpdater,
{
    let challenge = export_challenge(tcp)?;
    let payload = build_auth_payload(config, challenge);
    send_auth(tcp, &payload, tcp_write_timeout).await?;

    let limits = MessageLimits::new(AUTH_MAX_FRAME, AUTH_MAX_FRAME);

    loop {
        // A 0-byte read is EOF (server closed). A genuine I/O error stays
        // typed so its kind survives for retry policy.
        match tcp.read_more().await {
            Ok(0) => return Err(ConnectError::AuthDisconnected),
            Ok(n) => trace!(bytes_read = n, "received auth data"),
            Err(err) => return Err(ConnectError::Io(err)),
        }

        while let Some(msg_buf) = tcp.try_pop_message(limits)? {
            match handle_auth_message(tcp, msg_buf.message(), config, tcp_write_timeout).await {
                Ok(AuthResult::Continue) => {}
                Ok(AuthResult::Accepted) => {
                    metrics.inc_auth_successes();
                    return Ok(());
                }
                Ok(AuthResult::Disconnected) => {
                    return Err(ConnectError::AuthDisconnected);
                }
                // The rejection path: handle_auth_message decoded the
                // AuthFailCode and returned it as Err. Bump the metric here
                // (the channel does not own the Metrics handle) and propagate.
                Err(err @ ConnectError::AuthRejected { .. }) => {
                    metrics.inc_auth_failures();
                    return Err(err);
                }
                Err(other) => return Err(other),
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
/// Returns a [`ConnectError`] if:
/// - TLS key export fails ([`ConnectError::AuthTlsExport`])
/// - Connection times out during authentication ([`ConnectError::AuthTimeout`])
/// - Server rejects authentication ([`ConnectError::AuthRejected`], code preserved)
/// - Connection is closed unexpectedly ([`ConnectError::AuthDisconnected`])
#[cfg(test)]
pub async fn authenticate_with_channel<S, K>(
    tcp: &mut TcpChannel<S, K>,
    config: &ClientConfig,
    metrics: &Metrics,
) -> Result<(), ConnectError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    K: KeyUpdater,
{
    authenticate_with_channel_impl(tcp, config, metrics).await
}

fn export_challenge<S, K>(tcp: &TcpChannel<S, K>) -> Result<[u8; AUTH_CHALLENGE_LEN], ConnectError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    K: KeyUpdater,
{
    // `?` preserves the boring `ErrorStack` via `#[from]` on `AuthTlsExport`,
    // rather than stringifying it into an `io::Error`.
    Ok(slt_core::crypto::export_auth_challenge(tcp.ssl())?)
}

/// Build an authentication payload from client config and TLS challenge.
///
/// Delegates to [`slt_core::proto::build_auth_payload`], which owns the canonical
/// signature context shared with the server's verifier.
pub fn build_auth_payload(
    config: &ClientConfig,
    challenge: [u8; AUTH_CHALLENGE_LEN],
) -> AuthPayload {
    slt_core::proto::build_auth_payload(config, challenge)
}

async fn send_auth<S, K>(
    tcp: &mut TcpChannel<S, K>,
    payload: &AuthPayload,
    tcp_write_timeout: Duration,
) -> Result<(), ConnectError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    K: KeyUpdater,
{
    let mut payload_buf = Vec::with_capacity(slt_core::proto::AUTH_PAYLOAD_LEN);
    payload.encode(&mut payload_buf);
    write_message_with_timeout(
        tcp,
        Message::Auth {
            payload: &payload_buf,
        },
        tcp_write_timeout,
    )
    .await
    .map_err(map_auth_write_error)?;
    Ok(())
}

async fn handle_auth_message<S, K>(
    tcp: &mut TcpChannel<S, K>,
    message: Message<'_>,
    config: &ClientConfig,
    tcp_write_timeout: Duration,
) -> Result<AuthResult, ConnectError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    K: KeyUpdater,
{
    validate_message(
        message,
        MessageContext::new(
            MessageSender::Server,
            ProtocolPhase::Authentication,
            MessageTransport::Tcp,
        ),
    )?;

    match message {
        Message::AuthOk { payload } => {
            AuthOkPayload::decode(payload)?;
            info!("authentication accepted");
            Ok(AuthResult::Accepted)
        }
        Message::AuthFail { payload } => {
            // The auth-failure metric is bumped by the outer
            // `authenticate_with_channel_impl` loop when it observes the
            // rejection (it owns the `Metrics` handle; the channel does not).
            let fail = AuthFailPayload::decode(payload)?;
            warn!(code = ?fail.code, "authentication rejected");
            Err(ConnectError::AuthRejected {
                code: fail.code,
                client_id: config.identity.client_id,
                assigned_ipv4: config.identity.assigned_ipv4,
            })
        }
        Message::Ping { payload } => {
            let ping = PingPayload::decode(payload)?;
            debug!(nonce = ping.nonce, "received ping during auth");
            let pong_payload = PongPayload { nonce: ping.nonce };
            let mut pong_buf = Vec::with_capacity(8);
            pong_payload.encode(&mut pong_buf);
            write_message_with_timeout(
                tcp,
                Message::Pong { payload: &pong_buf },
                tcp_write_timeout,
            )
            .await
            .map_err(map_auth_write_error)?;
            Ok(AuthResult::Continue)
        }
        Message::Pong { payload } => {
            let pong = PongPayload::decode(payload)?;
            debug!(nonce = pong.nonce, "received pong during auth");
            Ok(AuthResult::Continue)
        }
        Message::Close { payload } => {
            let close = ClosePayload::decode(payload)?;
            warn!(code = ?close.code, "received close during auth");
            if close.code == CloseCode::ProtocolError {
                Err(ConnectError::AuthProtocolError)
            } else {
                Ok(AuthResult::Disconnected)
            }
        }
        Message::Auth { .. }
        | Message::RegisterCid { .. }
        | Message::RegisterOk { .. }
        | Message::RegisterFail { .. }
        | Message::Data { .. }
        | Message::UpgradeProbe { .. }
        | Message::UpgradeProbeAck { .. }
        | Message::UdpReady { .. }
        | Message::SwitchToUdp { .. }
        | Message::SwitchAck { .. }
        | Message::FallbackToTcp { .. }
        | Message::FallbackOk { .. }
        | Message::SwitchOk { .. } => {
            unreachable!("shared validation rejected inadmissible auth message")
        }
    }
}

fn map_auth_write_error(err: TcpWriteError) -> ConnectError {
    match err {
        TcpWriteError::Io(source) if source.kind() == std::io::ErrorKind::TimedOut => {
            ConnectError::AuthTimeout
        }
        other => other.into(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuthResult {
    Continue,
    Accepted,
    Disconnected,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_result_variants_are_debug_clone_copy() {
        // Test Debug trait
        assert_eq!(format!("{:?}", AuthResult::Continue), "Continue");
        assert_eq!(format!("{:?}", AuthResult::Accepted), "Accepted");
        assert_eq!(format!("{:?}", AuthResult::Disconnected), "Disconnected");

        // Test Clone trait
        let original = AuthResult::Accepted;
        let cloned = original;
        assert!(matches!(cloned, AuthResult::Accepted));

        // Test Copy trait
        let original = AuthResult::Disconnected;
        let copied = original;
        assert!(matches!(original, AuthResult::Disconnected)); // still valid due to Copy
        assert!(matches!(copied, AuthResult::Disconnected));
    }

    #[test]
    fn auth_result_variant_equality() {
        assert_eq!(AuthResult::Continue, AuthResult::Continue);
        assert_eq!(AuthResult::Accepted, AuthResult::Accepted);
        assert_ne!(AuthResult::Continue, AuthResult::Accepted);
        assert_ne!(AuthResult::Accepted, AuthResult::Disconnected);
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
    use crate::test_support::{
        MockTlsServer, test_config, tls_pair_with_parkable_client_writes, tls_server_pair,
    };

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
        // The server's AuthFailCode must survive to the caller — a kind-based
        // assertion would pass even if the code were dropped.
        assert!(
            matches!(
                err,
                crate::error::ConnectError::AuthRejected {
                    code: AuthFailCode::BadSignature,
                    ..
                }
            ),
            "expected AuthRejected {{ code: BadSignature, .. }}, got {err:?}"
        );
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
        assert!(
            matches!(err, crate::error::ConnectError::AuthTimeout),
            "expected AuthTimeout, got {err:?}"
        );
    }

    #[tokio::test]
    async fn auth_write_observes_tcp_write_timeout() {
        let mut config = test_config();
        config.timing.auth_timeout = Duration::from_secs(1);
        config.timing.tcp_write_timeout = Duration::from_millis(40);
        let (client_stream, _server_stream, write_gate) =
            tls_pair_with_parkable_client_writes().await;
        let metrics = Arc::new(crate::metrics::Metrics::default());
        let updater = crate::transport::tcp::ClientKeyUpdater::new(metrics.clone());
        let mut client = TcpChannel::with_key_updater(client_stream, updater);
        write_gate.park();

        let err = time::timeout(
            Duration::from_secs(1),
            authenticate_with_channel(&mut client, &config, &metrics),
        )
        .await
        .expect("auth write deadline must fire")
        .expect_err("parked AUTH write must fail");

        assert!(err.is_retriable());
        assert!(matches!(err, ConnectError::AuthTimeout));
        time::timeout(
            Duration::from_secs(1),
            write_gate.wait_until_write_blocked(),
        )
        .await
        .expect("AUTH write reached the parked transport");
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
        assert!(
            matches!(err, crate::error::ConnectError::AuthDisconnected),
            "expected AuthDisconnected, got {err:?}"
        );
    }

    #[tokio::test]
    async fn auth_classifies_protocol_error_close_as_fatal() {
        let config = test_config();
        let (mut client, server) = mock_transport_pair().await;
        let mut server = MockTlsServer::new(server);
        let metrics = Arc::new(crate::metrics::Metrics::default());

        let server_fut = async {
            server.recv_auth_verify(&config).await?;
            server.send_close(CloseCode::ProtocolError).await
        };
        let client_fut = authenticate_with_channel(&mut client, &config, &metrics);

        let (client_result, server_result) = tokio::join!(client_fut, server_fut);
        server_result.expect("server should complete without error");

        let err = client_result.expect_err("client auth should fail on protocol error close");
        assert!(
            matches!(err, ConnectError::AuthProtocolError),
            "expected AuthProtocolError, got {err:?}"
        );
        assert!(!err.is_retriable());
    }

    /// An unsolicited non-auth message during the auth exchange must be
    /// classified as a client-detected protocol violation
    /// (`AuthUnexpectedMessage`), not a synthesized `AuthRejected` — so
    /// `AuthRejected` stays reserved for codes the server actually sent inside
    /// a decoded `AUTH_FAIL`.
    #[tokio::test]
    async fn auth_unexpected_message_during_auth() {
        let config = test_config();
        let (mut client, server) = mock_transport_pair().await;
        let mut server = MockTlsServer::new(server);
        let metrics = Arc::new(crate::metrics::Metrics::default());

        // AUTH is a valid fixed-layout message type, but only clients may send
        // it. Direction validation must run before payload decoding.
        let server_fut = async {
            server.recv_auth_verify(&config).await?;
            server
                .write_message(slt_core::proto::Message::Auth { payload: &[] })
                .await
        };

        let client_fut = authenticate_with_channel(&mut client, &config, &metrics);

        let (client_result, server_result) = tokio::join!(client_fut, server_fut);
        server_result.expect("server should complete without error");

        let err = client_result.expect_err("client auth should fail on unexpected message");
        assert!(
            matches!(err, crate::error::ConnectError::AuthUnexpectedMessage),
            "expected AuthUnexpectedMessage, got {err:?}"
        );
    }
}
