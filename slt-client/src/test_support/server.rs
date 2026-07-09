//! Mock TLS server for integration tests.
//!
//! Provides a server that can complete TLS handshakes and respond to
//! AUTH, DISCOVERY, and `REGISTER_CID` messages. Uses the same test
//! certificates as `slt-core/src/transport/tcp.rs` tests.

use std::io;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};

use boring::ssl::{SslAcceptor, SslConnector, SslFiletype, SslMethod, SslVerifyMode};
use ed25519_dalek::{Signature, Verifier};
use slt_core::config::ClientConfig;
use slt_core::proto::{
    AUTH_CHALLENGE_LEN, AuthFailCode, AuthFailPayload, AuthPayload, Message, MessageLimits,
    PingPayload, PongPayload, RegisterOkPayload,
};
use slt_core::transport::tcp::TcpChannel;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};
use tokio::sync::Notify;
use tokio_boring::SslStream;

/// Boxed error used by the mock server's protocol helpers so that slt-core's
/// typed `FrameError`/`PayloadError` and the raw `io::Error` all flow via `?`
/// without being stringified. Test-only: callers in the integration tests
/// `.unwrap()` the result, so the dynamic dispatch cost is irrelevant.
pub type MockResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

use crate::metrics::Metrics;

/// Maximum frame size for mock server message parsing.
const MAX_FRAME: usize = 16 * 1024;

fn cert_paths() -> (PathBuf, PathBuf) {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    (
        root.join("../vendor/boring/test/cert.pem"),
        root.join("../vendor/boring/test/key.pem"),
    )
}

fn tls_acceptor() -> SslAcceptor {
    let (cert, key) = cert_paths();
    let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
    builder.set_certificate_chain_file(cert).unwrap();
    builder.set_private_key_file(key, SslFiletype::PEM).unwrap();
    builder.check_private_key().unwrap();
    builder.build()
}

fn tls_connector() -> SslConnector {
    let mut builder = SslConnector::builder(SslMethod::tls()).unwrap();
    builder.set_verify(SslVerifyMode::NONE);
    builder.build()
}

/// Create a connected TLS pair using in-memory duplex streams.
///
/// Returns `(client_stream, server_stream)` where both sides have completed
/// the TLS handshake and can export keying material.
pub async fn tls_server_pair() -> (SslStream<DuplexStream>, SslStream<DuplexStream>) {
    let acceptor = tls_acceptor();
    let connector = tls_connector();
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let server = tokio_boring::accept(&acceptor, server_io);
    let client = tokio_boring::connect(connector.configure().unwrap(), "localhost", client_io);
    tokio::try_join!(server, client).unwrap()
}

/// Gate that can park client writes after a TLS handshake completes.
#[derive(Debug, Default)]
pub struct WriteGate {
    parked: AtomicBool,
    blocked_write_seen: AtomicBool,
    blocked_write_notify: Notify,
}

impl WriteGate {
    /// Make subsequent writes remain pending.
    pub fn park(&self) {
        self.parked.store(true, Ordering::Release);
    }

    /// Allow subsequent writes to proceed.
    pub fn unpark(&self) {
        self.parked.store(false, Ordering::Release);
    }

    /// Wait until a write has observed the parked gate.
    pub async fn wait_until_write_blocked(&self) {
        loop {
            let notified = self.blocked_write_notify.notified();
            if self.blocked_write_seen.load(Ordering::Acquire) {
                return;
            }
            notified.await;
        }
    }
}

/// In-memory stream whose writes can be parked after TLS setup.
#[derive(Debug)]
pub struct ParkableWriteStream {
    inner: DuplexStream,
    gate: Arc<WriteGate>,
}

impl AsyncRead for ParkableWriteStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for ParkableWriteStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.gate.parked.load(Ordering::Acquire) {
            this.gate.blocked_write_seen.store(true, Ordering::Release);
            this.gate.blocked_write_notify.notify_waiters();
            return Poll::Pending;
        }
        Pin::new(&mut this.inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// Create a TLS pair whose client-side writes can be parked after setup.
pub async fn tls_pair_with_parkable_client_writes() -> (
    SslStream<ParkableWriteStream>,
    SslStream<DuplexStream>,
    Arc<WriteGate>,
) {
    let acceptor = tls_acceptor();
    let connector = tls_connector();
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let gate = Arc::new(WriteGate::default());
    let client_io = ParkableWriteStream {
        inner: client_io,
        gate: gate.clone(),
    };
    let server = tokio_boring::accept(&acceptor, server_io);
    let client = tokio_boring::connect(connector.configure().unwrap(), "localhost", client_io);
    let (server_tls, client_tls) = tokio::join!(server, client);
    (client_tls.unwrap(), server_tls.unwrap(), gate)
}

/// Create a TLS pair with a client `TcpChannel` ready for protocol use.
///
/// Returns `(client_channel, server_stream)` where the client channel
/// is wrapped with the standard `TcpChannel` interface.
pub async fn tls_client_channel_pair() -> (
    TcpChannel<DuplexStream, crate::transport::tcp::ClientKeyUpdater>,
    SslStream<DuplexStream>,
) {
    let (client_stream, server_stream) = tls_server_pair().await;
    let metrics = Arc::new(Metrics::default());
    let updater = crate::transport::tcp::ClientKeyUpdater::new(metrics);
    let client_channel = TcpChannel::with_key_updater(client_stream, updater);
    (client_channel, server_stream)
}

/// Create a connected TLS pair over real loopback `TcpStream`s.
///
/// Returns `(connector_side, acceptor_side)`, both with the handshake complete.
/// Unlike [`tls_server_pair`] (in-memory duplex streams), these wrap real
/// `TcpStream`s, so the connector side satisfies
/// `TcpTransport = TcpChannel<TcpStream, _>` for tests that build a
/// `ClientSession` directly.
pub async fn tls_tcp_stream_pair() -> (
    SslStream<tokio::net::TcpStream>,
    SslStream<tokio::net::TcpStream>,
) {
    use tokio::net::TcpListener;

    let acceptor = tls_acceptor();
    let connector = tls_connector();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = async {
        let (stream, _) = listener.accept().await.unwrap();
        tokio_boring::accept(&acceptor, stream).await.unwrap()
    };
    let client = async {
        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        tokio_boring::connect(connector.configure().unwrap(), "localhost", stream)
            .await
            .unwrap()
    };
    let (server_stream, client_stream) = tokio::join!(server, client);
    (client_stream, server_stream)
}

/// Mock TLS server for integration tests.
///
/// Wraps a server-side TLS stream and provides helpers for responding
/// to client protocol messages.
pub struct MockTlsServer {
    stream: SslStream<DuplexStream>,
    read_buf: Vec<u8>,
}

impl MockTlsServer {
    /// Create a new mock server from an existing TLS stream.
    #[must_use]
    pub const fn new(stream: SslStream<DuplexStream>) -> Self {
        Self {
            stream,
            read_buf: Vec::new(),
        }
    }

    /// Read more data from the TLS stream into the internal buffer.
    pub async fn read_more(&mut self) -> io::Result<usize> {
        self.stream.read_buf(&mut self.read_buf).await
    }

    /// Attempt to pop the next message from the internal read buffer.
    ///
    /// # Errors
    ///
    /// Returns a boxed error if the buffered bytes contain an invalid frame;
    /// the slt-core `FrameError` is preserved (not stringified).
    pub fn try_pop_message(&mut self) -> MockResult<Option<MockMessage>> {
        let limits = MessageLimits::new(MAX_FRAME, MAX_FRAME);
        let Some((frame, consumed)) =
            slt_core::proto::decode_frame(&self.read_buf, limits.max_frame_len)?
        else {
            return Ok(None);
        };

        let ty = frame.ty;
        let rest = self.read_buf.split_off(consumed);
        let buf = std::mem::replace(&mut self.read_buf, rest);
        Ok(Some(MockMessage { ty, buf }))
    }

    /// Write a protocol message to the client.
    ///
    /// # Errors
    ///
    /// Returns a boxed error if frame encoding or the underlying write fails;
    /// both the slt-core `FrameError` and the `io::Error` are preserved (not
    /// stringified).
    pub async fn write_message(&mut self, message: Message<'_>) -> MockResult<()> {
        let mut frame = Vec::new();
        slt_core::proto::encode_message(message, &mut frame)?;
        self.stream.write_all(&frame).await?;
        Ok(())
    }

    /// Export keying material for auth challenge verification.
    pub fn export_keying_material(&mut self) -> io::Result<[u8; AUTH_CHALLENGE_LEN]> {
        slt_core::crypto::export_auth_challenge(self.stream.ssl())
            .map_err(|err| io::Error::other(format!("tls key export failed: {err}")))
    }

    /// Read until a message is available and return it.
    async fn recv_message(&mut self) -> MockResult<MockMessage> {
        loop {
            if let Some(msg) = self.try_pop_message()? {
                return Ok(msg);
            }
            let n = self.read_more().await?;
            if n == 0 {
                return Err(
                    io::Error::new(io::ErrorKind::UnexpectedEof, "connection closed").into(),
                );
            }
        }
    }

    /// Receive an AUTH message and verify the signature.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The next message is not AUTH
    /// - Signature verification fails
    pub async fn recv_auth_verify(&mut self, config: &ClientConfig) -> MockResult<AuthPayload> {
        let msg = self.recv_message().await?;

        if msg.ty != slt_core::proto::MessageType::Auth {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("expected AUTH, got {:?}", msg.ty),
            )
            .into());
        }

        // Find the payload start (skip type + length header)
        let payload = &msg.buf[5..];
        let payload = AuthPayload::decode(payload)?;

        // Verify signature
        let challenge = self.export_keying_material()?;
        verify_auth_signature(&payload, challenge, config)?;

        Ok(payload)
    }

    /// Receive an AUTH message and send `AUTH_OK`.
    ///
    /// # Errors
    ///
    /// Returns an error if signature verification fails or I/O fails.
    pub async fn recv_auth_and_send_ok(&mut self, config: &ClientConfig) -> MockResult<()> {
        self.recv_auth_verify(config).await?;
        self.write_message(Message::AuthOk {
            payload: &[], // AuthOkPayload is empty
        })
        .await
    }

    /// Receive an AUTH message and send `AUTH_FAIL`.
    ///
    /// # Errors
    ///
    /// Returns an error if I/O fails.
    #[allow(dead_code)]
    pub async fn recv_auth_and_send_fail(
        &mut self,
        config: &ClientConfig,
        code: AuthFailCode,
    ) -> MockResult<()> {
        // Still verify to consume the message, but ignore the result
        let _ = self.recv_auth_verify(config).await;
        let fail = AuthFailPayload { code };
        let mut buf = Vec::new();
        fail.encode(&mut buf);
        self.write_message(Message::AuthFail { payload: &buf })
            .await
    }

    /// Send a PING message with the given nonce.
    pub async fn send_ping(&mut self, nonce: u64) -> MockResult<()> {
        let payload = PingPayload { nonce };
        let mut buf = Vec::with_capacity(8);
        payload.encode(&mut buf);
        self.write_message(Message::Ping { payload: &buf }).await
    }

    /// Receive a PONG message and return the nonce.
    #[allow(dead_code)]
    pub async fn recv_pong(&mut self) -> MockResult<u64> {
        let msg = self.recv_message().await?;

        if msg.ty != slt_core::proto::MessageType::Pong {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("expected PONG, got {:?}", msg.ty),
            )
            .into());
        }

        let payload = &msg.buf[5..];
        let pong = PongPayload::decode(payload)?;
        Ok(pong.nonce)
    }

    /// Receive a `REGISTER_CID` message and send `REGISTER_OK`.
    ///
    /// Returns the DCID from the registration.
    #[allow(dead_code)]
    pub async fn recv_register_and_send_ok(&mut self) -> MockResult<slt_core::types::Cid> {
        let msg = self.recv_message().await?;

        if msg.ty != slt_core::proto::MessageType::RegisterCid {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("expected REGISTER_CID, got {:?}", msg.ty),
            )
            .into());
        }

        let payload = &msg.buf[5..];
        let register = slt_core::proto::RegisterCidPayload::decode(payload)?;

        let dcid = register.client_to_server_cid;
        let ok_payload = RegisterOkPayload {
            client_to_server_cid: dcid,
        };
        let mut ok_buf = Vec::new();
        ok_payload.encode(&mut ok_buf).unwrap();
        self.write_message(Message::RegisterOk { payload: &ok_buf })
            .await?;

        Ok(dcid)
    }

    /// Send a CLOSE message with the given code.
    #[allow(dead_code)]
    pub async fn send_close(&mut self, code: slt_core::proto::CloseCode) -> MockResult<()> {
        let payload = slt_core::proto::ClosePayload { code };
        let mut buf = Vec::new();
        payload.encode(&mut buf);
        self.write_message(Message::Close { payload: &buf }).await
    }
}

/// A received message buffer for the mock server.
pub struct MockMessage {
    /// Message type.
    pub ty: slt_core::proto::MessageType,
    /// Raw message buffer (includes frame header).
    pub buf: Vec<u8>,
}

impl MockMessage {
    /// Returns a decoded `Message` view into the frame buffer.
    #[must_use]
    pub fn message(&self) -> slt_core::proto::Message<'_> {
        const HEADER_LEN: usize = 5;
        debug_assert!(self.buf.len() >= HEADER_LEN);
        let payload = &self.buf[HEADER_LEN..];
        slt_core::proto::Message::from(slt_core::proto::Frame {
            ty: self.ty,
            payload,
        })
    }
}

/// Verify an auth signature against the client config's public key.
fn verify_auth_signature(
    payload: &AuthPayload,
    challenge: [u8; AUTH_CHALLENGE_LEN],
    config: &ClientConfig,
) -> io::Result<()> {
    use ed25519_dalek::SigningKey;

    // Build verification context
    let context = slt_core::proto::auth_signature_context(
        &payload.client_id,
        payload.assigned_ipv4,
        &challenge,
    );

    // Derive verifying key from the config's private key
    let signing_key = SigningKey::from_bytes(config.identity.privkey_ed25519.as_bytes());
    let verifying_key = signing_key.verifying_key();

    let signature = Signature::from_bytes(&payload.signature);
    verifying_key.verify(&context, &signature).map_err(|_| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "signature verification failed",
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::test_config;

    #[tokio::test]
    async fn tls_server_pair_completes_handshake() {
        let (client, server) = tls_server_pair().await;
        // Both sides should be able to export keying material (handshake completed)
        let client_challenge = slt_core::crypto::export_auth_challenge(client.ssl()).unwrap();
        let server_challenge = slt_core::crypto::export_auth_challenge(server.ssl()).unwrap();
        // Both sides should derive the same challenge from the TLS session
        assert_eq!(client_challenge, server_challenge);
    }

    #[tokio::test]
    async fn tls_server_can_export_keying_material() {
        let (_client, server) = tls_server_pair().await;
        let mut server = MockTlsServer::new(server);
        let challenge = server.export_keying_material().unwrap();
        assert_eq!(challenge.len(), AUTH_CHALLENGE_LEN);
    }

    #[tokio::test]
    async fn mock_server_receives_auth_and_sends_ok() {
        let config = test_config();
        let (mut client, server) = tls_client_channel_pair().await;
        let mut server = MockTlsServer::new(server);

        // Client sends AUTH
        let challenge = slt_core::crypto::export_auth_challenge(client.ssl()).unwrap();

        let auth_payload = crate::auth::build_auth_payload(&config, challenge);
        let mut payload_buf = Vec::new();
        auth_payload.encode(&mut payload_buf);
        client
            .write_message(Message::Auth {
                payload: &payload_buf,
            })
            .await
            .unwrap();

        // Server receives and responds
        server.recv_auth_and_send_ok(&config).await.unwrap();

        // Client receives AUTH_OK
        client.read_more().await.unwrap();
        let msg = client
            .try_pop_message(MessageLimits::new(MAX_FRAME, MAX_FRAME))
            .unwrap()
            .unwrap();

        // Check that the message is AuthOk
        assert!(matches!(msg.message(), Message::AuthOk { .. }));
    }

    #[tokio::test]
    async fn mock_server_ping_pong() {
        let (client, server2) = tls_server_pair().await;
        let mut client = TcpChannel::new(client);
        let mut server2 = MockTlsServer::new(server2);

        server2.send_ping(0x1234_5678).await.unwrap();
        client.read_more().await.unwrap();
        let msg = client
            .try_pop_message(MessageLimits::new(MAX_FRAME, MAX_FRAME))
            .unwrap()
            .unwrap();

        // Check that the message is Ping
        match msg.message() {
            Message::Ping { payload } => {
                let ping = PingPayload::decode(payload).unwrap();
                assert_eq!(ping.nonce, 0x1234_5678);
            }
            _ => panic!("expected PING"),
        }
    }
}
