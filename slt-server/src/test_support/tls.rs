//! TLS test utilities.

use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};

use boring::ssl::{SslAcceptor, SslConnector, SslFiletype, SslMethod, SslVerifyMode};
use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};
use tokio::sync::Notify;

/// Returns paths to test certificate and key files.
#[must_use]
pub fn cert_paths() -> (PathBuf, PathBuf) {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    (
        root.join("../vendor/boring/test/cert.pem"),
        root.join("../vendor/boring/test/key.pem"),
    )
}

/// Creates a TLS acceptor for server-side testing.
///
/// # Panics
///
/// Panics if certificate or key files cannot be loaded.
#[must_use]
pub fn tls_acceptor() -> SslAcceptor {
    let (cert, key) = cert_paths();
    let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
    builder.set_certificate_chain_file(cert).unwrap();
    builder.set_private_key_file(key, SslFiletype::PEM).unwrap();
    builder.check_private_key().unwrap();
    builder.build()
}

/// Creates a TLS connector for client-side testing.
///
/// # Panics
///
/// Panics if the connector cannot be built.
#[must_use]
pub fn tls_connector() -> SslConnector {
    let mut builder = SslConnector::builder(SslMethod::tls()).unwrap();
    builder.set_verify(SslVerifyMode::NONE);
    builder.build()
}

/// Type alias for a TLS stream using duplex I/O.
pub type TlsDuplexStream = tokio_boring::SslStream<DuplexStream>;

/// Test gate that can park the server side of an established TLS stream.
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

/// In-memory stream whose writes can be parked after the TLS handshake.
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
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for ParkableWriteStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        if this.gate.parked.load(Ordering::Acquire) {
            this.gate.blocked_write_seen.store(true, Ordering::Release);
            this.gate.blocked_write_notify.notify_waiters();
            return Poll::Pending;
        }
        Pin::new(&mut this.inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// Creates a connected TLS pair for testing.
///
/// Returns (`server_tls`, `client_tls`) where:
/// - `server_tls` is the server-side of the connection
/// - `client_tls` is the client-side of the connection
///
/// # Panics
///
/// Panics if TLS handshake fails.
pub async fn tls_pair() -> (TlsDuplexStream, TlsDuplexStream) {
    let acceptor = tls_acceptor();
    let connector = tls_connector();
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let server = tokio_boring::accept(&acceptor, server_io);
    let client = tokio_boring::connect(connector.configure().unwrap(), "localhost", client_io);
    let (server_tls, client_tls) = tokio::try_join!(server, client).unwrap();
    (server_tls, client_tls)
}

/// Creates a TLS pair whose server-side writes can be parked after setup.
pub async fn tls_pair_with_parkable_server_writes() -> (
    tokio_boring::SslStream<ParkableWriteStream>,
    TlsDuplexStream,
    Arc<WriteGate>,
) {
    let acceptor = tls_acceptor();
    let connector = tls_connector();
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let gate = Arc::new(WriteGate::default());
    let server_io = ParkableWriteStream {
        inner: server_io,
        gate: gate.clone(),
    };
    let server = tokio_boring::accept(&acceptor, server_io);
    let client = tokio_boring::connect(connector.configure().unwrap(), "localhost", client_io);
    let (server_tls, client_tls) = tokio::join!(server, client);
    let server_tls = server_tls.unwrap();
    let client_tls = client_tls.unwrap();
    (server_tls, client_tls, gate)
}
