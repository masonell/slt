//! TLS test utilities.

use std::path::PathBuf;

use boring::ssl::{SslAcceptor, SslConnector, SslFiletype, SslMethod, SslVerifyMode};
use tokio::io::DuplexStream;

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
