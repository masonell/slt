//! `ClientHello` test utilities.
//!
//! Provides helpers for generating TLS `ClientHello` bytes for testing.

use std::io::{self, Read, Write};

use boring::ssl::{HandshakeError, Ssl, SslContextBuilder, SslMethod, SslVerifyMode};

use crate::crypto::client_hello::client_hello_session_id_callback;
use crate::types::SharedSecret;

/// Capture stream that records written bytes for inspection.
#[derive(Default, Debug)]
pub struct CaptureStream {
    /// All bytes written to this stream.
    pub written: Vec<u8>,
}

impl Read for CaptureStream {
    fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
        Err(io::ErrorKind::WouldBlock.into())
    }
}

impl Write for CaptureStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.written.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// TLS record header size: `content_type(1)` + version(2) + length(2).
pub const TLS_RECORD_HEADER_LEN: usize = 5;

/// Generate a real TLS `ClientHello` using `BoringSSL` with the given secret.
///
/// Returns the full TLS record including the 5-byte record header.
/// Use [`client_hello_handshake_bytes`] to get just the handshake message.
#[must_use]
pub fn generate_client_hello_tls_record(secret: SharedSecret) -> Vec<u8> {
    let mut ctx = SslContextBuilder::new(SslMethod::tls()).unwrap();
    ctx.set_verify(SslVerifyMode::NONE);
    ctx.set_curves_list("X25519").unwrap();
    ctx.set_client_hello_session_id_callback(client_hello_session_id_callback(secret));

    let ctx = ctx.build();
    let mut ssl = Ssl::new(&ctx).unwrap();
    ssl.set_hostname("example.com").unwrap();

    let mid = ssl.setup_connect(CaptureStream::default());
    let mid = match mid.handshake() {
        Err(HandshakeError::WouldBlock(mid)) => mid,
        Err(err) => panic!("handshake failed: {err:?}"),
        Ok(_) => panic!("handshake unexpectedly completed"),
    };

    mid.into_source_stream().written
}

/// Generate a TLS `ClientHello` handshake message (without TLS record header).
///
/// This returns bytes suitable for passing directly to
/// [`parse_client_hello`](crate::crypto::client_hello::parse_client_hello).
#[must_use]
pub fn generate_client_hello_handshake(secret: SharedSecret) -> Vec<u8> {
    let record = generate_client_hello_tls_record(secret);
    record[TLS_RECORD_HEADER_LEN..].to_vec()
}
