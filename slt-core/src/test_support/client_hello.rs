//! `ClientHello` test utilities.
//!
//! Provides helpers for generating TLS `ClientHello` bytes for testing.

use std::io::{self, Read, Write};

use boring::ssl::{
    HandshakeError, Ssl, SslContextBuilder, SslMethod, SslSessionCacheMode, SslVerifyMode,
};

use crate::crypto::client_hello::{
    HANDSHAKE_TYPE_CLIENT_HELLO, LEGACY_SESSION_ID_LEN, client_hello_session_id_callback,
    fill_legacy_session_id,
};
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
    ctx.set_session_cache_mode(SslSessionCacheMode::OFF);
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

/// Generate a valid single-record `ClientHello` with an exact TLS-framed length.
///
/// The hello is extended with an ignored private-use extension and its claim
/// token is recomputed over the resulting handshake message.
///
/// # Panics
///
/// Panics if `wire_len` cannot contain the generated hello plus an extension
/// header, or if the requested record exceeds TLS's `u16` record-length field.
#[must_use]
pub fn generate_sized_client_hello_tls_record(secret: SharedSecret, wire_len: usize) -> Vec<u8> {
    const PRIVATE_EXTENSION_TYPE: u16 = 0xffa5;
    const EXTENSION_HEADER_LEN: usize = 4;

    let mut record = generate_client_hello_tls_record(secret);
    let original_record_len = usize::from(u16::from_be_bytes([record[3], record[4]]));
    assert_eq!(record.len(), TLS_RECORD_HEADER_LEN + original_record_len);
    assert!(wire_len >= record.len() + EXTENSION_HEADER_LEN);

    let extension_value_len = wire_len - record.len() - EXTENSION_HEADER_LEN;
    let extension_value_len = u16::try_from(extension_value_len).unwrap();
    let (session_id_start, extensions_len_start) = client_hello_offsets(&record);
    let extensions_len = usize::from(u16::from_be_bytes([
        record[extensions_len_start],
        record[extensions_len_start + 1],
    ]));
    let extended_extensions_len =
        extensions_len + EXTENSION_HEADER_LEN + extension_value_len as usize;

    record.extend_from_slice(&PRIVATE_EXTENSION_TYPE.to_be_bytes());
    record.extend_from_slice(&extension_value_len.to_be_bytes());
    record.resize(wire_len, 0);

    let record_payload_len = u16::try_from(wire_len - TLS_RECORD_HEADER_LEN).unwrap();
    record[3..5].copy_from_slice(&record_payload_len.to_be_bytes());
    let handshake_body_len = u32::from(record_payload_len) - 4;
    record[6..9].copy_from_slice(&handshake_body_len.to_be_bytes()[1..]);
    record[extensions_len_start..extensions_len_start + 2].copy_from_slice(
        &u16::try_from(extended_extensions_len)
            .unwrap()
            .to_be_bytes(),
    );

    let session_id_end = session_id_start + LEGACY_SESSION_ID_LEN;
    record[session_id_start..session_id_end].fill(0);
    let mut session_id = [0u8; LEGACY_SESSION_ID_LEN];
    fill_legacy_session_id(&record[TLS_RECORD_HEADER_LEN..], &mut session_id, &secret).unwrap();
    record[session_id_start..session_id_end].copy_from_slice(&session_id);
    record
}

/// Reframe a single-record `ClientHello` across `record_count` TLS records.
///
/// # Panics
///
/// Panics unless `record` contains exactly one TLS record or `record_count`
/// cannot give every output record at least one handshake byte.
#[must_use]
pub fn fragment_client_hello_tls_record(record: &[u8], record_count: usize) -> Vec<u8> {
    assert_eq!(record[0], 0x16);
    let payload_len = usize::from(u16::from_be_bytes([record[3], record[4]]));
    assert_eq!(record.len(), TLS_RECORD_HEADER_LEN + payload_len);
    assert!((1..=payload_len).contains(&record_count));

    let payload = &record[TLS_RECORD_HEADER_LEN..];
    let mut fragmented =
        Vec::with_capacity(record.len() + TLS_RECORD_HEADER_LEN * (record_count - 1));
    let mut payload_start = 0usize;
    for records_remaining in (1..=record_count).rev() {
        let payload_remaining = payload.len() - payload_start;
        let chunk_len = payload_remaining / records_remaining;
        let payload_end = payload_start + chunk_len;
        append_tls_record(&mut fragmented, &payload[payload_start..payload_end]);
        payload_start = payload_end;
    }
    assert_eq!(payload_start, payload.len());
    fragmented
}

/// Generate a TLS `ClientHello` handshake message (without TLS record header).
///
/// This returns bytes suitable for passing directly to
/// [`verify_legacy_session_id`](crate::crypto::client_hello::verify_legacy_session_id).
#[must_use]
pub fn generate_client_hello_handshake(secret: SharedSecret) -> Vec<u8> {
    let record = generate_client_hello_tls_record(secret);
    record[TLS_RECORD_HEADER_LEN..].to_vec()
}

fn client_hello_offsets(record: &[u8]) -> (usize, usize) {
    let handshake = &record[TLS_RECORD_HEADER_LEN..];
    assert_eq!(handshake[0], HANDSHAKE_TYPE_CLIENT_HELLO);

    let mut pos = 4 + 2 + 32;
    let session_id_len = handshake[pos] as usize;
    assert_eq!(session_id_len, LEGACY_SESSION_ID_LEN);
    let session_id_start = TLS_RECORD_HEADER_LEN + pos + 1;
    pos += 1 + session_id_len;

    let cipher_suites_len = u16::from_be_bytes([handshake[pos], handshake[pos + 1]]) as usize;
    pos += 2 + cipher_suites_len;
    let compression_methods_len = handshake[pos] as usize;
    pos += 1 + compression_methods_len;

    let extensions_len_start = TLS_RECORD_HEADER_LEN + pos;
    let extensions_len = u16::from_be_bytes([handshake[pos], handshake[pos + 1]]) as usize;
    assert_eq!(pos + 2 + extensions_len, handshake.len());
    (session_id_start, extensions_len_start)
}

fn append_tls_record(output: &mut Vec<u8>, payload: &[u8]) {
    output.push(0x16);
    output.extend_from_slice(&[0x03, 0x03]);
    output.extend_from_slice(&u16::try_from(payload.len()).unwrap().to_be_bytes());
    output.extend_from_slice(payload);
}
