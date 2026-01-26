//! TLS/QUIC crypto helpers.

pub mod client_hello;
pub mod udp_qsp;

use boring::error::ErrorStack;
use boring::ssl::{
    CertificateCompressionAlgorithm, CertificateCompressor, SslContextBuilder, SslMethod, SslRef,
};
use boring_sys as ffi;
use foreign_types::ForeignTypeRef;
use std::io::{Cursor, Write};

const ALPN_H2_HTTP1: &[u8] = b"\x02h2\x08http/1.1";
const CHROME_SIGALGS: &str = "ecdsa_secp256r1_sha256:\
    rsa_pss_rsae_sha256:\
    rsa_pkcs1_sha256:\
    ecdsa_secp384r1_sha384:\
    rsa_pss_rsae_sha384:\
    rsa_pkcs1_sha384:\
    rsa_pss_rsae_sha512:\
    rsa_pkcs1_sha512";

const CHROME_CIPHERS: &str = "AES128-GCM-SHA256:\
    AES256-GCM-SHA384:\
    ECDHE-PSK-CHACHA20-POLY1305:\
    ECDHE-ECDSA-AES128-GCM-SHA256:\
    ECDHE-RSA-AES128-GCM-SHA256:\
    ECDHE-ECDSA-AES256-GCM-SHA384:\
    ECDHE-RSA-AES256-GCM-SHA384:\
    ECDHE-ECDSA-CHACHA20-POLY1305:\
    ECDHE-RSA-CHACHA20-POLY1305:\
    ECDHE-RSA-AES128-SHA:\
    ECDHE-RSA-AES256-SHA:\
    AES128-GCM-SHA256:\
    AES256-GCM-SHA384:\
    AES128-SHA:\
    AES256-SHA";

const CHROME_QUIC_CURVE_LIST: &str = "X25519MLKEM768:X25519:P-256:P-384";

/// Build a QUIC client config that mirrors Chrome's transport parameters.
///
/// This uses a `BoringSSL` context (for Chrome fingerprint parity) and applies
/// the currently known defaults for Chrome QUIC transport parameters.
pub fn quic_client_chrome_config() -> quiche::Result<quiche::Config> {
    let tls_ctx = quic_client_chrome_ctx_builder().map_err(|_| quiche::Error::TlsFail)?;

    let mut config =
        quiche::Config::with_boring_ssl_ctx_builder(quiche::PROTOCOL_VERSION, tls_ctx)?;
    config.set_application_protos(quiche::h3::APPLICATION_PROTOCOL)?;
    config.set_tls_configure_callback(|ssl| {
        configure_quic_client_ssl(ssl).map_err(|_| quiche::Error::TlsFail)
    });

    let mut tp = config.local_transport_params().clone();
    tp.google_quic_version = Some([0x00, 0x00, 0x00, 0x01]);
    tp.max_datagram_frame_size = Some(65_536);
    tp.max_idle_timeout = 30_000;
    tp.initial_max_streams_bidi = 100;
    tp.initial_max_streams_uni = 103;
    tp.initial_max_data = 15_728_640;
    tp.initial_max_stream_data_uni = 6_291_456;
    tp.initial_max_stream_data_bidi_local = 6_291_456;
    tp.initial_max_stream_data_bidi_remote = 6_291_456;
    tp.max_udp_payload_size = 1_472;
    tp.max_ack_delay = 0;
    tp.ack_delay_exponent = 0;
    tp.version_information = Some(vec![
        0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0xaa, 0x4a, 0x0a, 0x8a,
    ]);
    tp.grease = true;

    config.set_local_transport_params(tp);

    Ok(config)
}

/// Build a TLS client context builder with Chrome-like defaults.
pub fn tcp_client_chrome_ctx_builder() -> Result<SslContextBuilder, ErrorStack> {
    let mut builder = SslContextBuilder::new(SslMethod::tls())?;
    builder.set_sigalgs_list(CHROME_SIGALGS)?;
    builder.set_cipher_list(CHROME_CIPHERS)?;
    builder.set_grease_enabled(true);
    builder.enable_signed_cert_timestamps();
    builder.add_certificate_compression_algorithm(BrotliCertificateCompressor {})?;
    builder.enable_ocsp_stapling();
    Ok(builder)
}

/// Apply Chrome-like per-connection SSL defaults.
///
/// This configures ALPN and enables ALPS using the new codepoint (17613).
pub fn configure_client_chrome_ssl(ssl: &mut SslRef) -> Result<(), ErrorStack> {
    ssl.set_enable_ech_grease(true);
    ssl.set_alpn_protos(ALPN_H2_HTTP1)?;
    ssl.set_permute_extensions(true);
    configure_alps(ssl, b"h2", &[], true)?;
    Ok(())
}

fn configure_quic_client_ssl(ssl: &mut SslRef) -> Result<(), ErrorStack> {
    ssl.set_enable_ech_grease(true);
    configure_alps(ssl, b"h3", &[], true)?;
    Ok(())
}

/// Configure ALPS (`application_settings`) on a client SSL object.
///
/// The ALPN list must already include `protocol` and the handshake must not
/// have started. Use `SslContextBuilder::set_alpn_protos` or
/// `SslRef::set_alpn_protos` to configure ALPN before calling this.
fn configure_alps(
    ssl: &mut SslRef,
    protocol: &[u8],
    settings: &[u8],
    use_new_codepoint: bool,
) -> Result<(), ErrorStack> {
    unsafe {
        // SAFETY: FFI calls only borrow the buffers for the duration of the call.
        ffi::SSL_set_alps_use_new_codepoint(ssl.as_ptr(), use_new_codepoint as _);
        let ok = ffi::SSL_add_application_settings(
            ssl.as_ptr(),
            protocol.as_ptr(),
            protocol.len(),
            settings.as_ptr(),
            settings.len(),
        );
        if ok == 1 {
            Ok(())
        } else {
            Err(ErrorStack::get())
        }
    }
}

fn quic_client_chrome_ctx_builder() -> Result<SslContextBuilder, ErrorStack> {
    let mut builder = SslContextBuilder::new(SslMethod::tls())?;
    builder.set_curves_list(CHROME_QUIC_CURVE_LIST)?;
    builder.set_grease_enabled(true);
    builder.set_permute_extensions(true);
    builder.add_certificate_compression_algorithm(BrotliCertificateCompressor {})?;
    Ok(builder)
}

struct BrotliCertificateCompressor;

impl CertificateCompressor for BrotliCertificateCompressor {
    const ALGORITHM: CertificateCompressionAlgorithm = CertificateCompressionAlgorithm::BROTLI;
    const CAN_COMPRESS: bool = true;
    const CAN_DECOMPRESS: bool = true;

    fn compress<W>(&self, input: &[u8], output: &mut W) -> std::io::Result<()>
    where
        W: Write,
    {
        brotli::BrotliCompress(&mut Cursor::new(input), output, &Default::default())?;
        Ok(())
    }

    fn decompress<W>(&self, input: &[u8], output: &mut W) -> std::io::Result<()>
    where
        W: Write,
    {
        brotli::BrotliDecompress(&mut Cursor::new(input), output)?;
        Ok(())
    }
}
