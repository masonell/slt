//! TLS/QUIC crypto helpers.

pub mod client_hello;
pub mod udp_qsp;

use std::io::{Cursor, Write};

use boring::error::ErrorStack;
use boring::ssl::{
    CertificateCompressionAlgorithm, CertificateCompressor, SslContextBuilder, SslMethod, SslRef,
};
use boring::x509::X509;
use boring::x509::verify::X509VerifyFlags;
use boring_sys as ffi;
use brotli::enc::BrotliEncoderParams;
use foreign_types::ForeignTypeRef;

use crate::types::TlsMaterial;

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

/// A failure from QUIC client TLS-setup (`quic_client_chrome_config` /
/// `quic_client_chrome_config_with_ca` and their callees).
///
/// These helpers previously returned `quiche::Result<quiche::Config>` and
/// collapsed every distinct boring TLS-setup failure (context build, CA store
/// load, default verify paths, transport-parameter assembly) into the opaque
/// unit variant `quiche::Error::TlsFail`, **dropping the boring `ErrorStack`**.
/// `QuicConfigError` preserves that stack via `#[source]` so the structured
/// cause survives for `{:#}` and the log, per the design note's "preserve, don't
/// stringify" rule.
///
/// This is a layer-local typed error in `slt-core` because the QUIC TLS setup is
/// shared by every consumer of the Chrome QUIC config (client transport, the
/// QUIC discovery path). It deliberately does not wrap the still-callable
/// `quic_config_from_ctx` handshake-time `quiche::Error::TlsFail` produced
/// inside the `set_tls_configure_callback`: that callback's signature is fixed
/// by quiche to return `quiche::Error` (a unit `TlsFail`), so the per-connection
/// `ErrorStack` cannot be surfaced through it structurally — it is logged at the
/// callback site instead.
#[derive(Debug, thiserror::Error)]
pub enum QuicConfigError {
    /// `BoringSSL` TLS context / CA-store setup failed before the handshake could
    /// run (`quic_client_chrome_ctx_builder`, `configure_ca_store`,
    /// `set_default_verify_paths`). The boring [`ErrorStack`] is preserved.
    #[error("quic tls setup failed: {source}")]
    Setup {
        /// Preserved boring error stack from the failing setup operation.
        #[source]
        source: ErrorStack,
    },

    /// `quiche::Config` assembly from the built TLS context failed
    /// (`with_boring_ssl_ctx_builder`, application-protocol setup). The
    /// underlying [`quiche::Error`] is preserved.
    #[error("quic config assembly failed: {0}")]
    Quiche(#[from] quiche::Error),
}

impl From<ErrorStack> for QuicConfigError {
    /// Compose a setup [`ErrorStack`] into [`Self::Setup`].
    ///
    /// Lets the setup call sites use `?` to preserve the boring error stack
    /// without a flattening mapper.
    fn from(source: ErrorStack) -> Self {
        Self::Setup { source }
    }
}

/// Build a QUIC client config that mirrors Chrome's transport parameters.
///
/// This uses a `BoringSSL` context (for Chrome fingerprint parity) and applies
/// the currently known defaults for Chrome QUIC transport parameters.
///
/// # Errors
///
/// Returns a [`QuicConfigError`] if TLS context creation fails or if setting
/// application protocols fails — the boring `ErrorStack` (or `quiche::Error`)
/// is preserved, not collapsed to `quiche::Error::TlsFail`.
pub fn quic_client_chrome_config() -> Result<quiche::Config, QuicConfigError> {
    let tls_ctx = quic_client_chrome_ctx_builder()?;
    quic_config_from_ctx(tls_ctx)
}

/// Build a QUIC client config with optional CA trust anchors.
///
/// If `tls_ca` is `Some`, configures custom CA verification from the provided
/// TLS material. If `None`, uses the system's default CA store for verification.
///
/// For inline PEM, certs are parsed and added directly to the cert store
/// without writing to disk.
///
/// # Errors
///
/// Returns a [`QuicConfigError`] if TLS context creation fails, CA loading
/// fails, default-verify-path configuration fails, or application-protocol
/// setup fails — the boring `ErrorStack` (or `quiche::Error`) is preserved,
/// not collapsed to `quiche::Error::TlsFail`.
pub fn quic_client_chrome_config_with_ca(
    tls_ca: Option<&TlsMaterial>,
) -> Result<quiche::Config, QuicConfigError> {
    let mut tls_ctx = quic_client_chrome_ctx_builder()?;
    match tls_ca {
        Some(ca) => {
            configure_ca_store(&mut tls_ctx, ca)?;
        }
        None => {
            tls_ctx.set_default_verify_paths()?;
        }
    }
    quic_config_from_ctx(tls_ctx)
}

/// Configure a `BoringSSL` context builder to trust the provided certificate material.
///
/// For file paths, uses `BoringSSL`'s built-in loading. For inline PEM, parses
/// certificates and adds them directly to the cert store without writing to disk.
///
/// This function sets the `PARTIAL_CHAIN` flag, allowing any certificate in the
/// trust store to be used as a trust anchor, not just root CAs. This enables
/// certificate pinning where a specific server certificate (rather than a CA)
/// is trusted directly.
///
/// # Errors
///
/// Returns an error if the file cannot be read or PEM cannot be parsed.
pub fn configure_ca_store(
    ctx: &mut SslContextBuilder,
    tls_ca: &TlsMaterial,
) -> Result<(), ErrorStack> {
    match tls_ca {
        TlsMaterial::File { file } => ctx.set_ca_file(file),
        TlsMaterial::Pem(pem) => {
            let certs = X509::stack_from_pem(pem.as_bytes())?;
            for cert in certs {
                ctx.cert_store_mut().add_cert(cert)?;
            }
            Ok(())
        }
    }?;
    // Allow trusting non-CA certs (e.g., server cert directly via pinning)
    ctx.cert_store_mut()
        .set_flags(X509VerifyFlags::PARTIAL_CHAIN);
    Ok(())
}

fn quic_config_from_ctx(tls_ctx: SslContextBuilder) -> Result<quiche::Config, QuicConfigError> {
    let mut config =
        quiche::Config::with_boring_ssl_ctx_builder(quiche::PROTOCOL_VERSION, tls_ctx)?;
    config.set_application_protos(quiche::h3::APPLICATION_PROTOCOL)?;
    // The per-connection callback signature is fixed by quiche to return
    // `quiche::Result<()>`, so a setup `ErrorStack` from
    // `configure_quic_client_ssl` cannot be surfaced structurally through it
    // (the only failure quiche exposes here is the unit `quiche::Error::TlsFail`).
    // The structured stack is logged before being collapsed, so the cause is at
    // least visible in the run log — the closest "preserve, don't stringify"
    // option available inside quiche's callback boundary.
    config.set_tls_configure_callback(|ssl| {
        if let Err(stack) = configure_quic_client_ssl(ssl) {
            tracing::warn!(error = %stack, "quic per-connection ssl configure failed");
            return Err(quiche::Error::TlsFail);
        }
        Ok(())
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
///
/// # Errors
///
/// Returns an error if SSL context builder creation fails or if setting
/// cipher suites, signature algorithms, or compression algorithms fails.
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
///
/// # Errors
///
/// Returns an error if setting ALPN protocols or ALPS configuration fails.
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
        ffi::SSL_set_alps_use_new_codepoint(ssl.as_ptr(), use_new_codepoint.into());
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
        brotli::BrotliCompress(
            &mut Cursor::new(input),
            output,
            &BrotliEncoderParams::default(),
        )?;
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

#[cfg(test)]
mod tests {
    use std::io;

    use super::*;

    /// `From<ErrorStack>` produces [`QuicConfigError::Setup`], and the boring
    /// `ErrorStack` survives as the `source()` of the typed error (the phase's
    /// central "preserve, don't stringify" claim — the old code collapsed this
    /// to the opaque unit `quiche::Error::TlsFail`, dropping the stack).
    #[test]
    fn errorstack_preserved_as_setup_source() {
        let stack = ErrorStack::internal_error(io::Error::other("boring tls setup boom"));
        let err: QuicConfigError = stack.into();
        assert!(
            matches!(err, QuicConfigError::Setup { .. }),
            "From<ErrorStack> must produce QuicConfigError::Setup, got {err:?}"
        );
        // The ErrorStack survives as the std::error::Error source — not
        // stringified away.
        let source = std::error::Error::source(&err);
        assert!(
            source.is_some(),
            "Setup must expose the preserved ErrorStack via source()"
        );
        // And the structured stack text survives in the {:#} terminal render.
        let rendered = format!("{err:#}");
        assert!(
            rendered.contains("boring tls setup boom"),
            "ErrorStack text must survive in the terminal render: {rendered:?}"
        );
    }

    /// `From<quiche::Error>` produces [`QuicConfigError::Quiche`], preserving
    /// the quiche config-assembly error (the other failure mode of the
    /// QUIC-config helpers).
    #[test]
    fn quiche_error_preserved_as_quiche_variant() {
        let err: QuicConfigError = quiche::Error::TlsFail.into();
        assert!(
            matches!(err, QuicConfigError::Quiche(quiche::Error::TlsFail)),
            "From<quiche::Error> must produce QuicConfigError::Quiche, got {err:?}"
        );
    }
}
