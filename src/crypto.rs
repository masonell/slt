use boring::ssl::{SslContextBuilder, SslMethod};

/// Build a QUIC client config that mirrors Chrome's transport parameters.
///
/// This uses a BoringSSL context (for Chrome fingerprint parity) and applies
/// the currently known defaults for Chrome QUIC transport parameters.
pub fn quic_client_chrome_config() -> quiche::Result<quiche::Config> {
    let tls_ctx = SslContextBuilder::new(SslMethod::tls())
        .map_err(|_| quiche::Error::TlsFail)?;

    let mut config = quiche::Config::with_boring_ssl_ctx_builder(
        quiche::PROTOCOL_VERSION,
        tls_ctx,
    )?;

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
    tp.version_information = Some(vec![
        0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0xaa, 0x4a, 0x0a,
        0x8a,
    ]);
    tp.grease = true;

    config.set_local_transport_params(tp);

    Ok(config)
}
