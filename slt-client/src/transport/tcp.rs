use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use boring::error::ErrorStack;
use boring::ssl::{Ssl, SslRef, SslVerifyMode};
use boring::x509::verify::X509CheckFlags;
use slt_core::config::ClientConfig;
use slt_core::crypto::client_hello::client_hello_session_id_callback;
use slt_core::crypto::{
    configure_ca_store, configure_client_chrome_ssl, tcp_client_chrome_ctx_builder,
};
use slt_core::transport::tcp::{
    IntervalKeyUpdater, KeyUpdater, TcpChannel, default_interval_key_updater,
};
use tokio::net::{TcpStream, lookup_host};
use tokio::time::timeout;
use tokio_boring::HandshakeError;
use tracing::{debug, trace};

use crate::metrics::Metrics;

/// Maximum time allowed for TCP connect + TLS handshake.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// Metrics-aware TLS key updater used by client session channels.
#[derive(Debug, Clone)]
pub struct ClientKeyUpdater {
    inner: IntervalKeyUpdater,
    metrics: Arc<Metrics>,
}

impl ClientKeyUpdater {
    /// Create a metrics-aware key updater with default interval policy.
    #[must_use]
    pub const fn new(metrics: Arc<Metrics>) -> Self {
        Self {
            inner: default_interval_key_updater(),
            metrics,
        }
    }
}

impl KeyUpdater for ClientKeyUpdater {
    fn maybe_request_key_update(&mut self, ssl: &mut SslRef) -> io::Result<()> {
        let will_update = self.inner.messages_until_update() == 1;
        let request_peer_update = self.inner.requests_peer_update();
        self.inner.maybe_request_key_update(ssl)?;
        if will_update {
            self.metrics.inc_tls_key_update();
            trace!(
                request_peer_update,
                "client TCP TLS key update applied before outbound message"
            );
        }
        Ok(())
    }
}

/// Client TCP transport for framed VPN protocol I/O.
pub type TcpTransport = TcpChannel<TcpStream, ClientKeyUpdater>;

/// Connected TCP TLS session metadata.
pub struct TcpSession {
    /// TLS-wrapped TCP transport for protocol I/O.
    pub transport: TcpTransport,
    /// Connected peer address, if available.
    pub peer: Option<SocketAddr>,
    /// SNI hostname used for the handshake.
    pub sni: Option<String>,
}

/// Connect to the server and perform a TLS handshake.
pub async fn connect(config: &ClientConfig, metrics: Arc<Metrics>) -> io::Result<TcpSession> {
    metrics.inc_tcp_connections();

    let stream = timeout(CONNECT_TIMEOUT, connect_stream(config))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "tcp connect timeout"))??;
    let peer = stream.peer_addr().ok();
    debug!(peer = ?peer, "tcp connected");

    if config.network.hostname.is_empty() {
        metrics.inc_tcp_handshake_failures();
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "hostname is empty",
        ));
    }

    let mut ctx = tcp_client_chrome_ctx_builder().map_err(|err| {
        metrics.inc_tcp_handshake_failures();
        map_error(err)
    })?;
    configure_ca_store(&mut ctx, &config.tls.tls_ca).map_err(|err| {
        metrics.inc_tcp_handshake_failures();
        map_error(err)
    })?;
    ctx.set_verify(SslVerifyMode::PEER);
    ctx.set_client_hello_session_id_callback(client_hello_session_id_callback(
        config.identity.shared_secret,
    ));
    let ctx = ctx.build();

    let mut ssl = Ssl::new(&ctx).map_err(|err| {
        metrics.inc_tcp_handshake_failures();
        map_error(err)
    })?;
    configure_client_chrome_ssl(&mut ssl).map_err(|err| {
        metrics.inc_tcp_handshake_failures();
        map_error(err)
    })?;

    ssl.set_hostname(&config.network.hostname).map_err(|err| {
        metrics.inc_tcp_handshake_failures();
        map_error(err)
    })?;
    configure_hostname_verification(&mut ssl, &config.network.hostname).map_err(|err| {
        metrics.inc_tcp_handshake_failures();
        map_error(err)
    })?;

    let stream = timeout(
        CONNECT_TIMEOUT,
        tokio_boring::SslStreamBuilder::new(ssl, stream).connect(),
    )
    .await
    .map_err(|_| {
        metrics.inc_tcp_handshake_failures();
        io::Error::new(io::ErrorKind::TimedOut, "tls handshake timeout")
    })?
    .map_err(|err| {
        metrics.inc_tcp_handshake_failures();
        map_handshake_error(&err)
    })?;

    metrics.inc_tcp_handshake_successes();

    let sni = Some(config.network.hostname.clone());
    Ok(TcpSession {
        transport: TcpChannel::with_key_updater(stream, ClientKeyUpdater::new(metrics)),
        peer,
        sni,
    })
}

async fn connect_stream(config: &ClientConfig) -> io::Result<TcpStream> {
    if let Some(ip) = config.network.ip {
        return TcpStream::connect(SocketAddr::new(ip, config.network.port)).await;
    }

    let addrs: Vec<SocketAddr> =
        lookup_host((config.network.hostname.as_str(), config.network.port))
            .await?
            .collect();

    if addrs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "dns lookup returned no addresses",
        ));
    }

    let mut last_err = None;
    for addr in addrs {
        match TcpStream::connect(addr).await {
            Ok(stream) => return Ok(stream),
            Err(err) => last_err = Some(err),
        }
    }

    Err(last_err.unwrap_or_else(|| io::Error::other("tcp connect failed")))
}

fn configure_hostname_verification(ssl: &mut Ssl, host: &str) -> Result<(), ErrorStack> {
    let param = ssl.param_mut();
    param.set_hostflags(X509CheckFlags::NO_PARTIAL_WILDCARDS);
    match host.parse::<IpAddr>() {
        Ok(ip) => param.set_ip(ip),
        Err(_) => param.set_host(host),
    }
}

fn map_error(err: impl std::fmt::Display) -> io::Error {
    io::Error::other(err.to_string())
}

fn map_handshake_error(err: &HandshakeError<TcpStream>) -> io::Error {
    io::Error::other(format!("tls handshake failed: {err}"))
}
