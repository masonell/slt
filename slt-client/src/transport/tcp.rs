use boring::error::ErrorStack;
use boring::ssl::{Ssl, SslVerifyMode};
use boring::x509::verify::X509CheckFlags;
use slt_core::config::ClientConfig;
use slt_core::crypto::client_hello::client_hello_session_id_callback;
use slt_core::crypto::{
    configure_ca_store, configure_client_chrome_ssl, tcp_client_chrome_ctx_builder,
};
use slt_core::transport::tcp::{IntervalKeyUpdater, TcpChannel, default_interval_key_updater};
use std::io;
use std::net::{IpAddr, SocketAddr};
use tokio::net::{TcpStream, lookup_host};
use tokio_boring::HandshakeError;
use tracing::debug;

/// Client TCP transport for framed VPN protocol I/O.
pub type TcpTransport = TcpChannel<TcpStream, IntervalKeyUpdater>;

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
pub async fn connect(config: &ClientConfig) -> io::Result<TcpSession> {
    let stream = connect_stream(config).await?;
    let peer = stream.peer_addr().ok();
    debug!(peer = ?peer, "tcp connected");

    if config.hostname.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "hostname is empty",
        ));
    }

    let mut ctx = tcp_client_chrome_ctx_builder().map_err(map_error)?;
    configure_ca_store(&mut ctx, &config.tls_ca).map_err(map_error)?;
    ctx.set_verify(SslVerifyMode::PEER);
    ctx.set_client_hello_session_id_callback(client_hello_session_id_callback(
        config.shared_secret,
    ));
    let ctx = ctx.build();

    let mut ssl = Ssl::new(&ctx).map_err(map_error)?;
    configure_client_chrome_ssl(&mut ssl).map_err(map_error)?;

    ssl.set_hostname(&config.hostname).map_err(map_error)?;
    configure_hostname_verification(&mut ssl, &config.hostname).map_err(map_error)?;

    let stream = tokio_boring::SslStreamBuilder::new(ssl, stream)
        .connect()
        .await
        .map_err(|err| map_handshake_error(&err))?;

    let sni = Some(config.hostname.clone());
    Ok(TcpSession {
        transport: TcpChannel::with_key_updater(stream, default_interval_key_updater()),
        peer,
        sni,
    })
}

async fn connect_stream(config: &ClientConfig) -> io::Result<TcpStream> {
    if let Some(ip) = config.ip {
        return TcpStream::connect(SocketAddr::new(ip, config.port)).await;
    }

    let addrs: Vec<SocketAddr> = lookup_host((config.hostname.as_str(), config.port))
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

fn map_error(err: impl std::fmt::Debug) -> io::Error {
    io::Error::other(format!("{err:?}"))
}

fn map_handshake_error(err: &HandshakeError<TcpStream>) -> io::Error {
    io::Error::other(format!("{err:?}"))
}
