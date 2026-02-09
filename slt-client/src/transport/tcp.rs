use super::tls;
use boring::error::ErrorStack;
use boring::ssl::{Ssl, SslRef, SslVerifyMode};
use boring::x509::verify::X509CheckFlags;
use slt_core::config::ClientConfig;
use slt_core::crypto::client_hello::client_hello_session_id_callback;
use slt_core::crypto::{configure_client_chrome_ssl, tcp_client_chrome_ctx_builder};
use std::io;
use std::net::{IpAddr, SocketAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, lookup_host};
use tokio_boring::{HandshakeError, SslStream};
use tracing::debug;

/// TCP transport wrapper for the VPN protocol.
pub struct TcpTransport {
    stream: SslStream<TcpStream>,
    read_buf: Vec<u8>,
    write_buf: Vec<u8>,
}

impl TcpTransport {
    /// Create a new TCP transport around an established TLS stream.
    #[must_use]
    pub const fn new(stream: SslStream<TcpStream>) -> Self {
        Self {
            stream,
            read_buf: Vec::new(),
            write_buf: Vec::new(),
        }
    }

    /// Returns the TLS session handle.
    #[must_use]
    pub fn ssl(&self) -> &SslRef {
        self.stream.ssl()
    }

    /// Returns true if there are buffered bytes ready for parsing.
    #[must_use]
    pub const fn has_buffered_input(&self) -> bool {
        !self.read_buf.is_empty()
    }

    /// Read more bytes from the TLS stream into the internal buffer.
    pub async fn read_more(&mut self) -> io::Result<usize> {
        self.stream.read_buf(&mut self.read_buf).await
    }

    /// Attempt to pop the next message from the internal read buffer.
    pub fn try_pop_message(
        &mut self,
        limits: slt_core::proto::MessageLimits,
    ) -> Result<Option<crate::wire::OwnedMessageBuf>, slt_core::proto::MessageError> {
        crate::wire::pop_message_buf(&mut self.read_buf, limits)
    }

    /// Encode and write a protocol message on the TLS stream.
    pub async fn write_message(&mut self, message: slt_core::proto::Message<'_>) -> io::Result<()> {
        self.write_buf.clear();
        slt_core::proto::encode_message(message, &mut self.write_buf)
            .map_err(crate::wire::map_frame_error)?;
        self.stream.write_all(&self.write_buf).await
    }
}

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
    tls::configure_boring_ca_store(&mut ctx, &config.tls_ca).map_err(map_error)?;
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
        transport: TcpTransport::new(stream),
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
