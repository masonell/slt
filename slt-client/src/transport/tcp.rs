use std::future::{Future, poll_fn};
use std::io;
use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::task::Poll;
use std::time::Duration;

use boring::error::ErrorStack;
use boring::ssl::{Ssl, SslRef, SslVerifyMode};
use slt_core::config::ClientConfig;
use slt_core::crypto::client_hello::client_hello_session_id_callback;
use slt_core::crypto::{
    configure_ca_store, configure_client_chrome_ssl, configure_hostname_verification,
    tcp_client_chrome_ctx_builder,
};
use slt_core::proto::Message;
use slt_core::transport::tcp::{
    IntervalKeyUpdater, KeyUpdater, TcpChannel, TcpWriteError, default_interval_key_updater,
};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpSocket, TcpStream};
use tokio::time::{self, timeout};
use tracing::{debug, trace};

use crate::error::{ConnectError, TlsError};
use crate::metrics::Metrics;
use crate::transport::host_resolver::HostResolver;
use crate::transport::socket_protector::{SocketKind, SocketProtector};

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
    fn maybe_request_key_update(&mut self, ssl: &mut SslRef) -> std::io::Result<()> {
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
pub type TcpTransport<S = TcpStream> = TcpChannel<S, ClientKeyUpdater>;

/// Connected TCP TLS session metadata.
pub struct TcpSession<S = TcpStream> {
    /// TLS-wrapped TCP transport for protocol I/O.
    pub transport: TcpTransport<S>,
    /// Connected peer address, if available.
    pub peer: Option<SocketAddr>,
    /// SNI hostname used for the handshake.
    pub sni: Option<String>,
}

/// Write one framed TCP message before `write_timeout` expires.
///
/// The timer is registered only after the first write poll reports backpressure,
/// keeping immediately-ready writes on the direct path.
///
/// # Errors
///
/// Returns the channel's typed frame or I/O error. An expired deadline is an
/// I/O error with [`io::ErrorKind::TimedOut`].
pub async fn write_message_with_timeout<S, K>(
    tcp: &mut TcpChannel<S, K>,
    message: Message<'_>,
    write_timeout: Duration,
) -> Result<(), TcpWriteError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    K: KeyUpdater,
{
    let deadline = time::Instant::now() + write_timeout;
    let write = tcp.write_message(message);
    tokio::pin!(write);

    let first_poll = poll_fn(|cx| Poll::Ready(write.as_mut().poll(cx))).await;
    match first_poll {
        Poll::Ready(result) => result,
        Poll::Pending => {
            let Ok(result) = time::timeout_at(deadline, write.as_mut()).await else {
                return Err(
                    io::Error::new(io::ErrorKind::TimedOut, "tcp message write timed out").into(),
                );
            };
            result
        }
    }
}

/// Connect to the server and perform a TLS handshake.
///
/// Establishes a TCP connection to the server, performs a TLS handshake with
/// Chrome-compatible settings, and injects an HMAC token into the `ClientHello`
/// session ID for traffic classification.
///
/// # Errors
///
/// Returns a [`ConnectError`] describing the failure site:
/// - [`ConnectError::EmptyHostname`] if the configured hostname is empty.
/// - [`ConnectError::TcpSocketCreate`]/[`ConnectError::SocketProtect`]/
///   [`ConnectError::TcpConnect`]/[`ConnectError::TcpConnectTimeout`] for TCP
///   setup/connect failures (peer address preserved).
/// - [`ConnectError::TlsHandshake`] / [`ConnectError::TlsHandshakeTimeout`]
///   for TLS failures (boring error preserved via [`TlsError`], not
///   stringified).
pub async fn connect<SP, HR>(
    config: &ClientConfig,
    metrics: Arc<Metrics>,
    socket_protector: &SP,
    host_resolver: &HR,
) -> Result<TcpSession, ConnectError>
where
    SP: SocketProtector,
    HR: HostResolver,
{
    metrics.inc_tcp_connections();

    // Check the hostname up front so an empty-hostname config surfaces as a
    // Config-stage failure rather than a misleading DNS/TLS error downstream.
    if config.network.hostname.is_empty() {
        metrics.inc_tcp_handshake_failures();
        return Err(ConnectError::EmptyHostname);
    }

    let peer_for_timeout = config
        .network
        .ip
        .map(|ip| SocketAddr::new(ip, config.network.port));

    let stream = if let Ok(inner) = timeout(
        CONNECT_TIMEOUT,
        connect_stream(config, socket_protector, host_resolver),
    )
    .await
    {
        inner?
    } else {
        metrics.inc_tcp_handshake_failures();
        return Err(ConnectError::TcpConnectTimeout {
            peer: peer_for_timeout.unwrap_or_else(|| {
                SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0)
            }),
            timeout: CONNECT_TIMEOUT,
        });
    };
    let peer = stream.peer_addr().ok();
    debug!(peer = ?peer, "tcp connected");

    let sni = config.network.hostname.clone();

    let mut ctx = tcp_client_chrome_ctx_builder().map_err(|err| {
        metrics.inc_tcp_handshake_failures();
        tls_setup_error(&sni, err)
    })?;
    configure_ca_store(&mut ctx, &config.tls.tls_ca).map_err(|err| {
        metrics.inc_tcp_handshake_failures();
        tls_setup_error(&sni, err)
    })?;
    ctx.set_verify(SslVerifyMode::PEER);
    ctx.set_client_hello_session_id_callback(client_hello_session_id_callback(
        config.identity.shared_secret,
    ));
    let ctx = ctx.build();

    let mut ssl = Ssl::new(&ctx).map_err(|err| {
        metrics.inc_tcp_handshake_failures();
        tls_setup_error(&sni, err)
    })?;
    configure_client_chrome_ssl(&mut ssl).map_err(|err| {
        metrics.inc_tcp_handshake_failures();
        tls_setup_error(&sni, err)
    })?;

    ssl.set_hostname(&sni).map_err(|err| {
        metrics.inc_tcp_handshake_failures();
        tls_setup_error(&sni, err)
    })?;
    configure_hostname_verification(&mut ssl, &sni).map_err(|err| {
        metrics.inc_tcp_handshake_failures();
        tls_setup_error(&sni, err)
    })?;

    let stream = if let Ok(inner) = timeout(
        CONNECT_TIMEOUT,
        tokio_boring::SslStreamBuilder::new(ssl, stream).connect(),
    )
    .await
    {
        inner.map_err(|err| {
            metrics.inc_tcp_handshake_failures();
            tls_handshake_error(&sni, &err)
        })?
    } else {
        metrics.inc_tcp_handshake_failures();
        return Err(ConnectError::TlsHandshakeTimeout {
            sni,
            timeout: CONNECT_TIMEOUT,
        });
    };

    metrics.inc_tcp_handshake_successes();

    Ok(TcpSession {
        transport: TcpChannel::with_key_updater(stream, ClientKeyUpdater::new(metrics)),
        peer,
        sni: Some(sni),
    })
}

async fn connect_stream<SP, HR>(
    config: &ClientConfig,
    socket_protector: &SP,
    host_resolver: &HR,
) -> Result<TcpStream, ConnectError>
where
    SP: SocketProtector,
    HR: HostResolver,
{
    if let Some(ip) = config.network.ip {
        return connect_addr(SocketAddr::new(ip, config.network.port), socket_protector).await;
    }

    let addrs = host_resolver
        .resolve(config.network.hostname.as_str(), config.network.port)
        .await
        .map_err(|e| ConnectError::DnsResolution {
            hostname: config.network.hostname.clone(),
            source: e,
        })?;

    let mut last_err = None;
    for addr in addrs {
        match connect_addr(addr, socket_protector).await {
            Ok(stream) => return Ok(stream),
            Err(err) => last_err = Some(err),
        }
    }

    Err(last_err.unwrap_or_else(|| ConnectError::DnsResolution {
        hostname: config.network.hostname.clone(),
        source: std::io::Error::other("dns resolution returned no addresses"),
    }))
}

async fn connect_addr<SP>(
    addr: SocketAddr,
    socket_protector: &SP,
) -> Result<TcpStream, ConnectError>
where
    SP: SocketProtector,
{
    let socket = match addr {
        SocketAddr::V4(_) => TcpSocket::new_v4(),
        SocketAddr::V6(_) => TcpSocket::new_v6(),
    }
    .map_err(|e| ConnectError::TcpSocketCreate {
        peer: addr,
        source: e,
    })?;

    let fd = socket.as_raw_fd();
    socket_protector
        .protect(fd, SocketKind::Tcp)
        .map_err(|e| ConnectError::SocketProtect {
            fd,
            kind: SocketKind::Tcp,
            peer: addr,
            source: e,
        })?;

    socket
        .connect(addr)
        .await
        .map_err(|e| ConnectError::TcpConnect {
            peer: addr,
            source: e,
        })
}

/// Wrap a TLS setup [`ErrorStack`] as a fatal [`ConnectError::TlsHandshake`].
///
/// All TLS setup sites (context builder, CA store, `Ssl::new`, chrome SSL
/// config, hostname configuration) are config/capability faults; they flow
/// through [`TlsError::Setup`] so the cause chain survives. `sni` is the
/// configured hostname, in scope at every setup call site in [`connect`].
fn tls_setup_error(sni: &str, err: ErrorStack) -> ConnectError {
    ConnectError::TlsHandshake {
        sni: sni.to_string(),
        source: TlsError::Setup(err),
    }
}

/// Wrap a boring [`tokio_boring::HandshakeError`] as a [`ConnectError`],
/// preserving the structured boring error decoupled from the stream type and
/// capturing the X.509 verification error and any underlying I/O error.
///
/// `tokio_boring::HandshakeError<S>` keeps its inner `boring::ssl::HandshakeError`
/// private, so this extracts the structured fields it exposes (`code`,
/// `verify_result` via `ssl()`, `as_io_error`) into [`TlsError::Handshake`].
/// `sni` is the configured hostname used for the handshake. Setup failures
/// (`ErrorStack` from the context/`Ssl::new`/hostname sites) are wrapped via
/// [`tls_setup_error`].
fn tls_handshake_error(sni: &str, err: &tokio_boring::HandshakeError<TcpStream>) -> ConnectError {
    // Capture the cert verification error: its presence forces a fatal retry
    // policy regardless of the boring error code. `ssl()` is only `Some` for a
    // mid-handshake `Failure`.
    let verify_error = err.ssl().and_then(|ssl_ref| ssl_ref.verify_result().err());
    let code = err.code().unwrap_or(boring::ssl::ErrorCode::SSL);
    // Capture the underlying io::Error's kind (the retry-relevant part).
    // `io::Error` is not `Clone`, so only the `ErrorKind` is preserved here;
    // the kind is what `TlsError::is_transient_io` keys off.
    let io_error_kind = err.as_io_error().map(io::Error::kind);
    ConnectError::TlsHandshake {
        sni: sni.to_string(),
        source: TlsError::Handshake {
            code,
            verify_error,
            io_error_kind,
        },
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use tokio::net::TcpListener;

    use super::*;
    use crate::error::{ConnectError, Stage};
    use crate::test_support::test_config;
    use crate::transport::host_resolver::TokioHostResolver;

    #[derive(Default)]
    struct RecordingProtector {
        calls: Mutex<Vec<(i32, SocketKind)>>,
        fail: bool,
    }

    impl SocketProtector for RecordingProtector {
        fn protect(&self, fd: i32, kind: SocketKind) -> io::Result<()> {
            self.calls.lock().unwrap().push((fd, kind));
            if self.fail {
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "test protection failure",
                ))
            } else {
                Ok(())
            }
        }
    }

    #[tokio::test]
    async fn connect_stream_protects_socket_before_connect() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accept = tokio::spawn(async move {
            let _ = listener.accept().await.unwrap();
        });

        let mut config = test_config();
        config.network.ip = Some(addr.ip());
        config.network.port = addr.port();
        let protector = RecordingProtector::default();

        let stream = connect_stream(&config, &protector, &TokioHostResolver)
            .await
            .unwrap();
        assert_eq!(stream.peer_addr().unwrap(), addr);

        // Scope the guard so it isn't held across the `.await` below.
        {
            let calls = protector.calls.lock().unwrap();
            assert_eq!(calls.len(), 1);
            assert_eq!(calls[0].1, SocketKind::Tcp);
            assert!(calls[0].0 >= 0);
        }

        drop(stream);
        accept.await.unwrap();
    }

    #[tokio::test]
    async fn connect_stream_returns_socket_protect_error_when_protection_fails() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let mut config = test_config();
        config.network.ip = Some(addr.ip());
        config.network.port = addr.port();
        let protector = RecordingProtector {
            fail: true,
            ..RecordingProtector::default()
        };

        let err = connect_stream(&config, &protector, &TokioHostResolver)
            .await
            .expect_err("protection failure should error");
        assert!(
            matches!(err, ConnectError::SocketProtect { .. }),
            "expected SocketProtect, got {err:?}"
        );
        // The protection failure must NOT be classified as an auth error.
        assert_ne!(err.stage(), Stage::Auth);

        let calls = protector.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].1, SocketKind::Tcp);

        drop(listener);
    }

    /// A `PermissionDenied` from `TcpSocket::new_v4` (e.g. missing Android
    /// `INTERNET` capability) must surface as `TcpSocketCreate`, never as an
    /// auth failure.
    #[tokio::test]
    async fn connect_stream_socket_create_failure_is_classified() {
        // Bind a listener so the peer address is real, then inject a
        // socket-create failure via a protector that *also* fails — but the
        // TcpSocket::new_v4 path itself can't be cheaply forced to fail without
        // capability drops. Instead, assert the mapping at the unit level by
        // constructing the variant the way connect_addr does and checking
        // stage()/is_retriable(). This pins the policy for the design-note
        // anchor "TCP socket-create PermissionDenied -> TcpSocketCreate".
        let peer: SocketAddr = "127.0.0.1:8443".parse().unwrap();
        let err = ConnectError::TcpSocketCreate {
            peer,
            source: io::Error::from(io::ErrorKind::PermissionDenied),
        };
        assert_eq!(err.stage(), Stage::TcpSocketCreate);
        assert!(!err.is_retriable());
    }

    /// A TCP connect timeout must surface as `TcpConnectTimeout` with the peer
    /// and timeout preserved, and must be retriable.
    #[tokio::test]
    async fn connect_tcp_timeout_is_classified() {
        let peer: SocketAddr = "127.0.0.1:8443".parse().unwrap();
        let timeout = CONNECT_TIMEOUT;
        let err = ConnectError::TcpConnectTimeout { peer, timeout };
        assert!(matches!(err, ConnectError::TcpConnectTimeout { .. }));
        assert_eq!(err.stage(), Stage::TcpConnect);
        assert!(err.is_retriable());
        // The timeout variant must not be classified as auth.
        assert_ne!(err.stage(), Stage::Auth);
        let rendered = err.to_string().to_ascii_lowercase();
        assert!(
            !rendered.contains("auth"),
            "TcpConnectTimeout must not render auth: {rendered:?}"
        );
    }
}
