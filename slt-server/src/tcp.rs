//! TCP front-door handling.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use slt_core::classifier::{Verdict, classify_tcp_client_hello};
use slt_core::config::ServerConfig;
use slt_core::types::SharedSecret;
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, trace, warn};

use super::metrics::Metrics;

const PEEK_LEN: usize = 16 * 1024;
const CLASSIFY_TIMEOUT: Duration = Duration::from_millis(250);
const CLASSIFY_RETRY_DELAY: Duration = Duration::from_millis(5);

/// TCP acceptor and `ClientHello` classifier.
///
/// Listens for TCP connections, inspects TLS `ClientHello` messages to
/// identify VPN clients, and routes connections either to the claim handler
/// (for VPN clients) or proxies them to nginx (for regular traffic).
#[derive(Debug)]
pub struct TcpFrontDoor {
    listener: TcpListener,
    classification_secret: SharedSecret,
    nginx_tcp_upstream: SocketAddr,
    metrics: Arc<Metrics>,
}

impl TcpFrontDoor {
    /// Bind to the configured TCP listener.
    ///
    /// # Errors
    ///
    /// Returns an error if TCP listener binding fails.
    pub async fn bind(config: &ServerConfig, metrics: Arc<Metrics>) -> io::Result<Self> {
        debug!(listen_addr = %config.network.listen_tcp, upstream_addr = %config.network.nginx_tcp_upstream, "binding TCP front door");
        let listener = TcpListener::bind(config.network.listen_tcp).await?;
        info!(listen_addr = %config.network.listen_tcp, "TCP front door bound successfully");
        Ok(Self {
            listener,
            classification_secret: config.server_secret,
            nginx_tcp_upstream: config.network.nginx_tcp_upstream,
            metrics,
        })
    }

    /// Return the bound listener.
    #[must_use]
    pub const fn listener(&self) -> &TcpListener {
        &self.listener
    }

    /// Classify a TCP buffer that starts with TLS records.
    #[must_use]
    pub fn classify(&self, buf: &[u8]) -> Verdict {
        let verdict = classify_tcp_client_hello(buf, &self.classification_secret);
        trace!(buf_len = buf.len(), verdict = ?verdict, "classified TCP buffer");
        verdict
    }

    /// Run the TCP accept loop and route connections by classification.
    ///
    /// Claimed connections are handed to `claim_handler`; other traffic is
    /// proxied to the nginx upstream. The loop exits once `cancel` is canceled.
    ///
    /// # Errors
    ///
    /// Returns an error if accepting a connection fails.
    pub async fn run(
        &self,
        cancel: CancellationToken,
        claim_handler: impl Fn(TcpStream, SocketAddr) + Send + Sync + 'static,
    ) -> io::Result<()> {
        debug!("starting TCP accept loop");
        let claim_handler = Arc::new(claim_handler);
        loop {
            let (stream, addr) = tokio::select! {
                () = cancel.cancelled() => {
                    debug!("TCP accept loop cancelled");
                    return Ok(());
                }
                res = self.listener.accept() => res?,
            };
            debug!(client_addr = %addr, "accepted TCP connection");
            self.metrics.inc_tcp_accepted();
            let server_secret = self.classification_secret;
            let upstream = self.nginx_tcp_upstream;
            let claim_handler = claim_handler.clone();
            let metrics = self.metrics.clone();

            tokio::spawn(async move {
                match Self::classify_stream(&stream, server_secret).await {
                    Ok(verdict @ Verdict::Claim) => {
                        debug!(client_addr = %addr, verdict = ?verdict, "connection claimed");
                        metrics.inc_claimed();
                        (claim_handler)(stream, addr);
                    }
                    Ok(verdict @ (Verdict::Pass | Verdict::Incomplete)) => {
                        debug!(client_addr = %addr, verdict = ?verdict, upstream_addr = %upstream, "passing connection to upstream");
                        metrics.inc_passed();
                        if let Err(e) = Self::proxy_to_upstream(stream, upstream).await {
                            warn!(client_addr = %addr, upstream_addr = %upstream, error = %e, "upstream proxy error");
                        }
                    }
                    Ok(verdict @ Verdict::Drop) => {
                        debug!(client_addr = %addr, verdict = ?verdict, "dropping connection");
                        metrics.inc_dropped();
                        // Drop the connection.
                    }
                    Err(e) => {
                        warn!(client_addr = %addr, error = %e, "classification error, dropping connection");
                        metrics.inc_dropped();
                        // Drop the connection.
                    }
                }
            });
        }
    }

    /// Proxy a TCP stream to the nginx upstream.
    ///
    /// Connects to the upstream server and performs bidirectional copying
    /// of data between the inbound client stream and the upstream stream.
    ///
    /// # Arguments
    ///
    /// * `inbound` - Client TCP stream
    /// * `upstream` - Nginx upstream address to connect to
    ///
    /// # Errors
    ///
    /// Returns an error if connecting to upstream or bidirectional copy fails.
    async fn proxy_to_upstream(mut inbound: TcpStream, upstream: SocketAddr) -> io::Result<()> {
        trace!(upstream_addr = %upstream, "connecting to upstream");
        let mut outbound = TcpStream::connect(upstream).await?;
        trace!(upstream_addr = %upstream, "connected to upstream, starting bidirectional copy");
        let result = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
        match &result {
            Ok((bytes_inbound, bytes_outbound)) => {
                trace!(upstream_addr = %upstream, bytes_inbound = bytes_inbound, bytes_outbound = bytes_outbound, "proxy completed");
            }
            Err(e) => {
                error!(upstream_addr = %upstream, error = %e, "proxy bidirectional copy failed");
            }
        }
        result?;
        Ok(())
    }

    /// Classify a TCP stream by inspecting its TLS `ClientHello`.
    ///
    /// Peeks at the stream data with retries to handle slow arrivals,
    /// classifies the buffer, and returns a verdict. Respects the
    /// classification timeout and drops connections that send no data.
    ///
    /// # Arguments
    ///
    /// * `stream` - TCP stream to classify
    /// * `server_secret` - Secret key for HMAC verification
    ///
    /// # Returns
    ///
    /// The classification verdict (Claim, Pass, Drop, or Incomplete).
    ///
    /// # Errors
    ///
    /// Returns an error if peeking at the stream fails.
    async fn classify_stream(
        stream: &TcpStream,
        server_secret: SharedSecret,
    ) -> io::Result<Verdict> {
        let mut buf = vec![0u8; PEEK_LEN];
        let deadline = tokio::time::Instant::now() + CLASSIFY_TIMEOUT;
        let mut attempts = 0usize;

        trace!(
            timeout_ms = CLASSIFY_TIMEOUT.as_millis(),
            retry_delay_ms = CLASSIFY_RETRY_DELAY.as_millis(),
            buf_size = PEEK_LEN,
            "starting stream classification"
        );

        loop {
            let now = tokio::time::Instant::now();
            if now >= deadline {
                debug!(
                    attempts = attempts,
                    timeout_ms = CLASSIFY_TIMEOUT.as_millis(),
                    "classification timed out, verdict incomplete"
                );
                return Ok(Verdict::Incomplete);
            }

            let remaining = deadline.saturating_duration_since(now);
            let attempt = attempts;
            attempts += 1;
            let n = if let Ok(res) = tokio::time::timeout(remaining, stream.peek(&mut buf)).await {
                res?
            } else {
                debug!(
                    attempts = attempts,
                    timeout_ms = CLASSIFY_TIMEOUT.as_millis(),
                    "classification timed out waiting for stream data"
                );
                return Ok(Verdict::Incomplete);
            };
            trace!(attempt = attempt, bytes_peeked = n, "peeked at stream");

            if n == 0 {
                debug!("received zero bytes on peek, dropping connection");
                return Ok(Verdict::Drop);
            }

            let verdict = classify_tcp_client_hello(&buf[..n], &server_secret);
            trace!(attempt = attempt, bytes_peeked = n, verdict = ?verdict, "classification attempt");

            if verdict != Verdict::Incomplete {
                debug!(attempts = attempt + 1, final_bytes_peeked = n, verdict = ?verdict, "classification complete");
                return Ok(verdict);
            }

            trace!(
                attempt = attempt,
                bytes_peeked = n,
                "classification incomplete, waiting for more data"
            );

            let wait = CLASSIFY_RETRY_DELAY
                .min(deadline.saturating_duration_since(tokio::time::Instant::now()));
            if wait.is_zero() {
                continue;
            }
            tokio::time::sleep(wait).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use slt_core::config::ServerConfig;
    use slt_core::testing::generate_client_hello_tls_record;
    use slt_core::types::{
        ClientId, PubKeyEd25519, ServerClient, ServerNetworkConfig, ServerTimingConfig,
        ServerTlsConfig, SharedSecret, TlsMaterial, TunConfig,
    };
    use tokio::io::AsyncWriteExt;
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::mpsc;
    use tokio::time::timeout;
    use tokio_util::sync::CancellationToken;

    use super::TcpFrontDoor;
    use crate::metrics::Metrics;

    /// Create a test config with listen address set to "127.0.0.1:0" (any available port)
    /// and the upstream address set to the provided address.
    fn test_config(upstream_addr: SocketAddr) -> ServerConfig {
        ServerConfig {
            server_secret: SharedSecret([0x42u8; 32]),
            network: ServerNetworkConfig {
                listen_tcp: "127.0.0.1:0".parse().unwrap(),
                listen_udp: "127.0.0.1:0".parse().unwrap(),
                nginx_tcp_upstream: upstream_addr,
                nginx_udp_upstream: upstream_addr,
            },
            tls: ServerTlsConfig {
                tls_cert: TlsMaterial::Pem(String::new()),
                tls_key: TlsMaterial::Pem(String::new()),
            },
            tun: TunConfig {
                tun_name: "tun0".to_string(),
                tun_mtu: 1280,
            },
            timing: ServerTimingConfig {
                ping_min: Duration::from_secs(10),
                ping_max: Duration::from_secs(20),
                auth_timeout: Duration::from_secs(10),
                idle_timeout: Duration::from_secs(60),
            },
            udp_nat_max_entries: 1024,
            session_queue_size: 256,
            clients: vec![ServerClient {
                client_id: ClientId([0u8; 16]),
                pubkey_ed25519: PubKeyEd25519([0u8; 32]),
                assigned_ipv4: Ipv4Addr::new(10, 10, 0, 2),
                enabled: true,
            }],
        }
    }

    #[test]
    fn classify_delegates_to_classifier() {
        let secret = SharedSecret([0x42u8; 32]);
        let client_hello = generate_client_hello_tls_record(secret);

        let metrics = Arc::new(Metrics::default());
        // Bind upstream first to reserve its port (avoid TOCTOU race)
        let upstream_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();
        let config = test_config(upstream_addr);

        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            // Keep upstream_listener alive until front_door binds
            let _upstream = upstream_listener;
            let front_door = TcpFrontDoor::bind(&config, metrics).await.unwrap();

            // Claim verdict for matching secret
            assert_eq!(
                front_door.classify(&client_hello),
                slt_core::classifier::Verdict::Claim
            );

            // Pass verdict for non-matching secret
            let wrong_secret_client_hello =
                generate_client_hello_tls_record(SharedSecret([0x99u8; 32]));
            assert_eq!(
                front_door.classify(&wrong_secret_client_hello),
                slt_core::classifier::Verdict::Pass
            );

            // Incomplete for empty buffer
            assert_eq!(
                front_door.classify(&[]),
                slt_core::classifier::Verdict::Incomplete
            );

            // Incomplete for buffer smaller than TLS record header (5 bytes)
            assert_eq!(
                front_door.classify(&[0x00, 0x01, 0x02]),
                slt_core::classifier::Verdict::Incomplete
            );

            // Pass for non-TLS handshake data (content_type != 0x16)
            assert_eq!(
                front_door.classify(&[0x00, 0x03, 0x03, 0x00, 0x10]),
                slt_core::classifier::Verdict::Pass
            );
        });
    }

    #[tokio::test]
    async fn bind_creates_listener_on_configured_address() {
        let metrics = Arc::new(Metrics::default());
        // Bind upstream first to reserve its port
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();
        let config = test_config(upstream_addr);

        // Keep upstream_listener alive until front_door binds
        let _upstream = upstream_listener;
        let front_door = TcpFrontDoor::bind(&config, metrics).await.unwrap();

        // Verify listener is bound to localhost
        let addr = front_door.listener().local_addr().unwrap();
        assert_eq!(addr.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
    }

    #[tokio::test]
    async fn listener_returns_bound_socket() {
        let metrics = Arc::new(Metrics::default());
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();
        let config = test_config(upstream_addr);

        let _upstream = upstream_listener;
        let front_door = TcpFrontDoor::bind(&config, metrics).await.unwrap();
        let listener = front_door.listener();

        let addr = listener.local_addr().unwrap();
        assert!(!addr.ip().is_unspecified() || addr.ip() == IpAddr::V4(Ipv4Addr::LOCALHOST));
    }

    #[tokio::test]
    async fn run_exits_on_cancellation() {
        let metrics = Arc::new(Metrics::default());
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();
        let config = test_config(upstream_addr);

        let _upstream = upstream_listener;
        let front_door = TcpFrontDoor::bind(&config, metrics).await.unwrap();
        let cancel = CancellationToken::new();

        let cancel_clone = cancel.clone();
        let run_task = tokio::spawn(async move { front_door.run(cancel_clone, |_, _| {}).await });

        cancel.cancel();

        let result = timeout(Duration::from_millis(500), run_task).await;
        assert!(result.is_ok(), "run should exit quickly on cancellation");
        assert!(result.unwrap().is_ok(), "run should return Ok(())");
    }

    #[tokio::test]
    async fn run_invokes_claim_handler_for_matching_client_hello() {
        let secret = SharedSecret([0x42u8; 32]);
        let metrics = Arc::new(Metrics::default());
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();
        let config = test_config(upstream_addr);

        let _upstream = upstream_listener;
        let front_door = TcpFrontDoor::bind(&config, metrics.clone()).await.unwrap();
        let cancel = CancellationToken::new();
        let listen_addr = front_door.listener().local_addr().unwrap();

        let claim_count = Arc::new(AtomicUsize::new(0));
        let claim_count_clone = claim_count.clone();
        let cancel_for_run = cancel.clone();
        let cancel_for_handler = cancel.clone();

        let run_task = tokio::spawn(async move {
            front_door
                .run(cancel_for_run, move |_, _| {
                    claim_count_clone.fetch_add(1, Ordering::SeqCst);
                    cancel_for_handler.cancel();
                })
                .await
        });

        let mut stream = TcpStream::connect(listen_addr).await.unwrap();
        let client_hello = generate_client_hello_tls_record(secret);
        stream.write_all(&client_hello).await.unwrap();

        let result = timeout(Duration::from_secs(2), run_task).await;
        assert!(result.is_ok(), "run should exit after claim");
        assert_eq!(
            claim_count.load(Ordering::SeqCst),
            1,
            "claim handler should be called once"
        );

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.tcp_accepted, 1);
        assert_eq!(snapshot.claimed, 1);
    }

    #[tokio::test]
    async fn run_proxies_to_upstream_for_non_matching_client_hello() {
        let metrics = Arc::new(Metrics::default());
        // Bind upstream first to reserve its port
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();
        let config = test_config(upstream_addr);

        let front_door = TcpFrontDoor::bind(&config, metrics.clone()).await.unwrap();
        let cancel = CancellationToken::new();
        let listen_addr = front_door.listener().local_addr().unwrap();

        let cancel_clone = cancel.clone();
        let run_task = tokio::spawn(async move { front_door.run(cancel_clone, |_, _| {}).await });

        // Accept on upstream
        let upstream_task = tokio::spawn(async move {
            let (mut upstream_stream, _) = upstream_listener.accept().await.unwrap();
            use tokio::io::AsyncReadExt;
            let mut buf = [0u8; 1024];
            let n = upstream_stream.read(&mut buf).await.unwrap();
            upstream_stream.write_all(&buf[..n]).await.unwrap();
        });

        let mut stream = TcpStream::connect(listen_addr).await.unwrap();
        let wrong_secret = SharedSecret([0x99u8; 32]);
        let client_hello = generate_client_hello_tls_record(wrong_secret);
        stream.write_all(&client_hello).await.unwrap();

        let upstream_result = timeout(Duration::from_secs(2), upstream_task).await;
        assert!(
            upstream_result.is_ok(),
            "upstream should receive connection"
        );

        cancel.cancel();
        let _ = timeout(Duration::from_millis(500), run_task).await;

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.tcp_accepted, 1);
        assert_eq!(snapshot.passed, 1);
    }

    #[tokio::test]
    async fn run_drops_connection_on_zero_byte_peek() {
        let metrics = Arc::new(Metrics::default());
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();
        let config = test_config(upstream_addr);

        let _upstream = upstream_listener;
        let front_door = TcpFrontDoor::bind(&config, metrics.clone()).await.unwrap();
        let cancel = CancellationToken::new();
        let listen_addr = front_door.listener().local_addr().unwrap();

        let cancel_clone = cancel.clone();
        let run_task = tokio::spawn(async move { front_door.run(cancel_clone, |_, _| {}).await });

        // Connect and immediately close without sending data
        {
            let _stream = TcpStream::connect(listen_addr).await.unwrap();
        }

        tokio::time::sleep(Duration::from_millis(100)).await;

        cancel.cancel();
        let _ = timeout(Duration::from_millis(500), run_task).await;

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.tcp_accepted, 1);
        assert_eq!(snapshot.dropped, 1);
    }

    #[tokio::test]
    async fn run_handles_multiple_connections_concurrently() {
        let secret = SharedSecret([0x42u8; 32]);
        let metrics = Arc::new(Metrics::default());
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();
        let config = test_config(upstream_addr);

        let _upstream = upstream_listener;
        let front_door = TcpFrontDoor::bind(&config, metrics.clone()).await.unwrap();
        let cancel = CancellationToken::new();
        let listen_addr = front_door.listener().local_addr().unwrap();

        let claim_count = Arc::new(AtomicUsize::new(0));
        let claim_count_clone = claim_count.clone();
        let (tx, mut rx) = mpsc::channel::<()>(3);

        let cancel_clone = cancel.clone();
        let tx_clone = tx.clone();
        let run_task = tokio::spawn(async move {
            front_door
                .run(cancel_clone, move |_, _| {
                    claim_count_clone.fetch_add(1, Ordering::SeqCst);
                    let _ = tx_clone.try_send(());
                })
                .await
        });

        let mut handles = vec![];
        for _ in 0..3 {
            let addr = listen_addr;
            let secret = secret;
            let handle = tokio::spawn(async move {
                let mut stream = TcpStream::connect(addr).await.unwrap();
                let client_hello = generate_client_hello_tls_record(secret);
                stream.write_all(&client_hello).await.unwrap();
            });
            handles.push(handle);
        }

        for _ in 0..3 {
            let result = timeout(Duration::from_secs(2), rx.recv()).await;
            assert!(result.is_ok(), "should receive claim notification");
        }

        cancel.cancel();
        let _ = timeout(Duration::from_millis(500), run_task).await;

        assert_eq!(claim_count.load(Ordering::SeqCst), 3);

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.tcp_accepted, 3);
        assert_eq!(snapshot.claimed, 3);
    }

    /// Test that `Verdict::Incomplete` routes to upstream.
    /// This covers the branch where classification returns `Incomplete`
    /// after the classification timeout.
    #[tokio::test]
    async fn run_routes_incomplete_verdict_to_upstream() {
        let metrics = Arc::new(Metrics::default());
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();
        let config = test_config(upstream_addr);

        let front_door = TcpFrontDoor::bind(&config, metrics.clone()).await.unwrap();
        let cancel = CancellationToken::new();
        let listen_addr = front_door.listener().local_addr().unwrap();

        let cancel_clone = cancel.clone();
        let run_task = tokio::spawn(async move { front_door.run(cancel_clone, |_, _| {}).await });

        // Track if upstream received a connection
        let upstream_received = Arc::new(AtomicUsize::new(0));
        let upstream_received_clone = upstream_received.clone();
        let upstream_task = tokio::spawn(async move {
            // Accept on upstream with timeout
            let accept_result = timeout(Duration::from_secs(2), upstream_listener.accept()).await;
            if let Ok(Ok((mut upstream_stream, _))) = accept_result {
                upstream_received_clone.fetch_add(1, Ordering::SeqCst);
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut buf = [0u8; 1024];
                if let Ok(n) = upstream_stream.read(&mut buf).await {
                    // Echo back
                    let _ = upstream_stream.write_all(&buf[..n]).await;
                }
            }
        });

        // Send partial TLS data that triggers Incomplete (less than 5 bytes)
        let mut stream = TcpStream::connect(listen_addr).await.unwrap();
        // Send only 3 bytes - too small for TLS record header, classifier returns Incomplete
        stream.write_all(&[0x16, 0x03, 0x01]).await.unwrap();
        // Keep stream alive briefly then close
        tokio::time::sleep(Duration::from_millis(100)).await;
        drop(stream);

        let upstream_result = timeout(Duration::from_secs(2), upstream_task).await;
        assert!(
            upstream_result.is_ok(),
            "upstream should receive connection for Incomplete verdict"
        );
        assert_eq!(
            upstream_received.load(Ordering::SeqCst),
            1,
            "upstream should have received exactly one connection"
        );

        cancel.cancel();
        let _ = timeout(Duration::from_millis(500), run_task).await;

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.tcp_accepted, 1);
        assert_eq!(
            snapshot.passed, 1,
            "Incomplete verdict should increment passed metric"
        );
    }

    /// Test upstream connect failure path (lines 100, 121).
    /// When upstream is unreachable, the proxy should handle the error gracefully.
    #[tokio::test]
    async fn run_handles_upstream_connect_failure() {
        let metrics = Arc::new(Metrics::default());
        // Use a non-routable address to trigger connect failure
        // 10.255.255.1 is typically not routed
        let non_routable_upstream: SocketAddr = "10.255.255.1:12345".parse().unwrap();
        let config = test_config(non_routable_upstream);

        let front_door = TcpFrontDoor::bind(&config, metrics.clone()).await.unwrap();
        let cancel = CancellationToken::new();
        let listen_addr = front_door.listener().local_addr().unwrap();

        let cancel_clone = cancel.clone();
        let (tx, mut rx) = mpsc::channel::<()>(1);
        let tx_clone = tx.clone();
        let run_task = tokio::spawn(async move {
            front_door
                .run(cancel_clone, move |_, _| {
                    let _ = tx_clone.try_send(());
                })
                .await
        });

        // Send non-matching ClientHello to trigger upstream routing
        let mut stream = TcpStream::connect(listen_addr).await.unwrap();
        let wrong_secret = SharedSecret([0x99u8; 32]);
        let client_hello = generate_client_hello_tls_record(wrong_secret);
        stream.write_all(&client_hello).await.unwrap();

        // Wait for the connection attempt to complete (with timeout since connect will fail)
        // The run loop should continue despite the failure
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Verify the front door is still running by sending another connection
        let mut stream2 = TcpStream::connect(listen_addr).await.unwrap();
        stream2.write_all(&client_hello).await.unwrap();

        tokio::time::sleep(Duration::from_millis(100)).await;

        cancel.cancel();
        let _ = timeout(Duration::from_millis(500), run_task).await;

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.tcp_accepted, 2);
        assert_eq!(
            snapshot.passed, 2,
            "both connections should be passed to upstream"
        );
        // Verify claim handler was never called
        assert!(
            rx.try_recv().is_err(),
            "claim handler should not be called for non-matching ClientHello"
        );
    }

    /// Test upstream bidirectional copy failure path (line 123).
    /// When upstream closes connection during proxy, error should be handled.
    #[tokio::test]
    async fn run_handles_upstream_copy_failure() {
        let metrics = Arc::new(Metrics::default());
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();
        let config = test_config(upstream_addr);

        let front_door = TcpFrontDoor::bind(&config, metrics.clone()).await.unwrap();
        let cancel = CancellationToken::new();
        let listen_addr = front_door.listener().local_addr().unwrap();

        let cancel_clone = cancel.clone();
        let run_task = tokio::spawn(async move { front_door.run(cancel_clone, |_, _| {}).await });

        // Accept upstream connection and immediately close it
        let upstream_task = tokio::spawn(async move {
            let (upstream_stream, _) = timeout(Duration::from_secs(2), upstream_listener.accept())
                .await
                .expect("upstream should receive connection")
                .expect("accept should succeed");
            // Immediately drop to cause copy failure
            drop(upstream_stream);
        });

        // Send non-matching ClientHello
        let mut stream = TcpStream::connect(listen_addr).await.unwrap();
        let wrong_secret = SharedSecret([0x99u8; 32]);
        let client_hello = generate_client_hello_tls_record(wrong_secret);
        stream.write_all(&client_hello).await.unwrap();

        // Wait for upstream to close
        let upstream_result = timeout(Duration::from_secs(2), upstream_task).await;
        assert!(upstream_result.is_ok(), "upstream task should complete");

        // Give time for the proxy error to be handled
        tokio::time::sleep(Duration::from_millis(100)).await;

        cancel.cancel();
        let _ = timeout(Duration::from_millis(500), run_task).await;

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.tcp_accepted, 1);
        assert_eq!(snapshot.passed, 1);
    }

    /// Test bind() error path when address is already in use (line 36).
    #[tokio::test]
    async fn bind_fails_when_address_in_use() {
        let metrics = Arc::new(Metrics::default());

        // Bind to a specific port first
        let first_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let bound_addr = first_listener.local_addr().unwrap();

        // Create config with the same address
        let mut config = test_config("127.0.0.1:0".parse().unwrap());
        config.network.listen_tcp = bound_addr;

        // Keep first listener alive and try to bind to same address
        let _first = first_listener;
        let result = TcpFrontDoor::bind(&config, metrics).await;

        assert!(
            result.is_err(),
            "bind should fail when address is already in use"
        );
        let err = result.unwrap_err();
        assert_eq!(
            err.kind(),
            std::io::ErrorKind::AddrInUse,
            "error should be AddrInUse"
        );
    }

    /// Test that classify_stream correctly classifies complete ClientHello data.
    /// This verifies the peek loop logic works correctly when full data is available.
    #[tokio::test]
    async fn classify_stream_classifies_complete_client_hello() {
        let secret = SharedSecret([0x42u8; 32]);

        // Create a listener for our test connection
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Spawn a task that accepts connection and classifies it
        let classify_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            TcpFrontDoor::classify_stream(&stream, secret).await
        });

        // Connect and send complete ClientHello
        let mut client = TcpStream::connect(addr).await.unwrap();
        let client_hello = generate_client_hello_tls_record(secret);
        client.write_all(&client_hello).await.unwrap();
        client.flush().await.unwrap();

        // Classification should succeed with complete data
        let result = tokio::select! {
            result = classify_task => result,
            _ = tokio::time::sleep(Duration::from_secs(2)) => {
                panic!("classification timed out");
            }
        };

        let verdict = result
            .expect("task should not panic")
            .expect("classification should not error");
        assert!(
            matches!(verdict, slt_core::classifier::Verdict::Claim),
            "should claim valid ClientHello"
        );

        drop(client);
    }

    /// Test that classification timeout returns Incomplete.
    /// When data never arrives to complete classification, it should return Incomplete.
    #[tokio::test]
    async fn classify_stream_returns_incomplete_after_classification_timeout() {
        let secret = SharedSecret([0x42u8; 32]);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let classify_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            TcpFrontDoor::classify_stream(&stream, secret).await
        });

        // Connect and send minimal data that triggers Incomplete
        let mut client = TcpStream::connect(addr).await.unwrap();
        // Send just 4 bytes - too small for TLS record header (needs 5)
        client.write_all(&[0x16, 0x03, 0x01, 0x00]).await.unwrap();

        // Don't send more data - let classification timeout expire
        let result = timeout(Duration::from_secs(2), classify_task).await;
        assert!(result.is_ok(), "classification should complete");
        let verdict = result
            .expect("classification should complete")
            .expect("task should not panic")
            .expect("classification should not error");
        assert!(
            matches!(verdict, slt_core::classifier::Verdict::Incomplete),
            "should return Incomplete when classification timeout expires without complete data"
        );
    }

    #[tokio::test]
    async fn classify_stream_returns_incomplete_when_no_data_arrives() {
        let secret = SharedSecret([0x42u8; 32]);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let classify_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            TcpFrontDoor::classify_stream(&stream, secret).await
        });

        // Connect but never send data.
        let _client = TcpStream::connect(addr).await.unwrap();

        let result = timeout(Duration::from_secs(2), classify_task).await;
        assert!(result.is_ok(), "classification should complete");
        let verdict = result
            .expect("classification should complete")
            .expect("task should not panic")
            .expect("classification should not error");
        assert!(
            matches!(verdict, slt_core::classifier::Verdict::Incomplete),
            "should return Incomplete when no bytes arrive before classification timeout"
        );
    }
}
