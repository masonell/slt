use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use slt_core::classifier::Verdict;
use slt_core::config::ServerConfig;
use slt_core::testing::generate_client_hello_tls_record;
use slt_core::types::{
    ClientId, PubKeyEd25519, ServerClient, ServerNetworkConfig, ServerTimingConfig,
    ServerTlsConfig, ServerTransportConfig, SharedSecret, TlsMaterial, TunConfig,
};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

use super::TcpFrontDoor;
use super::admission::{EMPTY_EVICTION_SCAN_LIMIT, TcpAdmission};
use super::classification::{
    CLASSIFY_RETRY_DELAY, CLASSIFY_STABLE_RETRY_MAX_DELAY, classify_stream, classify_stream_fast,
    next_incomplete_retry_delay,
};
use super::stream_io::stream_has_no_buffered_data;
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
            tun_ipv4: Ipv4Addr::new(10, 10, 0, 1),
            tun_prefix: 24,
        },
        timing: ServerTimingConfig {
            ping_min: Duration::from_secs(10),
            ping_max: Duration::from_secs(20),
            auth_timeout: Duration::from_secs(10),
            tcp_write_timeout: Duration::from_secs(10),
            idle_timeout: Duration::from_mins(1),
            metrics_interval: Duration::from_mins(5),
            tcp_classification_timeout: Duration::from_secs(60),
        },
        transport: ServerTransportConfig::default(),
        udp_nat_max_entries: 1024,
        session_queue_size: 256,
        max_auth_inflight: 128,
        tcp_connection_cap: 512,
        clients: vec![ServerClient {
            client_id: ClientId([0u8; 16]),
            pubkey_ed25519: PubKeyEd25519([0u8; 32]),
            assigned_ipv4: Ipv4Addr::new(10, 10, 0, 2),
            enabled: true,
        }],
    }
}

fn test_config_with_tcp_limits(
    upstream_addr: SocketAddr,
    tcp_connection_cap: usize,
    tcp_classification_timeout: Duration,
) -> ServerConfig {
    let mut config = test_config(upstream_addr);
    config.tcp_connection_cap = tcp_connection_cap;
    config.timing.tcp_classification_timeout = tcp_classification_timeout;
    config
}

#[test]
fn incomplete_retry_delay_backs_off_until_buffer_grows() {
    let mut last_len = None;
    let mut delay = CLASSIFY_RETRY_DELAY;

    assert_eq!(
        next_incomplete_retry_delay(&mut last_len, &mut delay, 4),
        CLASSIFY_RETRY_DELAY
    );
    assert_eq!(
        next_incomplete_retry_delay(&mut last_len, &mut delay, 4),
        Duration::from_millis(10)
    );
    assert_eq!(
        next_incomplete_retry_delay(&mut last_len, &mut delay, 4),
        Duration::from_millis(20)
    );
    assert_eq!(
        next_incomplete_retry_delay(&mut last_len, &mut delay, 5),
        CLASSIFY_RETRY_DELAY
    );

    for _ in 0..16 {
        let _ = next_incomplete_retry_delay(&mut last_len, &mut delay, 5);
    }
    assert_eq!(delay, CLASSIFY_STABLE_RETRY_MAX_DELAY);
}

#[test]
fn admission_does_not_mark_fresh_permit_as_empty() {
    let admission = Arc::new(TcpAdmission::new(1));

    let first = admission.admit_or_evict_empty();
    assert!(first.permit.is_some());
    assert!(!first.evicted_empty);

    let second = admission.admit_or_evict_empty();
    assert!(second.permit.is_none());
    assert!(!second.evicted_empty);
}

#[cfg(unix)]
#[tokio::test]
async fn admission_does_not_evict_data_ready_empty_candidate() {
    let admission = Arc::new(TcpAdmission::new(1));
    let permit = admission
        .admit_or_evict_empty()
        .permit
        .expect("first connection should be admitted");

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let mut client = TcpStream::connect(addr).await.unwrap();
    let (server, _) = listener.accept().await.unwrap();
    let server = Arc::new(server);

    assert!(permit.mark_no_data_if_empty(&server));
    client.write_all(&[0x16]).await.unwrap();
    timeout(Duration::from_secs(1), async {
        while stream_has_no_buffered_data(&server) {
            server.readable().await.unwrap();
        }
    })
    .await
    .expect("server byte should become visible to nonblocking peek");

    let second = admission.admit_or_evict_empty();
    assert!(second.permit.is_none());
    assert!(!second.evicted_empty);
    assert!(permit.mark_data_seen());
}

#[cfg(unix)]
#[tokio::test]
async fn mark_data_seen_reports_concurrent_eviction() {
    let admission = Arc::new(TcpAdmission::new(1));
    let permit = admission
        .admit_or_evict_empty()
        .permit
        .expect("first connection should be admitted");

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let client = TcpStream::connect(addr).await.unwrap();
    let (server, _) = listener.accept().await.unwrap();
    let server = Arc::new(server);

    assert!(permit.mark_no_data_if_empty(&server));

    let second = admission.admit_or_evict_empty();
    assert!(second.permit.is_some());
    assert!(second.evicted_empty);
    assert!(!permit.mark_data_seen());

    drop(client);
}

#[cfg(unix)]
#[tokio::test]
async fn admission_rescans_once_after_unlinking_stale_no_data_entries() {
    let admission = Arc::new(TcpAdmission::new(EMPTY_EVICTION_SCAN_LIMIT + 1));
    let mut permits = Vec::new();
    let mut clients = Vec::new();
    let mut servers = Vec::new();

    for _ in 0..=EMPTY_EVICTION_SCAN_LIMIT {
        let permit = admission
            .admit_or_evict_empty()
            .permit
            .expect("connection should be admitted below cap");

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        let server = Arc::new(server);

        assert!(permit.mark_no_data_if_empty(&server));
        permits.push(permit);
        clients.push(client);
        servers.push(server);
    }

    for (client, server) in clients
        .iter_mut()
        .zip(servers.iter())
        .take(EMPTY_EVICTION_SCAN_LIMIT)
    {
        client.write_all(&[0x16]).await.unwrap();
        timeout(Duration::from_secs(1), async {
            while stream_has_no_buffered_data(server) {
                server.readable().await.unwrap();
            }
        })
        .await
        .expect("server byte should become visible to nonblocking peek");
    }

    let attempt = admission.admit_or_evict_empty();
    assert!(attempt.evicted_empty);
    assert!(attempt.permit.is_some());

    drop(permits);
    drop(clients);
    drop(servers);
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

/// Test that `Verdict::Incomplete` times out and drops without upstream proxying.
#[tokio::test]
async fn run_drops_incomplete_verdict_after_classification_timeout() {
    let metrics = Arc::new(Metrics::default());
    let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_listener.local_addr().unwrap();
    let config = test_config_with_tcp_limits(upstream_addr, 512, Duration::from_millis(50));

    let front_door = TcpFrontDoor::bind(&config, metrics.clone()).await.unwrap();
    let cancel = CancellationToken::new();
    let listen_addr = front_door.listener().local_addr().unwrap();

    let cancel_clone = cancel.clone();
    let run_task = tokio::spawn(async move { front_door.run(cancel_clone, |_, _| {}).await });

    let upstream_task = tokio::spawn(async move {
        timeout(Duration::from_millis(250), upstream_listener.accept()).await
    });

    let mut stream = TcpStream::connect(listen_addr).await.unwrap();
    stream.write_all(&[0x16, 0x03, 0x01]).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    drop(stream);

    let upstream_result = upstream_task.await.unwrap();
    assert_eq!(
        upstream_result.unwrap_err().to_string(),
        "deadline has elapsed"
    );

    cancel.cancel();
    let _ = timeout(Duration::from_millis(500), run_task).await;

    let snapshot = metrics.snapshot();
    assert_eq!(snapshot.tcp_accepted, 1);
    assert_eq!(snapshot.passed, 0);
    assert_eq!(snapshot.dropped, 1);
    assert_eq!(snapshot.tcp_classification_timeouts, 1);
}

#[tokio::test]
async fn run_evicts_oldest_empty_classifier_under_cap_pressure() {
    let metrics = Arc::new(Metrics::default());
    let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_listener.local_addr().unwrap();
    let config = test_config_with_tcp_limits(upstream_addr, 1, Duration::from_secs(2));

    let _upstream = upstream_listener;
    let front_door = TcpFrontDoor::bind(&config, metrics.clone()).await.unwrap();
    let cancel = CancellationToken::new();
    let listen_addr = front_door.listener().local_addr().unwrap();

    let cancel_clone = cancel.clone();
    let run_task = tokio::spawn(async move { front_door.run(cancel_clone, |_, _| {}).await });

    let first = TcpStream::connect(listen_addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;

    let second = TcpStream::connect(listen_addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    let snapshot = metrics.snapshot();
    assert_eq!(snapshot.tcp_accepted, 2);
    assert_eq!(snapshot.tcp_empty_classification_evictions, 1);
    assert_eq!(snapshot.tcp_frontdoor_cap_drops, 0);
    assert_eq!(snapshot.dropped, 1);

    drop(first);
    drop(second);
    cancel.cancel();
    let _ = timeout(Duration::from_millis(500), run_task).await;
}

#[tokio::test]
async fn run_drops_new_over_cap_connection_when_no_empty_slot_exists() {
    let metrics = Arc::new(Metrics::default());
    let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_listener.local_addr().unwrap();
    let config = test_config_with_tcp_limits(upstream_addr, 1, Duration::from_secs(2));

    let _upstream = upstream_listener;
    let front_door = TcpFrontDoor::bind(&config, metrics.clone()).await.unwrap();
    let cancel = CancellationToken::new();
    let listen_addr = front_door.listener().local_addr().unwrap();

    let cancel_clone = cancel.clone();
    let run_task = tokio::spawn(async move { front_door.run(cancel_clone, |_, _| {}).await });

    let mut first = TcpStream::connect(listen_addr).await.unwrap();
    first.write_all(&[0x16, 0x03, 0x01]).await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;

    let second = TcpStream::connect(listen_addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    let snapshot = metrics.snapshot();
    assert_eq!(snapshot.tcp_accepted, 2);
    assert_eq!(snapshot.tcp_empty_classification_evictions, 0);
    assert_eq!(snapshot.tcp_frontdoor_cap_drops, 1);
    assert_eq!(snapshot.dropped, 1);

    drop(first);
    drop(second);
    cancel.cancel();
    let _ = timeout(Duration::from_millis(500), run_task).await;
}

#[tokio::test]
async fn fast_classification_claims_when_full_client_hello_is_buffered() {
    let secret = SharedSecret([0x42u8; 32]);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let client_hello = generate_client_hello_tls_record(secret);
    let client_task = tokio::spawn(async move {
        let mut client = TcpStream::connect(addr).await.unwrap();
        client.write_all(&client_hello).await.unwrap();
        client
    });

    let (stream, _) = listener.accept().await.unwrap();
    let client = client_task.await.unwrap();

    let verdict = classify_stream_fast(&stream, secret).unwrap();
    assert_eq!(verdict, Verdict::Claim);

    drop(client);
}

/// Verify upstream connect failures do not stop the accept loop.
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

/// Verify upstream copy failures are contained to the proxied connection.
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

/// Test `bind()` error path when address is already in use.
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

/// Test that `classify_stream` correctly classifies complete `ClientHello` data.
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
        classify_stream(&stream, secret, Duration::from_secs(2)).await
    });

    // Connect and send complete ClientHello
    let mut client = TcpStream::connect(addr).await.unwrap();
    let client_hello = generate_client_hello_tls_record(secret);
    client.write_all(&client_hello).await.unwrap();
    client.flush().await.unwrap();

    // Classification should succeed with complete data
    let result = tokio::select! {
        result = classify_task => result,
        () = tokio::time::sleep(Duration::from_secs(2)) => {
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
        classify_stream(&stream, secret, Duration::from_millis(50)).await
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
        classify_stream(&stream, secret, Duration::from_millis(50)).await
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
