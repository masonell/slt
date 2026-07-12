use std::sync::Arc;
use std::time::Duration;

use slt_core::transport::gro_datagram_ranges;
use tokio::time::{Instant, timeout};
use tokio_util::sync::CancellationToken;

use super::super::QuicEndpoint;
use super::{FailingUpstreamSocketFactory, make_endpoint, make_quic_long_header, test_config};
use crate::metrics::Metrics;
use crate::registry::SessionRegistry;

/// The GRO stride-split math must produce one range per coalesced datagram,
/// with the last range clipped to `len`, and never panic/infinite-loop on a
/// malformed `stride == 0`.
#[test]
fn gro_datagram_ranges_splits_coalesced_buffer() {
    let eq: Vec<_> = gro_datagram_ranges(4096, 1024).collect();
    assert_eq!(
        eq,
        vec![(0, 1024), (1024, 2048), (2048, 3072), (3072, 4096)]
    );

    let partial: Vec<_> = gro_datagram_ranges(2500, 1024).collect();
    assert_eq!(partial, vec![(0, 1024), (1024, 2048), (2048, 2500)]);

    let single: Vec<_> = gro_datagram_ranges(1406, 1406).collect();
    assert_eq!(single, vec![(0, 1406)]);

    let zero: Vec<_> = gro_datagram_ranges(3, 0).collect();
    assert_eq!(zero, vec![(0, 1), (1, 2), (2, 3)]);

    assert!(gro_datagram_ranges(0, 1406).next().is_none());
}

#[tokio::test]
async fn bind_rejects_zero_udp_nat_max_entries() {
    let mut config = test_config();
    config.udp_nat_max_entries = 0;
    let registry = Arc::new(SessionRegistry::new());
    let metrics = Arc::new(Metrics::default());

    let result = QuicEndpoint::bind(&config, registry, metrics);
    assert!(result.is_err());
    if let Err(err) = result {
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert!(
            err.to_string()
                .contains("udp_nat_max_entries must be non-zero")
        );
    }
}

#[tokio::test]
async fn bind_rejects_zero_idle_timeout() {
    let mut config = test_config();
    config.timing.idle_timeout = Duration::ZERO;
    let registry = Arc::new(SessionRegistry::new());
    let metrics = Arc::new(Metrics::default());

    let result = QuicEndpoint::bind(&config, registry, metrics);
    assert!(result.is_err());
    if let Err(err) = result {
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains("idle_timeout must be non-zero"));
    }
}

#[tokio::test]
async fn bind_binds_udp_socket_on_listen_addr() {
    let config = test_config();
    let registry = Arc::new(SessionRegistry::new());
    let metrics = Arc::new(Metrics::default());

    let endpoint = QuicEndpoint::bind(&config, registry, metrics);
    assert!(endpoint.is_ok());
    let endpoint = endpoint.unwrap();
    let local_addr = endpoint.socket().local_addr().unwrap();
    assert!(local_addr.port() > 0);
    assert!(local_addr.ip().is_loopback());
}

#[tokio::test]
async fn run_exits_on_cancellation() {
    let mut endpoint = make_endpoint().await;
    let cancel = CancellationToken::new();
    let cancel_clone = cancel.clone();

    let handle = tokio::spawn(async move { endpoint.run(cancel_clone).await });

    tokio::time::sleep(Duration::from_millis(10)).await;
    cancel.cancel();

    let result = timeout(Duration::from_secs(1), handle).await;
    assert!(result.is_ok());
    let inner = result.unwrap();
    assert!(inner.is_ok());
    assert!(inner.unwrap().is_ok());
}

#[tokio::test]
async fn run_forwards_pass_datagrams_and_counts_udp_accepted_and_passed() {
    let upstream_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_socket.local_addr().unwrap();

    let mut config = test_config();
    config.network.nginx_udp_upstream = upstream_addr;
    config.timing.idle_timeout = Duration::from_millis(200);

    let registry = Arc::new(SessionRegistry::new());
    let metrics = Arc::new(Metrics::default());
    let mut endpoint = QuicEndpoint::bind(&config, registry, metrics.clone()).unwrap();
    let listen_addr = endpoint.socket().local_addr().unwrap();

    let cancel = CancellationToken::new();
    let cancel_clone = cancel.clone();
    let run_task = tokio::spawn(async move { endpoint.run(cancel_clone).await });

    let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let payload = make_quic_long_header();
    peer.send_to(&payload, listen_addr).await.unwrap();

    let mut buf = [0u8; 256];
    let (len, _) = timeout(Duration::from_secs(1), upstream_socket.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(len, payload.len());

    let deadline = Instant::now() + Duration::from_secs(1);
    loop {
        let snap = metrics.snapshot();
        if snap.udp_accepted == 1 && snap.passed == 1 {
            break;
        }
        assert!(Instant::now() < deadline, "metrics did not update in time");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    cancel.cancel();
    let run_result = timeout(Duration::from_secs(1), run_task).await.unwrap();
    assert!(run_result.unwrap().is_ok());
}

#[tokio::test]
async fn run_continues_after_upstream_socket_setup_failure() {
    let upstream_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_socket.local_addr().unwrap();

    let mut config = test_config();
    config.network.nginx_udp_upstream = upstream_addr;

    let registry = Arc::new(SessionRegistry::new());
    let metrics = Arc::new(Metrics::default());
    let factory = Arc::new(FailingUpstreamSocketFactory::new(1));
    let mut endpoint = QuicEndpoint::bind(&config, registry, metrics.clone())
        .unwrap()
        .with_upstream_socket_factory(factory.clone());
    let listen_addr = endpoint.socket().local_addr().unwrap();

    let cancel = CancellationToken::new();
    let cancel_clone = cancel.clone();
    let run_task = tokio::spawn(async move { endpoint.run(cancel_clone).await });

    let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let payload = make_quic_long_header();
    peer.send_to(&payload, listen_addr).await.unwrap();

    let deadline = Instant::now() + Duration::from_secs(1);
    loop {
        if metrics.snapshot().udp_upstream_setup_failure_drops == 1 {
            break;
        }
        assert!(Instant::now() < deadline, "failure metric did not update");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        !run_task.is_finished(),
        "UDP worker stopped after setup failure"
    );

    peer.send_to(&payload, listen_addr).await.unwrap();
    let mut buf = [0u8; 256];
    let (len, _) = timeout(Duration::from_secs(1), upstream_socket.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(len, payload.len());

    let snapshot = metrics.snapshot();
    assert_eq!(snapshot.udp_accepted, 2);
    assert_eq!(snapshot.passed, 2);
    assert_eq!(snapshot.udp_upstream_setup_failure_drops, 1);
    assert_eq!(factory.attempts(), 2);

    cancel.cancel();
    let run_result = timeout(Duration::from_secs(1), run_task).await.unwrap();
    assert!(run_result.unwrap().is_ok());
}

#[tokio::test]
async fn run_sweep_idle_recreates_nat_socket_after_timeout() {
    let upstream_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_socket.local_addr().unwrap();

    let mut config = test_config();
    config.network.nginx_udp_upstream = upstream_addr;
    config.timing.idle_timeout = Duration::from_millis(50);

    let registry = Arc::new(SessionRegistry::new());
    let metrics = Arc::new(Metrics::default());
    let mut endpoint = QuicEndpoint::bind(&config, registry, metrics).unwrap();
    let listen_addr = endpoint.socket().local_addr().unwrap();

    let cancel = CancellationToken::new();
    let cancel_clone = cancel.clone();
    let run_task = tokio::spawn(async move { endpoint.run(cancel_clone).await });

    let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let payload = make_quic_long_header();

    peer.send_to(&payload, listen_addr).await.unwrap();
    let mut buf = [0u8; 256];
    let (_, first_src) = timeout(Duration::from_secs(1), upstream_socket.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();

    tokio::time::sleep(Duration::from_millis(220)).await;

    peer.send_to(&payload, listen_addr).await.unwrap();
    let (_, second_src) = timeout(Duration::from_secs(1), upstream_socket.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();

    assert_ne!(
        first_src.port(),
        second_src.port(),
        "idle eviction should recreate upstream socket with a new local port"
    );

    cancel.cancel();
    let run_result = timeout(Duration::from_secs(1), run_task).await.unwrap();
    assert!(run_result.unwrap().is_ok());
}
