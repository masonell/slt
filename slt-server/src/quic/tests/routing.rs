use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Duration;

use slt_core::types::QUIC_DCID_PREFIX_LEN;
use tokio::sync::mpsc;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

use super::super::{PeerEntry, QuicEndpoint, QuicNatState};
use super::{
    FailingUpstreamSocketFactory, make_endpoint, make_non_quic_packet, make_quic_long_header,
    make_quic_short_header, register_test_cid_route,
};
use crate::metrics::Metrics;
use crate::registry::SessionRegistry;
use crate::sessions::SessionEvent;

#[tokio::test]
async fn handle_datagram_drop_increments_dropped_metric() {
    let endpoint = make_endpoint().await;
    let mut state = QuicNatState::new(NonZeroUsize::new(1024).unwrap());
    let cancel = CancellationToken::new();
    let peer = SocketAddr::from(([127, 0, 0, 1], 12345));
    let payload = make_non_quic_packet();

    let before = endpoint.metrics.snapshot().dropped;
    endpoint
        .handle_datagram(&mut state, cancel, peer, payload)
        .await;
    let after = endpoint.metrics.snapshot().dropped;
    assert_eq!(after, before + 1);
}

#[tokio::test]
async fn handle_datagram_upstream_setup_failures_drop_and_continue() {
    let factory = Arc::new(FailingUpstreamSocketFactory::new(2));
    let endpoint = make_endpoint()
        .await
        .with_upstream_socket_factory(factory.clone());
    let mut state = QuicNatState::new(NonZeroUsize::new(1024).unwrap());
    let cancel = CancellationToken::new();
    let peer = SocketAddr::from(([127, 0, 0, 1], 12345));
    let before = endpoint.metrics.snapshot();

    endpoint
        .handle_datagram(&mut state, cancel.clone(), peer, make_quic_long_header())
        .await;
    endpoint
        .handle_datagram(
            &mut state,
            cancel,
            peer,
            make_quic_short_header(&[0xBE; QUIC_DCID_PREFIX_LEN]),
        )
        .await;

    let after = endpoint.metrics.snapshot();
    assert_eq!(after.passed, before.passed + 2);
    assert_eq!(after.dropped, before.dropped);
    assert_eq!(
        after.udp_upstream_setup_failure_drops,
        before.udp_upstream_setup_failure_drops + 2
    );
    assert_eq!(factory.attempts(), 2);
    assert!(state.peers.is_empty());
}

#[tokio::test]
async fn handle_datagram_pass_forwards_to_upstream_and_increments_passed() {
    let upstream_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_socket.local_addr().unwrap();

    let registry = Arc::new(SessionRegistry::new());
    let metrics = Arc::new(Metrics::default());
    let downstream = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());

    let endpoint = QuicEndpoint::from_socket_for_test(
        downstream.clone(),
        upstream_addr,
        NonZeroUsize::new(1024).unwrap(),
        Duration::from_mins(1),
        registry,
        metrics,
    )
    .await;

    let mut state = QuicNatState::new(NonZeroUsize::new(1024).unwrap());
    let cancel = CancellationToken::new();
    let peer = SocketAddr::from(([127, 0, 0, 1], 12345));
    let payload = make_quic_long_header();

    let before = endpoint.metrics.snapshot().passed;
    endpoint
        .handle_datagram(&mut state, cancel.clone(), peer, payload.clone())
        .await;

    let mut buf = vec![0u8; 256];
    let recv_result = timeout(
        Duration::from_millis(500),
        upstream_socket.recv_from(&mut buf),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(recv_result.0, payload.len());

    let after = endpoint.metrics.snapshot().passed;
    assert_eq!(after, before + 1);
}

#[tokio::test]
async fn handle_datagram_pass_with_unconnected_upstream_socket_is_non_fatal() {
    let registry = Arc::new(SessionRegistry::new());
    let metrics = Arc::new(Metrics::default());
    let downstream = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());

    let endpoint = QuicEndpoint::from_socket_for_test(
        downstream,
        SocketAddr::from(([127, 0, 0, 1], 8080)),
        NonZeroUsize::new(1024).unwrap(),
        Duration::from_mins(1),
        registry,
        metrics.clone(),
    )
    .await;

    let mut state = QuicNatState::new(NonZeroUsize::new(1024).unwrap());
    let cancel = CancellationToken::new();
    let peer = SocketAddr::from(([127, 0, 0, 1], 12345));
    let payload = make_quic_long_header();
    let upstream_socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());

    state.peers.put(
        peer,
        PeerEntry {
            socket: upstream_socket,
            last_seen: std::time::Instant::now(),
            task: tokio::spawn(async {}),
            token: 1,
        },
    );

    let before = metrics.snapshot();
    endpoint
        .handle_datagram(&mut state, cancel, peer, payload)
        .await;
    let after = metrics.snapshot();
    assert_eq!(after.passed, before.passed + 1);
    assert_eq!(
        after.upstream_send_failures,
        before.upstream_send_failures + 1
    );
}

#[tokio::test]
async fn handle_datagram_short_with_registered_cid_sends_session_event() {
    let registry = Arc::new(SessionRegistry::new());
    let metrics = Arc::new(Metrics::default());
    let downstream = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());

    let endpoint = QuicEndpoint::from_socket_for_test(
        downstream.clone(),
        SocketAddr::from(([127, 0, 0, 1], 8080)),
        NonZeroUsize::new(1024).unwrap(),
        Duration::from_mins(1),
        registry.clone(),
        metrics,
    )
    .await;

    let dcid_prefix = [0xAA; QUIC_DCID_PREFIX_LEN];
    let (tx, mut rx) = mpsc::channel(1);
    register_test_cid_route(&registry, dcid_prefix, tx);

    let mut state = QuicNatState::new(NonZeroUsize::new(1024).unwrap());
    let cancel = CancellationToken::new();
    let peer = SocketAddr::from(([127, 0, 0, 1], 12345));
    let payload = make_quic_short_header(&dcid_prefix);

    let before = endpoint.metrics.snapshot().claimed;
    endpoint
        .handle_datagram(&mut state, cancel, peer, payload)
        .await;

    let event = timeout(Duration::from_millis(100), rx.recv())
        .await
        .unwrap()
        .unwrap();
    match event {
        SessionEvent::Udp(claim) => {
            assert_eq!(claim.peer, peer);
            assert_eq!(claim.dcid_prefix.as_bytes(), &dcid_prefix);
            assert!(!claim.payload.is_empty());
        }
        _ => panic!("expected Udp event"),
    }

    let after = endpoint.metrics.snapshot().claimed;
    assert_eq!(after, before + 1);
}

#[tokio::test]
async fn handle_datagram_short_with_missing_cid_passes_to_upstream() {
    let upstream_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_socket.local_addr().unwrap();

    let registry = Arc::new(SessionRegistry::new());
    let metrics = Arc::new(Metrics::default());
    let downstream = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());

    let endpoint = QuicEndpoint::from_socket_for_test(
        downstream.clone(),
        upstream_addr,
        NonZeroUsize::new(1024).unwrap(),
        Duration::from_mins(1),
        registry,
        metrics,
    )
    .await;

    let mut state = QuicNatState::new(NonZeroUsize::new(1024).unwrap());
    let cancel = CancellationToken::new();
    let peer = SocketAddr::from(([127, 0, 0, 1], 12345));
    let dcid_prefix = [0xBB; QUIC_DCID_PREFIX_LEN];
    let payload = make_quic_short_header(&dcid_prefix);

    let before = endpoint.metrics.snapshot().passed;
    endpoint
        .handle_datagram(&mut state, cancel.clone(), peer, payload.clone())
        .await;

    let mut buf = vec![0u8; 256];
    let recv_result = timeout(
        Duration::from_millis(500),
        upstream_socket.recv_from(&mut buf),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(recv_result.0, payload.len());

    let after = endpoint.metrics.snapshot().passed;
    assert_eq!(after, before + 1);
}

#[tokio::test]
async fn handle_datagram_short_with_missing_cid_and_unconnected_upstream_is_non_fatal() {
    let registry = Arc::new(SessionRegistry::new());
    let metrics = Arc::new(Metrics::default());
    let downstream = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());

    let endpoint = QuicEndpoint::from_socket_for_test(
        downstream,
        SocketAddr::from(([127, 0, 0, 1], 8080)),
        NonZeroUsize::new(1024).unwrap(),
        Duration::from_mins(1),
        registry,
        metrics.clone(),
    )
    .await;

    let mut state = QuicNatState::new(NonZeroUsize::new(1024).unwrap());
    let cancel = CancellationToken::new();
    let peer = SocketAddr::from(([127, 0, 0, 1], 12345));
    let dcid_prefix = [0xBD; QUIC_DCID_PREFIX_LEN];
    let payload = make_quic_short_header(&dcid_prefix);
    let upstream_socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());

    state.peers.put(
        peer,
        PeerEntry {
            socket: upstream_socket,
            last_seen: std::time::Instant::now(),
            task: tokio::spawn(async {}),
            token: 1,
        },
    );

    let before = metrics.snapshot();
    endpoint
        .handle_datagram(&mut state, cancel, peer, payload)
        .await;
    let after = metrics.snapshot();
    assert_eq!(after.passed, before.passed + 1);
    assert_eq!(
        after.upstream_send_failures,
        before.upstream_send_failures + 1
    );
}

#[tokio::test]
async fn handle_datagram_claim_channel_closed_logs_and_continues() {
    let registry = Arc::new(SessionRegistry::new());
    let metrics = Arc::new(Metrics::default());
    let downstream = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());

    let endpoint = QuicEndpoint::from_socket_for_test(
        downstream.clone(),
        SocketAddr::from(([127, 0, 0, 1], 8080)),
        NonZeroUsize::new(1024).unwrap(),
        Duration::from_mins(1),
        registry.clone(),
        metrics,
    )
    .await;

    let dcid_prefix = [0xCC; QUIC_DCID_PREFIX_LEN];
    let (tx, rx) = mpsc::channel(1);
    drop(rx);
    register_test_cid_route(&registry, dcid_prefix, tx);

    let mut state = QuicNatState::new(NonZeroUsize::new(1024).unwrap());
    let cancel = CancellationToken::new();
    let peer = SocketAddr::from(([127, 0, 0, 1], 12345));
    let payload = make_quic_short_header(&dcid_prefix);

    endpoint
        .handle_datagram(&mut state, cancel, peer, payload)
        .await;

    let snapshot = endpoint.metrics.snapshot();
    assert!(snapshot.claimed > 0);
}

#[tokio::test]
async fn handle_datagram_claim_channel_full_increments_drop_counter() {
    let registry = Arc::new(SessionRegistry::new());
    let metrics = Arc::new(Metrics::default());
    let downstream = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());

    let endpoint = QuicEndpoint::from_socket_for_test(
        downstream.clone(),
        SocketAddr::from(([127, 0, 0, 1], 8080)),
        NonZeroUsize::new(1024).unwrap(),
        Duration::from_mins(1),
        registry.clone(),
        metrics.clone(),
    )
    .await;

    let dcid_prefix = [0xDD; QUIC_DCID_PREFIX_LEN];
    let (tx, rx) = mpsc::channel(1);
    let _rx = rx;
    register_test_cid_route(&registry, dcid_prefix, tx);

    let mut state = QuicNatState::new(NonZeroUsize::new(1024).unwrap());
    let cancel = CancellationToken::new();
    let peer = SocketAddr::from(([127, 0, 0, 1], 12345));

    let before = metrics.snapshot();

    endpoint
        .handle_datagram(
            &mut state,
            cancel.clone(),
            peer,
            make_quic_short_header(&dcid_prefix),
        )
        .await;
    endpoint
        .handle_datagram(
            &mut state,
            cancel,
            peer,
            make_quic_short_header(&dcid_prefix),
        )
        .await;

    let after = metrics.snapshot();
    assert_eq!(
        after.udp_claim_channel_full_drops,
        before.udp_claim_channel_full_drops + 1
    );
}
