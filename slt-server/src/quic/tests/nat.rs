use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Duration;

use tokio_util::sync::CancellationToken;

use super::super::{PeerEntry, QuicNatState, TokioUpstreamSocketFactory};

#[tokio::test]
async fn get_or_create_upstream_reuses_socket_for_same_peer() {
    let downstream = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let upstream_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_socket.local_addr().unwrap();

    let mut state = QuicNatState::new(NonZeroUsize::new(1024).unwrap());
    let factory = TokioUpstreamSocketFactory;
    let cancel = CancellationToken::new();
    let peer = SocketAddr::from(([127, 0, 0, 1], 12345));

    let socket1 = state
        .get_or_create_upstream(
            &factory,
            downstream.clone(),
            upstream_addr,
            peer,
            cancel.clone(),
        )
        .await
        .unwrap();
    let socket2 = state
        .get_or_create_upstream(&factory, downstream, upstream_addr, peer, cancel)
        .await
        .unwrap();

    assert!(Arc::ptr_eq(&socket1, &socket2));
}

#[tokio::test]
async fn get_or_create_upstream_creates_distinct_sockets_per_peer() {
    let downstream = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let upstream_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_socket.local_addr().unwrap();

    let mut state = QuicNatState::new(NonZeroUsize::new(1024).unwrap());
    let factory = TokioUpstreamSocketFactory;
    let cancel = CancellationToken::new();
    let peer1 = SocketAddr::from(([127, 0, 0, 1], 12345));
    let peer2 = SocketAddr::from(([127, 0, 0, 1], 12346));

    let socket1 = state
        .get_or_create_upstream(
            &factory,
            downstream.clone(),
            upstream_addr,
            peer1,
            cancel.clone(),
        )
        .await
        .unwrap();
    let socket2 = state
        .get_or_create_upstream(&factory, downstream, upstream_addr, peer2, cancel)
        .await
        .unwrap();

    assert!(!Arc::ptr_eq(&socket1, &socket2));

    let addr1 = socket1.local_addr().unwrap();
    let addr2 = socket2.local_addr().unwrap();
    assert_ne!(addr1.port(), addr2.port());
}

#[tokio::test]
async fn get_or_create_upstream_evicts_lru_and_aborts_old_task() {
    let downstream = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let upstream_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_socket.local_addr().unwrap();

    let mut state = QuicNatState::new(NonZeroUsize::new(2).unwrap());
    let factory = TokioUpstreamSocketFactory;
    let cancel = CancellationToken::new();

    let peer1 = SocketAddr::from(([127, 0, 0, 1], 12345));
    let peer2 = SocketAddr::from(([127, 0, 0, 1], 12346));
    let peer3 = SocketAddr::from(([127, 0, 0, 1], 12347));

    let _socket1 = state
        .get_or_create_upstream(
            &factory,
            downstream.clone(),
            upstream_addr,
            peer1,
            cancel.clone(),
        )
        .await
        .unwrap();
    let _socket2 = state
        .get_or_create_upstream(
            &factory,
            downstream.clone(),
            upstream_addr,
            peer2,
            cancel.clone(),
        )
        .await
        .unwrap();

    let _socket3 = state
        .get_or_create_upstream(&factory, downstream, upstream_addr, peer3, cancel)
        .await
        .unwrap();

    assert!(state.peers.contains(&peer2));
    assert!(state.peers.contains(&peer3));
    assert!(!state.peers.contains(&peer1));
}

#[tokio::test]
async fn handle_reader_done_removes_matching_token() {
    let mut state = QuicNatState::new(NonZeroUsize::new(1024).unwrap());
    let peer = SocketAddr::from(([127, 0, 0, 1], 12345));
    let token = 42u64;

    let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let entry = PeerEntry {
        socket,
        last_seen: std::time::Instant::now(),
        task: tokio::spawn(async {}),
        token,
    };
    state.peers.put(peer, entry);

    assert!(state.peers.contains(&peer));

    state.handle_reader_done(peer, token);

    assert!(!state.peers.contains(&peer));
}

#[tokio::test]
async fn handle_reader_done_ignores_stale_token() {
    let mut state = QuicNatState::new(NonZeroUsize::new(1024).unwrap());
    let peer = SocketAddr::from(([127, 0, 0, 1], 12345));
    let correct_token = 42u64;
    let stale_token = 99u64;

    let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let entry = PeerEntry {
        socket,
        last_seen: std::time::Instant::now(),
        task: tokio::spawn(async {}),
        token: correct_token,
    };
    state.peers.put(peer, entry);

    state.handle_reader_done(peer, stale_token);

    assert!(state.peers.contains(&peer));
}

#[tokio::test]
async fn sweep_idle_evicts_stale_peers() {
    let mut state = QuicNatState::new(NonZeroUsize::new(1024).unwrap());
    let peer = SocketAddr::from(([127, 0, 0, 1], 12345));
    let idle_timeout = Duration::from_mins(1);

    let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let old_time = std::time::Instant::now()
        .checked_sub(idle_timeout + Duration::from_secs(1))
        .unwrap();
    let entry = PeerEntry {
        socket,
        last_seen: old_time,
        task: tokio::spawn(async {}),
        token: 1,
    };
    state.peers.put(peer, entry);

    assert!(state.peers.contains(&peer));

    state.sweep_idle(idle_timeout);

    assert!(!state.peers.contains(&peer));
}

#[tokio::test]
async fn sweep_idle_keeps_recent_peers() {
    let mut state = QuicNatState::new(NonZeroUsize::new(1024).unwrap());
    let peer = SocketAddr::from(([127, 0, 0, 1], 12345));
    let idle_timeout = Duration::from_mins(1);

    let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let entry = PeerEntry {
        socket,
        last_seen: std::time::Instant::now(),
        task: tokio::spawn(async {}),
        token: 1,
    };
    state.peers.put(peer, entry);

    assert!(state.peers.contains(&peer));

    state.sweep_idle(idle_timeout);

    assert!(state.peers.contains(&peer));
}
