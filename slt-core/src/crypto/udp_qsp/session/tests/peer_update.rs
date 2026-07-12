use super::*;

#[tokio::test]
async fn session_proxies_set_peer_to_io() {
    let (io, state) = BufferingIo::pair();
    let mut session = QuicQspSession::new(
        io,
        Cid::from([0xCD; 20]),
        Cid::from([0xAB; 20]),
        buffering_keys(),
        0,
        0,
        false,
    );

    assert!(state.lock().expect("state lock").last_peer.is_none());

    let peer: SocketAddr = "127.0.0.1:9999".parse().expect("valid addr");
    session.set_peer(peer);

    assert_eq!(state.lock().expect("state lock").last_peer, Some(peer));
}
