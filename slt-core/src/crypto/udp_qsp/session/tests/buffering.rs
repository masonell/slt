use super::*;

#[tokio::test]
async fn session_proxies_flush_and_pending_flush_state() {
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

    assert!(!session.has_pending_flush());

    // `send` buffers through the underlying I/O, so a pending flush becomes
    // visible through the session's proxy.
    session.send(b"hello").await.unwrap();
    assert!(session.has_pending_flush());
    assert_eq!(state.lock().expect("state lock").pending.len(), 1);
    assert!(state.lock().expect("state lock").flushed.is_empty());

    // `flush` proxies to the I/O layer and drains the buffered packet.
    session.flush().await.unwrap();
    assert!(!session.has_pending_flush());
    assert!(state.lock().expect("state lock").pending.is_empty());
    assert_eq!(state.lock().expect("state lock").flushed.len(), 1);
}

#[tokio::test]
async fn session_discards_pending_send_without_flushing() {
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
    session.send(b"one").await.unwrap();
    session.send(b"two").await.unwrap();

    assert_eq!(session.discard_pending_send(), 2);
    assert!(!session.has_pending_flush());
    let state = state.lock().expect("state lock");
    assert!(state.pending.is_empty());
    assert!(state.flushed.is_empty());
}
