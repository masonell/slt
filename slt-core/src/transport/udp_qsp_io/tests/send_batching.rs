use std::io;
use std::net::{Ipv4Addr, UdpSocket};
use std::time::Duration;

use tokio::time::timeout;

use super::super::{MAX_UDP_GSO_PAYLOAD, UdpQspIo, max_gso_segments_for_size};
use super::socket_pair;
use crate::crypto::udp_qsp::SessionIo;

#[test]
fn max_gso_segments_caps_by_socket_and_payload() {
    assert_eq!(max_gso_segments_for_size(64, 1200), 54);
    assert_eq!(max_gso_segments_for_size(16, 1200), 16);
    assert_eq!(max_gso_segments_for_size(1, 1200), 1);
    assert_eq!(max_gso_segments_for_size(0, 1200), 1);
    assert_eq!(max_gso_segments_for_size(64, MAX_UDP_GSO_PAYLOAD), 1);
}

#[tokio::test]
async fn flush_sends_one_datagram_to_peer() -> io::Result<()> {
    let (a, b) = socket_pair()?;
    let a_addr = a.local_addr()?;
    let b_addr = b.local_addr()?;
    let mut tx = UdpQspIo::new(a, b_addr)?;
    let mut rx = UdpQspIo::new(b, a_addr)?;

    tx.send(b"packet").await?;
    assert!(tx.has_pending_flush());
    tx.flush().await?;
    assert!(!tx.has_pending_flush());

    let mut buf = [0u8; 64];
    let len = timeout(Duration::from_secs(1), rx.recv(&mut buf)).await??;
    assert_eq!(&buf[..len], b"packet");
    Ok(())
}

#[tokio::test]
async fn set_peer_retargets_pending_send() -> io::Result<()> {
    let sender = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
    let old_peer = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
    let new_peer = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
    sender.set_nonblocking(true)?;
    old_peer.set_nonblocking(true)?;
    new_peer.set_nonblocking(true)?;

    let sender_addr = sender.local_addr()?;
    let old_peer_addr = old_peer.local_addr()?;
    let new_peer_addr = new_peer.local_addr()?;
    let mut tx = UdpQspIo::new(sender, old_peer_addr)?;
    let mut new_peer_rx = UdpQspIo::new(new_peer, sender_addr)?;

    tx.send(b"pending packet").await?;
    assert!(tx.has_pending_flush());
    tx.set_peer(new_peer_addr);
    tx.flush().await?;

    let mut buf = [0u8; 64];
    let len = timeout(Duration::from_secs(1), new_peer_rx.recv(&mut buf)).await??;
    assert_eq!(&buf[..len], b"pending packet");
    assert_eq!(
        old_peer.recv(&mut buf).unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    Ok(())
}

#[tokio::test]
async fn discard_pending_send_clears_slab_without_transmitting() -> io::Result<()> {
    let (a, b) = socket_pair()?;
    let b_addr = b.local_addr()?;
    let mut tx = UdpQspIo::new(a, b_addr)?;

    tx.send(b"one").await?;
    tx.send(b"two").await?;
    assert!(tx.has_pending_flush());
    assert_eq!(tx.discard_pending_send(), 2);
    assert!(!tx.has_pending_flush());

    let mut buf = [0u8; 64];
    assert_eq!(
        b.recv(&mut buf).unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    Ok(())
}

#[tokio::test]
async fn full_send_slab_flushes_inline() -> io::Result<()> {
    let (a, b) = socket_pair()?;
    let a_addr = a.local_addr()?;
    let b_addr = b.local_addr()?;
    let mut tx = UdpQspIo::new(a, b_addr)?;
    let mut rx = UdpQspIo::new(b, a_addr)?;
    let packet = vec![0xA5; 64];
    let max_segments = max_gso_segments_for_size(tx.state.max_gso_segments(), packet.len());

    for _ in 0..max_segments {
        tx.send(&packet).await?;
    }

    assert!(!tx.has_pending_flush());
    let mut buf = [0u8; 128];
    for _ in 0..max_segments {
        let len = timeout(Duration::from_secs(1), rx.recv(&mut buf)).await??;
        assert_eq!(&buf[..len], packet);
    }
    Ok(())
}

#[tokio::test]
async fn segment_size_change_flushes_existing_batch() -> io::Result<()> {
    let (a, b) = socket_pair()?;
    let a_addr = a.local_addr()?;
    let b_addr = b.local_addr()?;
    let mut tx = UdpQspIo::new(a, b_addr)?;
    let mut rx = UdpQspIo::new(b, a_addr)?;
    let first = vec![0xA5; 64];
    let second = vec![0x5A; 65];
    if max_gso_segments_for_size(tx.state.max_gso_segments(), first.len()) <= 1 {
        return Ok(());
    }

    tx.send(&first).await?;
    assert!(tx.has_pending_flush());
    tx.send(&second).await?;
    assert!(tx.has_pending_flush());

    let mut buf = [0u8; 128];
    let len = timeout(Duration::from_secs(1), rx.recv(&mut buf)).await??;
    assert_eq!(&buf[..len], first);
    assert!(
        timeout(Duration::from_millis(50), rx.recv(&mut buf))
            .await
            .is_err(),
        "second packet should remain buffered until explicit flush"
    );

    tx.flush().await?;
    let len = timeout(Duration::from_secs(1), rx.recv(&mut buf)).await??;
    assert_eq!(&buf[..len], second);
    Ok(())
}

#[tokio::test]
async fn send_rejects_empty_packet() -> io::Result<()> {
    let (a, b) = socket_pair()?;
    let b_addr = b.local_addr()?;
    let mut tx = UdpQspIo::new(a, b_addr)?;

    let err = tx
        .send(b"")
        .await
        .expect_err("empty packet must be rejected");
    assert_eq!(err.kind(), io::ErrorKind::InvalidInput);

    // A rejected send must never leave the slab half-populated.
    assert!(!tx.has_pending_flush());
    Ok(())
}

#[tokio::test]
async fn send_rejects_oversized_packet() -> io::Result<()> {
    let (a, b) = socket_pair()?;
    let b_addr = b.local_addr()?;
    let mut tx = UdpQspIo::new(a, b_addr)?;

    let oversize = vec![0u8; MAX_UDP_GSO_PAYLOAD + 1];
    let err = tx
        .send(&oversize)
        .await
        .expect_err("oversized packet must be rejected");
    assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    assert!(!tx.has_pending_flush());
    Ok(())
}

/// A failed send surfaces the error but must not corrupt or drop an
/// already-buffered batch: `flush_pending` only clears the slab on success,
/// so any error leaves it pending and the prior packet still deliverable.
#[tokio::test]
async fn send_error_preserves_pending_slab() -> io::Result<()> {
    let (a, b) = socket_pair()?;
    let a_addr = a.local_addr()?;
    let b_addr = b.local_addr()?;
    let mut tx = UdpQspIo::new(a, b_addr)?;
    let mut rx = UdpQspIo::new(b, a_addr)?;

    // Buffer a valid packet; the slab now holds pending data.
    let valid = vec![0xA5; 64];
    tx.send(&valid).await?;
    assert!(tx.has_pending_flush());

    // A rejected send (oversized) must surface an error without touching the
    // already-buffered packet.
    let oversize = vec![0xFF; MAX_UDP_GSO_PAYLOAD + 1];
    let err = tx
        .send(&oversize)
        .await
        .expect_err("oversized packet must be rejected");
    assert_eq!(err.kind(), io::ErrorKind::InvalidInput);

    // The slab is still pending and still contains exactly the valid packet.
    assert!(tx.has_pending_flush());
    tx.flush().await?;
    assert!(!tx.has_pending_flush());

    let mut buf = [0u8; 128];
    let len = timeout(Duration::from_secs(1), rx.recv(&mut buf)).await??;
    assert_eq!(&buf[..len], &valid);

    // The rejected oversized packet never reached the peer.
    assert!(
        timeout(Duration::from_millis(50), rx.recv(&mut buf))
            .await
            .is_err(),
        "no second packet should arrive"
    );
    Ok(())
}
