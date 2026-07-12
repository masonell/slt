use std::io;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::time::Duration;

use tokio::time::timeout;

use super::super::UdpQspIo;
use super::socket_pair;
use crate::crypto::udp_qsp::SessionIo;

#[tokio::test]
async fn recv_buffers_are_allocated_lazily() -> io::Result<()> {
    let (a, b) = socket_pair()?;
    let a_addr = a.local_addr()?;
    let b_addr = b.local_addr()?;
    let mut tx = UdpQspIo::new(a, b_addr)?;
    let mut rx = UdpQspIo::new(b, a_addr)?;

    assert!(tx.recv.is_none());
    assert!(rx.recv.is_none());

    tx.send(b"packet").await?;
    tx.flush().await?;
    assert!(tx.recv.is_none());
    assert!(rx.recv.is_none());

    let mut buf = [0u8; 64];
    let len = timeout(Duration::from_secs(1), rx.recv(&mut buf)).await??;
    assert_eq!(&buf[..len], b"packet");
    assert!(rx.recv.is_some());
    Ok(())
}

#[tokio::test]
async fn recv_filters_to_current_peer() -> io::Result<()> {
    let (a, b) = socket_pair()?;
    let noise = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
    let a_addr = a.local_addr()?;
    let b_addr = b.local_addr()?;
    let mut tx = UdpQspIo::new(a, b_addr)?;
    let mut rx = UdpQspIo::new(b, a_addr)?;

    noise.send_to(b"noise", b_addr)?;
    tx.send(b"wanted").await?;
    tx.flush().await?;

    let mut buf = [0u8; 64];
    let len = timeout(Duration::from_secs(1), rx.recv(&mut buf)).await??;
    assert_eq!(&buf[..len], b"wanted");

    rx.set_peer(noise.local_addr()?);
    noise.send_to(b"updated", b_addr)?;
    let len = timeout(Duration::from_secs(1), rx.recv(&mut buf)).await??;
    assert_eq!(&buf[..len], b"updated");
    Ok(())
}

#[tokio::test]
async fn recv_rejects_too_small_caller_buffer() -> io::Result<()> {
    let (a, b) = socket_pair()?;
    let a_addr = a.local_addr()?;
    let b_addr = b.local_addr()?;
    let mut tx = UdpQspIo::new(a, b_addr)?;
    let mut rx = UdpQspIo::new(b, a_addr)?;

    tx.send(b"too large").await?;
    tx.flush().await?;

    let mut buf = [0u8; 3];
    let err = timeout(Duration::from_secs(1), rx.recv(&mut buf))
        .await?
        .expect_err("small caller buffer should be rejected");
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    Ok(())
}

/// Already-queued receive datagrams survive a peer change. They matched the
/// previously accepted peer when received, so they are kept in the queue and
/// drained by later `recv()` calls even after `set_peer()` redirects future
/// batches to a new endpoint.
#[tokio::test]
async fn queued_recv_datagrams_survive_set_peer() -> io::Result<()> {
    let (a, b) = socket_pair()?;
    let a_addr = a.local_addr()?;
    let b_addr = b.local_addr()?;
    let mut tx = UdpQspIo::new(a, b_addr)?;
    let mut rx = UdpQspIo::new(b, a_addr)?;

    // Send two datagrams and let both land in the kernel receive buffer
    // before reading. quinn-udp's `recvmmsg` returns every buffered datagram
    // in a single batch, so the first `recv()` queues both and hands back
    // only the first.
    tx.send(b"first").await?;
    tx.send(b"second").await?;
    tx.flush().await?;
    tokio::time::sleep(Duration::from_millis(50)).await;

    let mut buf = [0u8; 64];
    let len = timeout(Duration::from_secs(1), rx.recv(&mut buf))
        .await?
        .expect("first datagram");
    assert_eq!(&buf[..len], b"first");

    // The second datagram is still queued. Redirecting the peer must not drop
    // it; `recv()` still drains the queue without needing traffic from the
    // new (bogus) endpoint.
    let bogus: SocketAddr = (Ipv4Addr::new(203, 0, 113, 7), 9999).into();
    rx.set_peer(bogus);

    let len = timeout(Duration::from_secs(1), rx.recv(&mut buf))
        .await?
        .expect("second datagram survived set_peer");
    assert_eq!(&buf[..len], b"second");
    Ok(())
}
