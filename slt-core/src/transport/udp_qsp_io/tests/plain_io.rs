use std::io;
use std::time::Duration;

use tokio::time::timeout;

use super::super::PlainUdpQspIo;
use super::socket_pair;
use crate::crypto::udp_qsp::SessionIo;

#[tokio::test]
async fn plain_backend_sends_immediately_without_pending_flush() -> io::Result<()> {
    let (a, b) = socket_pair()?;
    let a_addr = a.local_addr()?;
    let b_addr = b.local_addr()?;
    let mut tx = PlainUdpQspIo::new(a, b_addr)?;
    let mut rx = PlainUdpQspIo::new(b, a_addr)?;

    tx.send(b"packet").await?;
    assert!(!tx.has_pending_flush());
    tx.flush().await?;

    let mut buf = [0u8; 64];
    let len = timeout(Duration::from_secs(1), rx.recv(&mut buf)).await??;
    assert_eq!(&buf[..len], b"packet");
    Ok(())
}
