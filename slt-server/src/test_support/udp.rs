//! UDP socket test utilities.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::sync::mpsc;

use crate::sessions::UdpSocketIo;

/// Test UDP socket that captures sent packets to a channel.
pub struct TestUdpSocket {
    /// Channel to capture packets sent via UDP.
    pub tx: mpsc::Sender<Vec<u8>>,
}

impl UdpSocketIo for TestUdpSocket {
    fn send_to<'a>(
        &'a self,
        buf: &'a [u8],
        _peer: SocketAddr,
    ) -> impl Future<Output = io::Result<usize>> + Send + 'a {
        let tx = self.tx.clone();
        async move {
            let _ = tx.send(buf.to_vec()).await;
            Ok(buf.len())
        }
    }
}

impl TestUdpSocket {
    /// Creates a new TestUdpSocket with a channel for capturing packets.
    ///
    /// Returns (TestUdpSocket, receiver for captured packets).
    pub fn new(channel_size: usize) -> (Arc<Self>, mpsc::Receiver<Vec<u8>>) {
        let (tx, rx) = mpsc::channel(channel_size);
        (Arc::new(Self { tx }), rx)
    }
}
