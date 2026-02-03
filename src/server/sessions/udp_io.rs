//! UDP socket helpers for session IO.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::UdpSocket;

use crate::crypto::udp_qsp::SessionIo;

/// UDP socket interface used for session traffic.
pub trait UdpSocketIo: Send + Sync + 'static {
    /// Send bytes to a peer.
    fn send_to<'a>(
        &'a self,
        buf: &'a [u8],
        peer: SocketAddr,
    ) -> impl std::future::Future<Output = io::Result<usize>> + Send + 'a;
}

impl UdpSocketIo for UdpSocket {
    fn send_to<'a>(
        &'a self,
        buf: &'a [u8],
        peer: SocketAddr,
    ) -> impl std::future::Future<Output = io::Result<usize>> + Send + 'a {
        self.send_to(buf, peer)
    }
}

pub(super) struct UdpIo<U: UdpSocketIo> {
    socket: Arc<U>,
    peer: SocketAddr,
}

impl<U: UdpSocketIo> UdpIo<U> {
    pub(super) const fn new(socket: Arc<U>, peer: SocketAddr) -> Self {
        Self { socket, peer }
    }

    pub(super) const fn set_peer(&mut self, peer: SocketAddr) {
        self.peer = peer;
    }
}

impl<U: UdpSocketIo> SessionIo for UdpIo<U> {
    async fn send<'a>(&'a mut self, bytes: &'a [u8]) -> io::Result<()> {
        let _ = self.socket.send_to(bytes, self.peer).await?;
        Ok(())
    }

    async fn recv<'a>(&'a mut self, _buf: &'a mut [u8]) -> io::Result<usize> {
        Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "direct recv not supported",
        ))
    }
}
