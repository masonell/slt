//! UDP socket helpers for session IO.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use slt_core::crypto::udp_qsp::SessionIo;
use tokio::net::UdpSocket;

/// Abstraction over UDP socket I/O for session traffic.
///
/// This trait allows session code to work with different UDP socket
/// implementations (e.g., real sockets, test doubles, mock implementations).
pub trait UdpSocketIo: Send + Sync + 'static {
    /// Sends a datagram to the specified peer address.
    ///
    /// # Parameters
    ///
    /// * `buf` - The bytes to send
    /// * `peer` - The destination socket address
    ///
    /// # Returns
    ///
    /// The number of bytes sent on success
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

/// UDP I/O wrapper implementing the [`SessionIo`] trait for UDP-QSP.
///
/// Combines a UDP socket with a peer address to provide send/recv operations
/// for the QUIC-QSP session layer. The peer address can be updated dynamically
/// as UDP packets arrive from different endpoints.
///
/// # Type Parameters
///
/// * `U` - The UDP socket implementation (must implement [`UdpSocketIo`])
pub(super) struct UdpIo<U: UdpSocketIo> {
    socket: Arc<U>,
    peer: SocketAddr,
}

impl<U: UdpSocketIo> UdpIo<U> {
    /// Creates a new UDP I/O wrapper with the given socket and peer address.
    ///
    /// # Parameters
    ///
    /// * `socket` - The UDP socket to use for sending
    /// * `peer` - The initial peer address (may be a placeholder, updated later)
    #[must_use]
    pub(super) const fn new(socket: Arc<U>, peer: SocketAddr) -> Self {
        Self { socket, peer }
    }

    /// Updates the peer address for subsequent sends.
    ///
    /// Called when UDP packets arrive from a new endpoint, allowing the session
    /// to track the client's current address (e.g., after a NAT remapping).
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
