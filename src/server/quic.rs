//! QUIC front-door handling.

use std::io;
use std::net::{SocketAddr, UdpSocket};

/// QUIC endpoint wrapper.
pub struct QuicEndpoint {
    socket: UdpSocket,
    config: quiche::Config,
}

impl QuicEndpoint {
    /// Bind a UDP socket and attach the provided QUIC config.
    pub fn bind(addr: SocketAddr, config: quiche::Config) -> io::Result<Self> {
        let socket = UdpSocket::bind(addr)?;
        Ok(Self { socket, config })
    }

    /// Returns the underlying UDP socket.
    #[must_use]
    pub fn socket(&self) -> &UdpSocket {
        &self.socket
    }

    /// Returns the configured QUIC config.
    #[must_use]
    pub fn config(&self) -> &quiche::Config {
        &self.config
    }
}
