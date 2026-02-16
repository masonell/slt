//! TUN device wrapper.

use std::future::Future;
use std::io;

use tun_rs::AsyncDevice;

/// Async TUN device interface used by server sessions.
///
/// Abstraction over TUN device I/O to allow mocking in tests and
/// flexibility in implementation. Sessions use this trait to send
/// packets to the VPN tunnel.
pub trait TunDeviceIo: Send + Sync + 'static {
    /// Send a packet to the TUN device.
    ///
    /// # Arguments
    ///
    /// * `buf` - Packet payload to write
    ///
    /// # Returns
    ///
    /// The number of bytes written on success.
    fn send<'a>(&'a self, buf: &'a [u8]) -> impl Future<Output = io::Result<usize>> + Send + 'a;
}

impl TunDeviceIo for AsyncDevice {
    fn send<'a>(&'a self, buf: &'a [u8]) -> impl Future<Output = io::Result<usize>> + Send + 'a {
        Self::send(self, buf)
    }
}
