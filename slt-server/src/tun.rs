//! TUN device wrapper.

use std::future::Future;
use std::io;

use tun_rs::AsyncDevice;

/// Async TUN device interface used by server sessions.
pub trait TunDeviceIo: Send + Sync + 'static {
    /// Send a packet to the TUN device.
    fn send<'a>(&'a self, buf: &'a [u8]) -> impl Future<Output = io::Result<usize>> + Send + 'a;
}

impl TunDeviceIo for AsyncDevice {
    fn send<'a>(&'a self, buf: &'a [u8]) -> impl Future<Output = io::Result<usize>> + Send + 'a {
        Self::send(self, buf)
    }
}
