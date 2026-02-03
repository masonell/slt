//! TUN device wrapper.

use std::future::Future;
use std::io;

use tun_rs::AsyncDevice;

/// Basic TUN device configuration.
#[derive(Debug, Clone)]
pub struct TunDevice {
    /// Interface name.
    pub name: String,
    /// MTU value.
    pub mtu: u16,
}

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

impl TunDevice {
    /// Create a new TUN device configuration.
    ///
    /// # Errors
    ///
    /// This function currently never returns an error, but the return type
    /// allows for future validation (e.g., MTU bounds checking).
    pub fn new(name: impl Into<String>, mtu: u16) -> io::Result<Self> {
        Ok(Self {
            name: name.into(),
            mtu,
        })
    }
}
