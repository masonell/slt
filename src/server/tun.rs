//! TUN device wrapper.

use std::io;

/// Basic TUN device configuration.
#[derive(Debug, Clone)]
pub struct TunDevice {
    /// Interface name.
    pub name: String,
    /// MTU value.
    pub mtu: u16,
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
