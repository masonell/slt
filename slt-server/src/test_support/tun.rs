//! TUN device test utilities.

use std::future::Future;
use std::io;

use crate::tun::TunDeviceIo;

/// Null TUN device that discards all packets.
#[derive(Clone, Copy, Debug)]
pub struct NullTun;

impl TunDeviceIo for NullTun {
    fn send<'a>(&'a self, _buf: &'a [u8]) -> impl Future<Output = io::Result<usize>> + Send + 'a {
        std::future::ready(Ok(0))
    }
}
