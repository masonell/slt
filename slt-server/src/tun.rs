//! TUN device wrapper.

use std::future::Future;
use std::io;

use tokio::sync::mpsc;
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

/// Channel-based TUN sender for batched writes.
///
/// Wraps an mpsc channel to decouple session packet sends from the
/// actual TUN device writes. The writer task batches packets and
/// uses `send_multiple` for efficient GSO when available.
#[derive(Clone)]
pub struct TunSender {
    tx: mpsc::Sender<Vec<u8>>,
}

impl TunSender {
    /// Creates a new `TunSender` from an mpsc sender.
    #[must_use]
    pub const fn new(tx: mpsc::Sender<Vec<u8>>) -> Self {
        Self { tx }
    }
}

impl TunDeviceIo for TunSender {
    fn send<'a>(&'a self, buf: &'a [u8]) -> impl Future<Output = io::Result<usize>> + Send + 'a {
        let tx = self.tx.clone();
        async move {
            match tx.send(buf.to_vec()).await {
                Ok(()) => Ok(buf.len()),
                Err(_) => Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "TUN channel closed",
                )),
            }
        }
    }
}
