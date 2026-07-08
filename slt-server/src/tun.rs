//! TUN device wrapper.

use std::future::Future;
use std::io;
use std::sync::Arc;

use tokio::sync::mpsc;
use tracing::debug;
use tun_rs::AsyncDevice;

use crate::metrics::Metrics;

/// Async TUN device interface used by server sessions.
///
/// Abstraction over TUN delivery to allow direct device writes, channel-backed
/// writer tasks, and test doubles behind the same session code.
pub trait TunDeviceIo: Send + Sync + 'static {
    /// Accept a packet for delivery to the TUN side.
    ///
    /// Direct-device implementations return the kernel write result. Queue-backed
    /// implementations may drop on a full queue and return `Ok(buf.len())` after
    /// recording the drop in metrics.
    ///
    /// # Arguments
    ///
    /// * `buf` - Packet payload to write
    ///
    /// # Returns
    ///
    /// The number of bytes accepted on success.
    fn send<'a>(&'a self, buf: &'a [u8]) -> impl Future<Output = io::Result<usize>> + Send + 'a;
}

impl TunDeviceIo for AsyncDevice {
    fn send<'a>(&'a self, buf: &'a [u8]) -> impl Future<Output = io::Result<usize>> + Send + 'a {
        Self::send(self, buf)
    }
}

/// Channel-based TUN sender for batched writes.
///
/// Wraps an mpsc channel to decouple session packet sends from device writes.
/// A full writer queue is lossy: packets are dropped and counted so session
/// tasks do not block behind a saturated TUN writer.
#[derive(Clone)]
pub struct TunSender {
    tx: mpsc::Sender<Vec<u8>>,
    metrics: Arc<Metrics>,
}

impl TunSender {
    /// Creates a new `TunSender` from an mpsc sender.
    #[must_use]
    pub const fn new(tx: mpsc::Sender<Vec<u8>>, metrics: Arc<Metrics>) -> Self {
        Self { tx, metrics }
    }
}

impl TunDeviceIo for TunSender {
    fn send<'a>(&'a self, buf: &'a [u8]) -> impl Future<Output = io::Result<usize>> + Send + 'a {
        let tx = self.tx.clone();
        let metrics = self.metrics.clone();
        async move {
            match tx.try_reserve() {
                Ok(permit) => {
                    permit.send(buf.to_vec());
                    Ok(buf.len())
                }
                Err(mpsc::error::TrySendError::Full(())) => {
                    metrics.inc_tun_writer_queue_full_drops();
                    debug!(
                        len = buf.len(),
                        "tun packet dropped before writer queue: queue full"
                    );
                    Ok(buf.len())
                }
                Err(mpsc::error::TrySendError::Closed(())) => Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "TUN channel closed",
                )),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tokio::sync::mpsc;

    use super::{TunDeviceIo, TunSender};
    use crate::metrics::Metrics;

    #[tokio::test]
    async fn tun_sender_drops_when_writer_queue_is_full() {
        let metrics = Arc::new(Metrics::default());
        let (tx, mut rx) = mpsc::channel(1);
        let sender = TunSender::new(tx, metrics.clone());

        sender.send(&[1]).await.unwrap();
        assert_eq!(sender.send(&[2]).await.unwrap(), 1);

        assert_eq!(rx.try_recv().unwrap(), vec![1]);
        assert!(matches!(
            rx.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
        assert_eq!(metrics.snapshot().tun_writer_queue_full_drops, 1);
    }
}
