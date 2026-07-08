//! TUN device wrapper.

use std::future::Future;
use std::io;
use std::sync::Arc;

use tokio::sync::mpsc;
use tracing::debug;
use tun_rs::AsyncDevice;

use crate::metrics::Metrics;

/// Outcome of accepting a packet for TUN-side delivery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum TunPacketSendOutcome {
    /// The packet was accepted by a direct device write or writer queue.
    Accepted,
    /// The packet was intentionally dropped by a lossy handoff.
    Dropped {
        /// Number of packet bytes dropped.
        bytes: usize,
    },
    /// The TUN delivery path is closed.
    Closed,
}

/// Async TUN device interface used by server sessions.
///
/// Abstraction over TUN delivery to allow direct device writes, channel-backed
/// writer tasks, and test doubles behind the same session code.
pub trait TunDeviceIo: Send + Sync + 'static {
    /// Accept a packet for delivery to the TUN side.
    ///
    /// Direct-device implementations return the kernel write outcome.
    /// Queue-backed implementations report whether the handoff was accepted,
    /// dropped due to backpressure, or closed.
    ///
    /// # Arguments
    ///
    /// * `packet` - Packet payload to deliver
    ///
    /// # Errors
    ///
    /// Direct-device implementations return the underlying write error.
    /// Queue-backed implementations report closed and dropped handoffs through
    /// `Ok(...)` outcomes.
    fn accept_packet<'a>(
        &'a self,
        packet: &'a [u8],
    ) -> impl Future<Output = io::Result<TunPacketSendOutcome>> + Send + 'a;
}

impl TunDeviceIo for AsyncDevice {
    async fn accept_packet<'a>(&'a self, packet: &'a [u8]) -> io::Result<TunPacketSendOutcome> {
        Self::send(self, packet)
            .await
            .map(|_| TunPacketSendOutcome::Accepted)
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
    fn accept_packet<'a>(
        &'a self,
        packet: &'a [u8],
    ) -> impl Future<Output = io::Result<TunPacketSendOutcome>> + Send + 'a {
        let tx = self.tx.clone();
        let metrics = self.metrics.clone();
        async move {
            match tx.try_reserve() {
                Ok(permit) => {
                    permit.send(packet.to_vec());
                    Ok(TunPacketSendOutcome::Accepted)
                }
                Err(mpsc::error::TrySendError::Full(())) => {
                    metrics.inc_tun_writer_queue_full_drops();
                    debug!(
                        len = packet.len(),
                        "tun packet dropped before writer queue: queue full"
                    );
                    Ok(TunPacketSendOutcome::Dropped {
                        bytes: packet.len(),
                    })
                }
                Err(mpsc::error::TrySendError::Closed(())) => Ok(TunPacketSendOutcome::Closed),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tokio::sync::mpsc;

    use super::{TunDeviceIo, TunPacketSendOutcome, TunSender};
    use crate::metrics::Metrics;

    #[tokio::test]
    async fn tun_sender_drops_when_writer_queue_is_full() {
        let metrics = Arc::new(Metrics::default());
        let (tx, mut rx) = mpsc::channel(1);
        let sender = TunSender::new(tx, metrics.clone());

        assert_eq!(
            sender.accept_packet(&[1]).await.unwrap(),
            TunPacketSendOutcome::Accepted
        );
        assert_eq!(
            sender.accept_packet(&[2]).await.unwrap(),
            TunPacketSendOutcome::Dropped { bytes: 1 }
        );

        assert_eq!(rx.try_recv().unwrap(), vec![1]);
        assert!(matches!(
            rx.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
        assert_eq!(metrics.snapshot().tun_writer_queue_full_drops, 1);
    }

    #[tokio::test]
    async fn tun_sender_reports_closed_writer_queue() {
        let metrics = Arc::new(Metrics::default());
        let (tx, rx) = mpsc::channel(1);
        drop(rx);
        let sender = TunSender::new(tx, metrics.clone());

        assert_eq!(
            sender.accept_packet(&[1]).await.unwrap(),
            TunPacketSendOutcome::Closed
        );
        assert_eq!(metrics.snapshot().tun_writer_queue_full_drops, 0);
    }
}
