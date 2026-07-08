//! Client TUN packet I/O types and desktop (`tun-rs`) backend.
//!
//! `TunHandles`/`TunChannels` are the platform-agnostic packet-I/O contract the
//! runtime consumes. The desktop `tun-rs` implementation (Linux only) is
//! [`spawn_desktop`] in the `desktop` submodule; other
//! platforms provide their own spawn function — for example Android wraps a
//! `VpnService` fd.

use std::io;

use slt_core::proto::OwnedMessageBuf;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::warn;

/// TUN task handles for shutdown coordination.
pub struct TunHandles {
    reader: JoinHandle<io::Result<()>>,
    writer: JoinHandle<io::Result<()>>,
}

/// TUN channel endpoints for packet I/O with the session.
pub struct TunChannels {
    /// Receives packets from TUN destined for the session.
    pub to_session_rx: mpsc::Receiver<Vec<u8>>,
    /// Sends owned DATA frames from the session to TUN.
    pub to_tun_tx: mpsc::Sender<OwnedMessageBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunQueueSend {
    Sent,
    Closed,
    Cancelled,
}

pub async fn send_to_session_queue(
    tx: &mpsc::Sender<Vec<u8>>,
    packet: Vec<u8>,
    cancel: &CancellationToken,
) -> TunQueueSend {
    tokio::select! {
        biased;

        () = cancel.cancelled() => TunQueueSend::Cancelled,
        result = tx.send(packet) => match result {
            Ok(()) => TunQueueSend::Sent,
            Err(_) => TunQueueSend::Closed,
        },
    }
}

impl TunHandles {
    /// Wait for the TUN reader/writer tasks to stop.
    ///
    /// Gracefully shuts down the TUN reader and writer tasks, logging any
    /// errors or panics that occurred during execution.
    pub async fn shutdown(self) {
        join_task("tun_reader", self.reader).await;
        join_task("tun_writer", self.writer).await;
    }
}

async fn join_task(name: &'static str, handle: JoinHandle<io::Result<()>>) {
    match handle.await {
        Ok(Ok(())) => {}
        Ok(Err(err)) => {
            warn!(task = name, error = %err, "task exited with error");
        }
        Err(err) => {
            warn!(task = name, error = %err, "task panicked");
        }
    }
}

#[cfg(test)]
mod tests {
    use tokio::sync::mpsc;
    use tokio_util::sync::CancellationToken;

    use super::{TunQueueSend, send_to_session_queue};

    #[tokio::test]
    async fn send_to_session_queue_exits_when_cancelled_while_full() {
        let (tx, mut rx) = mpsc::channel(1);
        tx.send(vec![1]).await.unwrap();

        let cancel = CancellationToken::new();
        cancel.cancel();

        let result = send_to_session_queue(&tx, vec![2], &cancel).await;

        assert_eq!(result, TunQueueSend::Cancelled);
        assert_eq!(rx.try_recv().unwrap(), vec![1]);
        assert!(matches!(
            rx.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
    }
}

/// Desktop `tun-rs` backend (Linux only).
#[cfg(target_os = "linux")]
mod desktop;

#[cfg(target_os = "linux")]
pub use desktop::spawn_desktop;

/// Android `tun-rs` backend wrapping a `VpnService` file descriptor.
#[cfg(target_os = "android")]
mod android;

#[cfg(target_os = "android")]
pub use android::spawn_from_fd;
