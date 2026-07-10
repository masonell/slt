//! Client TUN packet I/O types and desktop (`tun-rs`) backend.
//!
//! `TunHandles`/`TunChannels` are the platform-agnostic packet-I/O contract the
//! runtime consumes. The desktop `tun-rs` implementation (Linux only) is
//! [`spawn_desktop`] in the `desktop` submodule; other
//! platforms provide their own spawn function — for example Android wraps a
//! `VpnService` fd.

use std::{fmt, io};

use slt_core::proto::OwnedMessageBuf;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::warn;

/// TUN task handles for runtime supervision and shutdown coordination.
pub struct TunHandles {
    reader: Option<JoinHandle<io::Result<()>>>,
    writer: Option<JoinHandle<io::Result<()>>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunTask {
    Reader,
    Writer,
}

impl fmt::Display for TunTask {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Reader => f.write_str("reader"),
            Self::Writer => f.write_str("writer"),
        }
    }
}

/// Failure reported by a TUN reader or writer task while the runtime is active.
#[derive(Debug, thiserror::Error)]
pub enum TunTaskError {
    /// The task returned an I/O error.
    #[error("TUN {task} task failed: {source}")]
    Io {
        task: TunTask,
        #[source]
        source: io::Error,
    },
    /// The task panicked.
    #[error("TUN {task} task panicked: {source}")]
    Panic {
        task: TunTask,
        #[source]
        source: tokio::task::JoinError,
    },
    /// The task was cancelled without runtime cancellation being requested.
    #[error("TUN {task} task was cancelled unexpectedly: {source}")]
    Cancelled {
        task: TunTask,
        #[source]
        source: tokio::task::JoinError,
    },
    /// The task returned successfully without runtime cancellation being requested.
    #[error("TUN {task} task exited unexpectedly")]
    UnexpectedExit { task: TunTask },
    /// A task-owned packet channel closed before its task completion was observed.
    #[error("TUN {task} task channel closed unexpectedly")]
    ChannelClosed { task: TunTask },
    /// Runtime supervision requested session cleanup for an observed TUN fault.
    #[error("TUN task failure signalled")]
    FaultSignalled,
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
    pub(super) const fn new(
        reader: JoinHandle<io::Result<()>>,
        writer: JoinHandle<io::Result<()>>,
    ) -> Self {
        Self {
            reader: Some(reader),
            writer: Some(writer),
        }
    }

    /// Wait for either TUN task to finish and classify its completion.
    pub(super) async fn wait_for_exit(&mut self) -> TunTaskError {
        enum Completed {
            Reader(Result<io::Result<()>, tokio::task::JoinError>),
            Writer(Result<io::Result<()>, tokio::task::JoinError>),
        }

        let completed = tokio::select! {
            result = self.reader.as_mut().expect("TUN reader handle missing") => {
                Completed::Reader(result)
            }
            result = self.writer.as_mut().expect("TUN writer handle missing") => {
                Completed::Writer(result)
            }
        };

        match completed {
            Completed::Reader(result) => {
                self.reader.take();
                classify_task_exit(TunTask::Reader, result)
            }
            Completed::Writer(result) => {
                self.writer.take();
                classify_task_exit(TunTask::Writer, result)
            }
        }
    }

    /// Wait for a specific TUN task to finish and classify its completion.
    pub(super) async fn wait_for_task(&mut self, task: TunTask) -> TunTaskError {
        let result = match task {
            TunTask::Reader => {
                self.reader
                    .as_mut()
                    .expect("TUN reader handle missing")
                    .await
            }
            TunTask::Writer => {
                self.writer
                    .as_mut()
                    .expect("TUN writer handle missing")
                    .await
            }
        };

        match task {
            TunTask::Reader => {
                self.reader.take();
            }
            TunTask::Writer => {
                self.writer.take();
            }
        }
        classify_task_exit(task, result)
    }

    /// Wait for the TUN reader/writer tasks to stop.
    ///
    /// Gracefully shuts down the TUN reader and writer tasks, logging any
    /// errors or panics that occurred during execution.
    pub async fn shutdown(self) {
        if let Some(reader) = self.reader {
            join_task("tun_reader", reader).await;
        }
        if let Some(writer) = self.writer {
            join_task("tun_writer", writer).await;
        }
    }
}

fn classify_task_exit(
    task: TunTask,
    result: Result<io::Result<()>, tokio::task::JoinError>,
) -> TunTaskError {
    match result {
        Ok(Ok(())) => TunTaskError::UnexpectedExit { task },
        Ok(Err(source)) => TunTaskError::Io { task, source },
        Err(source) if source.is_panic() => TunTaskError::Panic { task, source },
        Err(source) => TunTaskError::Cancelled { task, source },
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
