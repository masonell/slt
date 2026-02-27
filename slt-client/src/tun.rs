use std::io;
use std::net::Ipv4Addr;
use std::sync::Arc;

use slt_core::config::ClientConfig;
use slt_core::packet::extract_src_ipv4;
use slt_core::proto::{Message, OwnedMessageBuf};
#[cfg(not(target_os = "linux"))]
use slt_core::transport::tun::tun_mtu_to_usize;
use slt_core::transport::tun::{DEFAULT_TUN_CHANNEL_SIZE, build_async_tun_device};
#[cfg(target_os = "linux")]
use slt_core::transport::tun::{LinuxRecvBatch, LinuxSendBatch};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{debug, trace, warn};
use tun_rs::AsyncDevice;

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

/// Create TUN device and spawn reader/writer tasks.
///
/// Configures and creates a TUN device with the specified name and MTU,
/// then spawns reader and writer tasks for asynchronous packet I/O.
/// On Linux, enables GRO/GSO offload for improved performance.
///
/// # Arguments
///
/// * `config` - Client configuration containing TUN device settings
/// * `cancel` - Cancellation token to signal task shutdown
///
/// # Returns
///
/// A tuple containing:
/// - `TunHandles`: Join handles for the reader/writer tasks
/// - `TunChannels`: MPSC channels for packet I/O
///
/// # Errors
///
/// Returns an error if:
/// - TUN device creation fails (permission denied, device name invalid, etc.)
/// - MTU configuration is invalid
pub fn create(
    config: &ClientConfig,
    cancel: CancellationToken,
) -> io::Result<(TunHandles, TunChannels)> {
    let tun = Arc::new(build_async_tun_device(
        &config.tun.tun_name,
        config.tun.tun_mtu,
    )?);

    let (handles, channels) = spawn(
        tun,
        config.identity.assigned_ipv4,
        cancel,
        config.tun.tun_mtu,
    );

    Ok((handles, channels))
}

/// Spawn TUN reader/writer tasks.
///
/// Returns handles for shutdown coordination and channels for packet I/O.
fn spawn(
    tun: Arc<AsyncDevice>,
    assigned_ipv4: Ipv4Addr,
    cancel: CancellationToken,
    mtu: u16,
) -> (TunHandles, TunChannels) {
    let (to_session_tx, to_session_rx) = mpsc::channel(DEFAULT_TUN_CHANNEL_SIZE);
    let (to_tun_tx, to_tun_rx) = mpsc::channel(DEFAULT_TUN_CHANNEL_SIZE);

    let reader = spawn_tun_reader(
        tun.clone(),
        assigned_ipv4,
        to_session_tx,
        cancel.clone(),
        mtu,
    );
    let writer = spawn_tun_writer(tun, to_tun_rx, cancel);

    (
        TunHandles { reader, writer },
        TunChannels {
            to_session_rx,
            to_tun_tx,
        },
    )
}

fn spawn_tun_reader(
    tun: Arc<AsyncDevice>,
    assigned_ipv4: Ipv4Addr,
    tx: mpsc::Sender<Vec<u8>>,
    cancel: CancellationToken,
    mtu: u16,
) -> JoinHandle<io::Result<()>> {
    tokio::spawn(async move { run_tun_reader(tun, assigned_ipv4, tx, cancel, mtu).await })
}

fn spawn_tun_writer(
    tun: Arc<AsyncDevice>,
    rx: mpsc::Receiver<OwnedMessageBuf>,
    cancel: CancellationToken,
) -> JoinHandle<io::Result<()>> {
    tokio::spawn(async move { run_tun_writer(tun, rx, cancel).await })
}

/// Reads packets from the TUN device and sends them to the session.
///
/// On Linux with GRO enabled, uses `recv_multiple` to batch packets per syscall.
/// On other platforms, falls back to single-packet reads.
#[cfg(target_os = "linux")]
async fn run_tun_reader(
    tun: Arc<AsyncDevice>,
    assigned_ipv4: Ipv4Addr,
    tx: mpsc::Sender<Vec<u8>>,
    cancel: CancellationToken,
    mtu: u16,
) -> io::Result<()> {
    let mut recv_batch = LinuxRecvBatch::new(mtu)?;

    loop {
        let (original_buffer, bufs, sizes) = recv_batch.recv_args();
        let count = tokio::select! {
            () = cancel.cancelled() => return Ok(()),
            res = tun.recv_multiple(original_buffer, bufs, sizes, 0) => res?,
        };

        if count == 0 {
            continue;
        }

        for i in 0..count {
            let size = recv_batch.packet_len(i);
            if size == 0 {
                continue;
            }

            let packet = recv_batch.packet(i);
            let Some(src_ip) = extract_src_ipv4(packet) else {
                debug!(len = size, "tun packet missing IPv4 src");
                continue;
            };
            trace!(len = size, src_ip = %src_ip, "tun packet received");

            if src_ip != assigned_ipv4 {
                warn!(
                    src_ip = %src_ip,
                    assigned_ip = %assigned_ipv4,
                    "dropping tun packet due to source IP mismatch"
                );
                continue;
            }

            if tx.send(packet.to_vec()).await.is_err() {
                debug!(len = size, "tun queue closed, exiting reader");
                return Ok(());
            }
        }
    }
}

#[cfg(not(target_os = "linux"))]
async fn run_tun_reader(
    tun: Arc<AsyncDevice>,
    assigned_ipv4: Ipv4Addr,
    tx: mpsc::Sender<Vec<u8>>,
    cancel: CancellationToken,
    mtu: u16,
) -> io::Result<()> {
    let mtu = tun_mtu_to_usize(mtu)?;
    let mut packet = vec![0u8; mtu];
    loop {
        let n = tokio::select! {
            () = cancel.cancelled() => return Ok(()),
            res = tun.recv(&mut packet) => res?,
        };

        if n == 0 {
            continue;
        }

        packet.truncate(n);
        let Some(src_ip) = extract_src_ipv4(&packet) else {
            debug!(len = n, "tun packet missing IPv4 src");
            packet.resize(mtu, 0);
            continue;
        };
        trace!(len = n, src_ip = %src_ip, "tun packet received");
        if src_ip != assigned_ipv4 {
            warn!(
                src_ip = %src_ip,
                assigned_ip = %assigned_ipv4,
                "dropping tun packet due to source IP mismatch"
            );
            packet.resize(mtu, 0);
            continue;
        }

        if tx.send(packet).await.is_err() {
            debug!(len = n, "tun queue closed, exiting reader");
            return Ok(());
        }
        packet = vec![0u8; mtu];
    }
}

/// Writes packets to the TUN device from the channel.
///
/// On Linux with GSO enabled, batches packets and uses `send_multiple`.
/// On other platforms, sends packets individually.
#[cfg(target_os = "linux")]
async fn run_tun_writer(
    tun: Arc<AsyncDevice>,
    mut rx: mpsc::Receiver<OwnedMessageBuf>,
    cancel: CancellationToken,
) -> io::Result<()> {
    use tun_rs::GROTable;

    let mut gro_table = GROTable::new();
    let mut send_batch = LinuxSendBatch::new();

    loop {
        send_batch.clear();

        // Wait for first packet
        let first = tokio::select! {
            () = cancel.cancelled() => return Ok(()),
            maybe = rx.recv() => match maybe {
                Some(frame) => frame,
                None => return Ok(()),
            },
        };

        let Message::Data { packet } = first.message() else {
            debug!("dropping non-data frame in tun writer");
            continue;
        };

        if packet.is_empty() {
            continue;
        }

        if let Err(err) = send_batch.push_packet(packet) {
            debug!(
                len = err.len,
                max = err.max,
                "tun write packet too large, dropping"
            );
            continue;
        }

        // Drain any additional packets
        while !send_batch.is_full() {
            match rx.try_recv() {
                Ok(frame) => {
                    let Message::Data { packet } = frame.message() else {
                        debug!("dropping non-data frame in tun writer");
                        continue;
                    };
                    if packet.is_empty() {
                        continue;
                    }
                    if let Err(err) = send_batch.push_packet(packet) {
                        debug!(
                            len = err.len,
                            max = err.max,
                            "tun write packet too large, dropping"
                        );
                    }
                }
                Err(mpsc::error::TryRecvError::Empty) => break,
                Err(mpsc::error::TryRecvError::Disconnected) => return Ok(()),
            }
        }

        let header_offset = send_batch.header_offset();
        let payload_bytes = send_batch.payload_bytes();
        let input_packets = send_batch.packet_count();

        // Send batch with GSO
        let written = match tun
            .send_multiple(
                &mut gro_table,
                send_batch.queued_buffers_mut(),
                header_offset,
            )
            .await
        {
            Ok(bytes) => bytes,
            Err(err) => {
                warn!(error = %err, count = input_packets, "tun send_multiple error");
                return Err(err);
            }
        };

        let virtio_overhead_bytes = written.saturating_sub(payload_bytes);
        let estimated_output_packets = (virtio_overhead_bytes > 0
            && virtio_overhead_bytes % header_offset == 0)
            .then_some(virtio_overhead_bytes / header_offset);
        let estimated_coalesced_packets =
            estimated_output_packets.map(|output| input_packets.saturating_sub(output));

        trace!(
            input_packets,
            input_payload_bytes = payload_bytes,
            written_bytes = written,
            virtio_overhead_bytes,
            estimated_output_packets = ?estimated_output_packets,
            estimated_coalesced_packets = ?estimated_coalesced_packets,
            "tun writer batch stats"
        );
    }
}

#[cfg(not(target_os = "linux"))]
async fn run_tun_writer(
    tun: Arc<AsyncDevice>,
    mut rx: mpsc::Receiver<OwnedMessageBuf>,
    cancel: CancellationToken,
) -> io::Result<()> {
    loop {
        let frame = tokio::select! {
            () = cancel.cancelled() => return Ok(()),
            maybe = rx.recv() => match maybe {
                Some(frame) => frame,
                None => return Ok(()),
            },
        };

        let Message::Data { packet } = frame.message() else {
            debug!("dropping non-data frame in tun writer");
            continue;
        };

        if packet.is_empty() {
            continue;
        }

        // TUN writes are atomic: the kernel either accepts the entire packet or
        // fails with an error. Partial writes should never occur; if they do,
        // something is very wrong and worth investigating.
        let written = tun.send(packet).await?;
        if written != packet.len() {
            warn!(
                written,
                expected = packet.len(),
                "unexpected partial tun write"
            );
        }
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
