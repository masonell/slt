use std::io;
use std::net::Ipv4Addr;
use std::sync::Arc;

use slt_core::config::ClientConfig;
use slt_core::packet::extract_src_ipv4;
use slt_core::proto::{Message, OwnedMessageBuf};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{debug, trace, warn};
use tun_rs::{AsyncDevice, DeviceBuilder};

const TUN_QUEUE_SIZE: usize = 256;

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
    // Build TUN device with GRO/GSO offload on Linux
    #[cfg(target_os = "linux")]
    let tun = {
        let device = DeviceBuilder::new()
            .name(&config.tun.tun_name)
            .mtu(config.tun.tun_mtu)
            .offload(true)
            .build_async()?;
        Arc::new(device)
    };

    #[cfg(not(target_os = "linux"))]
    let tun = {
        let device = DeviceBuilder::new()
            .name(&config.tun.tun_name)
            .mtu(config.tun.tun_mtu)
            .build_async()?;
        Arc::new(device)
    };

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
    let (to_session_tx, to_session_rx) = mpsc::channel(TUN_QUEUE_SIZE);
    let (to_tun_tx, to_tun_rx) = mpsc::channel(TUN_QUEUE_SIZE);

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
    use tun_rs::{IDEAL_BATCH_SIZE, VIRTIO_NET_HDR_LEN};

    let mtu = mtu as usize;
    if mtu == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "tun mtu must be greater than zero",
        ));
    }

    let min_split_buffers = (65535 / mtu) + 1;
    let split_buffer_count = IDEAL_BATCH_SIZE.max(min_split_buffers);

    // Buffer for raw GRO data (virtio header + max packet)
    let mut original_buffer = vec![0u8; VIRTIO_NET_HDR_LEN + 65535];
    // Buffers for split packets
    let mut bufs: Vec<Vec<u8>> = (0..split_buffer_count).map(|_| vec![0u8; mtu]).collect();
    let mut sizes = vec![0usize; split_buffer_count];

    loop {
        let count = tokio::select! {
            () = cancel.cancelled() => return Ok(()),
            res = tun.recv_multiple(&mut original_buffer, &mut bufs, &mut sizes, 0) => res?,
        };

        if count == 0 {
            continue;
        }

        for i in 0..count {
            let size = sizes[i];
            if size == 0 {
                continue;
            }

            let packet = &bufs[i][..size];
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
    let mtu = mtu as usize;
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
    use tun_rs::{GROTable, IDEAL_BATCH_SIZE, VIRTIO_NET_HDR_LEN};

    let mut gro_table = GROTable::new();
    // Buffers with headroom for virtio header
    let mut bufs: Vec<Vec<u8>> = (0..IDEAL_BATCH_SIZE)
        .map(|_| vec![0u8; VIRTIO_NET_HDR_LEN + 65535])
        .collect();

    loop {
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

        let mut count = 0;
        let offset = VIRTIO_NET_HDR_LEN;
        let max = bufs[count].capacity().saturating_sub(offset);
        if packet.len() > max {
            debug!(
                len = packet.len(),
                max, "tun write packet too large, dropping"
            );
            continue;
        }
        let first_len = offset + packet.len();
        if bufs[count].len() != first_len {
            bufs[count].resize(first_len, 0);
        }
        let mut payload_bytes = packet.len();
        bufs[count][offset..first_len].copy_from_slice(packet);
        count += 1;

        // Drain any additional packets
        while count < IDEAL_BATCH_SIZE {
            match rx.try_recv() {
                Ok(frame) => {
                    let Message::Data { packet } = frame.message() else {
                        debug!("dropping non-data frame in tun writer");
                        continue;
                    };
                    if packet.is_empty() {
                        continue;
                    }
                    let max = bufs[count].capacity().saturating_sub(offset);
                    if packet.len() > max {
                        debug!(
                            len = packet.len(),
                            max, "tun write packet too large, dropping"
                        );
                        continue;
                    }
                    let packet_len = offset + packet.len();
                    if bufs[count].len() != packet_len {
                        bufs[count].resize(packet_len, 0);
                    }
                    payload_bytes += packet.len();
                    bufs[count][offset..packet_len].copy_from_slice(packet);
                    count += 1;
                }
                Err(mpsc::error::TryRecvError::Empty) => break,
                Err(mpsc::error::TryRecvError::Disconnected) => return Ok(()),
            }
        }

        // Send batch with GSO
        let written = match tun
            .send_multiple(&mut gro_table, &mut bufs[..count], offset)
            .await
        {
            Ok(bytes) => bytes,
            Err(err) => {
                warn!(error = %err, count, "tun send_multiple error");
                return Err(err);
            }
        };

        let virtio_overhead_bytes = written.saturating_sub(payload_bytes);
        let estimated_output_packets = (virtio_overhead_bytes > 0
            && virtio_overhead_bytes % VIRTIO_NET_HDR_LEN == 0)
            .then_some(virtio_overhead_bytes / VIRTIO_NET_HDR_LEN);
        let estimated_coalesced_packets =
            estimated_output_packets.map(|output| count.saturating_sub(output));

        trace!(
            input_packets = count,
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
