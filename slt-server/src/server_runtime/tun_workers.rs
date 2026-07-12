use std::io;
use std::sync::Arc;

use slt_core::packet::extract_dst_ipv4;
#[cfg(target_os = "linux")]
use slt_core::transport::tun::{LinuxRecvBatch, LinuxSendBatch};
use slt_server::metrics::Metrics;
use slt_server::sessions::SessionEvent;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, trace, warn};

use super::TunRuntime;

pub(super) fn spawn(
    tun: TunRuntime,
    metrics: Arc<Metrics>,
    cancel: CancellationToken,
) -> (
    tokio::task::JoinHandle<io::Result<()>>,
    tokio::task::JoinHandle<io::Result<()>>,
) {
    let TunRuntime {
        device,
        packets,
        registry,
        mtu,
    } = tun;
    let reader = tokio::spawn(run_reader(
        device.clone(),
        registry,
        metrics,
        cancel.clone(),
        mtu,
    ));
    let writer = tokio::spawn(run_writer(device, packets, cancel));
    (reader, writer)
}

#[cfg(target_os = "linux")]
async fn run_reader(
    tun: Arc<tun_rs::AsyncDevice>,
    registry: Arc<slt_server::registry::SessionRegistry>,
    metrics: Arc<Metrics>,
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
            let Some(dst_ip) = extract_dst_ipv4(packet) else {
                debug!(len = size, "tun packet missing IPv4 dst");
                continue;
            };
            trace!(len = size, dst_ip = %dst_ip, "tun packet received");

            if let Some(tx) = registry.lookup_ip(dst_ip) {
                match tx.try_reserve() {
                    Ok(permit) => {
                        permit.send(SessionEvent::TunPacket(packet.to_vec()));
                    }
                    Err(mpsc::error::TrySendError::Full(())) => {
                        metrics.inc_tun_session_queue_full_drops();
                        debug!(dst_ip = %dst_ip, "tun packet dropped (session queue full)");
                    }
                    Err(mpsc::error::TrySendError::Closed(())) => {
                        debug!(dst_ip = %dst_ip, "tun packet dropped (session closed)");
                    }
                }
            } else {
                debug!(dst_ip = %dst_ip, "tun packet dropped (no session)");
            }
        }
    }
}

#[cfg(target_os = "linux")]
async fn run_writer(
    tun: Arc<tun_rs::AsyncDevice>,
    mut rx: mpsc::Receiver<Vec<u8>>,
    cancel: CancellationToken,
) -> io::Result<()> {
    use tun_rs::GROTable;

    let mut gro_table = GROTable::new();
    let mut send_batch = LinuxSendBatch::new();

    loop {
        send_batch.clear();

        let first = tokio::select! {
            () = cancel.cancelled() => return Ok(()),
            maybe = rx.recv() => match maybe {
                Some(pkt) => pkt,
                None => return Ok(()),
            },
        };

        if let Err(err) = send_batch.push_packet(&first) {
            debug!(
                len = err.len,
                max = err.max,
                "tun write packet too large, dropping"
            );
            continue;
        }

        while !send_batch.is_full() {
            match rx.try_recv() {
                Ok(pkt) => {
                    if let Err(err) = send_batch.push_packet(&pkt) {
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

        let written = match tokio::select! {
            () = cancel.cancelled() => return Ok(()),
            result = tun.send_multiple(
                &mut gro_table,
                send_batch.queued_buffers_mut(),
                header_offset,
            ) => result,
        } {
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
