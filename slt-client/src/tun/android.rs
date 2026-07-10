//! Android `tun-rs` packet-I/O backend.
//!
//! [`spawn_from_fd`] duplicates the `VpnService` TUN file descriptor borrowed
//! from Kotlin, wraps the duplicate with `tun-rs`, and spawns packet reader and
//! writer tasks for the platform-agnostic runtime.

use std::io;
use std::net::Ipv4Addr;
use std::sync::Arc;

use slt_core::config::ClientConfig;
use slt_core::packet::extract_src_ipv4;
use slt_core::proto::{Message, OwnedMessageBuf};
use slt_core::transport::tun::{DEFAULT_TUN_CHANNEL_SIZE, tun_mtu_to_usize};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{debug, trace, warn};
use tun_rs::AsyncDevice;

use super::{TunChannels, TunHandles, TunQueueSend, send_to_session_queue};

/// Wrap an Android `VpnService` fd and spawn TUN reader/writer tasks.
///
/// The supplied fd is borrowed from Android. This function duplicates it with
/// `dup(2)` and gives only the duplicate to `tun-rs`, so Kotlin remains
/// responsible for closing the original `ParcelFileDescriptor`.
///
/// # Errors
///
/// Returns an error if the fd is invalid, duplication fails, the duplicated fd
/// cannot be wrapped as a `tun-rs` async device, or the configured TUN MTU is
/// invalid.
pub fn spawn_from_fd(
    config: &ClientConfig,
    tun_fd: i32,
    cancel: CancellationToken,
) -> io::Result<(TunHandles, TunChannels)> {
    if tun_fd < 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid Android TUN fd: {tun_fd}"),
        ));
    }

    let mtu = config.tun.tun_mtu;
    let duplicate = duplicate_fd(tun_fd)?;
    let tun = unsafe {
        // SAFETY: duplicate is a fresh owned fd created from Android's valid
        // VPN fd. tun-rs owns and closes this duplicate when AsyncDevice drops.
        AsyncDevice::from_fd(duplicate)
    }?;
    let tun = Arc::new(tun);

    spawn_tasks(tun, config.identity.assigned_ipv4, cancel, mtu)
}

fn duplicate_fd(fd: i32) -> io::Result<i32> {
    let duplicate = unsafe {
        // SAFETY: dup does not take ownership of fd and returns a new owned fd.
        libc::dup(fd)
    };
    if duplicate < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(duplicate)
    }
}

fn spawn_tasks(
    tun: Arc<AsyncDevice>,
    assigned_ipv4: Ipv4Addr,
    cancel: CancellationToken,
    mtu: u16,
) -> io::Result<(TunHandles, TunChannels)> {
    let mtu = tun_mtu_to_usize(mtu)?;
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

    Ok((
        TunHandles::new(reader, writer),
        TunChannels {
            to_session_rx,
            to_tun_tx,
        },
    ))
}

fn spawn_tun_reader(
    tun: Arc<AsyncDevice>,
    assigned_ipv4: Ipv4Addr,
    tx: mpsc::Sender<Vec<u8>>,
    cancel: CancellationToken,
    mtu: usize,
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

async fn run_tun_reader(
    tun: Arc<AsyncDevice>,
    assigned_ipv4: Ipv4Addr,
    tx: mpsc::Sender<Vec<u8>>,
    cancel: CancellationToken,
    mtu: usize,
) -> io::Result<()> {
    let mut buf = vec![0u8; mtu];

    loop {
        let len = tokio::select! {
            () = cancel.cancelled() => return Ok(()),
            res = tun.recv(&mut buf) => res?,
        };

        if len == 0 {
            continue;
        }

        let packet = &buf[..len];
        let Some(src_ip) = extract_src_ipv4(packet) else {
            debug!(len, "dropping non-IPv4 Android TUN packet");
            continue;
        };
        trace!(len, src_ip = %src_ip, "Android TUN packet received");

        if src_ip != assigned_ipv4 {
            warn!(
                src_ip = %src_ip,
                assigned_ip = %assigned_ipv4,
                "dropping Android TUN packet due to source IP mismatch"
            );
            continue;
        }

        match send_to_session_queue(&tx, packet.to_vec(), &cancel).await {
            TunQueueSend::Sent => {}
            TunQueueSend::Closed => {
                debug!(len, "Android TUN queue closed, exiting reader");
                return Ok(());
            }
            TunQueueSend::Cancelled => return Ok(()),
        }
    }
}

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
            debug!("dropping non-data frame in Android TUN writer");
            continue;
        };

        if packet.is_empty() {
            continue;
        }

        let written = tokio::select! {
            () = cancel.cancelled() => return Ok(()),
            result = tun.send(packet) => result?,
        };
        if written != packet.len() {
            // Android/Linux TUN writes are packet-oriented: a successful write
            // accepts exactly one whole packet. A short positive write would
            // mean the fd/backend violated that contract; retrying the tail
            // would inject it as a malformed second packet.
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "short Android TUN packet write: wrote {written} of {} bytes",
                    packet.len()
                ),
            ));
        }

        trace!(len = written, "Android TUN packet written");
    }
}
