use slt_core::packet::extract_src_ipv4;
use std::io;
use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{debug, trace, warn};
use tun_rs::AsyncDevice;

const TUN_QUEUE_SIZE: usize = 256;

/// TUN channel endpoints plus task handles.
pub struct TunHandles {
    /// Packets read from TUN and destined for the session.
    pub to_session_rx: mpsc::Receiver<Vec<u8>>,
    /// Packets written to TUN from the session.
    pub to_tun_tx: mpsc::Sender<Vec<u8>>,
    reader: JoinHandle<io::Result<()>>,
    writer: JoinHandle<io::Result<()>>,
}

impl TunHandles {
    /// Wait for the TUN reader/writer tasks to stop.
    pub async fn shutdown(self) {
        join_task("tun_reader", self.reader).await;
        join_task("tun_writer", self.writer).await;
    }
}

/// Spawn TUN reader/writer tasks and return channels plus handles.
pub fn spawn(
    tun: Arc<AsyncDevice>,
    assigned_ipv4: Ipv4Addr,
    cancel: CancellationToken,
    mtu: u16,
) -> TunHandles {
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

    TunHandles {
        to_session_rx,
        to_tun_tx,
        reader,
        writer,
    }
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
    rx: mpsc::Receiver<Vec<u8>>,
    cancel: CancellationToken,
) -> JoinHandle<io::Result<()>> {
    tokio::spawn(async move { run_tun_writer(tun, rx, cancel).await })
}

async fn run_tun_reader(
    tun: Arc<AsyncDevice>,
    assigned_ipv4: Ipv4Addr,
    tx: mpsc::Sender<Vec<u8>>,
    cancel: CancellationToken,
    mtu: u16,
) -> io::Result<()> {
    let mut buf = vec![0u8; mtu as usize];
    loop {
        let n = tokio::select! {
            () = cancel.cancelled() => return Ok(()),
            res = tun.recv(&mut buf) => res?,
        };

        if n == 0 {
            continue;
        }

        let packet = &buf[..n];
        let Some(src_ip) = extract_src_ipv4(packet) else {
            debug!(len = n, "tun packet missing IPv4 src");
            continue;
        };
        trace!(len = n, src_ip = %src_ip, "tun packet received");
        if src_ip != assigned_ipv4 {
            warn!(
                src_ip = %src_ip,
                assigned_ip = %assigned_ipv4,
                "dropping tun packet due to source IP mismatch"
            );
            continue;
        }

        if tx.try_send(packet.to_vec()).is_err() {
            debug!(len = n, "tun packet dropped (session queue full/closed)");
        }
    }
}

async fn run_tun_writer(
    tun: Arc<AsyncDevice>,
    mut rx: mpsc::Receiver<Vec<u8>>,
    cancel: CancellationToken,
) -> io::Result<()> {
    loop {
        let packet = tokio::select! {
            () = cancel.cancelled() => return Ok(()),
            maybe = rx.recv() => match maybe {
                Some(packet) => packet,
                None => return Ok(()),
            },
        };

        if packet.is_empty() {
            continue;
        }

        let written = tun.send(&packet).await?;
        if written != packet.len() {
            debug!(written, expected = packet.len(), "partial tun write");
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
