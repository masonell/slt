use clap::Parser;
use slt::config::ClientConfig;
use slt::server::router::PacketRouter;
use std::fs;
use std::io;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, trace, warn};
use tracing_error::ErrorLayer;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tun_rs::{AsyncDevice, DeviceBuilder};

const TUN_QUEUE_SIZE: usize = 256;

#[derive(Parser, Debug)]
#[command(about = "Run the SLT client.")]
struct Args {
    /// Path to the client configuration file (TOML).
    #[arg(long, value_name = "PATH")]
    config: PathBuf,
    /// Optional tracing filter override (e.g., "slt=debug").
    #[arg(long, value_name = "FILTER")]
    log: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    init_tracing(args.log.as_deref());

    let raw = fs::read_to_string(&args.config)?;
    let config: ClientConfig = toml::from_str(&raw)?;
    info!(config_path = %args.config.display(), "config parsed successfully");
    log_config(&config);

    let cancel = CancellationToken::new();
    spawn_ctrl_c(cancel.clone());

    info!(
        server_addr = %config.server_addr,
        tun_name = %config.tun_name,
        tun_mtu = config.tun_mtu,
        "client starting"
    );

    run_client(config, cancel).await
}

fn init_tracing(filter: Option<&str>) {
    let filter = filter.map_or_else(
        || EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("slt=info")),
        EnvFilter::new,
    );
    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer())
        .with(ErrorLayer::default())
        .init();
}

fn spawn_ctrl_c(cancel: CancellationToken) {
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            debug!("received ctrl_c signal");
            cancel.cancel();
        }
    });
}

fn log_config(config: &ClientConfig) {
    info!(
        server_addr = %config.server_addr,
        client_id = %config.client_id,
        assigned_ipv4 = %config.assigned_ipv4,
        tun_name = %config.tun_name,
        tun_mtu = config.tun_mtu,
        has_upgrade = config.upgrade.is_some(),
        "client config loaded (secrets redacted)"
    );
}

async fn run_client(
    config: ClientConfig,
    cancel: CancellationToken,
) -> Result<(), Box<dyn std::error::Error>> {
    let tun = Arc::new(
        DeviceBuilder::new()
            .name(&config.tun_name)
            .mtu(config.tun_mtu)
            .build_async()?,
    );

    let (tun_to_session_tx, tun_to_session_rx) = mpsc::channel(TUN_QUEUE_SIZE);
    let (session_to_tun_tx, session_to_tun_rx) = mpsc::channel(TUN_QUEUE_SIZE);

    let tun_reader = spawn_tun_reader(
        tun.clone(),
        config.assigned_ipv4,
        tun_to_session_tx,
        cancel.clone(),
        config.tun_mtu,
    );
    let tun_writer = spawn_tun_writer(tun, session_to_tun_rx, cancel.clone());

    let _tun_to_session_rx = tun_to_session_rx;
    let _session_to_tun_tx = session_to_tun_tx;

    info!("client runtime not implemented yet; waiting for shutdown");
    cancel.cancelled().await;
    join_task("tun_reader", tun_reader).await;
    join_task("tun_writer", tun_writer).await;
    info!("client shutdown complete");
    Ok(())
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
        let Some(src_ip) = PacketRouter::extract_src_ipv4(packet) else {
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
