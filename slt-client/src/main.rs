use clap::Parser;
use slt_core::config::ClientConfig;
use std::fs;
use std::path::PathBuf;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info};
use tracing_error::ErrorLayer;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

mod runtime;
mod tun;

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
    runtime::run_client(config, cancel).await
}
