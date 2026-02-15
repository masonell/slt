use std::fs;
use std::path::PathBuf;

use clap::Parser;
use slt_core::config::ClientConfig;
use slt_core::types::TlsMaterial;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info};
use tracing_error::ErrorLayer;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

mod auth;
mod metrics;
mod runtime;
mod transport;
mod tun;
mod wire;

#[cfg(test)]
mod test_support;

#[cfg(test)]
mod test_integration;

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
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    init_tracing(args.log.as_deref());

    let raw = fs::read_to_string(&args.config)?;
    let config = ClientConfig::from_toml_str(&raw)?;
    info!(config_path = %args.config.display(), "config parsed successfully");
    log_config(&config);

    let cancel = CancellationToken::new();
    spawn_ctrl_c(cancel.clone());

    info!(
        hostname = %config.network.hostname,
        port = config.network.port,
        ip = ?config.network.ip,
        tun_name = %config.tun.tun_name,
        tun_mtu = config.tun.tun_mtu,
        "client starting"
    );

    Box::pin(runtime::run_client(config, cancel)).await
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
        hostname = %config.network.hostname,
        port = config.network.port,
        ip = ?config.network.ip,
        tls_ca = tls_material_source(&config.tls.tls_ca),
        client_id = %config.identity.client_id,
        assigned_ipv4 = %config.identity.assigned_ipv4,
        tun_name = %config.tun.tun_name,
        tun_mtu = config.tun.tun_mtu,
        enable_upgrade = config.enable_upgrade,
        "client config loaded (secrets redacted)"
    );
}

const fn tls_material_source(material: &TlsMaterial) -> &'static str {
    match material {
        TlsMaterial::Pem(_) => "pem",
        TlsMaterial::File { .. } => "file",
    }
}
