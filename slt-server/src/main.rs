use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use slt_core::config::ServerConfig;
use tracing::info;
use tracing_error::ErrorLayer;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

mod server_runtime;

const DEFAULT_TRACING_FILTER: &str = "slt_server=info,slt_core=info";

/// Command-line arguments for the SLT server.
#[derive(Parser, Debug)]
#[command(about = "Run the SLT server front door.", version)]
struct Args {
    /// Path to the server configuration file (TOML).
    #[arg(long, value_name = "PATH")]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_tracing();
    let args = Args::parse();
    let raw = fs::read_to_string(&args.config)?;
    let config = ServerConfig::from_toml_str(&raw)?;
    info!(config_path = %args.config.display(), "config parsed successfully");
    let config = Arc::new(config);

    info!(
        listen_tcp = %config.network.listen_tcp,
        listen_udp = %config.network.listen_udp,
        tun_name = %config.tun.tun_name,
        tun_mtu = config.tun.tun_mtu,
        "server starting"
    );

    server_runtime::run(config).await
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(DEFAULT_TRACING_FILTER));
    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer())
        .with(ErrorLayer::default())
        .init();
}

#[cfg(test)]
mod tests {
    use super::DEFAULT_TRACING_FILTER;

    #[test]
    fn default_tracing_filter_includes_server_and_core_targets() {
        assert!(DEFAULT_TRACING_FILTER.contains("slt_server=info"));
        assert!(DEFAULT_TRACING_FILTER.contains("slt_core=info"));
    }
}
