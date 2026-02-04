use crate::{tcp, tun};
use slt_core::config::ClientConfig;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;
use tracing::info;
use tun_rs::DeviceBuilder;

/// Run the client runtime until shutdown.
pub async fn run_client(
    config: ClientConfig,
    cancel: CancellationToken,
) -> Result<(), Box<dyn std::error::Error>> {
    let tun = Arc::new(
        DeviceBuilder::new()
            .name(&config.tun_name)
            .mtu(config.tun_mtu)
            .build_async()?,
    );

    let tun_handles = tun::spawn(tun, config.assigned_ipv4, cancel.clone(), config.tun_mtu);
    let _ = (&tun_handles.to_session_rx, &tun_handles.to_tun_tx);

    let tcp = tcp::connect(&config).await?;
    let _ = &tcp.stream;
    info!(peer = ?tcp.peer, sni = ?tcp.sni, "tcp handshake complete");

    info!("client runtime not implemented yet; waiting for shutdown");
    cancel.cancelled().await;
    tun_handles.shutdown().await;
    info!("client shutdown complete");
    Ok(())
}
