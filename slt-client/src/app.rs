use crate::runtime;
use slt_core::config::ClientConfig;
use tokio_util::sync::CancellationToken;

/// Run the SLT client application.
pub async fn run(
    config: ClientConfig,
    cancel: CancellationToken,
) -> Result<(), Box<dyn std::error::Error>> {
    Box::pin(runtime::run_client(config, cancel)).await
}
