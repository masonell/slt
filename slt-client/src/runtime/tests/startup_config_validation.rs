use std::io;
use std::time::Duration;

use slt_core::config::ConfigError;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use super::super::run_client;
use crate::runtime::services::DesktopServices;
use crate::test_support::test_config;
use crate::tun;

#[tokio::test]
async fn run_client_rejects_invalid_config() {
    let mut config = test_config();
    config.timing.reconnect_min = Duration::ZERO;

    let cancel = CancellationToken::new();
    let reader_cancel = cancel.clone();
    let writer_cancel = cancel.clone();
    let reader = tokio::spawn(async move {
        reader_cancel.cancelled().await;
        Ok::<(), io::Error>(())
    });
    let writer = tokio::spawn(async move {
        writer_cancel.cancelled().await;
        Ok::<(), io::Error>(())
    });
    let tun_handles = tun::TunHandles::new(reader, writer);
    let (_to_session_tx, to_session_rx) = mpsc::channel(1);
    let (to_tun_tx, _to_tun_rx) = mpsc::channel(1);
    let tun_channels = tun::TunChannels {
        to_session_rx,
        to_tun_tx,
    };

    let err = run_client(
        config,
        tun_handles,
        tun_channels,
        cancel.clone(),
        DesktopServices::new(),
        None,
    )
    .await
    .unwrap_err();

    assert!(cancel.is_cancelled());
    assert!(matches!(
        err.downcast_ref::<ConfigError>(),
        Some(ConfigError::IntervalTooSmall {
            field: "reconnect_min",
            ..
        })
    ));
}
