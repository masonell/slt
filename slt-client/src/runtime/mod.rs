mod register;
mod session;

use crate::{auth, quic, tcp, tun};
use slt_core::config::ClientConfig;
use slt_core::proto::{FrameError, MessageError, PayloadError};
use std::io;
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};
use tun_rs::DeviceBuilder;

const PING_MIN: Duration = Duration::from_secs(10);
const PING_MAX: Duration = Duration::from_secs(20);
const IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// Run the client runtime until shutdown.
pub async fn run_client(
    config: ClientConfig,
    cancel: CancellationToken,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut tcp = tcp::connect(&config).await?;
    info!(peer = ?tcp.peer, sni = ?tcp.sni, "tcp handshake complete");
    let auth_outcome = auth::authenticate(&mut tcp.stream, &config).await?;
    tcp.read_buf = auth_outcome.leftover;
    if !tcp.read_buf.is_empty() {
        debug!(len = tcp.read_buf.len(), "preserved auth leftovers");
    }

    let quic_ids = if config.upgrade.is_some() {
        match Box::pin(quic::discover_quic_ids(&config, &cancel, tcp.peer)).await {
            Ok(ids) => {
                info!(
                    dcid_len = ids.dcid.len(),
                    scid_len = ids.scid.len(),
                    "quic dcid discovery succeeded"
                );
                Some(ids)
            }
            Err(err) => {
                warn!(error = %err, "quic dcid discovery failed");
                None
            }
        }
    } else {
        debug!("upgrade disabled; skipping quic dcid discovery");
        None
    };

    let tun = Arc::new(
        DeviceBuilder::new()
            .name(&config.tun_name)
            .mtu(config.tun_mtu)
            .build_async()?,
    );

    let mut tun_handles = tun::spawn(tun, config.assigned_ipv4, cancel.clone(), config.tun_mtu);
    let limits = register::message_limits_from_mtu(config.tun_mtu);

    let (to_session_rx, to_tun_tx) = tun_handles.take_channels();

    let udp_session = if let Some(ids) = &quic_ids {
        match Box::pin(register::register_udp_qsp(
            &mut tcp.stream,
            &mut tcp.read_buf,
            limits,
            &to_tun_tx,
            ids,
        ))
        .await
        {
            Ok(session) => {
                info!(
                    dcid_len = ids.dcid.len(),
                    scid_len = ids.scid.len(),
                    peer = %ids.peer,
                    "register_cid accepted"
                );
                Some(session)
            }
            Err(err) => {
                warn!(error = %err, "register_cid failed");
                None
            }
        }
    } else {
        None
    };
    let mut session = session::ClientSession::new(
        tcp.stream,
        tcp.read_buf,
        to_session_rx,
        to_tun_tx,
        cancel.clone(),
        limits,
        PING_MIN,
        PING_MAX,
        IDLE_TIMEOUT,
        quic_ids,
        udp_session,
    );

    let result = session.run().await;
    cancel.cancel();
    tun_handles.shutdown().await;

    if let Err(err) = result {
        warn!(error = %err, "client session exited with error");
        return Err(err.into());
    }

    info!("client shutdown complete");
    Ok(())
}

fn map_frame_error(err: FrameError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("frame error: {err:?}"))
}

fn map_message_error(err: MessageError) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("message error: {err:?}"),
    )
}

fn map_payload_error(err: PayloadError) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("payload error: {err:?}"),
    )
}
