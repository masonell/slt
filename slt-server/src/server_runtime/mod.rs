use std::error::Error;
use std::sync::Arc;

use slt_core::config::ServerConfig;
use slt_core::proto::MessageLimits;
use slt_core::transport::tun::{
    DEFAULT_TUN_CHANNEL_SIZE, build_async_tun_device, tun_offload_enabled,
};
use slt_server::auth::{AuthHandlerBase, Authenticator, SessionManager};
use slt_server::metrics::Metrics;
use slt_server::quic::QuicEndpoint;
use slt_server::registry::SessionRegistry;
use slt_server::sessions::SessionTimeouts;
use slt_server::tcp::TcpFrontDoor;
use slt_server::tun::TunSender;
use tokio::sync::mpsc;
use tracing::{debug, info};

mod supervision;
mod tls;
mod tun_workers;

struct RuntimeComponents {
    frontdoor: TcpFrontDoor,
    quic: QuicEndpoint,
    auth_handler: Arc<AuthHandlerBase<TunSender>>,
    sessions: SessionManager<TunSender>,
    tun: TunRuntime,
    metrics: Arc<Metrics>,
    metrics_interval: std::time::Duration,
}

struct TunRuntime {
    device: Arc<tun_rs::AsyncDevice>,
    packets: mpsc::Receiver<Vec<u8>>,
    registry: Arc<SessionRegistry>,
    mtu: u16,
}

pub async fn run(config: Arc<ServerConfig>) -> Result<(), Box<dyn Error>> {
    debug!("server runtime: initializing components");

    let metrics = Arc::new(Metrics::default());
    let registry = Arc::new(SessionRegistry::new());
    let frontdoor = TcpFrontDoor::bind(&config, metrics.clone()).await?;
    let quic = QuicEndpoint::bind(&config, registry.clone(), metrics.clone())?;
    let acceptor = tls::build_acceptor(&config)?;
    let authenticator = Authenticator::from_config(&config);
    let tun = Arc::new(build_async_tun_device(&config.tun)?);
    if tun_offload_enabled(tun.as_ref()) {
        info!("TUN device attached with GRO/GSO offload enabled");
    }

    let (tun_tx, tun_rx) = mpsc::channel(DEFAULT_TUN_CHANNEL_SIZE);
    let tun_sender = Arc::new(TunSender::new(tun_tx, metrics.clone()));
    let session_timeouts = SessionTimeouts {
        ping_min: config.timing.ping_min,
        ping_max: config.timing.ping_max,
        udp_liveness_timeout: config.timing.udp_liveness_timeout,
        idle_timeout: config.timing.idle_timeout,
        tcp_write_timeout: config.timing.tcp_write_timeout,
    };
    let sessions = SessionManager::new(
        registry.clone(),
        metrics.clone(),
        tun_sender,
        quic.socket().clone(),
        MessageLimits::from_mtu(config.tun.tun_mtu),
        session_timeouts,
        config.session_queue_size,
        config.transport.udp_qsp.clone(),
    );
    let auth_handler = Arc::new(AuthHandlerBase::<TunSender>::new(
        acceptor,
        authenticator,
        sessions.clone(),
        config.timing.auth_timeout,
        config.max_auth_inflight,
    ));

    supervision::run(RuntimeComponents {
        frontdoor,
        quic,
        auth_handler,
        sessions,
        tun: TunRuntime {
            device: tun,
            packets: tun_rx,
            registry,
            mtu: config.tun.tun_mtu,
        },
        metrics,
        metrics_interval: config.timing.metrics_interval,
    })
    .await?;
    Ok(())
}
