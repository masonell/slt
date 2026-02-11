use boring::pkey::PKey;
use boring::ssl::{SslAcceptor, SslFiletype, SslMethod};
use boring::x509::X509;
use clap::Parser;
use slt_core::config::ServerConfig;
use slt_core::packet::extract_dst_ipv4;
use slt_core::types::TlsMaterial;
use slt_server::auth::{AuthHandler, Authenticator};
use slt_server::metrics::Metrics;
use slt_server::quic::QuicEndpoint;
use slt_server::registry::SessionRegistry;
use slt_server::sessions::SessionEvent;
use slt_server::sessions::{SessionTimeouts, message_limits_from_mtu};
use slt_server::tcp::TcpFrontDoor;
use std::fs;
use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::time::{self, Duration};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, trace, warn};
use tracing_error::ErrorLayer;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tun_rs::DeviceBuilder;

#[derive(Parser, Debug)]
#[command(about = "Run the SLT server front door.")]
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
        listen_tcp = %config.listen_tcp,
        listen_udp = %config.listen_udp,
        tun_name = %config.tun_name,
        tun_mtu = config.tun_mtu,
        "server starting"
    );

    run_server(config).await
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("slt=info"));
    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer())
        .with(ErrorLayer::default())
        .init();
}

async fn run_server(config: Arc<ServerConfig>) -> Result<(), Box<dyn std::error::Error>> {
    debug!("server runtime: initializing components");

    let metrics = Arc::new(Metrics::default());
    let registry = Arc::new(SessionRegistry::new());
    let frontdoor = TcpFrontDoor::bind(&config, metrics.clone()).await?;
    let quic = QuicEndpoint::bind(&config, registry.clone(), metrics.clone()).await?;
    let acceptor = build_tls_acceptor(&config)?;
    let authenticator = Authenticator::from_config(&config);
    let tun = Arc::new(
        DeviceBuilder::new()
            .name(&config.tun_name)
            .mtu(config.tun_mtu)
            .build_async()?,
    );
    let session_timeouts = SessionTimeouts {
        ping_min: config.ping_min,
        ping_max: config.ping_max,
        idle_timeout: config.idle_timeout,
        udp_verify_timeout: config.udp_verify_timeout,
    };
    let limits = message_limits_from_mtu(config.tun_mtu);
    let auth_handler = Arc::new(AuthHandler::new(
        acceptor,
        authenticator,
        registry.clone(),
        metrics.clone(),
        tun.clone(),
        quic.socket().clone(),
        limits,
        session_timeouts,
        config.auth_timeout,
        config.session_queue_size,
    ));
    let cancel = CancellationToken::new();

    spawn_ctrl_c(cancel.clone());

    debug!("server runtime: spawning worker tasks");

    let mut tcp_task = spawn_tcp_task(frontdoor, auth_handler, cancel.clone());
    let mut udp_task = spawn_udp_task(quic, cancel.clone());
    let mut tun_task = spawn_tun_task(tun, registry, cancel.clone(), config.tun_mtu);
    let mut metrics_task = spawn_metrics_task(metrics, cancel.clone());

    let shutdown_result = tokio::select! {
        res = &mut tcp_task => {
            info!(reason = "tcp_task_failure", "graceful shutdown initiated");
            cancel.cancel();
            let res = res;
            let _ = udp_task.await;
            let _ = tun_task.await;
            let _ = metrics_task.await;
            classify_task_result("tcp", res)
        }
        res = &mut udp_task => {
            info!(reason = "udp_task_failure", "graceful shutdown initiated");
            cancel.cancel();
            let res = res;
            let _ = tcp_task.await;
            let _ = tun_task.await;
            let _ = metrics_task.await;
            classify_task_result("udp", res)
        }
        res = &mut tun_task => {
            info!(reason = "tun_task_failure", "graceful shutdown initiated");
            cancel.cancel();
            let res = res;
            let _ = tcp_task.await;
            let _ = udp_task.await;
            let _ = metrics_task.await;
            classify_task_result("tun", res)
        }
        res = &mut metrics_task => {
            info!(reason = "metrics_task_failure", "graceful shutdown initiated");
            cancel.cancel();
            let res = res;
            let _ = tcp_task.await;
            let _ = udp_task.await;
            let _ = tun_task.await;
            classify_task_result("metrics", res)
        }
        () = cancel.cancelled() => {
            info!(reason = "ctrl_c", "graceful shutdown initiated");
            let _ = tcp_task.await;
            let _ = udp_task.await;
            let _ = tun_task.await;
            let _ = metrics_task.await;
            Ok(())
        }
    };

    info!("server shutdown complete");
    shutdown_result
}

fn spawn_ctrl_c(cancel: CancellationToken) {
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            debug!("received ctrl_c signal");
            cancel.cancel();
        }
    });
}

fn spawn_tcp_task(
    frontdoor: TcpFrontDoor,
    auth_handler: Arc<AuthHandler>,
    cancel: CancellationToken,
) -> tokio::task::JoinHandle<io::Result<()>> {
    tokio::spawn(async move {
        frontdoor
            .run(cancel, move |stream: TcpStream, addr| {
                let auth_handler = auth_handler.clone();
                tokio::spawn(async move {
                    info!(peer = %addr, "claimed tcp connection");
                    if let Err(err) = auth_handler.handle(stream).await {
                        warn!(peer = %addr, error = %err, "auth handler error");
                    }
                });
            })
            .await
    })
}

fn classify_task_result(
    task: &'static str,
    res: Result<io::Result<()>, tokio::task::JoinError>,
) -> Result<(), Box<dyn std::error::Error>> {
    match res {
        Ok(Ok(())) => Ok(()),
        Ok(Err(err)) => {
            error!(task, error = %err, "worker task failed");
            Err(Box::new(err))
        }
        Err(err) => {
            error!(task, error = %err, "worker task failed");
            Err(Box::new(err))
        }
    }
}

fn spawn_udp_task(
    quic: QuicEndpoint,
    cancel: CancellationToken,
) -> tokio::task::JoinHandle<io::Result<()>> {
    tokio::spawn(async move { quic.run(cancel).await })
}

fn spawn_tun_task(
    tun: Arc<tun_rs::AsyncDevice>,
    registry: Arc<SessionRegistry>,
    cancel: CancellationToken,
    mtu: u16,
) -> tokio::task::JoinHandle<io::Result<()>> {
    tokio::spawn(async move { run_tun_reader(tun, registry, cancel, mtu).await })
}

fn spawn_metrics_task(
    metrics: Arc<Metrics>,
    cancel: CancellationToken,
) -> tokio::task::JoinHandle<io::Result<()>> {
    tokio::spawn(async move {
        let mut interval = time::interval(Duration::from_secs(30));
        loop {
            tokio::select! {
                () = cancel.cancelled() => return Ok(()),
                _ = interval.tick() => {
                    let snap = metrics.snapshot();
                    info!(
                        tcp_accepted = snap.tcp_accepted,
                        udp_accepted = snap.udp_accepted,
                        claimed = snap.claimed,
                        passed = snap.passed,
                        dropped = snap.dropped,
                        auth_successes = snap.auth_successes,
                        auth_failures = snap.auth_failures,
                        tcp_to_udp = snap.transport_tcp_to_udp,
                        udp_to_tcp = snap.transport_udp_to_tcp,
                        disconnect_idle = snap.disconnect_idle_timeout,
                        disconnect_close = snap.disconnect_close,
                        disconnect_shutdown = snap.disconnect_shutdown,
                        disconnect_error = snap.disconnect_error,
                        "metrics snapshot"
                    );
                }
            }
        }
    })
}

fn build_tls_acceptor(config: &ServerConfig) -> Result<SslAcceptor, Box<dyn std::error::Error>> {
    let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls())?;

    // Load TLS certificate
    match &config.tls_cert {
        TlsMaterial::File { file } => {
            debug!(source = "file", path = %file.display(), "loading tls certificate");
            builder.set_certificate_chain_file(file)?;
        }
        TlsMaterial::Pem(pem) => {
            debug!(
                source = "pem",
                pem_length = pem.len(),
                "loading tls certificate"
            );
            let mut certs = X509::stack_from_pem(pem.as_bytes())?;
            let leaf = certs
                .drain(..1)
                .next()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "tls_cert is empty"))?;
            builder.set_certificate(&leaf)?;
            for cert in certs {
                builder.add_extra_chain_cert(cert)?;
            }
        }
    }

    // Load TLS private key
    match &config.tls_key {
        TlsMaterial::File { file } => {
            debug!(source = "file", path = %file.display(), "loading tls private key");
            builder.set_private_key_file(file, SslFiletype::PEM)?;
        }
        TlsMaterial::Pem(pem) => {
            debug!(
                source = "pem",
                pem_length = pem.len(),
                "loading tls private key"
            );
            let key = PKey::private_key_from_pem(pem.as_bytes())?;
            builder.set_private_key(&key)?;
        }
    }

    builder.check_private_key()?;
    trace!("tls acceptor built successfully");
    Ok(builder.build())
}

async fn run_tun_reader(
    tun: Arc<tun_rs::AsyncDevice>,
    registry: Arc<SessionRegistry>,
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
        let Some(dst_ip) = extract_dst_ipv4(packet) else {
            debug!(len = n, "tun packet missing IPv4 dst");
            continue;
        };
        trace!(len = n, dst_ip = %dst_ip, "tun packet received");
        if let Some(tx) = registry.lookup_ip(dst_ip) {
            if tx
                .try_send(SessionEvent::TunPacket(packet.to_vec()))
                .is_err()
            {
                debug!(dst_ip = %dst_ip, "tun packet dropped (session queue full)");
            }
        } else {
            debug!(dst_ip = %dst_ip, "tun packet dropped (no session)");
        }
    }
}
