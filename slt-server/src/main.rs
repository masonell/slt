use std::path::PathBuf;
use std::sync::Arc;
use std::{fs, io};

use boring::pkey::PKey;
use boring::ssl::{SslAcceptor, SslFiletype, SslMethod};
use boring::x509::X509;
use clap::Parser;
use slt_core::config::ServerConfig;
use slt_core::packet::extract_dst_ipv4;
use slt_core::proto::MessageLimits;
use slt_core::types::TlsMaterial;
use slt_server::auth::{AuthHandler, Authenticator, SessionManager};
use slt_server::metrics::Metrics;
use slt_server::quic::QuicEndpoint;
use slt_server::registry::SessionRegistry;
use slt_server::sessions::{SessionEvent, SessionTimeouts};
use slt_server::tcp::TcpFrontDoor;
use tokio::net::TcpStream;
use tokio::time::{self, Duration};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, trace, warn};
use tracing_error::ErrorLayer;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tun_rs::DeviceBuilder;

/// Command-line arguments for the SLT server.
///
/// Parsed using `clap` from command-line invocation.
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
            .name(&config.tun.tun_name)
            .mtu(config.tun.tun_mtu)
            .build_async()?,
    );
    let session_timeouts = SessionTimeouts {
        ping_min: config.timing.ping_min,
        ping_max: config.timing.ping_max,
        idle_timeout: config.timing.idle_timeout,
    };
    let limits = MessageLimits::from_mtu(config.tun.tun_mtu);
    let sessions = SessionManager::new(
        registry.clone(),
        metrics.clone(),
        tun.clone(),
        quic.socket().clone(),
        limits,
        session_timeouts,
        config.session_queue_size,
    );
    let auth_handler = Arc::new(AuthHandler::new(
        acceptor,
        authenticator,
        sessions,
        config.timing.auth_timeout,
    ));
    let cancel = CancellationToken::new();

    spawn_ctrl_c(cancel.clone());

    debug!("server runtime: spawning worker tasks");

    let mut tcp_task = spawn_tcp_task(frontdoor, auth_handler, cancel.clone());
    let mut udp_task = spawn_udp_task(quic, cancel.clone());
    let mut tun_task = spawn_tun_task(
        tun,
        registry,
        metrics.clone(),
        cancel.clone(),
        config.tun.tun_mtu,
    );
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

/// Spawns a task that listens for Ctrl+C and triggers graceful shutdown.
///
/// When Ctrl+C is received, the cancellation token is cancelled, which
/// signals all worker tasks to begin graceful shutdown.
fn spawn_ctrl_c(cancel: CancellationToken) {
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            debug!("received ctrl_c signal");
            cancel.cancel();
        }
    });
}

/// Spawns the TCP front door listener task.
///
/// Accepts incoming TCP connections and spawns authentication handlers for
/// each claimed connection.
///
/// # Arguments
///
/// * `frontdoor` - TCP listener and connection classifier
/// * `auth_handler` - Handler for TLS and client authentication
/// * `cancel` - Token to signal graceful shutdown
///
/// # Returns
///
/// A join handle for the spawned task.
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

/// Spawns the UDP front door listener task.
///
/// Runs the QUIC endpoint which processes incoming UDP packets.
///
/// # Arguments
///
/// * `quic` - QUIC endpoint for UDP packet handling
/// * `cancel` - Token to signal graceful shutdown
///
/// # Returns
///
/// A join handle for the spawned task.
fn spawn_udp_task(
    quic: QuicEndpoint,
    cancel: CancellationToken,
) -> tokio::task::JoinHandle<io::Result<()>> {
    tokio::spawn(async move { quic.run(cancel).await })
}

/// Spawns the TUN device reader task.
///
/// Reads packets from the TUN device and routes them to the appropriate
/// session based on destination IP address.
///
/// # Arguments
///
/// * `tun` - TUN device for reading VPN packets
/// * `registry` - Session registry for IP-to-session lookups
/// * `metrics` - Metrics tracker for queue overflow drops
/// * `cancel` - Token to signal graceful shutdown
/// * `mtu` - Maximum transmission unit for buffer sizing
///
/// # Returns
///
/// A join handle for the spawned task.
fn spawn_tun_task(
    tun: Arc<tun_rs::AsyncDevice>,
    registry: Arc<SessionRegistry>,
    metrics: Arc<Metrics>,
    cancel: CancellationToken,
    mtu: u16,
) -> tokio::task::JoinHandle<io::Result<()>> {
    tokio::spawn(async move { run_tun_reader(tun, registry, metrics, cancel, mtu).await })
}

/// Spawns the metrics reporting task.
///
/// Periodically logs a snapshot of all metric counters at 30-second intervals.
///
/// # Arguments
///
/// * `metrics` - Metrics tracker to read snapshots from
/// * `cancel` - Token to signal graceful shutdown
///
/// # Returns
///
/// A join handle for the spawned task.
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
                        upstream_send_failures = snap.upstream_send_failures,
                        tun_queue_overflow_drops = snap.tun_queue_overflow_drops,
                        auth_successes = snap.auth_successes,
                        auth_failures = snap.auth_failures,
                        tcp_to_udp = snap.transport_tcp_to_udp,
                        udp_to_tcp = snap.transport_udp_to_tcp,
                        disconnect_idle = snap.disconnect_idle_timeout,
                        disconnect_close = snap.disconnect_close,
                        disconnect_shutdown = snap.disconnect_shutdown,
                        disconnect_error = snap.disconnect_error,
                        tls_key_update_requested = snap.tls_key_update_requested,
                        tls_key_update_applied = snap.tls_key_update_applied,
                        udp_qsp_tx_phase = snap.udp_qsp_tx_key_phase_transitions,
                        udp_qsp_rx_phase = snap.udp_qsp_rx_key_phase_transitions,
                        udp_qsp_decrypt_replay = snap.udp_qsp_decrypt_fail_replay,
                        udp_qsp_decrypt_too_old = snap.udp_qsp_decrypt_fail_too_old,
                        udp_qsp_decrypt_crypto = snap.udp_qsp_decrypt_fail_crypto,
                        udp_qsp_decrypt_other = snap.udp_qsp_decrypt_fail_other,
                        udp_qsp_dead_channel = snap.udp_qsp_dead_channel,
                        "metrics snapshot"
                    );
                }
            }
        }
    })
}

/// Builds a TLS acceptor from server configuration.
///
/// Loads TLS certificates and private keys from either file paths or inline
/// PEM data, then constructs an `SslAcceptor` configured with Mozilla
/// Intermediate v5 settings.
///
/// # Arguments
///
/// * `config` - Server configuration containing TLS material
///
/// # Returns
///
/// A configured `SslAcceptor` ready for TLS handshakes.
///
/// # Errors
///
/// Returns an error if certificate/key loading fails or if the private key
/// doesn't match the certificate.
fn build_tls_acceptor(config: &ServerConfig) -> Result<SslAcceptor, Box<dyn std::error::Error>> {
    let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls())?;

    // Load TLS certificate
    match &config.tls.tls_cert {
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
    match &config.tls.tls_key {
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

/// Reads packets from the TUN device and routes them to active sessions.
///
/// Continuously reads IPv4 packets from the TUN device, extracts the
/// destination IP, and forwards the packet to the corresponding session.
/// Packets are dropped if no session exists for the destination IP or if
/// the session's queue is full.
///
/// # Arguments
///
/// * `tun` - TUN device to read packets from
/// * `registry` - Session registry for IP-to-session lookups
/// * `metrics` - Metrics tracker for queue overflow drops
/// * `cancel` - Token to signal graceful shutdown
/// * `mtu` - Maximum transmission unit for buffer size
///
/// # Returns
///
/// `Ok(())` on graceful shutdown, or an I/O error if reading fails.
async fn run_tun_reader(
    tun: Arc<tun_rs::AsyncDevice>,
    registry: Arc<SessionRegistry>,
    metrics: Arc<Metrics>,
    cancel: CancellationToken,
    mtu: u16,
) -> io::Result<()> {
    let mtu = mtu as usize;
    let mut packet = vec![0u8; mtu];
    loop {
        let n = tokio::select! {
            () = cancel.cancelled() => return Ok(()),
            res = tun.recv(&mut packet) => res?,
        };

        if n == 0 {
            continue;
        }

        packet.truncate(n);
        let Some(dst_ip) = extract_dst_ipv4(&packet) else {
            debug!(len = n, "tun packet missing IPv4 dst");
            packet.resize(mtu, 0);
            continue;
        };
        trace!(len = n, dst_ip = %dst_ip, "tun packet received");
        if let Some(tx) = registry.lookup_ip(dst_ip) {
            match tx.try_send(SessionEvent::TunPacket(packet)) {
                Ok(()) => {
                    packet = vec![0u8; mtu];
                }
                Err(err) => {
                    metrics.inc_tun_queue_overflow_drops();
                    debug!(dst_ip = %dst_ip, "tun packet dropped (session queue full)");
                    let SessionEvent::TunPacket(inner) = err.into_inner() else {
                        unreachable!("only TunPacket is sent from this site");
                    };
                    packet = inner;
                    packet.resize(mtu, 0);
                }
            }
        } else {
            debug!(dst_ip = %dst_ip, "tun packet dropped (no session)");
            packet.resize(mtu, 0);
        }
    }
}
