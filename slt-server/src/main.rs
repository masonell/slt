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
use slt_core::transport::tun::{
    DEFAULT_TUN_CHANNEL_SIZE, build_async_tun_device, tun_offload_enabled,
};
#[cfg(target_os = "linux")]
use slt_core::transport::tun::{LinuxRecvBatch, LinuxSendBatch};
use slt_core::types::TlsMaterial;
use slt_server::auth::{AuthHandlerBase, Authenticator, SessionManager};
use slt_server::metrics::Metrics;
use slt_server::quic::QuicEndpoint;
use slt_server::registry::SessionRegistry;
use slt_server::sessions::{SessionEvent, SessionTimeouts};
use slt_server::tcp::TcpFrontDoor;
use slt_server::tun::{TunDeviceIo, TunSender};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::{self, Duration};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, trace, warn};
use tracing_error::ErrorLayer;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

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

    run_server(config).await
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
#[allow(clippy::too_many_lines)]
async fn run_server(config: Arc<ServerConfig>) -> Result<(), Box<dyn std::error::Error>> {
    debug!("server runtime: initializing components");

    let metrics = Arc::new(Metrics::default());
    let registry = Arc::new(SessionRegistry::new());
    let frontdoor = TcpFrontDoor::bind(&config, metrics.clone()).await?;
    let quic = QuicEndpoint::bind(&config, registry.clone(), metrics.clone())?;
    let acceptor = build_tls_acceptor(&config)?;
    let authenticator = Authenticator::from_config(&config);
    let tun = Arc::new(build_async_tun_device(&config.tun)?);
    if tun_offload_enabled(tun.as_ref()) {
        info!("TUN device attached with GRO/GSO offload enabled");
    }

    // Channel for batched TUN writes
    let (tun_tx, tun_rx) = mpsc::channel(DEFAULT_TUN_CHANNEL_SIZE);
    let tun_sender = Arc::new(TunSender::new(tun_tx));

    let session_timeouts = SessionTimeouts {
        ping_min: config.timing.ping_min,
        ping_max: config.timing.ping_max,
        idle_timeout: config.timing.idle_timeout,
    };
    let limits = MessageLimits::from_mtu(config.tun.tun_mtu);
    let sessions = SessionManager::new(
        registry.clone(),
        metrics.clone(),
        tun_sender,
        quic.socket().clone(),
        limits,
        session_timeouts,
        config.session_queue_size,
        config.transport.udp_qsp.clone(),
    );
    let auth_handler = Arc::new(AuthHandlerBase::<TunSender>::new(
        acceptor,
        authenticator,
        sessions,
        config.timing.auth_timeout,
        config.max_auth_inflight,
    ));
    let cancel = CancellationToken::new();

    spawn_ctrl_c(cancel.clone());

    debug!("server runtime: spawning worker tasks");

    let mut tcp_task = spawn_tcp_task(frontdoor, auth_handler, cancel.clone());
    let mut udp_task = spawn_udp_task(quic, cancel.clone());
    let (mut tun_reader_task, mut tun_writer_task) = spawn_tun_tasks(
        tun,
        tun_rx,
        registry,
        metrics.clone(),
        cancel.clone(),
        config.tun.tun_mtu,
    );
    let mut metrics_task =
        spawn_metrics_task(metrics, cancel.clone(), config.timing.metrics_interval);

    let trigger = tokio::select! {
        res = &mut tcp_task => ShutdownTrigger::WorkerFailed { task: "tcp", result: res },
        res = &mut udp_task => ShutdownTrigger::WorkerFailed { task: "udp", result: res },
        res = &mut tun_reader_task => ShutdownTrigger::WorkerFailed { task: "tun_reader", result: res },
        res = &mut tun_writer_task => ShutdownTrigger::WorkerFailed { task: "tun_writer", result: res },
        res = &mut metrics_task => ShutdownTrigger::WorkerFailed { task: "metrics", result: res },
        () = cancel.cancelled() => ShutdownTrigger::Cancelled,
    };

    let shutdown_result = match trigger {
        ShutdownTrigger::WorkerFailed { task, result } => {
            info!(
                reason = task_failure_reason(task),
                "graceful shutdown initiated"
            );
            cancel.cancel();

            let mut shutdown_result = classify_task_result(task, result);
            if task != "tcp" {
                merge_task_result(&mut shutdown_result, "tcp", tcp_task.await);
            }
            if task != "udp" {
                merge_task_result(&mut shutdown_result, "udp", udp_task.await);
            }
            if task != "tun_reader" {
                merge_task_result(&mut shutdown_result, "tun_reader", tun_reader_task.await);
            }
            if task != "tun_writer" {
                merge_task_result(&mut shutdown_result, "tun_writer", tun_writer_task.await);
            }
            if task != "metrics" {
                merge_task_result(&mut shutdown_result, "metrics", metrics_task.await);
            }
            shutdown_result
        }
        ShutdownTrigger::Cancelled => {
            info!(reason = "ctrl_c", "graceful shutdown initiated");
            join_ignoring_result(tcp_task).await;
            join_ignoring_result(udp_task).await;
            join_ignoring_result(tun_reader_task).await;
            join_ignoring_result(tun_writer_task).await;
            join_ignoring_result(metrics_task).await;
            Ok(())
        }
    };

    info!("server shutdown complete");
    shutdown_result.map_err(|err| Box::new(err) as Box<dyn std::error::Error>)
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
fn spawn_tcp_task<T: TunDeviceIo>(
    frontdoor: TcpFrontDoor,
    auth_handler: Arc<AuthHandlerBase<T>>,
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

enum ShutdownTrigger {
    WorkerFailed {
        task: &'static str,
        result: Result<io::Result<()>, tokio::task::JoinError>,
    },
    Cancelled,
}

fn task_failure_reason(task: &'static str) -> &'static str {
    match task {
        "tcp" => "tcp_task_failure",
        "udp" => "udp_task_failure",
        "tun_reader" => "tun_reader_task_failure",
        "tun_writer" => "tun_writer_task_failure",
        "metrics" => "metrics_task_failure",
        _ => "worker_task_failure",
    }
}

fn classify_task_result(
    task: &'static str,
    res: Result<io::Result<()>, tokio::task::JoinError>,
) -> io::Result<()> {
    match res {
        Ok(Ok(())) => Ok(()),
        Ok(Err(err)) => {
            error!(task, error = %err, "worker task failed");
            Err(err)
        }
        Err(err) => {
            error!(task, error = %err, "worker task failed");
            Err(io::Error::other(err))
        }
    }
}

fn merge_task_result(
    shutdown_result: &mut io::Result<()>,
    task: &'static str,
    res: Result<io::Result<()>, tokio::task::JoinError>,
) {
    let task_result = classify_task_result(task, res);
    if shutdown_result.is_ok() {
        *shutdown_result = task_result;
    }
}

async fn join_ignoring_result(handle: tokio::task::JoinHandle<io::Result<()>>) {
    let _ = handle.await;
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
    mut quic: QuicEndpoint,
    cancel: CancellationToken,
) -> tokio::task::JoinHandle<io::Result<()>> {
    tokio::spawn(async move { quic.run(cancel).await })
}

/// Spawns the TUN device reader and writer tasks.
///
/// Returns join handles for both tasks for proper shutdown coordination.
///
/// # Arguments
///
/// * `tun` - TUN device for packet I/O
/// * `tun_rx` - Channel receiver for packets to write to TUN
/// * `registry` - Session registry for IP-to-session lookups
/// * `metrics` - Metrics tracker for queue overflow drops
/// * `cancel` - Token to signal graceful shutdown
/// * `mtu` - Maximum transmission unit for buffer sizing
///
/// # Returns
///
/// A tuple of (reader handle, writer handle).
fn spawn_tun_tasks(
    tun: Arc<tun_rs::AsyncDevice>,
    tun_rx: mpsc::Receiver<Vec<u8>>,
    registry: Arc<SessionRegistry>,
    metrics: Arc<Metrics>,
    cancel: CancellationToken,
    mtu: u16,
) -> (
    tokio::task::JoinHandle<io::Result<()>>,
    tokio::task::JoinHandle<io::Result<()>>,
) {
    let reader = tokio::spawn(run_tun_reader(
        tun.clone(),
        registry,
        metrics,
        cancel.clone(),
        mtu,
    ));
    let writer = tokio::spawn(run_tun_writer(tun, tun_rx, cancel));
    (reader, writer)
}

/// Spawns the metrics reporting task.
///
/// Periodically logs a snapshot of all metric counters.
///
/// # Arguments
///
/// * `metrics` - Metrics tracker to read snapshots from
/// * `cancel` - Token to signal graceful shutdown
/// * `metrics_interval` - Duration between metrics snapshots
///
/// # Returns
///
/// A join handle for the spawned task.
fn spawn_metrics_task(
    metrics: Arc<Metrics>,
    cancel: CancellationToken,
    metrics_interval: Duration,
) -> tokio::task::JoinHandle<io::Result<()>> {
    tokio::spawn(async move {
        let mut interval = time::interval(metrics_interval);
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
                        auth_rejections = snap.auth_rejections,
                        auth_limit_drops = snap.auth_limit_drops,
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
/// Uses `recv_multiple` to batch packets per syscall with GRO offload.
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
#[cfg(target_os = "linux")]
async fn run_tun_reader(
    tun: Arc<tun_rs::AsyncDevice>,
    registry: Arc<SessionRegistry>,
    metrics: Arc<Metrics>,
    cancel: CancellationToken,
    mtu: u16,
) -> io::Result<()> {
    let mut recv_batch = LinuxRecvBatch::new(mtu)?;

    loop {
        let (original_buffer, bufs, sizes) = recv_batch.recv_args();
        let count = tokio::select! {
            () = cancel.cancelled() => return Ok(()),
            res = tun.recv_multiple(original_buffer, bufs, sizes, 0) => res?,
        };

        if count == 0 {
            continue;
        }

        for i in 0..count {
            let size = recv_batch.packet_len(i);
            if size == 0 {
                continue;
            }

            let packet = recv_batch.packet(i);
            let Some(dst_ip) = extract_dst_ipv4(packet) else {
                debug!(len = size, "tun packet missing IPv4 dst");
                continue;
            };
            trace!(len = size, dst_ip = %dst_ip, "tun packet received");

            if let Some(tx) = registry.lookup_ip(dst_ip) {
                if tx
                    .try_send(SessionEvent::TunPacket(packet.to_vec()))
                    .is_err()
                {
                    metrics.inc_tun_queue_overflow_drops();
                    debug!(dst_ip = %dst_ip, "tun packet dropped (session queue full)");
                }
            } else {
                debug!(dst_ip = %dst_ip, "tun packet dropped (no session)");
            }
        }
    }
}

/// Writes packets to the TUN device from the channel.
///
/// Batches packets and uses `send_multiple` with GSO offload.
///
/// # Arguments
///
/// * `tun` - TUN device to write packets to
/// * `rx` - Channel receiver for packets to write
/// * `cancel` - Token to signal graceful shutdown
///
/// # Returns
///
/// `Ok(())` on graceful shutdown, or an I/O error if writing fails.
#[cfg(target_os = "linux")]
async fn run_tun_writer(
    tun: Arc<tun_rs::AsyncDevice>,
    mut rx: mpsc::Receiver<Vec<u8>>,
    cancel: CancellationToken,
) -> io::Result<()> {
    use tun_rs::GROTable;

    let mut gro_table = GROTable::new();
    let mut send_batch = LinuxSendBatch::new();

    loop {
        send_batch.clear();

        // Wait for first packet
        let first = tokio::select! {
            () = cancel.cancelled() => return Ok(()),
            maybe = rx.recv() => match maybe {
                Some(pkt) => pkt,
                None => return Ok(()),
            },
        };

        if let Err(err) = send_batch.push_packet(&first) {
            debug!(
                len = err.len,
                max = err.max,
                "tun write packet too large, dropping"
            );
            continue;
        }

        // Drain any additional packets
        while !send_batch.is_full() {
            match rx.try_recv() {
                Ok(pkt) => {
                    if let Err(err) = send_batch.push_packet(&pkt) {
                        debug!(
                            len = err.len,
                            max = err.max,
                            "tun write packet too large, dropping"
                        );
                    }
                }
                Err(mpsc::error::TryRecvError::Empty) => break,
                Err(mpsc::error::TryRecvError::Disconnected) => return Ok(()),
            }
        }

        let header_offset = send_batch.header_offset();
        let payload_bytes = send_batch.payload_bytes();
        let input_packets = send_batch.packet_count();

        // Send batch with GSO
        let written = match tun
            .send_multiple(
                &mut gro_table,
                send_batch.queued_buffers_mut(),
                header_offset,
            )
            .await
        {
            Ok(bytes) => bytes,
            Err(err) => {
                warn!(error = %err, count = input_packets, "tun send_multiple error");
                return Err(err);
            }
        };

        let virtio_overhead_bytes = written.saturating_sub(payload_bytes);
        let estimated_output_packets = (virtio_overhead_bytes > 0
            && virtio_overhead_bytes % header_offset == 0)
            .then_some(virtio_overhead_bytes / header_offset);
        let estimated_coalesced_packets =
            estimated_output_packets.map(|output| input_packets.saturating_sub(output));

        trace!(
            input_packets,
            input_payload_bytes = payload_bytes,
            written_bytes = written,
            virtio_overhead_bytes,
            estimated_output_packets = ?estimated_output_packets,
            estimated_coalesced_packets = ?estimated_coalesced_packets,
            "tun writer batch stats"
        );
    }
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
