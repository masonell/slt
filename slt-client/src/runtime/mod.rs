mod limits;
mod register;
mod session;

use crate::{auth, metrics::Metrics, transport, tun};
use slt_core::config::ClientConfig;
use std::io;
use std::sync::Arc;
use std::time::Duration;
use tokio::time;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

/// Run the client runtime until shutdown.
pub async fn run_client(config: ClientConfig, cancel: CancellationToken) -> anyhow::Result<()> {
    let metrics = Arc::new(Metrics::default());
    let metrics_reporter = spawn_metrics_task(metrics.clone(), cancel.clone());

    let (tun_handles, mut tun_channels) = tun::create(&config, cancel.clone())?;

    let result = run_sessions(&config, &cancel, &metrics, &mut tun_channels).await;

    cancel.cancel();
    tun_handles.shutdown().await;
    let _ = metrics_reporter.await;

    if let Err(ref err) = result {
        warn!(error = %err, "client runtime exited with error");
    } else {
        info!("client shutdown complete");
    }
    result.map_err(Into::into)
}

/// Run the session loop until shutdown or fatal error.
async fn run_sessions(
    config: &ClientConfig,
    cancel: &CancellationToken,
    metrics: &Arc<Metrics>,
    tun_channels: &mut tun::TunChannels,
) -> io::Result<()> {
    let mut backoff =
        ReconnectBackoff::new(config.timing.reconnect_min, config.timing.reconnect_max);
    let mut attempt: u64 = 0;

    loop {
        match try_connect(config, cancel, metrics, &mut backoff, &mut attempt).await {
            ConnectOutcome::Connected(tcp) => {
                backoff.reset();
                let mut session = session::ClientSession::new(
                    config,
                    tcp,
                    tun_channels,
                    cancel.clone(),
                    metrics.clone(),
                );
                match handle_session_exit(session.run().await, cancel) {
                    SessionAction::Break => break Ok(()),
                    SessionAction::Fatal(err) => break Err(err),
                    SessionAction::Reconnect => sleep_backoff(cancel, &mut backoff).await,
                }
            }
            ConnectOutcome::Reconnect => {} // backoff already handled in try_connect
            ConnectOutcome::FatalError(err) => break Err(err),
            ConnectOutcome::Shutdown => break Ok(()),
        }
    }
}

/// Outcome of a connection attempt.
enum ConnectOutcome {
    /// Successfully connected and authenticated.
    Connected(transport::tcp::TcpSession),
    /// Connection failed; retry after backoff (already slept).
    Reconnect,
    /// Fatal error; exit the runtime.
    FatalError(io::Error),
    /// Shutdown requested.
    Shutdown,
}

/// Action to take after a session exits.
enum SessionAction {
    /// Break the main loop and exit.
    Break,
    /// Fatal error; exit with error.
    Fatal(io::Error),
    /// Reconnect to the server (caller should sleep backoff).
    Reconnect,
}

/// Attempt to connect and authenticate with the server.
async fn try_connect(
    config: &ClientConfig,
    cancel: &CancellationToken,
    metrics: &Arc<Metrics>,
    backoff: &mut ReconnectBackoff,
    attempt: &mut u64,
) -> ConnectOutcome {
    if cancel.is_cancelled() {
        return ConnectOutcome::Shutdown;
    }

    *attempt = attempt.saturating_add(1);
    info!(attempt, hostname = %config.network.hostname, port = config.network.port, "connecting");

    match connect_authenticated(config, cancel, metrics).await {
        Ok(tcp) => ConnectOutcome::Connected(tcp),
        Err(err) => {
            if cancel.is_cancelled() {
                return ConnectOutcome::Shutdown;
            }
            if err.kind() == io::ErrorKind::PermissionDenied {
                warn!(error = %err, "authentication rejected");
                return ConnectOutcome::FatalError(err);
            }
            if !should_reconnect(&err) {
                warn!(
                    attempt,
                    kind = ?err.kind(),
                    error = %err,
                    "connect/auth failed (non-recoverable)"
                );
                return ConnectOutcome::FatalError(err);
            }

            warn!(
                attempt,
                kind = ?err.kind(),
                error = %err,
                "connect/auth failed; retrying"
            );
            sleep_backoff(cancel, backoff).await;
            ConnectOutcome::Reconnect
        }
    }
}

/// Determine what action to take based on session exit result.
fn handle_session_exit(
    exit: io::Result<session::SessionExit>,
    cancel: &CancellationToken,
) -> SessionAction {
    match exit {
        Ok(session::SessionExit::Shutdown) => SessionAction::Break,
        Ok(session::SessionExit::TunClosed) => {
            warn!("tun tasks stopped; shutting down");
            SessionAction::Break
        }
        Ok(reason) => {
            warn!(reason = ?reason, "session ended; reconnecting");
            SessionAction::Reconnect
        }
        Err(err) => {
            if cancel.is_cancelled() {
                return SessionAction::Break;
            }
            if should_reconnect(&err) {
                warn!(kind = ?err.kind(), error = %err, "session error; reconnecting");
                SessionAction::Reconnect
            } else {
                SessionAction::Fatal(err)
            }
        }
    }
}

fn spawn_metrics_task(
    metrics: Arc<Metrics>,
    cancel: CancellationToken,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = time::interval(Duration::from_secs(30));
        loop {
            tokio::select! {
                () = cancel.cancelled() => return,
                _ = interval.tick() => {
                    let snap = metrics.snapshot();
                    info!(
                        tcp_connections = snap.tcp_connections,
                        tcp_handshake_successes = snap.tcp_handshake_successes,
                        tcp_handshake_failures = snap.tcp_handshake_failures,
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

fn should_reconnect(err: &io::Error) -> bool {
    !matches!(
        err.kind(),
        io::ErrorKind::InvalidData | io::ErrorKind::InvalidInput | io::ErrorKind::PermissionDenied
    )
}

async fn sleep_backoff(cancel: &CancellationToken, backoff: &mut ReconnectBackoff) {
    let delay = backoff.next_delay();
    tokio::select! {
        () = cancel.cancelled() => {}
        () = time::sleep(delay) => {}
    }
}

pub struct ReconnectBackoff {
    base: Duration,
    max: Duration,
    current: Duration,
}

impl ReconnectBackoff {
    pub const fn new(base: Duration, max: Duration) -> Self {
        Self {
            base,
            max,
            current: base,
        }
    }

    pub const fn reset(&mut self) {
        self.current = self.base;
    }

    pub fn next_delay(&mut self) -> Duration {
        let cap = self.current;
        let next = self.current.checked_mul(2).unwrap_or(self.max);
        self.current = std::cmp::min(next, self.max);

        let cap_ms = u64::try_from(cap.as_millis()).unwrap_or(u64::MAX);
        let half = cap_ms / 2;
        let jitter = if half > 0 { fastrand::u64(0..=half) } else { 0 };
        // Equal-jitter: base = cap - half, add random jitter up to half
        // Result: [half, cap] centered at ~0.75*cap
        Duration::from_millis(cap_ms.saturating_sub(half).saturating_add(jitter))
    }
}

async fn connect_authenticated(
    config: &ClientConfig,
    cancel: &CancellationToken,
    metrics: &Arc<Metrics>,
) -> io::Result<transport::tcp::TcpSession> {
    let mut tcp = tokio::select! {
        () = cancel.cancelled() => {
            return Err(io::Error::new(io::ErrorKind::Interrupted, "connect cancelled"));
        }
        res = transport::tcp::connect(config, metrics.clone()) => res,
    }?;

    info!(peer = ?tcp.peer, sni = ?tcp.sni, "tcp handshake complete");

    tokio::select! {
        () = cancel.cancelled() => {
            Err(io::Error::new(io::ErrorKind::Interrupted, "auth cancelled"))
        }
        res = auth::authenticate(&mut tcp.transport, config, metrics) => res,
    }?;

    if tcp.transport.has_buffered_input() {
        debug!("preserved auth leftovers");
    }

    Ok(tcp)
}
