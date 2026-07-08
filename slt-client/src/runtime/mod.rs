pub mod control;
pub mod observer;
mod register;
pub mod services;
mod session;

use std::sync::Arc;
use std::time::Duration;

use control::{ClientCommand, ClientCommandReceiver};
use observer::{ClientEventKind, ClientObserver, ObserverSink, Transport};
use services::ClientRuntimeServices;
// `pub` re-export so tests can assert structure on session-path errors; the
// effective visibility is bounded by `runtime` (a private module of the crate
// root), so this is crate-internal in practice. The re-export also brings
// `SessionError` into scope within this module.
pub use session::SessionError;
use session::SessionOutcome;
use slt_core::config::ClientConfig;
use thiserror::Error;
use tokio::time;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::error::ConnectError;
use crate::metrics::Metrics;
use crate::{auth, transport, tun};

/// A non-recoverable runtime failure.
///
/// Composes the two typed failure types at the `run_sessions` boundary: a
/// connect-path failure ([`ConnectError`]) or a session-path failure
/// ([`SessionError`]). Both preserve their sources, so the terminal
/// `{:#}` rendering carries the full cause chain. The terminal does not branch
/// on the variant, so this is converted to `anyhow::Error` once at the
/// [`run_client`] boundary — the design rule "typed where the caller branches;
/// anyhow where it doesn't".
#[derive(Debug, Error)]
pub enum RuntimeError {
    /// Fatal failure from the connect/auth sequence.
    #[error(transparent)]
    Connect(#[from] ConnectError),
    /// Fatal failure from an established session.
    #[error(transparent)]
    Session(#[from] SessionError),
}

impl RuntimeError {
    /// Whether Android should keep the VPN route installed and restart native
    /// runtime after this terminal error.
    #[must_use]
    pub fn is_android_restart_retriable(&self) -> bool {
        match self {
            Self::Connect(err) => err.is_retriable(),
            Self::Session(err) => matches!(
                err.exit(),
                session::SessionExit::TcpClosed
                    | session::SessionExit::IdleTimeout
                    | session::SessionExit::RemoteClose(_)
                    | session::SessionExit::ConnectionError
                    | session::SessionExit::NetworkChanged
            ),
        }
    }
}

/// Run the client runtime until shutdown.
///
/// # Errors
///
/// Returns an error if the runtime exits due to a non-recoverable condition,
/// such as an authentication rejection, a protocol error, a non-recoverable
/// connection or authentication failure, or a failed mandatory UDP upgrade.
///
/// Returns `Ok(())` on clean shutdown: cancellation requested, the TUN device
/// closed, or the remote end closed the session.
pub async fn run_client<S>(
    config: ClientConfig,
    tun_handles: tun::TunHandles,
    mut tun_channels: tun::TunChannels,
    cancel: CancellationToken,
    services: S,
    mut control_rx: Option<ClientCommandReceiver>,
) -> anyhow::Result<()>
where
    S: ClientRuntimeServices,
{
    let metrics = Arc::new(Metrics::default());
    let metrics_reporter = spawn_metrics_task(
        metrics.clone(),
        cancel.clone(),
        config.timing.metrics_interval,
    );

    // The runtime owns the full lifecycle event stream: Starting..Stopped/Error.
    // The bridge emits only pre-`run_client` setup failures. Keep a cheap clone
    // of the observer sink for the terminal events emitted after `run_sessions`
    // borrows `services`.
    let observer = services.observer().clone();
    observer.emit(ClientEventKind::Starting);
    observer.emit(ClientEventKind::TunReady);

    let result = run_sessions(
        &config,
        &cancel,
        &metrics,
        &mut tun_channels,
        &services,
        &mut control_rx,
    )
    .await;

    cancel.cancel();
    drop(tun_channels);
    tun_handles.shutdown().await;
    let _ = metrics_reporter.await;

    match &result {
        Ok(()) => {
            observer.emit(ClientEventKind::Stopping);
            observer.emit(ClientEventKind::Stopped);
            info!("client shutdown complete");
        }
        Err(err) => {
            warn!(error = %err, "client runtime exited with error");
            observer.emit(ClientEventKind::Error {
                detail: format!("{err:#}"),
                retryable: err.is_android_restart_retriable(),
            });
        }
    }
    result.map_err(Into::into)
}

/// Run the session loop until shutdown or fatal error.
///
/// Composes the connect path ([`ConnectError`]) and the session path
/// ([`SessionError`]) into [`RuntimeError`]; the terminal does not branch on
/// which path failed, so `RuntimeError` is the typed composition that converts
/// to `anyhow` once at the [`run_client`] boundary.
async fn run_sessions<S>(
    config: &ClientConfig,
    cancel: &CancellationToken,
    metrics: &Arc<Metrics>,
    tun_channels: &mut tun::TunChannels,
    services: &S,
    control_rx: &mut Option<ClientCommandReceiver>,
) -> Result<(), RuntimeError>
where
    S: ClientRuntimeServices,
{
    let mut backoff =
        ReconnectBackoff::new(config.timing.reconnect_min, config.timing.reconnect_max);
    let mut attempt: u64 = 0;

    loop {
        match try_connect(
            config,
            cancel,
            metrics,
            &mut backoff,
            &mut attempt,
            services,
            control_rx,
        )
        .await
        {
            ConnectOutcome::Connected(tcp) => {
                backoff.reset();
                let mut session = session::ClientSession::new(
                    config,
                    tcp,
                    tun_channels,
                    cancel.clone(),
                    metrics.clone(),
                    services,
                    control_rx.as_mut(),
                );
                match handle_session_exit(session.run().await, cancel) {
                    SessionAction::Break => break Ok(()),
                    // The session path flows a typed `SessionError` to the
                    // terminal directly. The error carries its preserved source
                    // (proto error, io::Error, etc.) and renders useful,
                    // stage-specific detail via `{:#}`.
                    SessionAction::Fatal(err) => break Err(RuntimeError::from(err)),
                    SessionAction::Reconnect => {
                        schedule_reconnect(
                            cancel,
                            &mut backoff,
                            services.observer(),
                            attempt + 1,
                            control_rx,
                        )
                        .await;
                    }
                    SessionAction::ReconnectNow => {}
                }
            }
            ConnectOutcome::Reconnect => {} // backoff already handled in try_connect
            ConnectOutcome::FatalError(err) => break Err(RuntimeError::from(err)),
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
    FatalError(ConnectError),
    /// Shutdown requested.
    Shutdown,
}

/// Action to take after a session exits.
enum SessionAction {
    /// Break the main loop and exit.
    Break,
    /// Fatal error; exit with the typed session error.
    Fatal(SessionError),
    /// Reconnect to the server (caller should sleep backoff).
    Reconnect,
    /// Reconnect to the server immediately.
    ReconnectNow,
}

/// Attempt to connect and authenticate with the server.
async fn try_connect<S>(
    config: &ClientConfig,
    cancel: &CancellationToken,
    metrics: &Arc<Metrics>,
    backoff: &mut ReconnectBackoff,
    attempt: &mut u64,
    services: &S,
    control_rx: &mut Option<ClientCommandReceiver>,
) -> ConnectOutcome
where
    S: ClientRuntimeServices,
{
    if cancel.is_cancelled() {
        return ConnectOutcome::Shutdown;
    }

    *attempt = attempt.saturating_add(1);
    info!(attempt, hostname = %config.network.hostname, port = config.network.port, "connecting");
    // Each attempt begins on TCP (ClientSession starts on ActiveTransport::Tcp).
    // Reset the tracked transport so a reconnect after a UDP-committed session
    // does not report stale UdpQsp for the fresh TCP connection.
    services.observer().set_transport(Transport::Tcp);
    services
        .observer()
        .emit(ClientEventKind::Connecting { attempt: *attempt });

    let connect = connect_authenticated(config, cancel, metrics, services);
    tokio::pin!(connect);
    let result = tokio::select! {
        result = &mut connect => result,
        command = recv_control(control_rx) => {
            return handle_connect_command(command, cancel, services.observer());
        }
    };

    match result {
        Ok(tcp) => ConnectOutcome::Connected(tcp),
        Err(err) => {
            // err: ConnectError — a typed failure whose variant carries the
            // site and detail. The runtime reads the variant's policy directly.
            if cancel.is_cancelled() {
                return ConnectOutcome::Shutdown;
            }
            if !err.is_retriable() {
                warn!(
                    attempt,
                    stage = ?err.stage(),
                    error = %err,
                    "connect/auth failed (non-recoverable)"
                );
                return ConnectOutcome::FatalError(err);
            }

            warn!(
                attempt,
                stage = ?err.stage(),
                error = %err,
                "connect/auth failed; retrying"
            );
            services.observer().emit(ClientEventKind::ReconnectFailed {
                attempt: *attempt,
                detail: err.to_string(),
            });
            schedule_reconnect(
                cancel,
                backoff,
                services.observer(),
                *attempt + 1,
                control_rx,
            )
            .await;
            ConnectOutcome::Reconnect
        }
    }
}

fn handle_connect_command<O>(
    command: Option<ClientCommand>,
    cancel: &CancellationToken,
    observer: &ObserverSink<O>,
) -> ConnectOutcome
where
    O: ClientObserver,
{
    match command {
        Some(ClientCommand::NetworkChanged) => {
            observer.emit(ClientEventKind::NetworkChanged {
                detail: "underlying network changed".to_string(),
            });
            ConnectOutcome::Reconnect
        }
        Some(ClientCommand::Stop) | None => {
            cancel.cancel();
            ConnectOutcome::Shutdown
        }
    }
}

/// Determine what action to take based on a session outcome.
///
/// Reads the [`SessionOutcome::exit`] control-flow reason to decide reconnect
/// policy. For the fatal exits, the preserved [`SessionError`] is carried
/// through `SessionAction::Fatal`, so the source chain survives to the
/// terminal `{:#}` rendering.
fn handle_session_exit(outcome: SessionOutcome, cancel: &CancellationToken) -> SessionAction {
    if cancel.is_cancelled() {
        return SessionAction::Break;
    }

    let SessionOutcome { exit, error } = outcome;
    match exit {
        session::SessionExit::Shutdown => SessionAction::Break,
        session::SessionExit::TunClosed => {
            warn!("tun tasks stopped; shutting down");
            SessionAction::Break
        }
        // Fatal exits. `error` is `Some` only for exits produced via
        // `SessionOutcome::from_error` (i.e. `SessionError::exit()`):
        // `ProtocolError` (proto decode failure / protocol violation) and
        // `PermissionDenied`. Exits produced via `from_exit` carry `error:
        // None` — notably `UdpUpgradeRequired` (emitted directly from the
        // upgrade FSM at five sites when `require_udp` fails, with no
        // underlying `SessionError`) and `ConnectionError` (emitted from the
        // UDP transport-loss branches). For those, the `unwrap_or_else`
        // fallbacks below are LIVE and synthesize the matching variant; this is
        // correct — `UdpUpgradeRequired` has no source to lose, and
        // `ConnectionError` is a reconnect exit that never reaches the terminal
        // fatal arm (it is matched by the `Reconnect` arm below).
        session::SessionExit::ProtocolError => {
            let err = error.unwrap_or_else(|| {
                debug!("ProtocolError exit without a typed SessionError; synthesizing fallback");
                SessionError::ProtocolViolation {
                    detail: "protocol error".into(),
                }
            });
            warn!(reason = ?exit, error = %err, "protocol error; exiting");
            SessionAction::Fatal(err)
        }
        session::SessionExit::PermissionDenied => {
            let err = error.unwrap_or_else(|| SessionError::PermissionDenied {
                source: std::io::Error::other("permission denied"),
            });
            warn!(reason = ?exit, error = %err, "permission denied; exiting");
            SessionAction::Fatal(err)
        }
        session::SessionExit::UdpUpgradeRequired => {
            let err = error.unwrap_or(SessionError::UdpUpgradeRequired);
            warn!(reason = ?exit, error = %err, "required udp upgrade failed; exiting");
            SessionAction::Fatal(err)
        }
        session::SessionExit::TcpClosed
        | session::SessionExit::IdleTimeout
        | session::SessionExit::RemoteClose(_)
        | session::SessionExit::ConnectionError => {
            warn!(reason = ?exit, "session ended; reconnecting");
            SessionAction::Reconnect
        }
        session::SessionExit::NetworkChanged => {
            info!(reason = ?exit, "underlying network changed; reconnecting immediately");
            SessionAction::ReconnectNow
        }
    }
}

fn spawn_metrics_task(
    metrics: Arc<Metrics>,
    cancel: CancellationToken,
    metrics_interval: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = time::interval(metrics_interval);
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
                        tls_key_updates = snap.tls_key_updates,
                        udp_discovery_failures = snap.udp_discovery_failures,
                        udp_register_failures = snap.udp_register_failures,
                        tun_dropped_oversized = snap.tun_packets_dropped_oversized,
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

async fn schedule_reconnect<O>(
    cancel: &CancellationToken,
    backoff: &mut ReconnectBackoff,
    observer: &ObserverSink<O>,
    next_attempt: u64,
    control_rx: &mut Option<ClientCommandReceiver>,
) where
    O: ClientObserver,
{
    let delay = backoff.next_delay();
    observer.emit(ClientEventKind::ReconnectScheduled {
        attempt: next_attempt,
        delay_ms: u64::try_from(delay.as_millis()).unwrap_or(u64::MAX),
    });
    tokio::select! {
        () = cancel.cancelled() => {}
        () = time::sleep(delay) => {}
        command = recv_control(control_rx) => {
            match command {
                Some(ClientCommand::NetworkChanged) => {
                    observer.emit(ClientEventKind::NetworkChanged {
                        detail: "underlying network changed".to_string(),
                    });
                }
                Some(ClientCommand::Stop) | None => {
                    cancel.cancel();
                }
            }
        }
    }
}

async fn recv_control(control_rx: &mut Option<ClientCommandReceiver>) -> Option<ClientCommand> {
    match control_rx {
        Some(rx) => {
            let command = rx.recv().await;
            if command.is_none() {
                *control_rx = None;
            }
            command
        }
        None => std::future::pending().await,
    }
}

/// Exponential backoff with jitter for reconnection attempts.
///
/// The backoff starts at `base` duration and doubles each call up to `max`.
/// Each delay includes equal jitter to prevent thundering herd.
pub struct ReconnectBackoff {
    base: Duration,
    max: Duration,
    current: Duration,
}

impl ReconnectBackoff {
    /// Creates a new backoff with the given base and maximum durations.
    pub const fn new(base: Duration, max: Duration) -> Self {
        Self {
            base,
            max,
            current: base,
        }
    }

    /// Resets the backoff to the base duration.
    pub const fn reset(&mut self) {
        self.current = self.base;
    }

    /// Returns the current backoff duration.
    #[cfg(test)]
    #[must_use]
    pub const fn current(&self) -> Duration {
        self.current
    }

    /// Returns the next delay duration with jitter and advances the backoff.
    ///
    /// The delay is in the range `[current/2, current]` using equal jitter.
    /// After this call, `current` doubles up to `max`.
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

async fn connect_authenticated<S>(
    config: &ClientConfig,
    cancel: &CancellationToken,
    metrics: &Arc<Metrics>,
    services: &S,
) -> Result<transport::tcp::TcpSession, ConnectError>
where
    S: ClientRuntimeServices,
{
    let mut tcp = tokio::select! {
        () = cancel.cancelled() => {
            return Err(ConnectError::Cancelled);
        }
        res = transport::tcp::connect(
            config,
            metrics.clone(),
            services.socket_protector(),
            services.host_resolver(),
        ) => res,
    }?;

    info!(peer = ?tcp.peer, sni = ?tcp.sni, "tcp handshake complete");
    services.observer().emit(ClientEventKind::ConnectedTcp {
        peer: tcp.peer.map(|peer| peer.to_string()),
    });

    services.observer().emit(ClientEventKind::Authenticating);
    tokio::select! {
        () = cancel.cancelled() => {
            Err(ConnectError::Cancelled)
        }
        res = auth::authenticate(&mut tcp.transport, config, metrics) => res,
    }?;
    services.observer().emit(ClientEventKind::Authenticated);

    if tcp.transport.has_buffered_input() {
        debug!("preserved auth leftovers");
    }

    Ok(tcp)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn millis(d: Duration) -> u64 {
        d.as_millis() as u64
    }

    #[test]
    fn reconnect_backoff_initial_state() {
        let base = Duration::from_millis(100);
        let max = Duration::from_secs(10);
        let backoff = ReconnectBackoff::new(base, max);

        assert_eq!(backoff.base, base);
        assert_eq!(backoff.max, max);
        assert_eq!(backoff.current, base);
    }

    #[test]
    fn reconnect_backoff_reset_returns_to_base() {
        let base = Duration::from_millis(100);
        let max = Duration::from_secs(10);
        let mut backoff = ReconnectBackoff::new(base, max);

        // Advance the backoff a few times
        let _ = backoff.next_delay();
        let _ = backoff.next_delay();
        let _ = backoff.next_delay();

        // Current should have increased
        assert!(backoff.current > base);

        // Reset should return to base
        backoff.reset();
        assert_eq!(backoff.current, base);
    }

    #[test]
    fn reconnect_backoff_delay_doubles_each_call() {
        let base = Duration::from_millis(100);
        let max = Duration::from_mins(1);
        let mut backoff = ReconnectBackoff::new(base, max);

        // Use deterministic seed for reproducible jitter
        fastrand::seed(42);

        // First call: current is 100ms, delay is in [50, 100]ms
        let d1 = backoff.next_delay();
        assert!(millis(d1) >= 50 && millis(d1) <= 100);

        // After first call, current should be 200ms (doubled)
        assert_eq!(millis(backoff.current), 200);

        // Second call: current is 200ms, delay is in [100, 200]ms
        let d2 = backoff.next_delay();
        assert!(millis(d2) >= 100 && millis(d2) <= 200);

        // After second call, current should be 400ms
        assert_eq!(millis(backoff.current), 400);

        // Third call: current is 400ms, delay is in [200, 400]ms
        let d3 = backoff.next_delay();
        assert!(millis(d3) >= 200 && millis(d3) <= 400);

        // After third call, current should be 800ms
        assert_eq!(millis(backoff.current), 800);
    }

    #[test]
    fn reconnect_backoff_capped_at_max() {
        let base = Duration::from_millis(100);
        let max = Duration::from_millis(500);
        let mut backoff = ReconnectBackoff::new(base, max);

        fastrand::seed(42);

        // Call next_delay multiple times until we hit max
        let _ = backoff.next_delay(); // current becomes 200
        let _ = backoff.next_delay(); // current becomes 400
        let _ = backoff.next_delay(); // current would be 800, but capped at 500

        // Current should be capped at max
        assert_eq!(backoff.current, max);

        // Further calls should stay at max
        let _ = backoff.next_delay();
        assert_eq!(backoff.current, max);
        let _ = backoff.next_delay();
        assert_eq!(backoff.current, max);
    }

    #[test]
    fn reconnect_backoff_jitter_bounds() {
        let base = Duration::from_millis(100);
        let max = Duration::from_mins(1);

        // Test jitter bounds over many samples
        // With equal-jitter: delay is in [current/2, current]
        for expected_current_ms in [100u64, 200, 400, 800, 1600] {
            let half = expected_current_ms / 2;
            let mut min_seen = u64::MAX;
            let mut max_seen = 0u64;

            // Sample many times to exercise jitter range
            for seed in 0..1000 {
                fastrand::seed(seed);
                let mut test_backoff = ReconnectBackoff::new(base, max);

                // Advance to the expected current value
                for _ in 0..match expected_current_ms {
                    100 => 0,
                    200 => 1,
                    400 => 2,
                    800 => 3,
                    1600 => 4,
                    _ => 5,
                } {
                    let _ = test_backoff.next_delay();
                }

                let delay = test_backoff.next_delay();
                let delay_ms = millis(delay);
                min_seen = min_seen.min(delay_ms);
                max_seen = max_seen.max(delay_ms);
            }

            // Verify jitter bounds: [half, current]
            assert!(
                min_seen >= half,
                "min_seen ({min_seen}) should be >= half ({half}) for current {expected_current_ms}"
            );
            assert!(
                max_seen <= expected_current_ms,
                "max_seen ({max_seen}) should be <= current ({expected_current_ms})"
            );

            // With enough samples, we should see values near both bounds
            assert!(
                min_seen <= half + 5,
                "should see values near lower bound half={half}, got min={min_seen}"
            );
            assert!(
                max_seen >= expected_current_ms.saturating_sub(5),
                "should see values near upper bound current={expected_current_ms}, got max={max_seen}"
            );
        }
    }

    #[test]
    fn reconnect_backoff_zero_base() {
        // Edge case: zero base duration
        let base = Duration::ZERO;
        let max = Duration::from_secs(10);
        let mut backoff = ReconnectBackoff::new(base, max);

        fastrand::seed(42);

        // First delay should be zero (cap=0, half=0, jitter=0)
        let d1 = backoff.next_delay();
        assert_eq!(millis(d1), 0);

        // Current doubles: 0 * 2 = 0
        assert_eq!(millis(backoff.current), 0);
    }

    #[test]
    fn reconnect_backoff_small_base_doubling() {
        // Test that very small values still double correctly
        let base = Duration::from_millis(1);
        let max = Duration::from_secs(10);
        let mut backoff = ReconnectBackoff::new(base, max);

        fastrand::seed(42);

        let _ = backoff.next_delay();
        assert_eq!(millis(backoff.current), 2);

        let _ = backoff.next_delay();
        assert_eq!(millis(backoff.current), 4);

        let _ = backoff.next_delay();
        assert_eq!(millis(backoff.current), 8);
    }

    #[test]
    fn reconnect_backoff_overflow_protection() {
        // Test that overflow is handled by falling back to max
        let base = Duration::from_secs(1);
        let max = Duration::from_secs(10);
        let mut backoff = ReconnectBackoff::new(base, max);

        // Manually set current to a very large value that would overflow when doubled
        backoff.current = Duration::from_secs(u64::MAX / 2 + 1);

        let _ = backoff.next_delay();

        // Should cap at max due to overflow protection
        assert_eq!(backoff.current, max);
    }
}
