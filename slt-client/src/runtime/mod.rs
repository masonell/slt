mod register;
mod session;

use std::io;
use std::sync::Arc;
use std::time::Duration;

use slt_core::config::ClientConfig;
use tokio::time;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::metrics::Metrics;
use crate::{auth, transport, tun};

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
fn handle_session_exit(exit: session::SessionExit, cancel: &CancellationToken) -> SessionAction {
    if cancel.is_cancelled() {
        return SessionAction::Break;
    }

    match exit {
        session::SessionExit::Shutdown => SessionAction::Break,
        session::SessionExit::TunClosed => {
            warn!("tun tasks stopped; shutting down");
            SessionAction::Break
        }
        session::SessionExit::ProtocolError => {
            warn!(reason = ?exit, "protocol error; exiting");
            SessionAction::Fatal(io::Error::new(io::ErrorKind::InvalidData, "protocol error"))
        }
        session::SessionExit::PermissionDenied => {
            warn!(reason = ?exit, "permission denied; exiting");
            SessionAction::Fatal(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "permission denied",
            ))
        }
        session::SessionExit::UdpUpgradeRequired => {
            warn!(reason = ?exit, "required udp upgrade failed; exiting");
            SessionAction::Fatal(io::Error::new(
                io::ErrorKind::TimedOut,
                "required udp upgrade failed",
            ))
        }
        session::SessionExit::TcpClosed
        | session::SessionExit::IdleTimeout
        | session::SessionExit::RemoteClose(_)
        | session::SessionExit::ConnectionError => {
            warn!(reason = ?exit, "session ended; reconnecting");
            SessionAction::Reconnect
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
        let max = Duration::from_secs(60);
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
        let max = Duration::from_secs(60);

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
