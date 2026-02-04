//! Metrics and counters.

use std::sync::atomic::{AtomicU64, Ordering};
use tracing::trace;

/// Server counters for basic observability.
#[derive(Debug, Default)]
pub struct Metrics {
    tcp_accepted: AtomicU64,
    udp_accepted: AtomicU64,
    claimed: AtomicU64,
    passed: AtomicU64,
    dropped: AtomicU64,
    auth_successes: AtomicU64,
    auth_failures: AtomicU64,
    transport_tcp_to_udp: AtomicU64,
    transport_udp_to_tcp: AtomicU64,
    disconnect_idle_timeout: AtomicU64,
    disconnect_close: AtomicU64,
    disconnect_shutdown: AtomicU64,
    disconnect_error: AtomicU64,
}

/// Snapshot of metric counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MetricsSnapshot {
    /// Accepted TCP connections.
    pub tcp_accepted: u64,
    /// Accepted UDP connections.
    pub udp_accepted: u64,
    /// Classified connections claimed by the server.
    pub claimed: u64,
    /// Classified connections passed through.
    pub passed: u64,
    /// Classified connections dropped.
    pub dropped: u64,
    /// Authentication failures.
    pub auth_failures: u64,
    /// Authentication successes.
    pub auth_successes: u64,
    /// TCP -> UDP transport switches.
    pub transport_tcp_to_udp: u64,
    /// UDP -> TCP transport switches.
    pub transport_udp_to_tcp: u64,
    /// Disconnects due to idle timeout.
    pub disconnect_idle_timeout: u64,
    /// Disconnects due to close frames or EOF.
    pub disconnect_close: u64,
    /// Disconnects due to explicit shutdown events.
    pub disconnect_shutdown: u64,
    /// Disconnects due to errors.
    pub disconnect_error: u64,
}

impl Metrics {
    /// Increment TCP accepted counter.
    pub fn inc_tcp_accepted(&self) {
        let prev = self.tcp_accepted.fetch_add(1, Ordering::Relaxed);
        trace!(tcp_accepted = prev + 1, "TCP connection accepted");
    }

    /// Increment UDP accepted counter.
    pub fn inc_udp_accepted(&self) {
        let prev = self.udp_accepted.fetch_add(1, Ordering::Relaxed);
        trace!(udp_accepted = prev + 1, "UDP connection accepted");
    }

    /// Increment claimed counter.
    pub fn inc_claimed(&self) {
        let prev = self.claimed.fetch_add(1, Ordering::Relaxed);
        trace!(claimed = prev + 1, "Connection claimed by server");
    }

    /// Increment passed counter.
    pub fn inc_passed(&self) {
        let prev = self.passed.fetch_add(1, Ordering::Relaxed);
        trace!(passed = prev + 1, "Connection passed through");
    }

    /// Increment dropped counter.
    pub fn inc_dropped(&self) {
        let prev = self.dropped.fetch_add(1, Ordering::Relaxed);
        trace!(dropped = prev + 1, "Connection dropped");
    }

    /// Increment auth failure counter.
    pub fn inc_auth_failures(&self) {
        let prev = self.auth_failures.fetch_add(1, Ordering::Relaxed);
        trace!(auth_failures = prev + 1, "Authentication failed");
    }

    /// Increment auth success counter.
    pub fn inc_auth_successes(&self) {
        let prev = self.auth_successes.fetch_add(1, Ordering::Relaxed);
        trace!(auth_successes = prev + 1, "Authentication succeeded");
    }

    /// Increment TCP -> UDP transport switch counter.
    pub fn inc_transport_tcp_to_udp(&self) {
        let prev = self.transport_tcp_to_udp.fetch_add(1, Ordering::Relaxed);
        trace!(
            transport_tcp_to_udp = prev + 1,
            "Transport switch: TCP -> UDP"
        );
    }

    /// Increment UDP -> TCP transport switch counter.
    pub fn inc_transport_udp_to_tcp(&self) {
        let prev = self.transport_udp_to_tcp.fetch_add(1, Ordering::Relaxed);
        trace!(
            transport_udp_to_tcp = prev + 1,
            "Transport switch: UDP -> TCP"
        );
    }

    /// Increment idle timeout disconnect counter.
    pub fn inc_disconnect_idle_timeout(&self) {
        let prev = self.disconnect_idle_timeout.fetch_add(1, Ordering::Relaxed);
        trace!(
            disconnect_idle_timeout = prev + 1,
            "Disconnect due to idle timeout"
        );
    }

    /// Increment disconnect close counter.
    pub fn inc_disconnect_close(&self) {
        let prev = self.disconnect_close.fetch_add(1, Ordering::Relaxed);
        trace!(
            disconnect_close = prev + 1,
            "Disconnect due to close frame/EOF"
        );
    }

    /// Increment disconnect shutdown counter.
    pub fn inc_disconnect_shutdown(&self) {
        let prev = self.disconnect_shutdown.fetch_add(1, Ordering::Relaxed);
        trace!(
            disconnect_shutdown = prev + 1,
            "Disconnect due to explicit shutdown"
        );
    }

    /// Increment disconnect error counter.
    pub fn inc_disconnect_error(&self) {
        let prev = self.disconnect_error.fetch_add(1, Ordering::Relaxed);
        trace!(disconnect_error = prev + 1, "Disconnect due to error");
    }

    /// Return a point-in-time snapshot of metrics.
    #[must_use]
    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            tcp_accepted: self.tcp_accepted.load(Ordering::Relaxed),
            udp_accepted: self.udp_accepted.load(Ordering::Relaxed),
            claimed: self.claimed.load(Ordering::Relaxed),
            passed: self.passed.load(Ordering::Relaxed),
            dropped: self.dropped.load(Ordering::Relaxed),
            auth_failures: self.auth_failures.load(Ordering::Relaxed),
            auth_successes: self.auth_successes.load(Ordering::Relaxed),
            transport_tcp_to_udp: self.transport_tcp_to_udp.load(Ordering::Relaxed),
            transport_udp_to_tcp: self.transport_udp_to_tcp.load(Ordering::Relaxed),
            disconnect_idle_timeout: self.disconnect_idle_timeout.load(Ordering::Relaxed),
            disconnect_close: self.disconnect_close.load(Ordering::Relaxed),
            disconnect_shutdown: self.disconnect_shutdown.load(Ordering::Relaxed),
            disconnect_error: self.disconnect_error.load(Ordering::Relaxed),
        }
    }
}
