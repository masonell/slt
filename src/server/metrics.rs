//! Metrics and counters.

use std::sync::atomic::{AtomicU64, Ordering};

/// Server counters for basic observability.
#[derive(Debug, Default)]
pub struct Metrics {
    tcp_accepted: AtomicU64,
    udp_accepted: AtomicU64,
    claimed: AtomicU64,
    passed: AtomicU64,
    dropped: AtomicU64,
    auth_failures: AtomicU64,
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
}

impl Metrics {
    /// Increment TCP accepted counter.
    pub fn inc_tcp_accepted(&self) {
        self.tcp_accepted.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment UDP accepted counter.
    pub fn inc_udp_accepted(&self) {
        self.udp_accepted.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment claimed counter.
    pub fn inc_claimed(&self) {
        self.claimed.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment passed counter.
    pub fn inc_passed(&self) {
        self.passed.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment dropped counter.
    pub fn inc_dropped(&self) {
        self.dropped.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment auth failure counter.
    pub fn inc_auth_failures(&self) {
        self.auth_failures.fetch_add(1, Ordering::Relaxed);
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
        }
    }
}
