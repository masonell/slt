//! Metrics and counters.

use std::sync::atomic::{AtomicU64, Ordering};

use tracing::trace;

/// Server counters for basic observability.
///
/// Thread-safe metrics collection using relaxed ordering atomic counters.
/// Provides snapshot functionality for point-in-time metric reads.
#[derive(Debug, Default)]
pub struct Metrics {
    tcp_accepted: AtomicU64,
    udp_accepted: AtomicU64,
    claimed: AtomicU64,
    passed: AtomicU64,
    dropped: AtomicU64,
    upstream_send_failures: AtomicU64,
    tun_queue_overflow_drops: AtomicU64,
    auth_successes: AtomicU64,
    auth_failures: AtomicU64,
    transport_tcp_to_udp: AtomicU64,
    transport_udp_to_tcp: AtomicU64,
    disconnect_idle_timeout: AtomicU64,
    disconnect_close: AtomicU64,
    disconnect_shutdown: AtomicU64,
    disconnect_error: AtomicU64,
    tls_key_update_requested: AtomicU64,
    tls_key_update_applied: AtomicU64,
    udp_qsp_tx_key_phase_transitions: AtomicU64,
    udp_qsp_rx_key_phase_transitions: AtomicU64,
    udp_qsp_decrypt_fail_replay: AtomicU64,
    udp_qsp_decrypt_fail_too_old: AtomicU64,
    udp_qsp_decrypt_fail_crypto: AtomicU64,
    udp_qsp_decrypt_fail_other: AtomicU64,
    udp_qsp_dead_channel: AtomicU64,
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
    /// Failed sends to upstream UDP socket.
    pub upstream_send_failures: u64,
    /// TUN packets dropped because session queue was full.
    pub tun_queue_overflow_drops: u64,
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
    /// TLS key updates requested.
    pub tls_key_update_requested: u64,
    /// TLS key updates successfully applied.
    pub tls_key_update_applied: u64,
    /// UDP-QSP transmit key phase transitions.
    pub udp_qsp_tx_key_phase_transitions: u64,
    /// UDP-QSP receive key phase transitions.
    pub udp_qsp_rx_key_phase_transitions: u64,
    /// UDP-QSP decrypt failures due to replay packets.
    pub udp_qsp_decrypt_fail_replay: u64,
    /// UDP-QSP decrypt failures due to too-old packets.
    pub udp_qsp_decrypt_fail_too_old: u64,
    /// UDP-QSP decrypt failures due to crypto failure.
    pub udp_qsp_decrypt_fail_crypto: u64,
    /// UDP-QSP decrypt failures for other reasons.
    pub udp_qsp_decrypt_fail_other: u64,
    /// UDP-QSP channels marked dead.
    pub udp_qsp_dead_channel: u64,
}

/// Atomically increments a counter and returns the new value.
///
/// Uses relaxed ordering for performance; exact ordering relative to other
/// operations is not required for metrics collection.
#[inline]
fn inc(counter: &AtomicU64) -> u64 {
    counter.fetch_add(1, Ordering::Relaxed) + 1
}

impl Metrics {
    /// Increment TCP accepted counter.
    pub fn inc_tcp_accepted(&self) {
        let count = inc(&self.tcp_accepted);
        trace!(tcp_accepted = count, "TCP connection accepted");
    }

    /// Increment UDP accepted counter.
    pub fn inc_udp_accepted(&self) {
        let count = inc(&self.udp_accepted);
        trace!(udp_accepted = count, "UDP connection accepted");
    }

    /// Increment claimed counter.
    pub fn inc_claimed(&self) {
        let count = inc(&self.claimed);
        trace!(claimed = count, "Connection claimed by server");
    }

    /// Increment passed counter.
    pub fn inc_passed(&self) {
        let count = inc(&self.passed);
        trace!(passed = count, "Connection passed through");
    }

    /// Increment dropped counter.
    pub fn inc_dropped(&self) {
        let count = inc(&self.dropped);
        trace!(dropped = count, "Connection dropped");
    }

    /// Increment upstream-send-failure counter.
    pub fn inc_upstream_send_failures(&self) {
        let count = inc(&self.upstream_send_failures);
        trace!(
            upstream_send_failures = count,
            "Failed to send datagram to upstream"
        );
    }

    /// Increment TUN queue-overflow drop counter.
    pub fn inc_tun_queue_overflow_drops(&self) {
        let count = inc(&self.tun_queue_overflow_drops);
        trace!(
            tun_queue_overflow_drops = count,
            "TUN packet dropped: session queue full"
        );
    }

    /// Increment auth failure counter.
    pub fn inc_auth_failures(&self) {
        let count = inc(&self.auth_failures);
        trace!(auth_failures = count, "Authentication failed");
    }

    /// Increment auth success counter.
    pub fn inc_auth_successes(&self) {
        let count = inc(&self.auth_successes);
        trace!(auth_successes = count, "Authentication succeeded");
    }

    /// Increment TCP -> UDP transport switch counter.
    pub fn inc_transport_tcp_to_udp(&self) {
        let count = inc(&self.transport_tcp_to_udp);
        trace!(transport_tcp_to_udp = count, "Transport switch: TCP -> UDP");
    }

    /// Increment UDP -> TCP transport switch counter.
    pub fn inc_transport_udp_to_tcp(&self) {
        let count = inc(&self.transport_udp_to_tcp);
        trace!(transport_udp_to_tcp = count, "Transport switch: UDP -> TCP");
    }

    /// Increment idle timeout disconnect counter.
    pub fn inc_disconnect_idle_timeout(&self) {
        let count = inc(&self.disconnect_idle_timeout);
        trace!(
            disconnect_idle_timeout = count,
            "Disconnect due to idle timeout"
        );
    }

    /// Increment disconnect close counter.
    pub fn inc_disconnect_close(&self) {
        let count = inc(&self.disconnect_close);
        trace!(
            disconnect_close = count,
            "Disconnect due to close frame/EOF"
        );
    }

    /// Increment disconnect shutdown counter.
    pub fn inc_disconnect_shutdown(&self) {
        let count = inc(&self.disconnect_shutdown);
        trace!(
            disconnect_shutdown = count,
            "Disconnect due to explicit shutdown"
        );
    }

    /// Increment disconnect error counter.
    pub fn inc_disconnect_error(&self) {
        let count = inc(&self.disconnect_error);
        trace!(disconnect_error = count, "Disconnect due to error");
    }

    /// Increment TLS key update requested counter.
    pub fn inc_tls_key_update_requested(&self) {
        let count = inc(&self.tls_key_update_requested);
        trace!(tls_key_update_requested = count, "TLS key update requested");
    }

    /// Increment TLS key update applied counter.
    pub fn inc_tls_key_update_applied(&self) {
        let count = inc(&self.tls_key_update_applied);
        trace!(tls_key_update_applied = count, "TLS key update applied");
    }

    /// Increment UDP-QSP TX key-phase transition counter.
    pub fn inc_udp_qsp_tx_key_phase_transition(&self) {
        let count = inc(&self.udp_qsp_tx_key_phase_transitions);
        trace!(
            udp_qsp_tx_key_phase_transitions = count,
            "UDP-QSP TX key phase transitioned"
        );
    }

    /// Increment UDP-QSP RX key-phase transition counter.
    pub fn inc_udp_qsp_rx_key_phase_transition(&self) {
        let count = inc(&self.udp_qsp_rx_key_phase_transitions);
        trace!(
            udp_qsp_rx_key_phase_transitions = count,
            "UDP-QSP RX key phase transitioned"
        );
    }

    /// Increment UDP-QSP replay decrypt failure counter.
    pub fn inc_udp_qsp_decrypt_fail_replay(&self) {
        let count = inc(&self.udp_qsp_decrypt_fail_replay);
        trace!(
            udp_qsp_decrypt_fail_replay = count,
            "UDP-QSP decrypt failure: replay"
        );
    }

    /// Increment UDP-QSP too-old decrypt failure counter.
    pub fn inc_udp_qsp_decrypt_fail_too_old(&self) {
        let count = inc(&self.udp_qsp_decrypt_fail_too_old);
        trace!(
            udp_qsp_decrypt_fail_too_old = count,
            "UDP-QSP decrypt failure: too old"
        );
    }

    /// Increment UDP-QSP crypto decrypt failure counter.
    pub fn inc_udp_qsp_decrypt_fail_crypto(&self) {
        let count = inc(&self.udp_qsp_decrypt_fail_crypto);
        trace!(
            udp_qsp_decrypt_fail_crypto = count,
            "UDP-QSP decrypt failure: crypto"
        );
    }

    /// Increment UDP-QSP generic decrypt failure counter.
    pub fn inc_udp_qsp_decrypt_fail_other(&self) {
        let count = inc(&self.udp_qsp_decrypt_fail_other);
        trace!(
            udp_qsp_decrypt_fail_other = count,
            "UDP-QSP decrypt failure: other"
        );
    }

    /// Increment UDP-QSP dead-channel counter.
    pub fn inc_udp_qsp_dead_channel(&self) {
        let count = inc(&self.udp_qsp_dead_channel);
        trace!(udp_qsp_dead_channel = count, "UDP-QSP channel marked dead");
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
            upstream_send_failures: self.upstream_send_failures.load(Ordering::Relaxed),
            tun_queue_overflow_drops: self.tun_queue_overflow_drops.load(Ordering::Relaxed),
            auth_failures: self.auth_failures.load(Ordering::Relaxed),
            auth_successes: self.auth_successes.load(Ordering::Relaxed),
            transport_tcp_to_udp: self.transport_tcp_to_udp.load(Ordering::Relaxed),
            transport_udp_to_tcp: self.transport_udp_to_tcp.load(Ordering::Relaxed),
            disconnect_idle_timeout: self.disconnect_idle_timeout.load(Ordering::Relaxed),
            disconnect_close: self.disconnect_close.load(Ordering::Relaxed),
            disconnect_shutdown: self.disconnect_shutdown.load(Ordering::Relaxed),
            disconnect_error: self.disconnect_error.load(Ordering::Relaxed),
            tls_key_update_requested: self.tls_key_update_requested.load(Ordering::Relaxed),
            tls_key_update_applied: self.tls_key_update_applied.load(Ordering::Relaxed),
            udp_qsp_tx_key_phase_transitions: self
                .udp_qsp_tx_key_phase_transitions
                .load(Ordering::Relaxed),
            udp_qsp_rx_key_phase_transitions: self
                .udp_qsp_rx_key_phase_transitions
                .load(Ordering::Relaxed),
            udp_qsp_decrypt_fail_replay: self.udp_qsp_decrypt_fail_replay.load(Ordering::Relaxed),
            udp_qsp_decrypt_fail_too_old: self.udp_qsp_decrypt_fail_too_old.load(Ordering::Relaxed),
            udp_qsp_decrypt_fail_crypto: self.udp_qsp_decrypt_fail_crypto.load(Ordering::Relaxed),
            udp_qsp_decrypt_fail_other: self.udp_qsp_decrypt_fail_other.load(Ordering::Relaxed),
            udp_qsp_dead_channel: self.udp_qsp_dead_channel.load(Ordering::Relaxed),
        }
    }
}
