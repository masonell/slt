//! Metrics and counters.

use std::sync::atomic::{AtomicU64, Ordering};

use tracing::trace;

/// Client counters for basic observability.
#[derive(Debug, Default)]
pub struct Metrics {
    tcp_connections: AtomicU64,
    tcp_handshake_successes: AtomicU64,
    tcp_handshake_failures: AtomicU64,
    auth_successes: AtomicU64,
    auth_failures: AtomicU64,
    transport_tcp_to_udp: AtomicU64,
    transport_udp_to_tcp: AtomicU64,
    transport_udp_to_tcp_server: AtomicU64,
    disconnect_idle_timeout: AtomicU64,
    disconnect_close: AtomicU64,
    disconnect_shutdown: AtomicU64,
    disconnect_error: AtomicU64,
    tls_key_updates: AtomicU64,
    udp_discovery_failures: AtomicU64,
    udp_register_failures: AtomicU64,
    tun_packets_dropped_oversized: AtomicU64,
    udp_qsp_tx_key_phase_transitions: AtomicU64,
    udp_qsp_rx_key_phase_transitions: AtomicU64,
    udp_qsp_decrypt_fail_replay: AtomicU64,
    udp_qsp_decrypt_fail_too_old: AtomicU64,
    udp_qsp_decrypt_fail_crypto: AtomicU64,
    udp_qsp_decrypt_fail_other: AtomicU64,
}

/// Snapshot of metric counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MetricsSnapshot {
    /// TCP connection attempts.
    pub tcp_connections: u64,
    /// Successful TCP handshakes.
    pub tcp_handshake_successes: u64,
    /// Failed TCP handshakes.
    pub tcp_handshake_failures: u64,
    /// Authentication failures.
    pub auth_failures: u64,
    /// Authentication successes.
    pub auth_successes: u64,
    /// TCP -> UDP transport switches.
    pub transport_tcp_to_udp: u64,
    /// UDP -> TCP transport switches (client-initiated: timeout/error).
    pub transport_udp_to_tcp: u64,
    /// UDP -> TCP transport switches (server-initiated).
    pub transport_udp_to_tcp_server: u64,
    /// Disconnects due to idle timeout.
    pub disconnect_idle_timeout: u64,
    /// Disconnects due to close frames or EOF.
    pub disconnect_close: u64,
    /// Disconnects due to explicit shutdown events.
    pub disconnect_shutdown: u64,
    /// Disconnects due to errors.
    pub disconnect_error: u64,
    /// TLS key updates applied.
    pub tls_key_updates: u64,
    /// UDP-QSP discovery failures.
    pub udp_discovery_failures: u64,
    /// UDP-QSP registration rejections (`REGISTER_FAIL` received).
    pub udp_register_failures: u64,
    /// TUN packets dropped due to size limits.
    pub tun_packets_dropped_oversized: u64,
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
}

#[inline]
fn inc(counter: &AtomicU64) -> u64 {
    counter.fetch_add(1, Ordering::Relaxed) + 1
}

impl Metrics {
    /// Increment TCP connection counter.
    pub fn inc_tcp_connections(&self) {
        let count = inc(&self.tcp_connections);
        trace!(tcp_connections = count, "TCP connection initiated");
    }

    /// Increment TCP handshake success counter.
    pub fn inc_tcp_handshake_successes(&self) {
        let count = inc(&self.tcp_handshake_successes);
        trace!(tcp_handshake_successes = count, "TCP handshake succeeded");
    }

    /// Increment TCP handshake failure counter.
    pub fn inc_tcp_handshake_failures(&self) {
        let count = inc(&self.tcp_handshake_failures);
        trace!(tcp_handshake_failures = count, "TCP handshake failed");
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

    /// Increment UDP -> TCP transport switch counter (client-initiated).
    ///
    /// Called when the client falls back to TCP due to UDP liveness timeout or
    /// error, as opposed to server-initiated switches.
    pub fn inc_transport_udp_to_tcp(&self) {
        let count = inc(&self.transport_udp_to_tcp);
        trace!(
            transport_udp_to_tcp = count,
            "Transport switch: UDP -> TCP (client-initiated)"
        );
    }

    /// Increment UDP -> TCP transport switch counter (server-initiated).
    ///
    /// Called when the server sends DATA or PING on TCP while UDP is active,
    /// indicating the server prefers TCP for this traffic.
    pub fn inc_transport_udp_to_tcp_server(&self) {
        let count = inc(&self.transport_udp_to_tcp_server);
        trace!(
            transport_udp_to_tcp_server = count,
            "Transport switch: UDP -> TCP (server-initiated)"
        );
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

    /// Increment TLS key update counter.
    pub fn inc_tls_key_update(&self) {
        let count = inc(&self.tls_key_updates);
        trace!(tls_key_updates = count, "TLS key update applied");
    }

    /// Increment UDP discovery failure counter.
    pub fn inc_udp_discovery_failure(&self) {
        let count = inc(&self.udp_discovery_failures);
        trace!(udp_discovery_failures = count, "UDP-QSP discovery failed");
    }

    /// Increment UDP registration failure counter.
    pub fn inc_udp_register_failure(&self) {
        let count = inc(&self.udp_register_failures);
        trace!(
            udp_register_failures = count,
            "UDP-QSP registration rejected"
        );
    }

    /// Increment dropped oversized TUN packet counter.
    pub fn inc_tun_packets_dropped_oversized(&self) {
        let count = inc(&self.tun_packets_dropped_oversized);
        trace!(
            tun_packets_dropped_oversized = count,
            "TUN packet dropped: size limit exceeded"
        );
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

    /// Return a point-in-time snapshot of metrics.
    #[must_use]
    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            tcp_connections: self.tcp_connections.load(Ordering::Relaxed),
            tcp_handshake_successes: self.tcp_handshake_successes.load(Ordering::Relaxed),
            tcp_handshake_failures: self.tcp_handshake_failures.load(Ordering::Relaxed),
            auth_failures: self.auth_failures.load(Ordering::Relaxed),
            auth_successes: self.auth_successes.load(Ordering::Relaxed),
            transport_tcp_to_udp: self.transport_tcp_to_udp.load(Ordering::Relaxed),
            transport_udp_to_tcp: self.transport_udp_to_tcp.load(Ordering::Relaxed),
            transport_udp_to_tcp_server: self.transport_udp_to_tcp_server.load(Ordering::Relaxed),
            disconnect_idle_timeout: self.disconnect_idle_timeout.load(Ordering::Relaxed),
            disconnect_close: self.disconnect_close.load(Ordering::Relaxed),
            disconnect_shutdown: self.disconnect_shutdown.load(Ordering::Relaxed),
            disconnect_error: self.disconnect_error.load(Ordering::Relaxed),
            tls_key_updates: self.tls_key_updates.load(Ordering::Relaxed),
            udp_discovery_failures: self.udp_discovery_failures.load(Ordering::Relaxed),
            udp_register_failures: self.udp_register_failures.load(Ordering::Relaxed),
            tun_packets_dropped_oversized: self
                .tun_packets_dropped_oversized
                .load(Ordering::Relaxed),
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
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_increment_counters() {
        let metrics = Metrics::default();

        metrics.inc_tcp_connections();
        metrics.inc_tcp_connections();
        assert_eq!(metrics.tcp_connections.load(Ordering::Relaxed), 2);

        metrics.inc_tcp_handshake_successes();
        assert_eq!(metrics.tcp_handshake_successes.load(Ordering::Relaxed), 1);

        metrics.inc_tcp_handshake_failures();
        assert_eq!(metrics.tcp_handshake_failures.load(Ordering::Relaxed), 1);

        metrics.inc_auth_successes();
        assert_eq!(metrics.auth_successes.load(Ordering::Relaxed), 1);

        metrics.inc_auth_failures();
        assert_eq!(metrics.auth_failures.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_transport_switch_counters() {
        let metrics = Metrics::default();

        metrics.inc_transport_tcp_to_udp();
        metrics.inc_transport_tcp_to_udp();
        assert_eq!(metrics.transport_tcp_to_udp.load(Ordering::Relaxed), 2);

        metrics.inc_transport_udp_to_tcp();
        assert_eq!(metrics.transport_udp_to_tcp.load(Ordering::Relaxed), 1);

        metrics.inc_transport_udp_to_tcp_server();
        metrics.inc_transport_udp_to_tcp_server();
        assert_eq!(
            metrics.transport_udp_to_tcp_server.load(Ordering::Relaxed),
            2
        );
    }

    #[test]
    fn test_disconnect_counters() {
        let metrics = Metrics::default();

        metrics.inc_disconnect_idle_timeout();
        assert_eq!(metrics.disconnect_idle_timeout.load(Ordering::Relaxed), 1);

        metrics.inc_disconnect_close();
        assert_eq!(metrics.disconnect_close.load(Ordering::Relaxed), 1);

        metrics.inc_disconnect_shutdown();
        assert_eq!(metrics.disconnect_shutdown.load(Ordering::Relaxed), 1);

        metrics.inc_disconnect_error();
        assert_eq!(metrics.disconnect_error.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_tls_key_update_counter() {
        let metrics = Metrics::default();

        metrics.inc_tls_key_update();
        assert_eq!(metrics.tls_key_updates.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_new_counters() {
        let metrics = Metrics::default();

        metrics.inc_udp_discovery_failure();
        assert_eq!(metrics.udp_discovery_failures.load(Ordering::Relaxed), 1);

        metrics.inc_udp_register_failure();
        assert_eq!(metrics.udp_register_failures.load(Ordering::Relaxed), 1);

        metrics.inc_tun_packets_dropped_oversized();
        assert_eq!(
            metrics
                .tun_packets_dropped_oversized
                .load(Ordering::Relaxed),
            1
        );
    }

    #[test]
    fn test_udp_qsp_counters() {
        let metrics = Metrics::default();

        metrics.inc_udp_qsp_tx_key_phase_transition();
        assert_eq!(
            metrics
                .udp_qsp_tx_key_phase_transitions
                .load(Ordering::Relaxed),
            1
        );

        metrics.inc_udp_qsp_rx_key_phase_transition();
        assert_eq!(
            metrics
                .udp_qsp_rx_key_phase_transitions
                .load(Ordering::Relaxed),
            1
        );

        metrics.inc_udp_qsp_decrypt_fail_replay();
        assert_eq!(
            metrics.udp_qsp_decrypt_fail_replay.load(Ordering::Relaxed),
            1
        );

        metrics.inc_udp_qsp_decrypt_fail_too_old();
        assert_eq!(
            metrics.udp_qsp_decrypt_fail_too_old.load(Ordering::Relaxed),
            1
        );

        metrics.inc_udp_qsp_decrypt_fail_crypto();
        assert_eq!(
            metrics.udp_qsp_decrypt_fail_crypto.load(Ordering::Relaxed),
            1
        );

        metrics.inc_udp_qsp_decrypt_fail_other();
        assert_eq!(
            metrics.udp_qsp_decrypt_fail_other.load(Ordering::Relaxed),
            1
        );
    }

    #[test]
    fn test_snapshot() {
        let metrics = Metrics::default();

        metrics.inc_tcp_connections();
        metrics.inc_tcp_handshake_successes();
        metrics.inc_auth_successes();
        metrics.inc_transport_tcp_to_udp();
        metrics.inc_disconnect_idle_timeout();

        let snapshot = metrics.snapshot();

        assert_eq!(snapshot.tcp_connections, 1);
        assert_eq!(snapshot.tcp_handshake_successes, 1);
        assert_eq!(snapshot.auth_successes, 1);
        assert_eq!(snapshot.transport_tcp_to_udp, 1);
        assert_eq!(snapshot.disconnect_idle_timeout, 1);

        // Verify defaults are zero
        assert_eq!(snapshot.tcp_handshake_failures, 0);
        assert_eq!(snapshot.auth_failures, 0);
        assert_eq!(snapshot.disconnect_error, 0);
    }

    #[test]
    fn test_snapshot_matches_fields() {
        let metrics = Metrics::default();

        // Increment all counters
        metrics.inc_tcp_connections();
        metrics.inc_tcp_handshake_successes();
        metrics.inc_tcp_handshake_failures();
        metrics.inc_auth_successes();
        metrics.inc_auth_failures();
        metrics.inc_transport_tcp_to_udp();
        metrics.inc_transport_udp_to_tcp();
        metrics.inc_transport_udp_to_tcp_server();
        metrics.inc_disconnect_idle_timeout();
        metrics.inc_disconnect_close();
        metrics.inc_disconnect_shutdown();
        metrics.inc_disconnect_error();
        metrics.inc_tls_key_update();
        metrics.inc_udp_discovery_failure();
        metrics.inc_udp_register_failure();
        metrics.inc_tun_packets_dropped_oversized();
        metrics.inc_udp_qsp_tx_key_phase_transition();
        metrics.inc_udp_qsp_rx_key_phase_transition();
        metrics.inc_udp_qsp_decrypt_fail_replay();
        metrics.inc_udp_qsp_decrypt_fail_too_old();
        metrics.inc_udp_qsp_decrypt_fail_crypto();
        metrics.inc_udp_qsp_decrypt_fail_other();

        let snapshot = metrics.snapshot();

        // All should be 1
        assert_eq!(snapshot.tcp_connections, 1);
        assert_eq!(snapshot.tcp_handshake_successes, 1);
        assert_eq!(snapshot.tcp_handshake_failures, 1);
        assert_eq!(snapshot.auth_successes, 1);
        assert_eq!(snapshot.auth_failures, 1);
        assert_eq!(snapshot.transport_tcp_to_udp, 1);
        assert_eq!(snapshot.transport_udp_to_tcp, 1);
        assert_eq!(snapshot.transport_udp_to_tcp_server, 1);
        assert_eq!(snapshot.disconnect_idle_timeout, 1);
        assert_eq!(snapshot.disconnect_close, 1);
        assert_eq!(snapshot.disconnect_shutdown, 1);
        assert_eq!(snapshot.disconnect_error, 1);
        assert_eq!(snapshot.tls_key_updates, 1);
        assert_eq!(snapshot.udp_discovery_failures, 1);
        assert_eq!(snapshot.udp_register_failures, 1);
        assert_eq!(snapshot.tun_packets_dropped_oversized, 1);
        assert_eq!(snapshot.udp_qsp_tx_key_phase_transitions, 1);
        assert_eq!(snapshot.udp_qsp_rx_key_phase_transitions, 1);
        assert_eq!(snapshot.udp_qsp_decrypt_fail_replay, 1);
        assert_eq!(snapshot.udp_qsp_decrypt_fail_too_old, 1);
        assert_eq!(snapshot.udp_qsp_decrypt_fail_crypto, 1);
        assert_eq!(snapshot.udp_qsp_decrypt_fail_other, 1);
    }
}
