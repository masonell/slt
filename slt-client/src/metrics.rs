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
    udp_qsp_dead_channel: AtomicU64,
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
    /// UDP-QSP channels marked dead.
    pub udp_qsp_dead_channel: u64,
}

impl Metrics {
    /// Increment TCP connection counter.
    pub fn inc_tcp_connections(&self) {
        let prev = self.tcp_connections.fetch_add(1, Ordering::Relaxed);
        trace!(tcp_connections = prev + 1, "TCP connection initiated");
    }

    /// Increment TCP handshake success counter.
    pub fn inc_tcp_handshake_successes(&self) {
        let prev = self.tcp_handshake_successes.fetch_add(1, Ordering::Relaxed);
        trace!(
            tcp_handshake_successes = prev + 1,
            "TCP handshake succeeded"
        );
    }

    /// Increment TCP handshake failure counter.
    pub fn inc_tcp_handshake_failures(&self) {
        let prev = self.tcp_handshake_failures.fetch_add(1, Ordering::Relaxed);
        trace!(tcp_handshake_failures = prev + 1, "TCP handshake failed");
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

    /// Increment UDP -> TCP transport switch counter (client-initiated).
    ///
    /// Called when the client falls back to TCP due to UDP idle timeout or
    /// error, as opposed to server-initiated switches.
    pub fn inc_transport_udp_to_tcp(&self) {
        let prev = self.transport_udp_to_tcp.fetch_add(1, Ordering::Relaxed);
        trace!(
            transport_udp_to_tcp = prev + 1,
            "Transport switch: UDP -> TCP (client-initiated)"
        );
    }

    /// Increment UDP -> TCP transport switch counter (server-initiated).
    ///
    /// Called when the server sends DATA or PING on TCP while UDP is active,
    /// indicating the server prefers TCP for this traffic.
    pub fn inc_transport_udp_to_tcp_server(&self) {
        let prev = self
            .transport_udp_to_tcp_server
            .fetch_add(1, Ordering::Relaxed);
        trace!(
            transport_udp_to_tcp_server = prev + 1,
            "Transport switch: UDP -> TCP (server-initiated)"
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

    /// Increment TLS key update counter.
    pub fn inc_tls_key_update(&self) {
        let prev = self.tls_key_updates.fetch_add(1, Ordering::Relaxed);
        trace!(tls_key_updates = prev + 1, "TLS key update applied");
    }

    /// Increment UDP discovery failure counter.
    pub fn inc_udp_discovery_failure(&self) {
        let prev = self.udp_discovery_failures.fetch_add(1, Ordering::Relaxed);
        trace!(
            udp_discovery_failures = prev + 1,
            "UDP-QSP discovery failed"
        );
    }

    /// Increment UDP registration failure counter.
    pub fn inc_udp_register_failure(&self) {
        let prev = self.udp_register_failures.fetch_add(1, Ordering::Relaxed);
        trace!(
            udp_register_failures = prev + 1,
            "UDP-QSP registration rejected"
        );
    }

    /// Increment dropped oversized TUN packet counter.
    pub fn inc_tun_packets_dropped_oversized(&self) {
        let prev = self
            .tun_packets_dropped_oversized
            .fetch_add(1, Ordering::Relaxed);
        trace!(
            tun_packets_dropped_oversized = prev + 1,
            "TUN packet dropped: size limit exceeded"
        );
    }

    /// Increment UDP-QSP TX key-phase transition counter.
    pub fn inc_udp_qsp_tx_key_phase_transition(&self) {
        let prev = self
            .udp_qsp_tx_key_phase_transitions
            .fetch_add(1, Ordering::Relaxed);
        trace!(
            udp_qsp_tx_key_phase_transitions = prev + 1,
            "UDP-QSP TX key phase transitioned"
        );
    }

    /// Increment UDP-QSP RX key-phase transition counter.
    pub fn inc_udp_qsp_rx_key_phase_transition(&self) {
        let prev = self
            .udp_qsp_rx_key_phase_transitions
            .fetch_add(1, Ordering::Relaxed);
        trace!(
            udp_qsp_rx_key_phase_transitions = prev + 1,
            "UDP-QSP RX key phase transitioned"
        );
    }

    /// Increment UDP-QSP replay decrypt failure counter.
    pub fn inc_udp_qsp_decrypt_fail_replay(&self) {
        let prev = self
            .udp_qsp_decrypt_fail_replay
            .fetch_add(1, Ordering::Relaxed);
        trace!(
            udp_qsp_decrypt_fail_replay = prev + 1,
            "UDP-QSP decrypt failure: replay"
        );
    }

    /// Increment UDP-QSP too-old decrypt failure counter.
    pub fn inc_udp_qsp_decrypt_fail_too_old(&self) {
        let prev = self
            .udp_qsp_decrypt_fail_too_old
            .fetch_add(1, Ordering::Relaxed);
        trace!(
            udp_qsp_decrypt_fail_too_old = prev + 1,
            "UDP-QSP decrypt failure: too old"
        );
    }

    /// Increment UDP-QSP crypto decrypt failure counter.
    pub fn inc_udp_qsp_decrypt_fail_crypto(&self) {
        let prev = self
            .udp_qsp_decrypt_fail_crypto
            .fetch_add(1, Ordering::Relaxed);
        trace!(
            udp_qsp_decrypt_fail_crypto = prev + 1,
            "UDP-QSP decrypt failure: crypto"
        );
    }

    /// Increment UDP-QSP generic decrypt failure counter.
    pub fn inc_udp_qsp_decrypt_fail_other(&self) {
        let prev = self
            .udp_qsp_decrypt_fail_other
            .fetch_add(1, Ordering::Relaxed);
        trace!(
            udp_qsp_decrypt_fail_other = prev + 1,
            "UDP-QSP decrypt failure: other"
        );
    }

    /// Increment UDP-QSP dead-channel counter.
    pub fn inc_udp_qsp_dead_channel(&self) {
        let prev = self.udp_qsp_dead_channel.fetch_add(1, Ordering::Relaxed);
        trace!(
            udp_qsp_dead_channel = prev + 1,
            "UDP-QSP channel marked dead"
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
            udp_qsp_dead_channel: self.udp_qsp_dead_channel.load(Ordering::Relaxed),
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

        metrics.inc_udp_qsp_dead_channel();
        assert_eq!(metrics.udp_qsp_dead_channel.load(Ordering::Relaxed), 1);
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
        metrics.inc_udp_qsp_dead_channel();

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
        assert_eq!(snapshot.udp_qsp_dead_channel, 1);
    }
}
