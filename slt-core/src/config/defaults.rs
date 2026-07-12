//! Default configuration values.

use std::time::Duration;

/// Conservative default TUN MTU for an outer IPv6 path MTU of 1280 bytes.
pub const DEFAULT_TUN_MTU: u16 = 1186;

/// Default bounded queue size for per-session events.
pub const DEFAULT_SESSION_QUEUE_SIZE: usize = 1024;

/// Default concurrent TLS/AUTH handshakes for VPN-claimed TCP connections.
pub const DEFAULT_MAX_AUTH_INFLIGHT: usize = 128;

/// Default maximum number of UDP NAT peers retained for nginx forwarding.
pub const DEFAULT_UDP_NAT_MAX_ENTRIES: usize = 1024;

/// Default minimum ping interval.
pub const DEFAULT_PING_MIN: Duration = Duration::from_secs(10);

/// Default maximum ping interval.
pub const DEFAULT_PING_MAX: Duration = Duration::from_secs(30);

/// Default authentication timeout.
pub const DEFAULT_AUTH_TIMEOUT: Duration = Duration::from_secs(10);

/// Default timeout for one TCP message write.
pub const DEFAULT_TCP_WRITE_TIMEOUT: Duration = Duration::from_secs(10);

/// Default idle timeout.
pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_mins(5);

/// Default authenticated UDP-QSP liveness timeout.
pub const DEFAULT_UDP_LIVENESS_TIMEOUT: Duration = Duration::from_secs(90);

/// Default metrics reporting interval.
pub const DEFAULT_METRICS_INTERVAL: Duration = Duration::from_mins(5);

/// Default TCP `ClientHello` classification timeout.
pub const DEFAULT_TCP_CLASSIFICATION_TIMEOUT: Duration = Duration::from_mins(1);

/// Default UDP-QSP registration timeout (client only).
pub const DEFAULT_REGISTER_TIMEOUT: Duration = Duration::from_secs(10);

/// Default QUIC DCID discovery timeout (client only).
pub const DEFAULT_QUIC_DISCOVERY_TIMEOUT: Duration = Duration::from_secs(15);

/// Default minimum reconnect backoff delay (client only).
pub const DEFAULT_RECONNECT_MIN: Duration = Duration::from_millis(200);

/// Default maximum reconnect backoff delay (client only).
pub const DEFAULT_RECONNECT_MAX: Duration = Duration::from_secs(5);

/// Returns the default minimum ping interval.
#[must_use]
pub const fn default_ping_min() -> Duration {
    DEFAULT_PING_MIN
}

/// Returns the default maximum ping interval.
#[must_use]
pub const fn default_ping_max() -> Duration {
    DEFAULT_PING_MAX
}

/// Returns the default authentication timeout.
#[must_use]
pub const fn default_auth_timeout() -> Duration {
    DEFAULT_AUTH_TIMEOUT
}

/// Returns the default timeout for one TCP message write.
#[must_use]
pub const fn default_tcp_write_timeout() -> Duration {
    DEFAULT_TCP_WRITE_TIMEOUT
}

/// Returns the default idle timeout.
#[must_use]
pub const fn default_idle_timeout() -> Duration {
    DEFAULT_IDLE_TIMEOUT
}

/// Returns the default authenticated UDP-QSP liveness timeout.
#[must_use]
pub const fn default_udp_liveness_timeout() -> Duration {
    DEFAULT_UDP_LIVENESS_TIMEOUT
}

/// Returns the default metrics reporting interval.
#[must_use]
pub const fn default_metrics_interval() -> Duration {
    DEFAULT_METRICS_INTERVAL
}

/// Returns the default TCP `ClientHello` classification timeout.
#[must_use]
pub const fn default_tcp_classification_timeout() -> Duration {
    DEFAULT_TCP_CLASSIFICATION_TIMEOUT
}

/// Returns the default UDP-QSP registration timeout (client only).
#[must_use]
pub const fn default_register_timeout() -> Duration {
    DEFAULT_REGISTER_TIMEOUT
}

/// Returns the default QUIC DCID discovery timeout (client only).
#[must_use]
pub const fn default_quic_discovery_timeout() -> Duration {
    DEFAULT_QUIC_DISCOVERY_TIMEOUT
}

/// Returns the default minimum reconnect backoff delay (client only).
#[must_use]
pub const fn default_reconnect_min() -> Duration {
    DEFAULT_RECONNECT_MIN
}

/// Returns the default maximum reconnect backoff delay (client only).
#[must_use]
pub const fn default_reconnect_max() -> Duration {
    DEFAULT_RECONNECT_MAX
}
