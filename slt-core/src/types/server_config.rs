//! Server configuration intermediate types.

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::config::{ConfigError, validate_ping_interval, validate_timeout};
use crate::types::{ClientId, PubKeyEd25519, TlsMaterial};

/// Server network configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerNetworkConfig {
    /// TCP listener for TLS-wrapped VPN traffic.
    pub listen_tcp: SocketAddr,
    /// UDP listener for QUIC-based VPN traffic.
    pub listen_udp: SocketAddr,
    /// Nginx TCP upstream address for pass-through traffic.
    pub nginx_tcp_upstream: SocketAddr,
    /// Nginx UDP upstream address for pass-through traffic.
    pub nginx_udp_upstream: SocketAddr,
}

/// Server TLS configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerTlsConfig {
    /// TLS certificate chain (PEM) or file reference for server auth.
    pub tls_cert: TlsMaterial,
    /// TLS private key (PEM) or file reference for server auth.
    pub tls_key: TlsMaterial,
}

/// Per-client entry in the server allowlist.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerClient {
    /// Stable 16-byte client identifier.
    pub client_id: ClientId,
    /// Ed25519 public key used for authentication.
    pub pubkey_ed25519: PubKeyEd25519,
    /// Assigned VPN IPv4 address.
    pub assigned_ipv4: Ipv4Addr,
    /// If false, the client is disabled without removing the entry.
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

const fn default_enabled() -> bool {
    true
}

/// Server timing configuration with defaults and validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerTimingConfig {
    /// Minimum ping interval.
    #[serde(default = "crate::config::default_ping_min", with = "humantime_serde")]
    pub ping_min: Duration,
    /// Maximum ping interval.
    #[serde(default = "crate::config::default_ping_max", with = "humantime_serde")]
    pub ping_max: Duration,
    /// Authentication timeout.
    #[serde(
        default = "crate::config::default_auth_timeout",
        with = "humantime_serde"
    )]
    pub auth_timeout: Duration,
    /// Idle connection timeout.
    #[serde(
        default = "crate::config::default_idle_timeout",
        with = "humantime_serde"
    )]
    pub idle_timeout: Duration,
}

impl Default for ServerTimingConfig {
    fn default() -> Self {
        use crate::config::{
            default_auth_timeout, default_idle_timeout, default_ping_max, default_ping_min,
        };
        Self {
            ping_min: default_ping_min(),
            ping_max: default_ping_max(),
            auth_timeout: default_auth_timeout(),
            idle_timeout: default_idle_timeout(),
        }
    }
}

impl ServerTimingConfig {
    /// Validate timing configuration.
    ///
    /// # Errors
    ///
    /// Returns `ConfigError` if:
    /// - `ping_min > ping_max`
    /// - Any timeout is zero or exceeds 1 hour
    pub fn validate(&self) -> Result<(), ConfigError> {
        validate_ping_interval(self.ping_min, self.ping_max)?;
        validate_timeout("auth_timeout", self.auth_timeout)?;
        validate_timeout("idle_timeout", self.idle_timeout)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_timing_config() -> ServerTimingConfig {
        ServerTimingConfig {
            ping_min: Duration::from_secs(10),
            ping_max: Duration::from_secs(20),
            auth_timeout: Duration::from_secs(10),
            idle_timeout: Duration::from_mins(1),
        }
    }

    #[test]
    fn validate_accepts_valid_timing_config() {
        let config = test_timing_config();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn validate_accepts_equal_ping_intervals() {
        let mut config = test_timing_config();
        config.ping_min = Duration::from_secs(15);
        config.ping_max = Duration::from_secs(15);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn validate_rejects_ping_min_greater_than_max() {
        let mut config = test_timing_config();
        config.ping_min = Duration::from_secs(30);
        config.ping_max = Duration::from_secs(10);
        let err = config.validate().unwrap_err();
        assert!(matches!(err, ConfigError::InvalidPingInterval { .. }));
    }

    #[test]
    fn validate_rejects_zero_timeout() {
        let mut config = test_timing_config();
        config.auth_timeout = Duration::ZERO;
        let err = config.validate().unwrap_err();
        assert!(matches!(err, ConfigError::ZeroTimeout { .. }));
    }

    #[test]
    fn validate_rejects_timeout_too_large() {
        let mut config = test_timing_config();
        config.idle_timeout = Duration::from_secs(3601);
        let err = config.validate().unwrap_err();
        assert!(matches!(err, ConfigError::TimeoutTooLarge { .. }));
    }
}
