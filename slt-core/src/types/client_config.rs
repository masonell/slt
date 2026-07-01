//! Client configuration intermediate types.

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::config::{ConfigError, validate_ping_interval, validate_timeout};
use crate::types::{ClientId, PrivKeyEd25519, SharedSecret, TlsMaterial};

/// Client network configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientNetworkConfig {
    /// Server hostname used for SNI and certificate verification.
    pub hostname: String,
    /// Server port to connect to.
    pub port: u16,
    /// Optional IP override for connecting without DNS.
    #[serde(default)]
    pub ip: Option<IpAddr>,
}

impl ClientNetworkConfig {
    /// Validate network configuration.
    ///
    /// # Errors
    ///
    /// Returns `ConfigError::EmptyHostname` if hostname is empty.
    pub const fn validate(&self) -> Result<(), ConfigError> {
        if self.hostname.is_empty() {
            return Err(ConfigError::EmptyHostname);
        }
        Ok(())
    }
}

/// Client TLS configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientTlsConfig {
    /// Certificate authority for verifying SLT server certificate (TCP).
    pub tls_ca: TlsMaterial,
    /// Optional CA for QUIC discovery. If `None`, uses host CA locations
    /// available to the Rust/BoringSSL verifier.
    ///
    /// Set this when nginx uses a custom CA. For Let's Encrypt, leave as `None`
    /// to use the host's built-in public trust anchors.
    #[serde(default)]
    pub quic_ca: Option<TlsMaterial>,
}

/// Client identity configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientIdentity {
    /// Stable 16-byte client identifier.
    pub client_id: ClientId,
    /// Pre-shared secret for `ClientHello` classification.
    pub shared_secret: SharedSecret,
    /// Assigned VPN IPv4 address.
    pub assigned_ipv4: Ipv4Addr,
    /// Ed25519 private key used for authentication.
    pub privkey_ed25519: PrivKeyEd25519,
}

/// Client timing configuration with defaults and validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientTimingConfig {
    /// Minimum ping interval.
    #[serde(default = "crate::config::default_ping_min", with = "humantime_serde")]
    pub ping_min: Duration,
    /// Maximum ping interval.
    #[serde(default = "crate::config::default_ping_max", with = "humantime_serde")]
    pub ping_max: Duration,
    /// Timeout for authentication handshake.
    #[serde(
        default = "crate::config::default_auth_timeout",
        with = "humantime_serde"
    )]
    pub auth_timeout: Duration,
    /// Timeout for UDP-QSP registration.
    #[serde(
        default = "crate::config::default_register_timeout",
        with = "humantime_serde"
    )]
    pub register_timeout: Duration,
    /// Session idle timeout (no activity before disconnect).
    #[serde(
        default = "crate::config::default_idle_timeout",
        with = "humantime_serde"
    )]
    pub idle_timeout: Duration,
    /// Minimum reconnect backoff delay.
    #[serde(
        default = "crate::config::default_reconnect_min",
        with = "humantime_serde"
    )]
    pub reconnect_min: Duration,
    /// Maximum reconnect backoff delay.
    #[serde(
        default = "crate::config::default_reconnect_max",
        with = "humantime_serde"
    )]
    pub reconnect_max: Duration,
}

impl Default for ClientTimingConfig {
    fn default() -> Self {
        use crate::config::{
            default_auth_timeout, default_idle_timeout, default_ping_max, default_ping_min,
            default_reconnect_max, default_reconnect_min, default_register_timeout,
        };
        Self {
            ping_min: default_ping_min(),
            ping_max: default_ping_max(),
            auth_timeout: default_auth_timeout(),
            register_timeout: default_register_timeout(),
            idle_timeout: default_idle_timeout(),
            reconnect_min: default_reconnect_min(),
            reconnect_max: default_reconnect_max(),
        }
    }
}

impl ClientTimingConfig {
    /// Validate timing configuration.
    ///
    /// # Errors
    ///
    /// Returns `ConfigError` if:
    /// - `ping_min > ping_max`
    /// - `reconnect_min > reconnect_max`
    /// - Any timeout is zero or exceeds 1 hour
    pub fn validate(&self) -> Result<(), ConfigError> {
        validate_ping_interval(self.ping_min, self.ping_max)?;
        if self.reconnect_min > self.reconnect_max {
            return Err(ConfigError::InvalidReconnectInterval {
                reconnect_min: self.reconnect_min,
                reconnect_max: self.reconnect_max,
            });
        }
        validate_timeout("auth_timeout", self.auth_timeout)?;
        validate_timeout("register_timeout", self.register_timeout)?;
        validate_timeout("idle_timeout", self.idle_timeout)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_network_config() -> ClientNetworkConfig {
        ClientNetworkConfig {
            hostname: "example.com".to_string(),
            port: 443,
            ip: None,
        }
    }

    fn test_timing_config() -> ClientTimingConfig {
        ClientTimingConfig {
            ping_min: Duration::from_secs(10),
            ping_max: Duration::from_secs(20),
            auth_timeout: Duration::from_secs(10),
            register_timeout: Duration::from_secs(10),
            idle_timeout: Duration::from_mins(1),
            reconnect_min: Duration::from_millis(200),
            reconnect_max: Duration::from_secs(5),
        }
    }

    #[test]
    fn validate_accepts_valid_network_config() {
        let config = test_network_config();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn validate_rejects_empty_hostname() {
        let mut config = test_network_config();
        config.hostname = String::new();
        let err = config.validate().unwrap_err();
        assert!(matches!(err, ConfigError::EmptyHostname));
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
    fn validate_rejects_reconnect_min_greater_than_max() {
        let mut config = test_timing_config();
        config.reconnect_min = Duration::from_secs(10);
        config.reconnect_max = Duration::from_millis(100);
        let err = config.validate().unwrap_err();
        assert!(matches!(err, ConfigError::InvalidReconnectInterval { .. }));
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
