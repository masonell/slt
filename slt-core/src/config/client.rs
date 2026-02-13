use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use super::{ConfigError, ConfigLoadError, validate_tun_mtu};
use crate::types::{ClientId, PrivKeyEd25519, SharedSecret, TlsMaterial};

/// Static client configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientConfig {
    /// Server hostname used for SNI and certificate verification.
    pub hostname: String,
    /// Server port to connect to.
    pub port: u16,
    /// Optional IP override for connecting without DNS.
    pub ip: Option<IpAddr>,
    /// Certificate authority or pinned certificate for server verification.
    pub tls_ca: TlsMaterial,
    /// Stable 16-byte client identifier.
    pub client_id: ClientId,
    /// Pre-shared secret for `ClientHello` classification.
    pub shared_secret: SharedSecret,
    /// Assigned VPN IPv4 address.
    pub assigned_ipv4: Ipv4Addr,
    /// Ed25519 private key used for authentication.
    pub privkey_ed25519: PrivKeyEd25519,
    /// TUN interface name.
    pub tun_name: String,
    /// TUN interface MTU.
    pub tun_mtu: u16,
    /// Enable QUIC DCID discovery and UDP-QSP upgrade.
    #[serde(default)]
    pub enable_upgrade: bool,
    /// Minimum ping interval.
    #[serde(with = "humantime_serde")]
    pub ping_min: Duration,
    /// Maximum ping interval.
    #[serde(with = "humantime_serde")]
    pub ping_max: Duration,
    /// Timeout for authentication handshake.
    #[serde(default = "default_auth_timeout", with = "humantime_serde")]
    pub auth_timeout: Duration,
    /// Timeout for UDP-QSP registration.
    #[serde(default = "default_register_timeout", with = "humantime_serde")]
    pub register_timeout: Duration,
    /// Session idle timeout (no activity before disconnect).
    #[serde(default = "default_idle_timeout", with = "humantime_serde")]
    pub idle_timeout: Duration,
    /// Minimum reconnect backoff delay.
    #[serde(default = "default_reconnect_min", with = "humantime_serde")]
    pub reconnect_min: Duration,
    /// Maximum reconnect backoff delay.
    #[serde(default = "default_reconnect_max", with = "humantime_serde")]
    pub reconnect_max: Duration,
}

const fn default_auth_timeout() -> Duration {
    Duration::from_secs(10)
}

const fn default_register_timeout() -> Duration {
    Duration::from_secs(10)
}

const fn default_idle_timeout() -> Duration {
    Duration::from_secs(60)
}

const fn default_reconnect_min() -> Duration {
    Duration::from_millis(200)
}

const fn default_reconnect_max() -> Duration {
    Duration::from_secs(5)
}

impl ClientConfig {
    /// Validate semantic constraints for a parsed client config.
    ///
    /// # Errors
    ///
    /// Returns `ConfigError` if any constraint is violated:
    /// - `InvalidTunMtu` if `tun_mtu` is out of range
    /// - `InvalidPingInterval` if `ping_min > ping_max`
    /// - `InvalidReconnectInterval` if `reconnect_min > reconnect_max`
    pub fn validate(&self) -> Result<(), ConfigError> {
        validate_tun_mtu(self.tun_mtu)?;
        if self.ping_min > self.ping_max {
            return Err(ConfigError::InvalidPingInterval {
                ping_min: self.ping_min,
                ping_max: self.ping_max,
            });
        }
        if self.reconnect_min > self.reconnect_max {
            return Err(ConfigError::InvalidReconnectInterval {
                reconnect_min: self.reconnect_min,
                reconnect_max: self.reconnect_max,
            });
        }
        Ok(())
    }

    /// Parse and validate a client config from TOML text.
    ///
    /// # Errors
    ///
    /// Returns `ConfigLoadError::ParseToml` if TOML deserialization fails, or
    /// `ConfigLoadError::Validate` if semantic validation fails.
    pub fn from_toml_str(raw: &str) -> Result<Self, ConfigLoadError> {
        let config: Self = toml::from_str(raw)?;
        config.validate()?;
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> ClientConfig {
        ClientConfig {
            hostname: "example.com".to_string(),
            port: 443,
            ip: None,
            tls_ca: TlsMaterial::Pem(String::new()),
            client_id: ClientId([0u8; 16]),
            shared_secret: SharedSecret([0u8; 32]),
            assigned_ipv4: Ipv4Addr::new(10, 10, 0, 2),
            privkey_ed25519: PrivKeyEd25519([0u8; 32]),
            tun_name: "tun0".to_string(),
            tun_mtu: 1280,
            enable_upgrade: false,
            ping_min: Duration::from_secs(10),
            ping_max: Duration::from_secs(20),
            auth_timeout: Duration::from_secs(10),
            register_timeout: Duration::from_secs(10),
            idle_timeout: Duration::from_secs(60),
            reconnect_min: Duration::from_millis(200),
            reconnect_max: Duration::from_secs(5),
        }
    }

    #[test]
    fn validate_accepts_valid_intervals() {
        let config = test_config();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn validate_accepts_equal_ping_intervals() {
        let mut config = test_config();
        config.ping_min = Duration::from_secs(15);
        config.ping_max = Duration::from_secs(15);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn validate_rejects_ping_min_greater_than_max() {
        let mut config = test_config();
        config.ping_min = Duration::from_secs(30);
        config.ping_max = Duration::from_secs(10);
        let err = config.validate().unwrap_err();
        assert!(matches!(err, ConfigError::InvalidPingInterval { .. }));
    }

    #[test]
    fn validate_rejects_reconnect_min_greater_than_max() {
        let mut config = test_config();
        config.reconnect_min = Duration::from_secs(10);
        config.reconnect_max = Duration::from_millis(100);
        let err = config.validate().unwrap_err();
        assert!(matches!(err, ConfigError::InvalidReconnectInterval { .. }));
    }
}
