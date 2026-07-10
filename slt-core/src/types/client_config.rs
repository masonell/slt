//! Client configuration intermediate types.

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::config::{ConfigError, validate_interval, validate_ping_interval, validate_timeout};
use crate::proto::CipherSuite;
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
    /// Returns `ConfigError` if hostname is empty or `port` is zero.
    pub const fn validate(&self) -> Result<(), ConfigError> {
        if self.hostname.is_empty() {
            return Err(ConfigError::EmptyHostname);
        }
        if self.port == 0 {
            return Err(ConfigError::ZeroPort {
                field: "network.port",
            });
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

/// Client-side UDP-QSP cipher selection policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum ClientUdpQspCipher {
    /// Select AES-128-GCM when native AES-GCM acceleration is available,
    /// otherwise select ChaCha20-Poly1305.
    #[serde(rename = "auto")]
    #[default]
    Auto,
    /// Always use AES-128-GCM.
    #[serde(rename = "aes-128-gcm")]
    Aes128Gcm,
    /// Always use ChaCha20-Poly1305.
    #[serde(rename = "chacha20-poly1305")]
    ChaCha20Poly1305,
}

impl ClientUdpQspCipher {
    /// Resolve this policy to a concrete UDP-QSP cipher suite.
    #[must_use]
    pub const fn select(self, aes_gcm_accelerated: bool) -> CipherSuite {
        match self {
            Self::Auto if aes_gcm_accelerated => CipherSuite::Aes128Gcm,
            Self::Auto | Self::ChaCha20Poly1305 => CipherSuite::ChaCha20Poly1305,
            Self::Aes128Gcm => CipherSuite::Aes128Gcm,
        }
    }
}

/// Client UDP-QSP transport configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ClientUdpQspConfig {
    /// Packet protection cipher selection policy.
    #[serde(default)]
    pub cipher: ClientUdpQspCipher,
}

/// Client transport configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ClientTransportConfig {
    /// UDP-QSP transport settings.
    #[serde(default)]
    pub udp_qsp: ClientUdpQspConfig,
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
    /// Maximum time for one TCP message write.
    #[serde(
        default = "crate::config::default_tcp_write_timeout",
        with = "humantime_serde"
    )]
    pub tcp_write_timeout: Duration,
    /// Timeout for UDP-QSP registration.
    #[serde(
        default = "crate::config::default_register_timeout",
        with = "humantime_serde"
    )]
    pub register_timeout: Duration,
    /// Timeout for the full QUIC DCID discovery attempt.
    #[serde(
        default = "crate::config::default_quic_discovery_timeout",
        with = "humantime_serde"
    )]
    pub quic_discovery_timeout: Duration,
    /// Session idle timeout (no activity before disconnect).
    #[serde(
        default = "crate::config::default_idle_timeout",
        with = "humantime_serde"
    )]
    pub idle_timeout: Duration,
    /// Metrics snapshot reporting interval.
    #[serde(
        default = "crate::config::default_metrics_interval",
        with = "humantime_serde"
    )]
    pub metrics_interval: Duration,
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
            default_auth_timeout, default_idle_timeout, default_metrics_interval, default_ping_max,
            default_ping_min, default_quic_discovery_timeout, default_reconnect_max,
            default_reconnect_min, default_register_timeout, default_tcp_write_timeout,
        };
        Self {
            ping_min: default_ping_min(),
            ping_max: default_ping_max(),
            auth_timeout: default_auth_timeout(),
            tcp_write_timeout: default_tcp_write_timeout(),
            register_timeout: default_register_timeout(),
            quic_discovery_timeout: default_quic_discovery_timeout(),
            idle_timeout: default_idle_timeout(),
            metrics_interval: default_metrics_interval(),
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
    /// - A ping or reconnect interval is below 1 millisecond
    /// - `ping_min > ping_max`
    /// - `reconnect_min > reconnect_max`
    /// - Any timeout is zero or exceeds 1 hour
    pub fn validate(&self) -> Result<(), ConfigError> {
        validate_ping_interval(self.ping_min, self.ping_max)?;
        validate_interval("reconnect_min", self.reconnect_min)?;
        validate_interval("reconnect_max", self.reconnect_max)?;
        if self.reconnect_min > self.reconnect_max {
            return Err(ConfigError::InvalidReconnectInterval {
                reconnect_min: self.reconnect_min,
                reconnect_max: self.reconnect_max,
            });
        }
        validate_timeout("auth_timeout", self.auth_timeout)?;
        validate_timeout("tcp_write_timeout", self.tcp_write_timeout)?;
        validate_timeout("register_timeout", self.register_timeout)?;
        validate_timeout("quic_discovery_timeout", self.quic_discovery_timeout)?;
        validate_timeout("idle_timeout", self.idle_timeout)?;
        validate_timeout("metrics_interval", self.metrics_interval)?;
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
            tcp_write_timeout: Duration::from_secs(10),
            register_timeout: Duration::from_secs(10),
            quic_discovery_timeout: Duration::from_secs(15),
            idle_timeout: Duration::from_mins(1),
            metrics_interval: Duration::from_mins(5),
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
    fn validate_rejects_zero_port() {
        let mut config = test_network_config();
        config.port = 0;
        let err = config.validate().unwrap_err();
        assert!(matches!(
            err,
            ConfigError::ZeroPort {
                field: "network.port"
            }
        ));
    }

    #[test]
    fn validate_accepts_valid_timing_config() {
        let config = test_timing_config();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn serde_defaults_quic_discovery_timeout_when_omitted() {
        let config: ClientTimingConfig = toml::from_str("").unwrap();
        assert_eq!(
            config.quic_discovery_timeout,
            crate::config::DEFAULT_QUIC_DISCOVERY_TIMEOUT
        );
    }

    #[test]
    fn serde_defaults_tcp_write_timeout_when_omitted() {
        let config: ClientTimingConfig = toml::from_str("").unwrap();
        assert_eq!(
            config.tcp_write_timeout,
            crate::config::DEFAULT_TCP_WRITE_TIMEOUT
        );
    }

    #[test]
    fn udp_qsp_cipher_selection_resolves_auto_from_aes_acceleration() {
        assert_eq!(
            ClientUdpQspCipher::Auto.select(true),
            CipherSuite::Aes128Gcm
        );
        assert_eq!(
            ClientUdpQspCipher::Auto.select(false),
            CipherSuite::ChaCha20Poly1305
        );
    }

    #[test]
    fn udp_qsp_cipher_selection_respects_explicit_cipher() {
        assert_eq!(
            ClientUdpQspCipher::Aes128Gcm.select(false),
            CipherSuite::Aes128Gcm
        );
        assert_eq!(
            ClientUdpQspCipher::ChaCha20Poly1305.select(true),
            CipherSuite::ChaCha20Poly1305
        );
    }

    #[test]
    fn serde_defaults_metrics_interval_when_omitted() {
        let config: ClientTimingConfig = toml::from_str("").unwrap();
        assert_eq!(
            config.metrics_interval,
            crate::config::DEFAULT_METRICS_INTERVAL
        );
    }

    #[test]
    fn validate_accepts_equal_ping_intervals() {
        let mut config = test_timing_config();
        config.ping_min = Duration::from_secs(15);
        config.ping_max = Duration::from_secs(15);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn validate_accepts_minimum_intervals() {
        let mut config = test_timing_config();
        config.ping_min = crate::config::MIN_INTERVAL;
        config.ping_max = crate::config::MIN_INTERVAL;
        config.reconnect_min = crate::config::MIN_INTERVAL;
        config.reconnect_max = crate::config::MIN_INTERVAL;
        assert!(config.validate().is_ok());
    }

    #[test]
    fn validate_rejects_small_ping_and_reconnect_intervals() {
        for value in [Duration::ZERO, Duration::from_micros(999)] {
            for field in ["ping_min", "ping_max", "reconnect_min", "reconnect_max"] {
                let mut config = test_timing_config();
                match field {
                    "ping_min" => config.ping_min = value,
                    "ping_max" => config.ping_max = value,
                    "reconnect_min" => config.reconnect_min = value,
                    "reconnect_max" => config.reconnect_max = value,
                    _ => unreachable!(),
                }

                let err = config.validate().unwrap_err();
                assert!(matches!(
                    err,
                    ConfigError::IntervalTooSmall {
                        field: rejected,
                        value: rejected_value,
                        min: crate::config::MIN_INTERVAL,
                    } if rejected == field && rejected_value == value
                ));
            }
        }
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
    fn validate_rejects_zero_quic_discovery_timeout() {
        let mut config = test_timing_config();
        config.quic_discovery_timeout = Duration::ZERO;
        let err = config.validate().unwrap_err();
        assert!(matches!(
            err,
            ConfigError::ZeroTimeout {
                field: "quic_discovery_timeout"
            }
        ));
    }

    #[test]
    fn validate_rejects_zero_tcp_write_timeout() {
        let mut config = test_timing_config();
        config.tcp_write_timeout = Duration::ZERO;
        let err = config.validate().unwrap_err();
        assert!(matches!(
            err,
            ConfigError::ZeroTimeout {
                field: "tcp_write_timeout"
            }
        ));
    }

    #[test]
    fn validate_rejects_zero_metrics_interval() {
        let mut config = test_timing_config();
        config.metrics_interval = Duration::ZERO;
        let err = config.validate().unwrap_err();
        assert!(matches!(
            err,
            ConfigError::ZeroTimeout {
                field: "metrics_interval"
            }
        ));
    }

    #[test]
    fn validate_rejects_timeout_too_large() {
        let mut config = test_timing_config();
        config.idle_timeout = Duration::from_secs(3601);
        let err = config.validate().unwrap_err();
        assert!(matches!(err, ConfigError::TimeoutTooLarge { .. }));
    }
}
