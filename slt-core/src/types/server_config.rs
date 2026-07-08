//! Server configuration intermediate types.

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::config::{ConfigError, validate_ping_interval, validate_timeout};
use crate::proto::CipherSuite;
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

impl ServerNetworkConfig {
    /// Validate server network endpoints.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::ZeroPort`] if any configured endpoint uses port zero.
    pub const fn validate(&self) -> Result<(), ConfigError> {
        if self.listen_tcp.port() == 0 {
            return Err(ConfigError::ZeroPort {
                field: "network.listen_tcp",
            });
        }
        if self.listen_udp.port() == 0 {
            return Err(ConfigError::ZeroPort {
                field: "network.listen_udp",
            });
        }
        if self.nginx_tcp_upstream.port() == 0 {
            return Err(ConfigError::ZeroPort {
                field: "network.nginx_tcp_upstream",
            });
        }
        if self.nginx_udp_upstream.port() == 0 {
            return Err(ConfigError::ZeroPort {
                field: "network.nginx_udp_upstream",
            });
        }
        Ok(())
    }
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

/// Server-side UDP-QSP cipher allowlist entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServerUdpQspCipher {
    /// Allow AES-128-GCM.
    #[serde(rename = "aes-128-gcm")]
    Aes128Gcm,
    /// Allow ChaCha20-Poly1305.
    #[serde(rename = "chacha20-poly1305")]
    ChaCha20Poly1305,
}

impl ServerUdpQspCipher {
    /// Returns the protocol cipher suite represented by this allowlist entry.
    #[must_use]
    pub const fn suite(self) -> CipherSuite {
        match self {
            Self::Aes128Gcm => CipherSuite::Aes128Gcm,
            Self::ChaCha20Poly1305 => CipherSuite::ChaCha20Poly1305,
        }
    }
}

fn default_allowed_udp_qsp_ciphers() -> Vec<ServerUdpQspCipher> {
    vec![
        ServerUdpQspCipher::Aes128Gcm,
        ServerUdpQspCipher::ChaCha20Poly1305,
    ]
}

/// Server UDP-QSP transport configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerUdpQspConfig {
    /// Cipher suites accepted from client `REGISTER_CID` requests.
    #[serde(default = "default_allowed_udp_qsp_ciphers")]
    pub allowed_ciphers: Vec<ServerUdpQspCipher>,
}

impl Default for ServerUdpQspConfig {
    fn default() -> Self {
        Self {
            allowed_ciphers: default_allowed_udp_qsp_ciphers(),
        }
    }
}

impl ServerUdpQspConfig {
    /// Validate UDP-QSP transport configuration.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::EmptyUdpQspAllowedCiphers`] if no cipher suites
    /// are allowed.
    pub const fn validate(&self) -> Result<(), ConfigError> {
        if self.allowed_ciphers.is_empty() {
            return Err(ConfigError::EmptyUdpQspAllowedCiphers);
        }
        Ok(())
    }

    /// Returns true if `cipher` is allowed by server policy.
    #[must_use]
    pub fn allows(&self, cipher: CipherSuite) -> bool {
        self.allowed_ciphers
            .iter()
            .any(|allowed| allowed.suite() == cipher)
    }
}

/// Server transport configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ServerTransportConfig {
    /// UDP-QSP transport settings.
    #[serde(default)]
    pub udp_qsp: ServerUdpQspConfig,
}

impl ServerTransportConfig {
    /// Validate server transport configuration.
    ///
    /// # Errors
    ///
    /// Returns `ConfigError` if a nested transport setting is invalid.
    pub const fn validate(&self) -> Result<(), ConfigError> {
        self.udp_qsp.validate()
    }
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
    /// Metrics snapshot reporting interval.
    #[serde(
        default = "crate::config::default_metrics_interval",
        with = "humantime_serde"
    )]
    pub metrics_interval: Duration,
    /// Maximum time to wait for enough `ClientHello` bytes to classify TCP.
    #[serde(
        default = "crate::config::default_tcp_classification_timeout",
        with = "humantime_serde"
    )]
    pub tcp_classification_timeout: Duration,
}

impl Default for ServerTimingConfig {
    fn default() -> Self {
        use crate::config::{
            default_auth_timeout, default_idle_timeout, default_metrics_interval, default_ping_max,
            default_ping_min, default_tcp_classification_timeout,
        };
        Self {
            ping_min: default_ping_min(),
            ping_max: default_ping_max(),
            auth_timeout: default_auth_timeout(),
            idle_timeout: default_idle_timeout(),
            metrics_interval: default_metrics_interval(),
            tcp_classification_timeout: default_tcp_classification_timeout(),
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
        validate_timeout("metrics_interval", self.metrics_interval)?;
        validate_timeout(
            "tcp_classification_timeout",
            self.tcp_classification_timeout,
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_network_config() -> ServerNetworkConfig {
        ServerNetworkConfig {
            listen_tcp: SocketAddr::from(([0, 0, 0, 0], 443)),
            listen_udp: SocketAddr::from(([0, 0, 0, 0], 443)),
            nginx_tcp_upstream: SocketAddr::from(([127, 0, 0, 1], 8080)),
            nginx_udp_upstream: SocketAddr::from(([127, 0, 0, 1], 8080)),
        }
    }

    fn test_timing_config() -> ServerTimingConfig {
        ServerTimingConfig {
            ping_min: Duration::from_secs(10),
            ping_max: Duration::from_secs(20),
            auth_timeout: Duration::from_secs(10),
            idle_timeout: Duration::from_mins(1),
            metrics_interval: Duration::from_mins(5),
            tcp_classification_timeout: Duration::from_secs(60),
        }
    }

    #[test]
    fn validate_accepts_valid_network_config() {
        let config = test_network_config();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn validate_rejects_zero_listen_tcp_port() {
        let mut config = test_network_config();
        config.listen_tcp.set_port(0);
        let err = config.validate().unwrap_err();
        assert!(matches!(
            err,
            ConfigError::ZeroPort {
                field: "network.listen_tcp"
            }
        ));
    }

    #[test]
    fn validate_rejects_zero_listen_udp_port() {
        let mut config = test_network_config();
        config.listen_udp.set_port(0);
        let err = config.validate().unwrap_err();
        assert!(matches!(
            err,
            ConfigError::ZeroPort {
                field: "network.listen_udp"
            }
        ));
    }

    #[test]
    fn validate_rejects_zero_nginx_tcp_upstream_port() {
        let mut config = test_network_config();
        config.nginx_tcp_upstream.set_port(0);
        let err = config.validate().unwrap_err();
        assert!(matches!(
            err,
            ConfigError::ZeroPort {
                field: "network.nginx_tcp_upstream"
            }
        ));
    }

    #[test]
    fn validate_rejects_zero_nginx_udp_upstream_port() {
        let mut config = test_network_config();
        config.nginx_udp_upstream.set_port(0);
        let err = config.validate().unwrap_err();
        assert!(matches!(
            err,
            ConfigError::ZeroPort {
                field: "network.nginx_udp_upstream"
            }
        ));
    }

    #[test]
    fn validate_accepts_valid_timing_config() {
        let config = test_timing_config();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn udp_qsp_allowed_ciphers_default_to_supported_suites() {
        let config = ServerUdpQspConfig::default();
        assert!(config.allows(CipherSuite::Aes128Gcm));
        assert!(config.allows(CipherSuite::ChaCha20Poly1305));
    }

    #[test]
    fn udp_qsp_allowed_ciphers_can_restrict_suites() {
        let config: ServerUdpQspConfig = toml::from_str(
            r#"
            allowed_ciphers = ["aes-128-gcm"]
            "#,
        )
        .unwrap();

        assert!(config.allows(CipherSuite::Aes128Gcm));
        assert!(!config.allows(CipherSuite::ChaCha20Poly1305));
    }

    #[test]
    fn validate_rejects_empty_udp_qsp_allowed_ciphers() {
        let config = ServerUdpQspConfig {
            allowed_ciphers: Vec::new(),
        };

        let err = config.validate().unwrap_err();
        assert!(matches!(err, ConfigError::EmptyUdpQspAllowedCiphers));
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
    fn serde_defaults_metrics_interval_when_omitted() {
        let config: ServerTimingConfig = toml::from_str("").unwrap();
        assert_eq!(
            config.metrics_interval,
            crate::config::DEFAULT_METRICS_INTERVAL
        );
        assert_eq!(
            config.tcp_classification_timeout,
            crate::config::DEFAULT_TCP_CLASSIFICATION_TIMEOUT
        );
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
    fn validate_rejects_zero_tcp_classification_timeout() {
        let mut config = test_timing_config();
        config.tcp_classification_timeout = Duration::ZERO;
        let err = config.validate().unwrap_err();
        assert!(matches!(
            err,
            ConfigError::ZeroTimeout {
                field: "tcp_classification_timeout"
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
