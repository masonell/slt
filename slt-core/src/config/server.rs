//! Server configuration.

use serde::{Deserialize, Serialize};

use super::{ConfigError, ConfigLoadError};
use crate::types::{
    ServerClient, ServerNetworkConfig, ServerTimingConfig, ServerTlsConfig, SharedSecret, TunConfig,
};

/// Default UDP NAT max entries.
const fn default_udp_nat_max_entries() -> usize {
    1024
}

/// Default session queue size.
const fn default_session_queue_size() -> usize {
    256
}

/// Static server configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Pre-shared secret for `ClientHello` classification.
    pub server_secret: SharedSecret,
    /// Network settings (listeners, upstreams).
    pub network: ServerNetworkConfig,
    /// TLS configuration.
    pub tls: ServerTlsConfig,
    /// TUN interface settings.
    pub tun: TunConfig,
    /// Timing configuration.
    #[serde(default)]
    pub timing: ServerTimingConfig,
    /// Max number of UDP NAT peers to keep for nginx forwarding.
    #[serde(default = "default_udp_nat_max_entries")]
    pub udp_nat_max_entries: usize,
    /// Bounded queue size for per-session event channels.
    #[serde(default = "default_session_queue_size")]
    pub session_queue_size: usize,
    /// Configured client entries.
    pub clients: Vec<ServerClient>,
}

impl ServerConfig {
    /// Validate semantic constraints for a parsed server config.
    ///
    /// # Errors
    ///
    /// Returns `ConfigError` if any constraint is violated:
    /// - `EmptyTunName` if `tun_name` is empty
    /// - `InvalidTunMtu` if `tun_mtu` is out of range
    /// - `InvalidTunPrefix` if `tun_prefix` is out of range
    /// - `ClientOutsideTunSubnet` if a configured client IP is outside the TUN subnet
    /// - `ClientUsesTunAddress` if a configured client IP equals `tun_ipv4`
    /// - `InvalidPingInterval` if `ping_min` > `ping_max`
    /// - `ZeroSessionQueueSize` if `session_queue_size` is zero
    /// - `ZeroUdpNatMaxEntries` if `udp_nat_max_entries` is zero
    /// - `ZeroTimeout` if any timeout is zero
    /// - `TimeoutTooLarge` if any timeout exceeds 1 hour
    pub fn validate(&self) -> Result<(), ConfigError> {
        self.tun.validate()?;
        for client in &self.clients {
            if client.assigned_ipv4 == self.tun.tun_ipv4 {
                return Err(ConfigError::ClientUsesTunAddress {
                    assigned_ipv4: client.assigned_ipv4,
                });
            }
            if !self.tun.contains_ipv4(client.assigned_ipv4) {
                return Err(ConfigError::ClientOutsideTunSubnet {
                    assigned_ipv4: client.assigned_ipv4,
                    tun_ipv4: self.tun.tun_ipv4,
                    tun_prefix: self.tun.tun_prefix,
                });
            }
        }
        self.timing.validate()?;
        if self.session_queue_size == 0 {
            return Err(ConfigError::ZeroSessionQueueSize);
        }
        if self.udp_nat_max_entries == 0 {
            return Err(ConfigError::ZeroUdpNatMaxEntries);
        }
        Ok(())
    }

    /// Parse and validate a server config from TOML text.
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
    use std::net::{Ipv4Addr, SocketAddr};
    use std::time::Duration;

    use super::*;
    use crate::types::{ClientId, PubKeyEd25519, SharedSecret, TlsMaterial};

    fn test_config() -> ServerConfig {
        ServerConfig {
            server_secret: SharedSecret([0u8; 32]),
            network: ServerNetworkConfig {
                listen_tcp: SocketAddr::from(([0, 0, 0, 0], 443)),
                listen_udp: SocketAddr::from(([0, 0, 0, 0], 443)),
                nginx_tcp_upstream: SocketAddr::from(([127, 0, 0, 1], 8080)),
                nginx_udp_upstream: SocketAddr::from(([127, 0, 0, 1], 8080)),
            },
            tls: ServerTlsConfig {
                tls_cert: TlsMaterial::Pem(String::new()),
                tls_key: TlsMaterial::Pem(String::new()),
            },
            tun: TunConfig {
                tun_name: "tun0".to_string(),
                tun_mtu: 1280,
                tun_ipv4: Ipv4Addr::new(10, 10, 0, 1),
                tun_prefix: 24,
            },
            timing: ServerTimingConfig {
                ping_min: Duration::from_secs(10),
                ping_max: Duration::from_secs(20),
                auth_timeout: Duration::from_secs(10),
                idle_timeout: Duration::from_mins(1),
                metrics_interval: Duration::from_mins(5),
            },
            udp_nat_max_entries: 1024,
            session_queue_size: 256,
            clients: vec![ServerClient {
                client_id: ClientId([0u8; 16]),
                pubkey_ed25519: PubKeyEd25519([0u8; 32]),
                assigned_ipv4: Ipv4Addr::new(10, 10, 0, 2),
                enabled: true,
            }],
        }
    }

    #[test]
    fn validate_accepts_valid_config() {
        let config = test_config();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn validate_rejects_empty_tun_name() {
        let mut config = test_config();
        config.tun.tun_name = String::new();
        let err = config.validate().unwrap_err();
        assert!(matches!(err, ConfigError::EmptyTunName));
    }

    #[test]
    fn validate_rejects_client_outside_tun_subnet() {
        let mut config = test_config();
        config.clients[0].assigned_ipv4 = Ipv4Addr::new(10, 10, 1, 2);
        let err = config.validate().unwrap_err();
        assert!(matches!(err, ConfigError::ClientOutsideTunSubnet { .. }));
    }

    #[test]
    fn validate_rejects_client_using_server_tun_ip() {
        let mut config = test_config();
        config.clients[0].assigned_ipv4 = config.tun.tun_ipv4;
        let err = config.validate().unwrap_err();
        assert!(matches!(err, ConfigError::ClientUsesTunAddress { .. }));
    }

    #[test]
    fn validate_rejects_zero_session_queue_size() {
        let mut config = test_config();
        config.session_queue_size = 0;
        let err = config.validate().unwrap_err();
        assert!(matches!(err, ConfigError::ZeroSessionQueueSize));
    }

    #[test]
    fn validate_rejects_zero_udp_nat_max_entries() {
        let mut config = test_config();
        config.udp_nat_max_entries = 0;
        let err = config.validate().unwrap_err();
        assert!(matches!(err, ConfigError::ZeroUdpNatMaxEntries));
    }

    #[test]
    fn validate_rejects_ping_min_greater_than_max() {
        let mut config = test_config();
        config.timing.ping_min = Duration::from_secs(30);
        config.timing.ping_max = Duration::from_secs(10);
        let err = config.validate().unwrap_err();
        assert!(matches!(err, ConfigError::InvalidPingInterval { .. }));
    }
}
