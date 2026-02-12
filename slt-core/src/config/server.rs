use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use super::{ConfigError, ConfigLoadError, validate_tun_mtu};
use crate::types::{ClientId, PubKeyEd25519, SharedSecret, TlsMaterial};

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
    pub enabled: bool,
}

/// Static server configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Pre-shared secret for `ClientHello` classification.
    pub server_secret: SharedSecret,
    /// TCP listener for TLS-wrapped VPN traffic.
    pub listen_tcp: SocketAddr,
    /// UDP listener for QUIC-based VPN traffic.
    pub listen_udp: SocketAddr,
    /// TLS certificate chain (PEM) or file reference for server auth.
    pub tls_cert: TlsMaterial,
    /// TLS private key (PEM) or file reference for server auth.
    pub tls_key: TlsMaterial,
    /// Nginx TCP upstream address for pass-through traffic.
    pub nginx_tcp_upstream: SocketAddr,
    /// Nginx UDP upstream address for pass-through traffic.
    pub nginx_udp_upstream: SocketAddr,
    /// TUN interface name.
    pub tun_name: String,
    /// TUN interface MTU.
    pub tun_mtu: u16,
    /// Minimum ping interval.
    #[serde(with = "humantime_serde")]
    pub ping_min: Duration,
    /// Maximum ping interval.
    #[serde(with = "humantime_serde")]
    pub ping_max: Duration,
    /// Authentication timeout.
    #[serde(with = "humantime_serde")]
    pub auth_timeout: Duration,
    /// Idle connection timeout.
    #[serde(with = "humantime_serde")]
    pub idle_timeout: Duration,
    /// Max number of UDP NAT peers to keep for nginx forwarding.
    pub udp_nat_max_entries: usize,
    /// Bounded queue size for per-session event channels.
    #[serde(default = "default_session_queue_size")]
    pub session_queue_size: usize,
    /// Configured client entries.
    pub clients: Vec<ServerClient>,
}

const fn default_session_queue_size() -> usize {
    256
}

impl ServerConfig {
    /// Validate semantic constraints for a parsed server config.
    ///
    /// # Errors
    ///
    /// Returns `ConfigError::InvalidTunMtu` if `tun_mtu` is out of range.
    pub const fn validate(&self) -> Result<(), ConfigError> {
        validate_tun_mtu(self.tun_mtu)
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
