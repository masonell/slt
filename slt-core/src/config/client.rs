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
}

impl ClientConfig {
    /// Validate semantic constraints for a parsed client config.
    ///
    /// # Errors
    ///
    /// Returns `ConfigError::InvalidTunMtu` if `tun_mtu` is out of range.
    pub const fn validate(&self) -> Result<(), ConfigError> {
        validate_tun_mtu(self.tun_mtu)
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
