use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use std::time::Duration;

/// Preferences for connection upgrade/fallback timing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpgradePreferences {
    /// Minimum delay before attempting an upgrade.
    #[serde(with = "humantime_serde")]
    pub min_delay: Duration,
    /// Maximum delay before attempting an upgrade.
    #[serde(with = "humantime_serde")]
    pub max_delay: Duration,
}

/// Static client configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientConfig {
    /// Server address (host:port or name:port).
    pub server_addr: String,
    /// Stable 16-byte client identifier.
    #[serde(with = "crate::config::serde_hex")]
    pub client_id: [u8; 16],
    /// Assigned VPN IPv4 address.
    pub assigned_ipv4: Ipv4Addr,
    /// Ed25519 private key used for authentication.
    #[serde(with = "crate::config::serde_hex")]
    pub privkey_ed25519: [u8; 32],
    /// TUN interface name.
    pub tun_name: String,
    /// TUN interface MTU.
    pub tun_mtu: u16,
    /// Optional upgrade/fallback preferences.
    pub upgrade: Option<UpgradePreferences>,
}
