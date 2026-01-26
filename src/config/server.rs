use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

/// Per-client entry in the server allowlist.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerClient {
    /// Stable 16-byte client identifier.
    #[serde(with = "crate::config::serde_hex")]
    pub client_id: [u8; 16],
    /// Ed25519 public key used for authentication.
    #[serde(with = "crate::config::serde_hex")]
    pub pubkey_ed25519: [u8; 32],
    /// Assigned VPN IPv4 address.
    pub assigned_ipv4: Ipv4Addr,
    /// If false, the client is disabled without removing the entry.
    pub enabled: bool,
}

/// Static server configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerConfig {
    /// 32-byte secret for `ClientHello` classification.
    #[serde(with = "crate::config::serde_secret")]
    pub server_secret: [u8; 32],
    /// TCP listener for TLS-wrapped VPN traffic.
    pub listen_tcp: SocketAddr,
    /// UDP listener for QUIC-based VPN traffic.
    pub listen_udp: SocketAddr,
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
    /// UDP verification timeout.
    #[serde(with = "humantime_serde")]
    pub udp_verify_timeout: Duration,
    /// Max number of UDP NAT peers to keep for nginx forwarding.
    pub udp_nat_max_entries: usize,
    /// Configured client entries.
    pub clients: Vec<ServerClient>,
}
