//! Server configuration.

use std::collections::HashSet;
use std::thread;

use serde::{Deserialize, Serialize};

use super::{
    ConfigError, ConfigLoadError, DEFAULT_MAX_AUTH_INFLIGHT, DEFAULT_SESSION_QUEUE_SIZE,
    DEFAULT_UDP_NAT_MAX_ENTRIES,
};
use crate::types::{
    ServerClient, ServerNetworkConfig, ServerTimingConfig, ServerTlsConfig, ServerTransportConfig,
    SharedSecret, TunConfig,
};

/// Default UDP NAT max entries.
const fn default_udp_nat_max_entries() -> usize {
    DEFAULT_UDP_NAT_MAX_ENTRIES
}

/// Default session queue size.
const fn default_session_queue_size() -> usize {
    DEFAULT_SESSION_QUEUE_SIZE
}

/// Default concurrent TLS/AUTH handshakes for VPN-claimed TCP connections.
const fn default_max_auth_inflight() -> usize {
    DEFAULT_MAX_AUTH_INFLIGHT
}

/// Default per-worker connection budget for the TCP front door.
pub const DEFAULT_TCP_CONNECTIONS_PER_WORKER: usize = 512;

/// Default cap for TCP connections owned by the front door.
///
/// Evaluates to `DEFAULT_TCP_CONNECTIONS_PER_WORKER * available_parallelism()`.
#[must_use]
pub fn default_tcp_connection_cap() -> usize {
    thread::available_parallelism()
        .map_or(1, std::num::NonZero::get)
        .saturating_mul(DEFAULT_TCP_CONNECTIONS_PER_WORKER)
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
    /// Transport-specific settings.
    #[serde(default)]
    pub transport: ServerTransportConfig,
    /// Max number of UDP NAT peers to keep for nginx forwarding.
    #[serde(default = "default_udp_nat_max_entries")]
    pub udp_nat_max_entries: usize,
    /// Bounded queue size for per-session event channels.
    #[serde(default = "default_session_queue_size")]
    pub session_queue_size: usize,
    /// Maximum number of VPN-claimed TCP connections concurrently in TLS/AUTH.
    #[serde(default = "default_max_auth_inflight")]
    pub max_auth_inflight: usize,
    /// Maximum classifying and nginx-proxied TCP connections held by the front door.
    #[serde(default = "default_tcp_connection_cap")]
    pub tcp_connection_cap: usize,
    /// Configured client entries.
    pub clients: Vec<ServerClient>,
}

impl ServerConfig {
    /// Validate semantic constraints for a parsed server config.
    ///
    /// # Errors
    ///
    /// Returns `ConfigError` if any constraint is violated:
    /// - `ZeroPort` if a configured network endpoint uses port zero
    /// - `EmptyTunName` if `tun_name` is empty
    /// - `InvalidTunMtu` if `tun_mtu` is out of range
    /// - `InvalidTunPrefix` if `tun_prefix` is out of range
    /// - `ClientOutsideTunSubnet` if a configured client IP is outside the TUN subnet
    /// - `ClientUsesTunAddress` if a configured client IP equals `tun_ipv4`
    /// - `DuplicateClientId` if two clients share a `client_id`
    /// - `DuplicateAssignedIpv4` if two clients share an `assigned_ipv4`
    /// - `IntervalTooSmall` if a ping interval is below 1 millisecond
    /// - `InvalidPingInterval` if `ping_min` > `ping_max`
    /// - `EmptyUdpQspAllowedCiphers` if UDP-QSP has no allowed cipher suites
    /// - `ZeroSessionQueueSize` if `session_queue_size` is zero
    /// - `ZeroMaxAuthInflight` if `max_auth_inflight` is zero
    /// - `ZeroTcpConnectionCap` if `tcp_connection_cap` is zero
    /// - `ZeroUdpNatMaxEntries` if `udp_nat_max_entries` is zero
    /// - `ZeroTimeout` if any timeout is zero
    /// - `TimeoutTooLarge` if any timeout exceeds 1 hour
    pub fn validate(&self) -> Result<(), ConfigError> {
        self.network.validate()?;
        self.tun.validate()?;
        let mut seen_client_ids = HashSet::new();
        let mut seen_assigned_ipv4 = HashSet::new();
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
            if !seen_client_ids.insert(client.client_id) {
                return Err(ConfigError::DuplicateClientId {
                    client_id: client.client_id,
                });
            }
            if !seen_assigned_ipv4.insert(client.assigned_ipv4) {
                return Err(ConfigError::DuplicateAssignedIpv4 {
                    assigned_ipv4: client.assigned_ipv4,
                });
            }
        }
        self.timing.validate()?;
        self.transport.validate()?;
        if self.session_queue_size == 0 {
            return Err(ConfigError::ZeroSessionQueueSize);
        }
        if self.max_auth_inflight == 0 {
            return Err(ConfigError::ZeroMaxAuthInflight);
        }
        if self.tcp_connection_cap == 0 {
            return Err(ConfigError::ZeroTcpConnectionCap);
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
mod tests;
