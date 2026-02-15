//! Configuration types for client and server.

pub mod client;
pub mod defaults;
pub mod server;
pub mod validate;

use std::time::Duration;

pub use client::ClientConfig;
pub use defaults::{
    DEFAULT_AUTH_TIMEOUT, DEFAULT_IDLE_TIMEOUT, DEFAULT_PING_MAX, DEFAULT_PING_MIN,
    DEFAULT_RECONNECT_MAX, DEFAULT_RECONNECT_MIN, DEFAULT_REGISTER_TIMEOUT, default_auth_timeout,
    default_idle_timeout, default_ping_max, default_ping_min, default_reconnect_max,
    default_reconnect_min, default_register_timeout,
};
pub use server::ServerConfig;
use thiserror::Error;
pub use validate::{validate_ping_interval, validate_timeout};

/// Maximum allowed timeout duration (1 hour).
pub const MAX_TIMEOUT: Duration = Duration::from_secs(60 * 60);

/// Ethernet IP MTU used as the transport envelope target.
pub const ETHERNET_IP_MTU: u16 = 1500;

/// Maximum allowed TUN MTU.
///
/// This cap guarantees that a UDP-QSP `DATA` message (worst-case CID/pn sizes plus framing and
/// AEAD tag) fits inside a 1500-byte Ethernet IP MTU with IPv6+UDP outer headers.
pub const MAX_TUN_MTU: u16 = 1406;

/// Configuration validation error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ConfigError {
    /// TUN MTU is zero or exceeds the supported maximum.
    #[error("invalid tun_mtu {tun_mtu}; expected 1..={max_tun_mtu}")]
    InvalidTunMtu {
        /// Configured TUN MTU.
        tun_mtu: u16,
        /// Maximum supported TUN MTU.
        max_tun_mtu: u16,
    },
    /// Ping interval minimum exceeds maximum.
    #[error("ping_min ({ping_min:?}) must not exceed ping_max ({ping_max:?})")]
    InvalidPingInterval {
        ping_min: Duration,
        ping_max: Duration,
    },
    /// Reconnect interval minimum exceeds maximum.
    #[error("reconnect_min ({reconnect_min:?}) must not exceed reconnect_max ({reconnect_max:?})")]
    InvalidReconnectInterval {
        reconnect_min: Duration,
        reconnect_max: Duration,
    },
    /// Hostname is empty.
    #[error("hostname must not be empty")]
    EmptyHostname,
    /// TUN name is empty.
    #[error("tun_name must not be empty")]
    EmptyTunName,
    /// Session queue size is zero.
    #[error("session_queue_size must be greater than zero")]
    ZeroSessionQueueSize,
    /// UDP NAT max entries is zero.
    #[error("udp_nat_max_entries must be greater than zero")]
    ZeroUdpNatMaxEntries,
    /// A timeout field is zero.
    #[error("{field} must be greater than zero")]
    ZeroTimeout {
        /// Field name.
        field: &'static str,
    },
    /// A timeout field exceeds the maximum.
    #[error("{field} ({value:?}) exceeds maximum ({max:?})")]
    TimeoutTooLarge {
        /// Field name.
        field: &'static str,
        /// Configured value.
        value: Duration,
        /// Maximum allowed value.
        max: Duration,
    },
}

/// Configuration load error combining TOML parse and semantic validation failures.
#[derive(Debug, Error)]
pub enum ConfigLoadError {
    /// TOML parsing failed.
    #[error("failed to parse config TOML: {0}")]
    ParseToml(#[from] toml::de::Error),
    /// Parsed config failed semantic validation.
    #[error("invalid config: {0}")]
    Validate(#[from] ConfigError),
}

#[cfg(test)]
mod tests {
    use super::{ETHERNET_IP_MTU, MAX_TUN_MTU};
    use crate::crypto::udp_qsp::AEAD_TAG_LEN;
    use crate::proto::HEADER_LEN;
    use crate::types::MAX_DCID_LEN;

    #[test]
    fn max_tun_mtu_budget_is_stable() {
        const IPV6_HEADER_LEN: usize = 40;
        const UDP_HEADER_LEN: usize = 8;
        const QSP_PACKET_HEADER_MAX_LEN: usize = 1 + MAX_DCID_LEN + 4;
        const UDP_QSP_WRAPPER_OVERHEAD: usize =
            QSP_PACKET_HEADER_MAX_LEN + AEAD_TAG_LEN + HEADER_LEN;
        let calculated = ETHERNET_IP_MTU as usize
            - (IPV6_HEADER_LEN + UDP_HEADER_LEN)
            - UDP_QSP_WRAPPER_OVERHEAD;

        assert_eq!(MAX_TUN_MTU, 1406);
        assert_eq!(usize::from(MAX_TUN_MTU), calculated);
    }
}
