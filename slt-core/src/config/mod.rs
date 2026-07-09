//! Configuration types for client and server.

pub mod client;
pub mod defaults;
pub mod server;
pub mod validate;

use std::time::Duration;

pub use client::ClientConfig;
pub use defaults::{
    DEFAULT_AUTH_TIMEOUT, DEFAULT_IDLE_TIMEOUT, DEFAULT_METRICS_INTERVAL, DEFAULT_PING_MAX,
    DEFAULT_PING_MIN, DEFAULT_QUIC_DISCOVERY_TIMEOUT, DEFAULT_RECONNECT_MAX, DEFAULT_RECONNECT_MIN,
    DEFAULT_REGISTER_TIMEOUT, DEFAULT_TCP_CLASSIFICATION_TIMEOUT, DEFAULT_TCP_WRITE_TIMEOUT,
    default_auth_timeout, default_idle_timeout, default_metrics_interval, default_ping_max,
    default_ping_min, default_quic_discovery_timeout, default_reconnect_max, default_reconnect_min,
    default_register_timeout, default_tcp_classification_timeout, default_tcp_write_timeout,
};
pub use server::{DEFAULT_TCP_CONNECTIONS_PER_WORKER, ServerConfig, default_tcp_connection_cap};
use thiserror::Error;
pub use validate::{validate_ping_interval, validate_timeout};

use crate::types::ClientId;

/// Maximum allowed timeout duration (1 hour).
pub const MAX_TIMEOUT: Duration = Duration::from_hours(1);

/// Ethernet IP MTU used as the transport envelope target.
pub const ETHERNET_IP_MTU: u16 = 1500;

/// Maximum allowed TUN MTU.
///
/// This cap guarantees that a UDP-QSP `DATA` message (worst-case CID/pn sizes plus framing and
/// AEAD tag) fits inside a 1500-byte Ethernet IP MTU with IPv6+UDP outer headers.
pub const MAX_TUN_MTU: u16 = 1406;

/// Configuration validation error.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
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
    /// A network port is zero.
    #[error("{field} must be greater than zero")]
    ZeroPort {
        /// Field name.
        field: &'static str,
    },
    /// TUN name is empty.
    #[error("tun_name must not be empty")]
    EmptyTunName,
    /// TUN overlay prefix is invalid.
    #[error("invalid tun_prefix {tun_prefix}; expected 1..=32")]
    InvalidTunPrefix {
        /// Configured TUN overlay prefix length.
        tun_prefix: u8,
    },
    /// Client config has a TUN IP that differs from its assigned identity IP.
    #[error("tun_ipv4 ({tun_ipv4}) must match assigned_ipv4 ({assigned_ipv4})")]
    ClientTunIpMismatch {
        /// Configured TUN interface address.
        tun_ipv4: std::net::Ipv4Addr,
        /// Assigned client identity address.
        assigned_ipv4: std::net::Ipv4Addr,
    },
    /// Server client address is outside the configured TUN subnet.
    #[error("client assigned_ipv4 {assigned_ipv4} is outside TUN subnet {tun_ipv4}/{tun_prefix}")]
    ClientOutsideTunSubnet {
        /// Client address.
        assigned_ipv4: std::net::Ipv4Addr,
        /// Server TUN interface address.
        tun_ipv4: std::net::Ipv4Addr,
        /// TUN overlay prefix length.
        tun_prefix: u8,
    },
    /// Server client address equals the server's TUN interface address.
    #[error("client assigned_ipv4 {assigned_ipv4} must not equal server tun_ipv4")]
    ClientUsesTunAddress {
        /// Client address.
        assigned_ipv4: std::net::Ipv4Addr,
    },
    /// Two configured clients share the same `client_id`.
    #[error("duplicate client_id {client_id}")]
    DuplicateClientId {
        /// Identifier claimed by more than one client.
        client_id: ClientId,
    },
    /// Two configured clients share the same `assigned_ipv4`.
    #[error("duplicate assigned_ipv4 {assigned_ipv4}")]
    DuplicateAssignedIpv4 {
        /// Address claimed by more than one client.
        assigned_ipv4: std::net::Ipv4Addr,
    },
    /// Session queue size is zero.
    #[error("session_queue_size must be greater than zero")]
    ZeroSessionQueueSize,
    /// Concurrent TLS/AUTH admission limit is zero.
    #[error("max_auth_inflight must be greater than zero")]
    ZeroMaxAuthInflight,
    /// TCP front-door connection cap is zero.
    #[error("tcp_connection_cap must be greater than zero")]
    ZeroTcpConnectionCap,
    /// UDP NAT max entries is zero.
    #[error("udp_nat_max_entries must be greater than zero")]
    ZeroUdpNatMaxEntries,
    /// Server UDP-QSP cipher allowlist is empty.
    #[error("transport.udp_qsp.allowed_ciphers must contain at least one cipher suite")]
    EmptyUdpQspAllowedCiphers,
    /// `require_udp` cannot be enabled when UDP upgrade is disabled.
    #[error("require_udp=true requires enable_upgrade=true")]
    RequireUdpNeedsUpgrade,
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
    use std::time::Duration;

    use super::{ConfigError, ConfigLoadError, ETHERNET_IP_MTU, MAX_TUN_MTU};
    use crate::crypto::udp_qsp::AEAD_TAG_LEN;
    use crate::proto::HEADER_LEN;
    use crate::types::{ClientId, MAX_DCID_LEN};

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

    // === ConfigError display tests ===

    #[test]
    fn config_error_invalid_tun_mtu_display() {
        let err = ConfigError::InvalidTunMtu {
            tun_mtu: 2000,
            max_tun_mtu: MAX_TUN_MTU,
        };
        let msg = err.to_string();
        assert!(msg.contains("invalid tun_mtu"));
        assert!(msg.contains("2000"));
        assert!(msg.contains("1406"));
    }

    #[test]
    fn config_error_invalid_ping_interval_display() {
        let err = ConfigError::InvalidPingInterval {
            ping_min: Duration::from_secs(30),
            ping_max: Duration::from_secs(10),
        };
        let msg = err.to_string();
        assert!(msg.contains("ping_min"));
        assert!(msg.contains("ping_max"));
        assert!(msg.contains("must not exceed"));
    }

    #[test]
    fn config_error_invalid_reconnect_interval_display() {
        let err = ConfigError::InvalidReconnectInterval {
            reconnect_min: Duration::from_secs(10),
            reconnect_max: Duration::from_secs(5),
        };
        let msg = err.to_string();
        assert!(msg.contains("reconnect_min"));
        assert!(msg.contains("reconnect_max"));
        assert!(msg.contains("must not exceed"));
    }

    #[test]
    fn config_error_empty_hostname_display() {
        let err = ConfigError::EmptyHostname;
        let msg = err.to_string();
        assert!(msg.contains("hostname"));
        assert!(msg.contains("empty"));
    }

    #[test]
    fn config_error_zero_port_display() {
        let err = ConfigError::ZeroPort {
            field: "network.port",
        };
        let msg = err.to_string();
        assert!(msg.contains("network.port"));
        assert!(msg.contains("greater than zero"));
    }

    #[test]
    fn config_error_empty_tun_name_display() {
        let err = ConfigError::EmptyTunName;
        let msg = err.to_string();
        assert!(msg.contains("tun_name"));
        assert!(msg.contains("empty"));
    }

    #[test]
    fn config_error_duplicate_client_id_display() {
        let err = ConfigError::DuplicateClientId {
            client_id: ClientId([0u8; 16]),
        };
        let msg = err.to_string();
        assert!(msg.contains("duplicate client_id"));
    }

    #[test]
    fn config_error_duplicate_assigned_ipv4_display() {
        let err = ConfigError::DuplicateAssignedIpv4 {
            assigned_ipv4: std::net::Ipv4Addr::new(10, 10, 0, 2),
        };
        let msg = err.to_string();
        assert!(msg.contains("duplicate assigned_ipv4"));
    }

    #[test]
    fn config_error_zero_session_queue_size_display() {
        let err = ConfigError::ZeroSessionQueueSize;
        let msg = err.to_string();
        assert!(msg.contains("session_queue_size"));
        assert!(msg.contains("greater than zero"));
    }

    #[test]
    fn config_error_zero_max_auth_inflight_display() {
        let err = ConfigError::ZeroMaxAuthInflight;
        let msg = err.to_string();
        assert!(msg.contains("max_auth_inflight"));
        assert!(msg.contains("greater than zero"));
    }

    #[test]
    fn config_error_zero_tcp_connection_cap_display() {
        let err = ConfigError::ZeroTcpConnectionCap;
        let msg = err.to_string();
        assert!(msg.contains("tcp_connection_cap"));
        assert!(msg.contains("greater than zero"));
    }

    #[test]
    fn config_error_zero_udp_nat_max_entries_display() {
        let err = ConfigError::ZeroUdpNatMaxEntries;
        let msg = err.to_string();
        assert!(msg.contains("udp_nat_max_entries"));
        assert!(msg.contains("greater than zero"));
    }

    #[test]
    fn config_error_empty_udp_qsp_allowed_ciphers_display() {
        let err = ConfigError::EmptyUdpQspAllowedCiphers;
        let msg = err.to_string();
        assert!(msg.contains("transport.udp_qsp.allowed_ciphers"));
        assert!(msg.contains("at least one"));
    }

    #[test]
    fn config_error_require_udp_needs_upgrade_display() {
        let err = ConfigError::RequireUdpNeedsUpgrade;
        let msg = err.to_string();
        assert!(msg.contains("require_udp=true"));
        assert!(msg.contains("enable_upgrade=true"));
    }

    #[test]
    fn config_error_zero_timeout_display() {
        let err = ConfigError::ZeroTimeout {
            field: "auth_timeout",
        };
        let msg = err.to_string();
        assert!(msg.contains("auth_timeout"));
        assert!(msg.contains("greater than zero"));
    }

    #[test]
    fn config_error_timeout_too_large_display() {
        let err = ConfigError::TimeoutTooLarge {
            field: "idle_timeout",
            value: Duration::from_hours(2),
            max: Duration::from_hours(1),
        };
        let msg = err.to_string();
        assert!(msg.contains("idle_timeout"));
        assert!(msg.contains("exceeds maximum"));
    }

    // === ConfigLoadError display tests ===

    #[test]
    fn config_load_error_parse_toml_display() {
        let toml_err = toml::from_str::<toml::Value>("invalid [toml").unwrap_err();
        let err = ConfigLoadError::ParseToml(toml_err);
        let msg = err.to_string();
        assert!(msg.contains("failed to parse config TOML"));
    }

    #[test]
    fn config_load_error_validate_display() {
        let err = ConfigLoadError::Validate(ConfigError::EmptyHostname);
        let msg = err.to_string();
        assert!(msg.contains("invalid config"));
        assert!(msg.contains("hostname"));
    }

    // === ConfigError error conversion tests ===

    #[test]
    fn config_error_converts_to_config_load_error() {
        let config_err = ConfigError::EmptyTunName;
        let load_err: ConfigLoadError = config_err.into();
        assert!(matches!(
            load_err,
            ConfigLoadError::Validate(ConfigError::EmptyTunName)
        ));
    }

    #[test]
    fn toml_error_converts_to_config_load_error() {
        let toml_err = toml::from_str::<toml::Value>("bad").unwrap_err();
        let load_err: ConfigLoadError = toml_err.into();
        assert!(matches!(load_err, ConfigLoadError::ParseToml(_)));
    }
}
