//! Configuration types for client and server.

pub mod client;
pub mod server;

use std::fmt;

pub use client::ClientConfig;
pub use server::{ServerClient, ServerConfig};

/// Ethernet IP MTU used as the transport envelope target.
pub const ETHERNET_IP_MTU: u16 = 1500;

/// Maximum allowed TUN MTU.
///
/// This cap guarantees that a UDP-QSP `DATA` message (worst-case CID/pn sizes plus framing and
/// AEAD tag) fits inside a 1500-byte Ethernet IP MTU with IPv6+UDP outer headers.
pub const MAX_TUN_MTU: u16 = 1406;

/// Configuration validation error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigError {
    /// TUN MTU is zero or exceeds the supported maximum.
    InvalidTunMtu {
        /// Configured TUN MTU.
        tun_mtu: u16,
        /// Maximum supported TUN MTU.
        max_tun_mtu: u16,
    },
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::InvalidTunMtu {
                tun_mtu,
                max_tun_mtu,
            } => write!(
                f,
                "invalid tun_mtu {tun_mtu}; expected 1..={max_tun_mtu} so UDP-QSP fits within {ETHERNET_IP_MTU}-byte Ethernet MTU",
            ),
        }
    }
}

impl std::error::Error for ConfigError {}

/// Configuration load error combining TOML parse and semantic validation failures.
#[derive(Debug)]
pub enum ConfigLoadError {
    /// TOML parsing failed.
    ParseToml(toml::de::Error),
    /// Parsed config failed semantic validation.
    Validate(ConfigError),
}

impl fmt::Display for ConfigLoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ParseToml(err) => write!(f, "failed to parse config TOML: {err}"),
            Self::Validate(err) => write!(f, "invalid config: {err}"),
        }
    }
}

impl std::error::Error for ConfigLoadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ParseToml(err) => Some(err),
            Self::Validate(err) => Some(err),
        }
    }
}

impl From<toml::de::Error> for ConfigLoadError {
    fn from(err: toml::de::Error) -> Self {
        Self::ParseToml(err)
    }
}

impl From<ConfigError> for ConfigLoadError {
    fn from(err: ConfigError) -> Self {
        Self::Validate(err)
    }
}

/// Validate TUN MTU constraints shared by client and server.
///
/// # Errors
///
/// Returns `ConfigError::InvalidTunMtu` if `tun_mtu` is zero or above `MAX_TUN_MTU`.
pub const fn validate_tun_mtu(tun_mtu: u16) -> Result<(), ConfigError> {
    if tun_mtu == 0 || tun_mtu > MAX_TUN_MTU {
        return Err(ConfigError::InvalidTunMtu {
            tun_mtu,
            max_tun_mtu: MAX_TUN_MTU,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{ETHERNET_IP_MTU, MAX_TUN_MTU, validate_tun_mtu};
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

    #[test]
    fn validate_tun_mtu_accepts_bounds() {
        assert!(validate_tun_mtu(1).is_ok());
        assert!(validate_tun_mtu(MAX_TUN_MTU).is_ok());
    }

    #[test]
    fn validate_tun_mtu_rejects_out_of_range() {
        assert!(validate_tun_mtu(0).is_err());
        assert!(validate_tun_mtu(MAX_TUN_MTU.saturating_add(1)).is_err());
    }
}
