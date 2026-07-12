//! TUN interface configuration shared by client and server.

use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};

use crate::config::{ConfigError, DEFAULT_TUN_MTU, MAX_TUN_MTU};

/// TUN interface configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TunConfig {
    /// TUN interface name.
    #[serde(default = "default_tun_name")]
    pub tun_name: String,
    /// TUN interface MTU.
    #[serde(default = "default_tun_mtu")]
    pub tun_mtu: u16,
    /// Local IPv4 address expected on the TUN interface.
    #[serde(default = "default_tun_ipv4")]
    pub tun_ipv4: Ipv4Addr,
    /// IPv4 overlay subnet prefix length.
    #[serde(default = "default_tun_prefix")]
    pub tun_prefix: u8,
}

fn default_tun_name() -> String {
    "tun0".to_string()
}

const fn default_tun_mtu() -> u16 {
    DEFAULT_TUN_MTU
}

const fn default_tun_ipv4() -> Ipv4Addr {
    Ipv4Addr::new(10, 10, 0, 1)
}

const fn default_tun_prefix() -> u8 {
    24
}

impl Default for TunConfig {
    fn default() -> Self {
        Self {
            tun_name: default_tun_name(),
            tun_mtu: DEFAULT_TUN_MTU,
            tun_ipv4: default_tun_ipv4(),
            tun_prefix: default_tun_prefix(),
        }
    }
}

impl TunConfig {
    /// Validate TUN configuration.
    ///
    /// # Errors
    ///
    /// Returns `ConfigError` if:
    /// - `tun_name` is empty
    /// - `tun_mtu` is zero or exceeds `MAX_TUN_MTU`
    /// - `tun_prefix` is outside `1..=32`
    pub const fn validate(&self) -> Result<(), ConfigError> {
        if self.tun_name.is_empty() {
            return Err(ConfigError::EmptyTunName);
        }
        if self.tun_mtu == 0 || self.tun_mtu > MAX_TUN_MTU {
            return Err(ConfigError::InvalidTunMtu {
                tun_mtu: self.tun_mtu,
                max_tun_mtu: MAX_TUN_MTU,
            });
        }
        if self.tun_prefix == 0 || self.tun_prefix > 32 {
            return Err(ConfigError::InvalidTunPrefix {
                tun_prefix: self.tun_prefix,
            });
        }
        Ok(())
    }

    /// Return true when `addr` belongs to this TUN overlay subnet.
    #[must_use]
    pub fn contains_ipv4(&self, addr: Ipv4Addr) -> bool {
        ipv4_network_bits(addr, self.tun_prefix)
            == ipv4_network_bits(self.tun_ipv4, self.tun_prefix)
    }
}

fn ipv4_network_bits(addr: Ipv4Addr, prefix: u8) -> u32 {
    let bits = u32::from(addr);
    let mask = match prefix {
        0 => 0,
        1..=32 => u32::MAX << (u32::BITS - u32::from(prefix)),
        _ => u32::MAX,
    };
    bits & mask
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_tun_config() -> TunConfig {
        TunConfig {
            tun_name: "tun0".to_string(),
            tun_mtu: 1280,
            tun_ipv4: Ipv4Addr::new(10, 10, 0, 1),
            tun_prefix: 24,
        }
    }

    #[test]
    fn validate_accepts_valid_config() {
        let config = test_tun_config();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn validate_rejects_empty_tun_name() {
        let mut config = test_tun_config();
        config.tun_name = String::new();
        let err = config.validate().unwrap_err();
        assert!(matches!(err, ConfigError::EmptyTunName));
    }

    #[test]
    fn validate_rejects_zero_mtu() {
        let mut config = test_tun_config();
        config.tun_mtu = 0;
        let err = config.validate().unwrap_err();
        assert!(matches!(err, ConfigError::InvalidTunMtu { .. }));
    }

    #[test]
    fn validate_rejects_mtu_too_large() {
        let mut config = test_tun_config();
        config.tun_mtu = MAX_TUN_MTU + 1;
        let err = config.validate().unwrap_err();
        assert!(matches!(err, ConfigError::InvalidTunMtu { .. }));
    }

    #[test]
    fn validate_rejects_invalid_prefix() {
        let mut config = test_tun_config();
        config.tun_prefix = 33;
        let err = config.validate().unwrap_err();
        assert!(matches!(err, ConfigError::InvalidTunPrefix { .. }));
    }

    #[test]
    fn contains_ipv4_checks_configured_subnet() {
        let config = test_tun_config();
        assert!(config.contains_ipv4(Ipv4Addr::new(10, 10, 0, 2)));
        assert!(!config.contains_ipv4(Ipv4Addr::new(10, 10, 1, 2)));
    }

    #[test]
    fn default_tun_mtu_is_canonical() {
        let config = TunConfig::default();
        assert_eq!(config.tun_mtu, 1186);
    }

    #[test]
    fn serde_defaults_tun_mtu_when_omitted() {
        let config: TunConfig = toml::from_str(r#"tun_ipv4 = "10.10.0.1""#).unwrap();
        assert_eq!(config.tun_mtu, DEFAULT_TUN_MTU);
    }

    #[test]
    fn serde_defaults_tun_name_when_omitted() {
        // Android configs omit `tun_name`; it should deserialize to the default,
        // not fail, and the result must still validate.
        let config: TunConfig = toml::from_str("tun_mtu = 1280").unwrap();
        assert_eq!(config.tun_name, "tun0");
        assert_eq!(config.tun_ipv4, Ipv4Addr::new(10, 10, 0, 1));
        assert_eq!(config.tun_prefix, 24);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn default_tun_config_validates() {
        assert!(TunConfig::default().validate().is_ok());
    }
}
