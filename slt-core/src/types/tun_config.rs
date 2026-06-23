//! TUN interface configuration shared by client and server.

use serde::{Deserialize, Serialize};

use crate::config::{ConfigError, MAX_TUN_MTU};

/// TUN interface configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TunConfig {
    /// TUN interface name.
    #[serde(default = "default_tun_name")]
    pub tun_name: String,
    /// TUN interface MTU.
    #[serde(default = "default_tun_mtu")]
    pub tun_mtu: u16,
}

fn default_tun_name() -> String {
    "tun0".to_string()
}

const fn default_tun_mtu() -> u16 {
    1280
}

impl Default for TunConfig {
    fn default() -> Self {
        Self {
            tun_name: default_tun_name(),
            tun_mtu: default_tun_mtu(),
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
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_tun_config() -> TunConfig {
        TunConfig {
            tun_name: "tun0".to_string(),
            tun_mtu: 1280,
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
    fn default_tun_mtu_is_valid() {
        let config = TunConfig::default();
        assert!(config.tun_mtu > 0);
        assert!(config.tun_mtu <= MAX_TUN_MTU);
    }

    #[test]
    fn serde_defaults_tun_name_when_omitted() {
        // Android configs omit `tun_name`; it should deserialize to the default,
        // not fail, and the result must still validate.
        let config: TunConfig = toml::from_str("tun_mtu = 1280").unwrap();
        assert_eq!(config.tun_name, "tun0");
        assert!(config.validate().is_ok());
    }

    #[test]
    fn default_tun_config_validates() {
        assert!(TunConfig::default().validate().is_ok());
    }
}
