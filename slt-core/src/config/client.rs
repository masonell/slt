//! Client configuration.

use serde::{Deserialize, Serialize};

use super::{ConfigError, ConfigLoadError};
use crate::types::{
    ClientIdentity, ClientNetworkConfig, ClientTimingConfig, ClientTlsConfig,
    ClientTransportConfig, TunConfig,
};

const fn default_enable_upgrade() -> bool {
    true
}

/// Static client configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientConfig {
    /// Network settings (hostname, port, IP override).
    pub network: ClientNetworkConfig,
    /// TLS configuration.
    pub tls: ClientTlsConfig,
    /// Client identity and credentials.
    pub identity: ClientIdentity,
    /// TUN interface settings.
    pub tun: TunConfig,
    /// Transport-specific settings.
    #[serde(default)]
    pub transport: ClientTransportConfig,
    /// Enable QUIC DCID discovery and UDP-QSP upgrade.
    #[serde(default = "default_enable_upgrade")]
    pub enable_upgrade: bool,
    /// Require UDP upgrade success; if upgrade times out, fail the session.
    #[serde(default)]
    pub require_udp: bool,
    /// Timing configuration.
    #[serde(default)]
    pub timing: ClientTimingConfig,
}

impl ClientConfig {
    /// Validate semantic constraints for a parsed client config.
    ///
    /// # Errors
    ///
    /// Returns `ConfigError` if any constraint is violated:
    /// - `EmptyHostname` if `hostname` is empty
    /// - `ZeroPort` if `network.port` is zero
    /// - `EmptyTunName` if `tun_name` is empty
    /// - `InvalidTunMtu` if `tun_mtu` is out of range
    /// - `InvalidTunPrefix` if `tun_prefix` is out of range
    /// - `ClientTunIpMismatch` if `tun_ipv4` differs from `assigned_ipv4`
    /// - `IntervalTooSmall` if a ping or reconnect interval is below 1 millisecond
    /// - `InvalidPingInterval` if `ping_min` > `ping_max`
    /// - `InvalidReconnectInterval` if `reconnect_min` > `reconnect_max`
    /// - `RequireUdpNeedsUpgrade` if `require_udp` is true but `enable_upgrade` is false
    /// - `ZeroTimeout` if any timeout is zero
    /// - `TimeoutTooLarge` if any timeout exceeds 1 hour
    pub fn validate(&self) -> Result<(), ConfigError> {
        self.network.validate()?;
        self.tun.validate()?;
        if self.tun.tun_ipv4 != self.identity.assigned_ipv4 {
            return Err(ConfigError::ClientTunIpMismatch {
                tun_ipv4: self.tun.tun_ipv4,
                assigned_ipv4: self.identity.assigned_ipv4,
            });
        }
        self.timing.validate()?;
        if self.require_udp && !self.enable_upgrade {
            return Err(ConfigError::RequireUdpNeedsUpgrade);
        }
        Ok(())
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

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::time::Duration;

    use super::*;
    use crate::types::{
        ClientId, ClientTransportConfig, ClientUdpQspCipher, PrivKeyEd25519, SharedSecret,
        TlsMaterial,
    };

    fn test_config() -> ClientConfig {
        ClientConfig {
            network: ClientNetworkConfig {
                hostname: "example.com".to_string(),
                port: 443,
                ip: None,
            },
            tls: ClientTlsConfig {
                tls_ca: TlsMaterial::Pem(String::new()),
                quic_ca: None,
            },
            identity: ClientIdentity {
                client_id: ClientId([0u8; 16]),
                shared_secret: SharedSecret([0u8; 32]),
                assigned_ipv4: Ipv4Addr::new(10, 10, 0, 2),
                privkey_ed25519: PrivKeyEd25519([0u8; 32]),
            },
            tun: TunConfig {
                tun_name: "tun0".to_string(),
                tun_mtu: 1280,
                tun_ipv4: Ipv4Addr::new(10, 10, 0, 2),
                tun_prefix: 24,
            },
            transport: ClientTransportConfig::default(),
            enable_upgrade: false,
            require_udp: false,
            timing: ClientTimingConfig {
                ping_min: Duration::from_secs(10),
                ping_max: Duration::from_secs(20),
                auth_timeout: Duration::from_secs(10),
                tcp_write_timeout: Duration::from_secs(10),
                register_timeout: Duration::from_secs(10),
                quic_discovery_timeout: Duration::from_secs(15),
                udp_liveness_timeout: Duration::from_secs(45),
                idle_timeout: Duration::from_mins(1),
                metrics_interval: Duration::from_mins(5),
                reconnect_min: Duration::from_millis(200),
                reconnect_max: Duration::from_secs(5),
            },
        }
    }

    fn serialized_test_config() -> toml::Value {
        let raw = toml::to_string(&test_config()).unwrap();
        toml::from_str(&raw).unwrap()
    }

    fn insert_unknown_field(value: &mut toml::Value, path: &[&str], field: &str) {
        let mut current = value;
        for key in path {
            current = current.as_table_mut().unwrap().get_mut(*key).unwrap();
        }
        current
            .as_table_mut()
            .unwrap()
            .insert(field.to_string(), toml::Value::Boolean(true));
    }

    fn assert_unknown_field_rejected(path: &[&str], field: &str) {
        let mut value = serialized_test_config();
        insert_unknown_field(&mut value, path, field);
        let raw = toml::to_string(&value).unwrap();

        let err = ClientConfig::from_toml_str(&raw).unwrap_err();
        assert!(matches!(&err, ConfigLoadError::ParseToml(_)));
        let message = err.to_string();
        assert!(message.contains("unknown field"), "{message}");
        assert!(message.contains(field), "{message}");
    }

    #[test]
    fn validate_accepts_valid_config() {
        let config = test_config();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn validate_rejects_empty_hostname() {
        let mut config = test_config();
        config.network.hostname = String::new();
        let err = config.validate().unwrap_err();
        assert!(matches!(err, ConfigError::EmptyHostname));
    }

    #[test]
    fn validate_rejects_zero_network_port() {
        let mut config = test_config();
        config.network.port = 0;
        let err = config.validate().unwrap_err();
        assert!(matches!(
            err,
            ConfigError::ZeroPort {
                field: "network.port"
            }
        ));
    }

    #[test]
    fn validate_rejects_empty_tun_name() {
        let mut config = test_config();
        config.tun.tun_name = String::new();
        let err = config.validate().unwrap_err();
        assert!(matches!(err, ConfigError::EmptyTunName));
    }

    #[test]
    fn validate_rejects_tun_ip_identity_mismatch() {
        let mut config = test_config();
        config.tun.tun_ipv4 = Ipv4Addr::new(10, 10, 0, 3);
        let err = config.validate().unwrap_err();
        assert!(matches!(err, ConfigError::ClientTunIpMismatch { .. }));
    }

    #[test]
    fn validate_rejects_ping_min_greater_than_max() {
        let mut config = test_config();
        config.timing.ping_min = Duration::from_secs(30);
        config.timing.ping_max = Duration::from_secs(10);
        let err = config.validate().unwrap_err();
        assert!(matches!(err, ConfigError::InvalidPingInterval { .. }));
    }

    #[test]
    fn validate_rejects_reconnect_min_greater_than_max() {
        let mut config = test_config();
        config.timing.reconnect_min = Duration::from_secs(10);
        config.timing.reconnect_max = Duration::from_millis(100);
        let err = config.validate().unwrap_err();
        assert!(matches!(err, ConfigError::InvalidReconnectInterval { .. }));
    }

    #[test]
    fn validate_rejects_require_udp_without_upgrade() {
        let mut config = test_config();
        config.enable_upgrade = false;
        config.require_udp = true;
        let err = config.validate().unwrap_err();
        assert!(matches!(err, ConfigError::RequireUdpNeedsUpgrade));
    }

    #[test]
    fn debug_redacts_secret_material() {
        const INLINE_PRIVATE_KEY: &str =
            "-----BEGIN PRIVATE KEY----- client-secret -----END PRIVATE KEY-----";

        let mut config = test_config();
        config.tls.tls_ca = TlsMaterial::Pem(INLINE_PRIVATE_KEY.to_string());
        config.identity.shared_secret = SharedSecret([0x51; 32]);
        config.identity.privkey_ed25519 = PrivKeyEd25519([0x52; 32]);

        let shared_secret_bytes = format!("{:?}", config.identity.shared_secret.as_bytes());
        let shared_secret_hex = hex::encode(config.identity.shared_secret.as_bytes());
        let privkey_bytes = format!("{:?}", config.identity.privkey_ed25519.as_bytes());
        let privkey_hex = hex::encode(config.identity.privkey_ed25519.as_bytes());
        let rendered = format!("{config:?}");

        assert!(rendered.contains("SharedSecret(<redacted>)"));
        assert!(rendered.contains("PrivKeyEd25519(<redacted>)"));
        assert!(rendered.contains("Pem(<redacted>)"));
        assert!(!rendered.contains(&shared_secret_bytes));
        assert!(!rendered.contains(&shared_secret_hex));
        assert!(!rendered.contains(&privkey_bytes));
        assert!(!rendered.contains(&privkey_hex));
        assert!(!rendered.contains(INLINE_PRIVATE_KEY));
    }

    #[test]
    fn serde_applies_optional_defaults_when_omitted() {
        let raw = r#"
            [network]
            hostname = "example.com"
            port = 443

            [tls]
            tls_ca = { pem = "" }

            [identity]
            client_id = "00000000000000000000000000000000"
            shared_secret = { hex = "0000000000000000000000000000000000000000000000000000000000000000" }
            assigned_ipv4 = "10.10.0.2"
            privkey_ed25519 = { hex = "0000000000000000000000000000000000000000000000000000000000000000" }

            [tun]
            tun_mtu = 1280
            tun_ipv4 = "10.10.0.2"
            tun_prefix = 24
        "#;

        let config = ClientConfig::from_toml_str(raw).unwrap();
        assert_eq!(config.transport.udp_qsp.cipher, ClientUdpQspCipher::Auto);
        assert!(config.enable_upgrade);
        assert!(!config.require_udp);
        assert_eq!(config.tun.tun_name, "tun0");
    }

    #[test]
    fn serde_parses_udp_qsp_cipher_selection() {
        let raw = r#"
            [network]
            hostname = "example.com"
            port = 443

            [tls]
            tls_ca = { pem = "" }

            [identity]
            client_id = "00000000000000000000000000000000"
            shared_secret = { hex = "0000000000000000000000000000000000000000000000000000000000000000" }
            assigned_ipv4 = "10.10.0.2"
            privkey_ed25519 = { hex = "0000000000000000000000000000000000000000000000000000000000000000" }

            [tun]
            tun_name = "tun0"
            tun_mtu = 1280
            tun_ipv4 = "10.10.0.2"
            tun_prefix = 24

            [transport.udp_qsp]
            cipher = "chacha20-poly1305"
        "#;

        let config = ClientConfig::from_toml_str(raw).unwrap();
        assert_eq!(
            config.transport.udp_qsp.cipher,
            ClientUdpQspCipher::ChaCha20Poly1305
        );
    }

    #[test]
    fn serde_rejects_unknown_fields_in_client_sections() {
        let cases: &[(&[&str], &str)] = &[
            (&[], "enable_upgarde"),
            (&["network"], "hostnmae"),
            (&["tls"], "tls_caa"),
            (&["identity"], "client_iid"),
            (&["tun"], "tun_mttu"),
            (&["timing"], "ping_miin"),
            (&["transport"], "udp_qspp"),
            (&["transport", "udp_qsp"], "cipheer"),
        ];

        for (path, field) in cases {
            assert_unknown_field_rejected(path, field);
        }
    }

    #[test]
    fn serde_rejects_root_setting_misplaced_under_tun() {
        let mut value = serialized_test_config();
        let enable_upgrade = value
            .as_table_mut()
            .unwrap()
            .remove("enable_upgrade")
            .unwrap();
        value
            .get_mut("tun")
            .unwrap()
            .as_table_mut()
            .unwrap()
            .insert("enable_upgrade".to_string(), enable_upgrade);
        let raw = toml::to_string(&value).unwrap();

        let err = ClientConfig::from_toml_str(&raw).unwrap_err();
        assert!(matches!(&err, ConfigLoadError::ParseToml(_)));
        let message = err.to_string();
        assert!(message.contains("unknown field"), "{message}");
        assert!(message.contains("enable_upgrade"), "{message}");
    }

    #[test]
    fn serde_requires_client_tun_ipv4() {
        let mut value = serialized_test_config();
        value
            .get_mut("tun")
            .unwrap()
            .as_table_mut()
            .unwrap()
            .remove("tun_ipv4")
            .unwrap();
        let raw = toml::to_string(&value).unwrap();

        let err = ClientConfig::from_toml_str(&raw).unwrap_err();
        assert!(matches!(&err, ConfigLoadError::ParseToml(_)));
        let message = err.to_string();
        assert!(message.contains("missing field"), "{message}");
        assert!(message.contains("tun_ipv4"), "{message}");
    }
}
