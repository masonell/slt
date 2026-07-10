//! Server configuration.

use std::collections::HashSet;
use std::thread;

use serde::{Deserialize, Serialize};

use super::{ConfigError, ConfigLoadError};
use crate::types::{
    ServerClient, ServerNetworkConfig, ServerTimingConfig, ServerTlsConfig, ServerTransportConfig,
    SharedSecret, TunConfig,
};

/// Default UDP NAT max entries.
const fn default_udp_nat_max_entries() -> usize {
    1024
}

/// Default session queue size.
const fn default_session_queue_size() -> usize {
    256
}

/// Default concurrent TLS/AUTH handshakes for VPN-claimed TCP connections.
const fn default_max_auth_inflight() -> usize {
    128
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
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};
    use std::time::Duration;

    use super::*;
    use crate::proto::CipherSuite;
    use crate::types::{ClientId, PubKeyEd25519, ServerUdpQspCipher, SharedSecret, TlsMaterial};

    fn test_config() -> ServerConfig {
        ServerConfig {
            server_secret: SharedSecret([0u8; 32]),
            network: ServerNetworkConfig {
                listen_tcp: SocketAddr::from(([0, 0, 0, 0], 443)),
                listen_udp: SocketAddr::from(([0, 0, 0, 0], 443)),
                nginx_tcp_upstream: SocketAddr::from(([127, 0, 0, 1], 8080)),
                nginx_udp_upstream: SocketAddr::from(([127, 0, 0, 1], 8080)),
            },
            tls: ServerTlsConfig {
                tls_cert: TlsMaterial::Pem(String::new()),
                tls_key: TlsMaterial::Pem(String::new()),
            },
            tun: TunConfig {
                tun_name: "tun0".to_string(),
                tun_mtu: 1280,
                tun_ipv4: Ipv4Addr::new(10, 10, 0, 1),
                tun_prefix: 24,
            },
            timing: ServerTimingConfig {
                ping_min: Duration::from_secs(10),
                ping_max: Duration::from_secs(20),
                auth_timeout: Duration::from_secs(10),
                tcp_write_timeout: Duration::from_secs(10),
                udp_liveness_timeout: Duration::from_secs(45),
                idle_timeout: Duration::from_mins(1),
                metrics_interval: Duration::from_mins(5),
                tcp_classification_timeout: Duration::from_secs(60),
            },
            transport: ServerTransportConfig::default(),
            udp_nat_max_entries: 1024,
            session_queue_size: 256,
            max_auth_inflight: 128,
            tcp_connection_cap: 512,
            clients: vec![ServerClient {
                client_id: ClientId([0u8; 16]),
                pubkey_ed25519: PubKeyEd25519([0u8; 32]),
                assigned_ipv4: Ipv4Addr::new(10, 10, 0, 2),
                enabled: true,
            }],
        }
    }

    #[test]
    fn validate_accepts_valid_config() {
        let config = test_config();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn validate_rejects_zero_listen_tcp_port() {
        let mut config = test_config();
        config.network.listen_tcp.set_port(0);
        let err = config.validate().unwrap_err();
        assert!(matches!(
            err,
            ConfigError::ZeroPort {
                field: "network.listen_tcp"
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
    fn validate_rejects_client_outside_tun_subnet() {
        let mut config = test_config();
        config.clients[0].assigned_ipv4 = Ipv4Addr::new(10, 10, 1, 2);
        let err = config.validate().unwrap_err();
        assert!(matches!(err, ConfigError::ClientOutsideTunSubnet { .. }));
    }

    #[test]
    fn validate_rejects_client_using_server_tun_ip() {
        let mut config = test_config();
        config.clients[0].assigned_ipv4 = config.tun.tun_ipv4;
        let err = config.validate().unwrap_err();
        assert!(matches!(err, ConfigError::ClientUsesTunAddress { .. }));
    }

    #[test]
    fn validate_rejects_duplicate_client_id() {
        let mut config = test_config();
        config.clients.push(ServerClient {
            client_id: ClientId([0u8; 16]),
            pubkey_ed25519: PubKeyEd25519([1u8; 32]),
            assigned_ipv4: Ipv4Addr::new(10, 10, 0, 3),
            enabled: true,
        });
        let err = config.validate().unwrap_err();
        assert!(matches!(err, ConfigError::DuplicateClientId { .. }));
    }

    #[test]
    fn validate_rejects_duplicate_assigned_ipv4() {
        let mut config = test_config();
        config.clients.push(ServerClient {
            client_id: ClientId([1u8; 16]),
            pubkey_ed25519: PubKeyEd25519([1u8; 32]),
            assigned_ipv4: Ipv4Addr::new(10, 10, 0, 2),
            enabled: true,
        });
        let err = config.validate().unwrap_err();
        assert!(matches!(err, ConfigError::DuplicateAssignedIpv4 { .. }));
    }

    #[test]
    fn validate_rejects_zero_session_queue_size() {
        let mut config = test_config();
        config.session_queue_size = 0;
        let err = config.validate().unwrap_err();
        assert!(matches!(err, ConfigError::ZeroSessionQueueSize));
    }

    #[test]
    fn validate_rejects_zero_max_auth_inflight() {
        let mut config = test_config();
        config.max_auth_inflight = 0;
        let err = config.validate().unwrap_err();
        assert!(matches!(err, ConfigError::ZeroMaxAuthInflight));
    }

    #[test]
    fn validate_rejects_zero_tcp_connection_cap() {
        let mut config = test_config();
        config.tcp_connection_cap = 0;
        let err = config.validate().unwrap_err();
        assert!(matches!(err, ConfigError::ZeroTcpConnectionCap));
    }

    #[test]
    fn validate_rejects_zero_udp_nat_max_entries() {
        let mut config = test_config();
        config.udp_nat_max_entries = 0;
        let err = config.validate().unwrap_err();
        assert!(matches!(err, ConfigError::ZeroUdpNatMaxEntries));
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
    fn debug_redacts_secret_material() {
        const INLINE_PRIVATE_KEY: &str =
            "-----BEGIN PRIVATE KEY----- server-secret -----END PRIVATE KEY-----";

        let mut config = test_config();
        config.server_secret = SharedSecret([0x61; 32]);
        config.tls.tls_key = TlsMaterial::Pem(INLINE_PRIVATE_KEY.to_string());

        let server_secret_bytes = format!("{:?}", config.server_secret.as_bytes());
        let server_secret_hex = hex::encode(config.server_secret.as_bytes());
        let rendered = format!("{config:?}");

        assert!(rendered.contains("SharedSecret(<redacted>)"));
        assert!(rendered.contains("Pem(<redacted>)"));
        assert!(!rendered.contains(&server_secret_bytes));
        assert!(!rendered.contains(&server_secret_hex));
        assert!(!rendered.contains(INLINE_PRIVATE_KEY));
    }

    #[test]
    fn serde_defaults_transport_allowed_ciphers_when_omitted() {
        let raw = r#"
            server_secret = { hex = "0000000000000000000000000000000000000000000000000000000000000000" }

            [network]
            listen_tcp = "0.0.0.0:443"
            listen_udp = "0.0.0.0:443"
            nginx_tcp_upstream = "127.0.0.1:8080"
            nginx_udp_upstream = "127.0.0.1:8080"

            [tls]
            tls_cert = { pem = "" }
            tls_key = { pem = "" }

            [tun]
            tun_name = "tun0"
            tun_mtu = 1280
            tun_ipv4 = "10.10.0.1"
            tun_prefix = 24

            [[clients]]
            client_id = "00000000000000000000000000000000"
            pubkey_ed25519 = "0000000000000000000000000000000000000000000000000000000000000000"
            assigned_ipv4 = "10.10.0.2"
        "#;

        let config = ServerConfig::from_toml_str(raw).unwrap();
        assert_eq!(config.max_auth_inflight, 128);
        assert_eq!(config.tcp_connection_cap, default_tcp_connection_cap());
        assert!(config.transport.udp_qsp.allows(CipherSuite::Aes128Gcm));
        assert!(
            config
                .transport
                .udp_qsp
                .allows(CipherSuite::ChaCha20Poly1305)
        );
    }

    #[test]
    fn serde_parses_udp_qsp_allowed_ciphers() {
        let raw = r#"
            server_secret = { hex = "0000000000000000000000000000000000000000000000000000000000000000" }

            [network]
            listen_tcp = "0.0.0.0:443"
            listen_udp = "0.0.0.0:443"
            nginx_tcp_upstream = "127.0.0.1:8080"
            nginx_udp_upstream = "127.0.0.1:8080"

            [tls]
            tls_cert = { pem = "" }
            tls_key = { pem = "" }

            [tun]
            tun_name = "tun0"
            tun_mtu = 1280
            tun_ipv4 = "10.10.0.1"
            tun_prefix = 24

            [transport.udp_qsp]
            allowed_ciphers = ["chacha20-poly1305"]

            [[clients]]
            client_id = "00000000000000000000000000000000"
            pubkey_ed25519 = "0000000000000000000000000000000000000000000000000000000000000000"
            assigned_ipv4 = "10.10.0.2"
        "#;

        let config = ServerConfig::from_toml_str(raw).unwrap();
        assert_eq!(
            config.transport.udp_qsp.allowed_ciphers,
            vec![ServerUdpQspCipher::ChaCha20Poly1305]
        );
    }

    #[test]
    fn serde_parses_max_auth_inflight() {
        let raw = r#"
            server_secret = { hex = "0000000000000000000000000000000000000000000000000000000000000000" }
            max_auth_inflight = 64

            [network]
            listen_tcp = "0.0.0.0:443"
            listen_udp = "0.0.0.0:443"
            nginx_tcp_upstream = "127.0.0.1:8080"
            nginx_udp_upstream = "127.0.0.1:8080"

            [tls]
            tls_cert = { pem = "" }
            tls_key = { pem = "" }

            [tun]
            tun_name = "tun0"
            tun_mtu = 1280
            tun_ipv4 = "10.10.0.1"
            tun_prefix = 24

            [[clients]]
            client_id = "00000000000000000000000000000000"
            pubkey_ed25519 = "0000000000000000000000000000000000000000000000000000000000000000"
            assigned_ipv4 = "10.10.0.2"
        "#;

        let config = ServerConfig::from_toml_str(raw).unwrap();
        assert_eq!(config.max_auth_inflight, 64);
    }

    #[test]
    fn serde_parses_tcp_connection_cap() {
        let raw = r#"
            server_secret = { hex = "0000000000000000000000000000000000000000000000000000000000000000" }
            tcp_connection_cap = 2048

            [network]
            listen_tcp = "0.0.0.0:443"
            listen_udp = "0.0.0.0:443"
            nginx_tcp_upstream = "127.0.0.1:8080"
            nginx_udp_upstream = "127.0.0.1:8080"

            [tls]
            tls_cert = { pem = "" }
            tls_key = { pem = "" }

            [tun]
            tun_name = "tun0"
            tun_mtu = 1280
            tun_ipv4 = "10.10.0.1"
            tun_prefix = 24

            [[clients]]
            client_id = "00000000000000000000000000000000"
            pubkey_ed25519 = "0000000000000000000000000000000000000000000000000000000000000000"
            assigned_ipv4 = "10.10.0.2"
        "#;

        let config = ServerConfig::from_toml_str(raw).unwrap();
        assert_eq!(config.tcp_connection_cap, 2048);
    }

    #[test]
    fn validate_rejects_empty_udp_qsp_allowed_ciphers() {
        let mut config = test_config();
        config.transport.udp_qsp.allowed_ciphers.clear();

        let err = config.validate().unwrap_err();
        assert!(matches!(err, ConfigError::EmptyUdpQspAllowedCiphers));
    }

    #[test]
    fn serde_rejects_empty_udp_qsp_allowed_ciphers() {
        let raw = r#"
            server_secret = { hex = "0000000000000000000000000000000000000000000000000000000000000000" }

            [network]
            listen_tcp = "0.0.0.0:443"
            listen_udp = "0.0.0.0:443"
            nginx_tcp_upstream = "127.0.0.1:8080"
            nginx_udp_upstream = "127.0.0.1:8080"

            [tls]
            tls_cert = { pem = "" }
            tls_key = { pem = "" }

            [tun]
            tun_name = "tun0"
            tun_mtu = 1280
            tun_ipv4 = "10.10.0.1"
            tun_prefix = 24

            [transport.udp_qsp]
            allowed_ciphers = []

            [[clients]]
            client_id = "00000000000000000000000000000000"
            pubkey_ed25519 = "0000000000000000000000000000000000000000000000000000000000000000"
            assigned_ipv4 = "10.10.0.2"
        "#;

        let err = ServerConfig::from_toml_str(raw).unwrap_err();
        assert!(matches!(
            err,
            ConfigLoadError::Validate(ConfigError::EmptyUdpQspAllowedCiphers)
        ));
    }
}
