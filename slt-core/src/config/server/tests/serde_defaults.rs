use super::test_config;
use crate::config::server::{ServerConfig, default_tcp_connection_cap};
use crate::config::{ConfigError, ConfigLoadError};
use crate::proto::CipherSuite;
use crate::types::ServerUdpQspCipher;

#[test]
fn from_toml_accepts_empty_client_list() {
    let mut config = test_config();
    config.clients.clear();
    let raw = toml::to_string(&config).unwrap();

    let parsed = ServerConfig::from_toml_str(&raw).unwrap();

    assert!(parsed.clients.is_empty());
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
