use super::test_config;
use crate::config::server::{ServerConfig, default_tcp_connection_cap};
use crate::config::{ConfigError, ConfigLoadError};
use crate::proto::CipherSuite;
use crate::types::ServerUdpQspCipher;

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

    let err = ServerConfig::from_toml_str(&raw).unwrap_err();
    assert!(matches!(&err, ConfigLoadError::ParseToml(_)));
    let message = err.to_string();
    assert!(message.contains("unknown field"), "{message}");
    assert!(message.contains(field), "{message}");
}

#[test]
fn from_toml_accepts_empty_client_list() {
    let mut config = test_config();
    config.clients.clear();
    let raw = toml::to_string(&config).unwrap();

    let parsed = ServerConfig::from_toml_str(&raw).unwrap();

    assert!(parsed.clients.is_empty());
}

#[test]
fn serde_applies_server_defaults_when_omitted() {
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
    assert_eq!(config.udp_nat_max_entries, 1024);
    assert_eq!(config.session_queue_size, 1024);
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

#[test]
fn serde_rejects_unknown_fields_in_server_sections() {
    let cases: &[(&[&str], &str)] = &[
        (&[], "session_quee_size"),
        (&["network"], "listen_tcq"),
        (&["tls"], "tls_crt"),
        (&["tun"], "tun_mttu"),
        (&["timing"], "auth_timout"),
        (&["transport"], "udp_qspp"),
        (&["transport", "udp_qsp"], "allowed_cipher"),
    ];

    for (path, field) in cases {
        assert_unknown_field_rejected(path, field);
    }

    let mut value = serialized_test_config();
    value
        .get_mut("clients")
        .unwrap()
        .as_array_mut()
        .unwrap()
        .first_mut()
        .unwrap()
        .as_table_mut()
        .unwrap()
        .insert("assigned_ip4".to_string(), toml::Value::Boolean(true));
    let raw = toml::to_string(&value).unwrap();
    let err = ServerConfig::from_toml_str(&raw).unwrap_err();
    assert!(matches!(&err, ConfigLoadError::ParseToml(_)));
    let message = err.to_string();
    assert!(message.contains("unknown field"), "{message}");
    assert!(message.contains("assigned_ip4"), "{message}");
}

#[test]
fn serde_requires_server_tun_ipv4() {
    let mut value = serialized_test_config();
    value
        .get_mut("tun")
        .unwrap()
        .as_table_mut()
        .unwrap()
        .remove("tun_ipv4")
        .unwrap();
    let raw = toml::to_string(&value).unwrap();

    let err = ServerConfig::from_toml_str(&raw).unwrap_err();
    assert!(matches!(&err, ConfigLoadError::ParseToml(_)));
    let message = err.to_string();
    assert!(message.contains("missing field"), "{message}");
    assert!(message.contains("tun_ipv4"), "{message}");
}
