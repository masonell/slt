use std::net::Ipv4Addr;
use std::time::Duration;

use super::test_config;
use crate::config::ConfigError;
use crate::types::{ClientId, PubKeyEd25519, ServerClient};

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
fn validate_rejects_empty_udp_qsp_allowed_ciphers() {
    let mut config = test_config();
    config.transport.udp_qsp.allowed_ciphers.clear();

    let err = config.validate().unwrap_err();
    assert!(matches!(err, ConfigError::EmptyUdpQspAllowedCiphers));
}
