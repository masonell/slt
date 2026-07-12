use slt_core::config::{ClientConfig, ServerConfig};

const SERVER_EXAMPLE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../docs/examples/server.toml"
));
const CLIENT_EXAMPLE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../docs/examples/client.toml"
));

#[test]
fn canonical_server_example_parses_and_validates() {
    let config = ServerConfig::from_toml_str(SERVER_EXAMPLE).unwrap();

    assert_eq!(config.clients.len(), 1);
    assert_eq!(config.tun.tun_mtu, 1186);
}

#[test]
fn canonical_client_example_parses_and_enables_upgrade() {
    let config = ClientConfig::from_toml_str(CLIENT_EXAMPLE).unwrap();

    assert!(config.enable_upgrade);
    assert!(!config.require_udp);
    assert_eq!(config.tun.tun_mtu, 1186);
}
