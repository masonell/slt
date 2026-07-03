//! Remove client command.
//!
//! Removes a client from the server configuration.

use std::path::Path;

use anyhow::{Result, bail};
use slt_core::types::ClientId;

use crate::client_id::parse_client_id;
use crate::config_io::{load_server_config, save_server_config};

/// Remove a client from the server configuration.
///
/// Deletes the client entry from server.toml. Does not revoke active sessions
/// (that would require server restart or runtime support).
///
/// # Errors
///
/// Returns an error if:
/// - The config file cannot be read or written
/// - The client ID is not found
/// - The client ID is invalid hex
pub fn remove_client(config_path: &Path, client_id: &str, quiet: bool) -> Result<()> {
    let mut config = load_server_config(config_path)?;

    // Parse client ID from hex
    let client_id_bytes = parse_client_id(client_id)?;
    let target_id = ClientId(client_id_bytes);

    // Find and remove the client
    let original_len = config.clients.len();
    config.clients.retain(|c| c.client_id != target_id);

    if config.clients.len() == original_len {
        bail!("client {client_id} not found");
    }

    // Save updated config
    save_server_config(config_path, &config)?;

    if !quiet {
        println!("Removed client: {client_id}");
        println!("Remaining clients: {}", config.clients.len());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use tempfile::NamedTempFile;

    use super::*;

    fn write_test_config_with_clients() -> NamedTempFile {
        let mut file = NamedTempFile::new().unwrap();
        let config = r#"
server_secret = "0000000000000000000000000000000000000000000000000000000000000003"

[network]
listen_tcp = "0.0.0.0:443"
listen_udp = "0.0.0.0:443"
nginx_tcp_upstream = "127.0.0.1:8080"
nginx_udp_upstream = "127.0.0.1:8080"

[tls]
tls_cert = '''-----BEGIN CERTIFICATE-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA test
-----END CERTIFICATE-----'''
tls_key = { file = "server-key.pem" }

[tun]
tun_name = "tun0"
tun_mtu = 1280
tun_ipv4 = "10.10.0.1"
tun_prefix = 24

[timing]
ping_min = "10s"
ping_max = "30s"
auth_timeout = "10s"
idle_timeout = "60s"
metrics_interval = "5m"

[[clients]]
client_id = "0102030405060708090a0b0c0d0e0f10"
pubkey_ed25519 = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
assigned_ipv4 = "10.10.0.2"
enabled = true

[[clients]]
client_id = "aabbccdd0102030405060708090a0b0c"
pubkey_ed25519 = "aabbccdd05060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
assigned_ipv4 = "10.10.0.3"
enabled = false
"#;
        file.write_all(config.as_bytes()).unwrap();
        file
    }

    #[test]
    fn remove_client_found() {
        let file = write_test_config_with_clients();

        let result = remove_client(file.path(), "0102030405060708090a0b0c0d0e0f10", true);
        assert!(result.is_ok());

        // Verify client was removed
        let config = load_server_config(file.path()).unwrap();
        assert_eq!(config.clients.len(), 1);
        assert_eq!(
            config.clients[0].client_id.to_string(),
            "aabbccdd0102030405060708090a0b0c"
        );
    }

    #[test]
    fn remove_client_with_0x_prefix() {
        let file = write_test_config_with_clients();

        let result = remove_client(file.path(), "0x0102030405060708090a0b0c0d0e0f10", true);
        assert!(result.is_ok());
    }

    #[test]
    fn remove_client_not_found() {
        let file = write_test_config_with_clients();

        let result = remove_client(file.path(), "ffffffffffffffffffffffffffffffff", true);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not found"));
    }

    #[test]
    fn remove_client_invalid_hex() {
        let file = write_test_config_with_clients();

        let result = remove_client(file.path(), "not-valid-hex!", true);
        assert!(result.is_err());
    }

    #[test]
    fn remove_last_client() {
        let file = write_test_config_with_clients();

        // Remove first client
        remove_client(file.path(), "0102030405060708090a0b0c0d0e0f10", true).unwrap();

        // Remove second client
        let result = remove_client(file.path(), "aabbccdd0102030405060708090a0b0c", true);
        assert!(result.is_ok());

        // Verify no clients remain
        let config = load_server_config(file.path()).unwrap();
        assert!(config.clients.is_empty());
    }
}
