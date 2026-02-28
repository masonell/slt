//! Show client command.
//!
//! Displays detailed client information from the server's perspective.

use std::path::Path;

use anyhow::{Context, Result};
use slt_core::types::ClientId;

use crate::client_id::parse_client_id;
use crate::config_io::load_server_config;

/// Display detailed information about a specific client.
///
/// Shows client ID, public key, assigned IP, and enabled status.
///
/// # Errors
///
/// Returns an error if:
/// - The config file cannot be read or parsed
/// - The client ID is not found
/// - The client ID is invalid hex
pub fn show_client(config_path: &Path, client_id: &str, quiet: bool) -> Result<()> {
    let config = load_server_config(config_path)?;

    // Parse client ID from hex
    let client_id_bytes = parse_client_id(client_id)?;

    // Find the client
    let client = config
        .clients
        .iter()
        .find(|c| c.client_id == ClientId(client_id_bytes))
        .context(format!("client {client_id} not found"))?;

    if quiet {
        return Ok(());
    }

    println!("Client: {}", client.client_id);
    println!();
    println!(
        "Public Key: {}",
        hex::encode(client.pubkey_ed25519.as_bytes())
    );
    println!("Assigned IP: {}", client.assigned_ipv4);
    println!(
        "Status: {}",
        if client.enabled {
            "enabled"
        } else {
            "disabled"
        }
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use tempfile::NamedTempFile;

    use super::*;

    fn write_test_config() -> NamedTempFile {
        let mut file = NamedTempFile::new().unwrap();
        let config = r#"
server_secret = "0000000000000000000000000000000000000000000000000000000000000000"

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

[timing]
ping_min = "10s"
ping_max = "30s"
auth_timeout = "10s"
idle_timeout = "60s"

[[clients]]
client_id = "0102030405060708090a0b0c0d0e0f10"
pubkey_ed25519 = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
assigned_ipv4 = "10.10.0.2"
enabled = true
"#;
        file.write_all(config.as_bytes()).unwrap();
        file
    }

    #[test]
    fn show_client_found() {
        let file = write_test_config();
        let result = show_client(file.path(), "0102030405060708090a0b0c0d0e0f10", false);
        assert!(result.is_ok());
    }

    #[test]
    fn show_client_with_0x_prefix() {
        let file = write_test_config();
        let result = show_client(file.path(), "0x0102030405060708090a0b0c0d0e0f10", false);
        assert!(result.is_ok());
    }

    #[test]
    fn show_client_not_found() {
        let file = write_test_config();
        let result = show_client(file.path(), "ffffffffffffffffffffffffffffffff", false);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not found"));
    }

    #[test]
    fn show_client_invalid_hex() {
        let file = write_test_config();
        let result = show_client(file.path(), "not-valid-hex!", false);
        assert!(result.is_err());
    }

    #[test]
    fn show_client_wrong_length() {
        let file = write_test_config();
        let result = show_client(file.path(), "01020304", false);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("expected 16 bytes")
        );
    }
}
