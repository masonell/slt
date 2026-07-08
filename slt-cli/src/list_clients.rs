//! List clients command.
//!
//! Displays all registered clients with their ID, IP address, and enabled status.

use std::path::Path;

use anyhow::Result;

use crate::config_io::load_server_config;

/// List all clients registered in the server config.
///
/// Displays client ID, assigned IPv4 address, and enabled status in a table format.
///
/// # Errors
///
/// Returns an error if the config file cannot be read or parsed.
pub fn list_clients(config_path: &Path, quiet: bool) -> Result<()> {
    let config = load_server_config(config_path)?;

    if quiet {
        return Ok(());
    }

    if config.clients.is_empty() {
        println!("No clients registered.");
        return Ok(());
    }

    println!("Clients ({}):", config.clients.len());
    println!("{:<34} {:<16} STATUS", "CLIENT ID", "IP ADDRESS");
    println!("{}", "-".repeat(60));

    for client in &config.clients {
        let status = if client.enabled {
            "enabled"
        } else {
            "disabled"
        };
        println!(
            "{:<34} {:<16} {}",
            client.client_id, client.assigned_ipv4, status
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use tempfile::NamedTempFile;

    use super::*;

    fn write_test_config(clients: &str) -> NamedTempFile {
        let mut file = NamedTempFile::new().unwrap();
        let config = format!(
            r#"
server_secret = {{ hex = "0000000000000000000000000000000000000000000000000000000000000000" }}

{clients}

[network]
listen_tcp = "0.0.0.0:443"
listen_udp = "0.0.0.0:443"
nginx_tcp_upstream = "127.0.0.1:8080"
nginx_udp_upstream = "127.0.0.1:8080"

[tls.tls_cert]
pem = '''-----BEGIN CERTIFICATE-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA test
-----END CERTIFICATE-----'''

[tls.tls_key]
file = "server-key.pem"

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
"#
        );
        file.write_all(config.as_bytes()).unwrap();
        file
    }

    #[test]
    fn list_clients_empty() {
        let file = write_test_config("clients = []");
        let result = list_clients(file.path(), false);
        if let Err(ref e) = result {
            eprintln!("Error: {e:?}");
        }
        assert!(result.is_ok());
    }

    #[test]
    fn list_clients_with_clients() {
        let clients = r#"
clients = [
    { client_id = "0102030405060708090a0b0c0d0e0f10", pubkey_ed25519 = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20", assigned_ipv4 = "10.10.0.2", enabled = true },
    { client_id = "aabbccdd0102030405060708090a0b0c", pubkey_ed25519 = "aabbccdd05060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20", assigned_ipv4 = "10.10.0.3", enabled = false },
]
"#;
        let file = write_test_config(clients);
        let result = list_clients(file.path(), false);
        if let Err(ref e) = result {
            eprintln!("Error: {e:?}");
        }
        assert!(result.is_ok());
    }

    #[test]
    fn list_clients_missing_file() {
        let result = list_clients(Path::new("/nonexistent/path.toml"), false);
        assert!(result.is_err());
    }
}
