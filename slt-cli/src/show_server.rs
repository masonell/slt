//! Server configuration display command.

use std::path::Path;

use anyhow::Result;

use crate::config_io::load_server_config;

/// Display server configuration summary.
///
/// Shows network settings, TLS configuration, TUN settings, timing, and client list.
/// Secrets (`server_secret`, TLS key content) are hidden by default unless
/// `reveal_secrets` is true.
///
/// # Errors
///
/// Returns an error if the config file cannot be read or parsed.
pub fn show_server(config_path: &Path, reveal_secrets: bool) -> Result<()> {
    let config = load_server_config(config_path)?;

    println!("Server Configuration");
    println!("====================");
    println!();

    // Server secret
    if reveal_secrets {
        println!(
            "Server Secret: {}",
            hex::encode(config.server_secret.as_bytes())
        );
    } else {
        println!("Server Secret: <hidden>");
    }
    println!();

    // Network settings
    println!("Network:");
    println!("  Listen TCP:    {}", config.network.listen_tcp);
    println!("  Listen UDP:    {}", config.network.listen_udp);
    println!("  Nginx TCP Up:  {}", config.network.nginx_tcp_upstream);
    println!("  Nginx UDP Up:  {}", config.network.nginx_udp_upstream);
    println!();

    // TLS settings
    println!("TLS:");
    match &config.tls.tls_cert {
        slt_core::types::TlsMaterial::Pem(pem) => {
            println!("  Certificate: <inline, {} bytes>", pem.len());
        }
        slt_core::types::TlsMaterial::File { file } => {
            println!("  Certificate: {}", file.display());
        }
    }
    match &config.tls.tls_key {
        slt_core::types::TlsMaterial::Pem(pem) => {
            if reveal_secrets {
                println!("  Private Key:  <inline, {} bytes>", pem.len());
            } else {
                println!("  Private Key:  <hidden>");
            }
        }
        slt_core::types::TlsMaterial::File { file } => {
            if reveal_secrets {
                println!("  Private Key:  {}", file.display());
            } else {
                println!("  Private Key:  {} <hidden>", file.display());
            }
        }
    }
    println!();

    // TUN settings
    println!("TUN:");
    println!("  Interface: {}", config.tun.tun_name);
    println!("  MTU:       {}", config.tun.tun_mtu);
    println!();

    // Timing settings
    println!("Timing:");
    println!("  Ping Min:       {:?}", config.timing.ping_min);
    println!("  Ping Max:       {:?}", config.timing.ping_max);
    println!("  Auth Timeout:   {:?}", config.timing.auth_timeout);
    println!("  Idle Timeout:   {:?}", config.timing.idle_timeout);
    println!();

    // Advanced settings
    println!("Advanced:");
    println!("  UDP NAT Entries:  {}", config.udp_nat_max_entries);
    println!("  Session Queue:    {}", config.session_queue_size);
    println!();

    // Clients
    println!("Clients ({}):", config.clients.len());
    if config.clients.is_empty() {
        println!("  (none)");
    } else {
        for client in &config.clients {
            let status = if client.enabled {
                "enabled"
            } else {
                "disabled"
            };
            println!(
                "  {} -> {} [{}]",
                client.client_id, client.assigned_ipv4, status
            );
        }
    }

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
    fn show_server_works_with_valid_config() {
        let file = write_test_config();
        let result = show_server(file.path(), false);
        assert!(result.is_ok());
    }

    #[test]
    fn show_server_reveals_secrets_when_requested() {
        let file = write_test_config();
        let result = show_server(file.path(), true);
        assert!(result.is_ok());
    }

    #[test]
    fn show_server_fails_on_missing_file() {
        let result = show_server(Path::new("/nonexistent/path.toml"), false);
        assert!(result.is_err());
    }
}
