//! Show client config command.
//!
//! Reconstructs and outputs a complete client.toml from server data.

use std::path::Path;

use anyhow::{Context, Result};
use slt_core::types::{ClientId, PrivKeyEd25519};

use crate::cert::extract_domain_from_cert;
use crate::client_config::build_client_config;
use crate::client_id::parse_client_id;
use crate::config_io::{load_server_config, read_cert_content};

/// Output complete client configuration to stdout.
///
/// Reconstructs a client.toml from the server's client entry. The output
/// includes a placeholder private key (all zeros) since the server only
/// stores the public key.
///
/// The domain is extracted from the server certificate if not provided.
/// The server certificate (not CA) is embedded for certificate pinning.
///
/// # Errors
///
/// Returns an error if:
/// - The config file cannot be read or parsed
/// - The client ID is not found
/// - The client ID is invalid hex
/// - Domain cannot be extracted from certificate and wasn't provided
pub fn show_client_config(
    config_path: &Path,
    client_id: &str,
    domain: Option<&str>,
    quiet: bool,
) -> Result<()> {
    let config = load_server_config(config_path)?;

    let client_id_bytes = parse_client_id(client_id)?;

    let client = config
        .clients
        .iter()
        .find(|c| c.client_id == ClientId(client_id_bytes))
        .context(format!("client {client_id} not found"))?;

    let cert_pem = read_cert_content(config_path, &config.tls.tls_cert)?;

    let domain = if let Some(d) = domain {
        d.to_string()
    } else {
        extract_domain_from_cert(&cert_pem)?
    };

    let client_config = build_client_config(
        config.server_secret,
        client.client_id,
        PrivKeyEd25519([0u8; 32]), // Placeholder - server doesn't store privkey
        client.assigned_ipv4,
        &domain,
        &cert_pem,
        &config.tun,
    );

    if quiet {
        return Ok(());
    }

    println!("# WARNING: Private key is a PLACEHOLDER (all zeros).");
    println!("# Replace privkey_ed25519 with the original key from client creation.");
    println!();
    let toml =
        toml::to_string_pretty(&client_config).context("failed to serialize client config")?;
    println!("{toml}");

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use rcgen::{CertificateParams, DnType, KeyPair, SanType};
    use tempfile::NamedTempFile;

    use super::*;

    fn write_test_config_with_cert(cert_pem: &str) -> NamedTempFile {
        let mut file = NamedTempFile::new().unwrap();
        let config = format!(
            r#"
server_secret = {{ hex = "0000000000000000000000000000000000000000000000000000000000000002" }}

[network]
listen_tcp = "0.0.0.0:443"
listen_udp = "0.0.0.0:443"
nginx_tcp_upstream = "127.0.0.1:8080"
nginx_udp_upstream = "127.0.0.1:8080"

[tls.tls_cert]
pem = '''{cert_pem}'''

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

[[clients]]
client_id = "0102030405060708090a0b0c0d0e0f10"
pubkey_ed25519 = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
assigned_ipv4 = "10.10.0.2"
enabled = true
"#
        );
        file.write_all(config.as_bytes()).unwrap();
        file
    }

    fn write_test_config() -> NamedTempFile {
        write_test_config_with_cert(
            "-----BEGIN CERTIFICATE-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA test\n-----END CERTIFICATE-----",
        )
    }

    fn test_cert_pem(cn: &str, sans: &[&str]) -> String {
        let mut params = CertificateParams::default();
        params.distinguished_name.push(DnType::CommonName, cn);
        params.subject_alt_names = sans
            .iter()
            .map(|name| SanType::DnsName((*name).try_into().unwrap()))
            .collect();

        let key_pair = KeyPair::generate().unwrap();
        params.self_signed(&key_pair).unwrap().pem()
    }

    #[test]
    fn show_client_config_with_domain() {
        let file = write_test_config();
        let result = show_client_config(
            file.path(),
            "0102030405060708090a0b0c0d0e0f10",
            Some("vpn.example.com"),
            false,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn show_client_config_extracts_domain_from_cert() {
        let cert_pem = test_cert_pem("unused.example.com", &["vpn.example.com"]);
        let file = write_test_config_with_cert(&cert_pem);
        let result =
            show_client_config(file.path(), "0102030405060708090a0b0c0d0e0f10", None, true);
        assert!(result.is_ok());
    }

    #[test]
    fn show_client_config_rejects_wildcard_domain_from_cert() {
        let cert_pem = test_cert_pem("unused.example.com", &["*.example.com"]);
        let file = write_test_config_with_cert(&cert_pem);
        let result =
            show_client_config(file.path(), "0102030405060708090a0b0c0d0e0f10", None, true);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("wildcard"));
    }

    #[test]
    fn show_client_config_not_found() {
        let file = write_test_config();
        let result = show_client_config(
            file.path(),
            "ffffffffffffffffffffffffffffffff",
            Some("example.com"),
            false,
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not found"));
    }

    #[test]
    fn show_client_config_invalid_id() {
        let file = write_test_config();
        let result = show_client_config(file.path(), "invalid", Some("example.com"), false);
        assert!(result.is_err());
    }
}
