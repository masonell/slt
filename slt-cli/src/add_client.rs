//! Add client command.
//!
//! Generates a new client configuration with Ed25519 keypair, assigns the specified
//! IP address, and updates the server configuration.

use std::fs;
use std::net::Ipv4Addr;
use std::path::Path;

use anyhow::{Context, Result, bail};
use ed25519_dalek::SigningKey;
use rand::RngCore;
use rand::rngs::OsRng;
use slt_core::types::{ClientId, PrivKeyEd25519, PubKeyEd25519, ServerClient};

use crate::cert::extract_domain_from_cert;
use crate::client_config::build_client_config;
use crate::config_io::{
    load_server_config, read_cert_content, save_client_config, save_server_config,
};

/// Add a new client to the server configuration.
///
/// Generates an Ed25519 keypair, creates a unique client ID, assigns the specified
/// IP address, and writes a client config file.
///
/// # Errors
///
/// Returns an error if:
/// - The server config cannot be read or written
/// - The output directory cannot be created
/// - The specified IP is invalid or already in use
/// - A client ID collision occurs (extremely unlikely)
/// - Domain cannot be extracted from certificate and wasn't provided
pub fn add_client(
    config_path: &Path,
    output_dir: &Path,
    domain: Option<&str>,
    ip: &str,
    quiet: bool,
) -> Result<()> {
    let mut config = load_server_config(config_path)?;

    // Parse and validate IP address
    let assigned_ipv4: Ipv4Addr = ip
        .parse()
        .with_context(|| format!("invalid IP address: {ip}"))?;

    // Check if IP is already in use
    if config
        .clients
        .iter()
        .any(|c| c.assigned_ipv4 == assigned_ipv4)
    {
        bail!("IP address {assigned_ipv4} is already assigned to another client");
    }

    // Read server certificate content and determine domain BEFORE modifying config
    // This ensures we fail early if cert is unreadable or domain can't be extracted
    let cert_pem = read_cert_content(config_path, &config.tls.tls_cert)?;
    let domain = if let Some(d) = domain {
        d.to_string()
    } else {
        extract_domain_from_cert(&cert_pem)?
    };

    // Generate client ID (16 random bytes)
    let mut client_id_bytes = [0u8; 16];
    OsRng.fill_bytes(&mut client_id_bytes);
    let client_id = ClientId(client_id_bytes);

    // Check for client ID collision (extremely unlikely but defensive)
    if config.clients.iter().any(|c| c.client_id == client_id) {
        bail!("client ID collision detected (extremely unlikely, please try again)");
    }

    // Generate Ed25519 keypair
    let mut key_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut key_bytes);
    let signing_key = SigningKey::from_bytes(&key_bytes);
    let verifying_key = signing_key.verifying_key();

    let privkey = PrivKeyEd25519(signing_key.to_bytes());
    let pubkey = PubKeyEd25519(verifying_key.to_bytes());

    // Build client config with embedded server cert (certificate pinning)
    let client_config = build_client_config(
        config.server_secret,
        client_id,
        privkey,
        assigned_ipv4,
        &domain,
        &cert_pem,
        &config.tun,
    );

    // Create output directory if needed
    if !output_dir.exists() {
        fs::create_dir_all(output_dir).with_context(|| {
            format!("failed to create output directory {}", output_dir.display())
        })?;
    }

    // Write client config file FIRST - if this fails, server config is unchanged
    let client_filename = format!("client-{client_id}.toml");
    let client_path = output_dir.join(&client_filename);
    save_client_config(&client_path, &client_config)?;

    // Now update server config
    let server_client = ServerClient {
        client_id,
        pubkey_ed25519: pubkey,
        assigned_ipv4,
        enabled: true,
    };
    config.clients.push(server_client);
    save_server_config(config_path, &config)?;

    if !quiet {
        println!("Added client: {client_id}");
        println!("  Assigned IP: {assigned_ipv4}");
        println!("  Config file: {}", client_path.display());
        println!();
        println!("Public key (for reference):");
        println!("  {}", hex::encode(pubkey.as_bytes()));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::Write;

    use rcgen::{CertificateParams, DnType, KeyPair, SanType};
    use slt_core::config::ClientConfig;
    use tempfile::{NamedTempFile, TempDir};

    use super::*;

    fn write_test_config_with_cert(cert_pem: &str) -> NamedTempFile {
        let mut file = NamedTempFile::new().unwrap();
        let config = format!(
            r#"
server_secret = "0000000000000000000000000000000000000000000000000000000000000001"
clients = []

[network]
listen_tcp = "0.0.0.0:443"
listen_udp = "0.0.0.0:443"
nginx_tcp_upstream = "127.0.0.1:8080"
nginx_udp_upstream = "127.0.0.1:8080"

[tls]
tls_cert = '''{cert_pem}'''
tls_key = {{ file = "server-key.pem" }}

[tun]
tun_name = "tun0"
tun_mtu = 1280

[timing]
ping_min = "10s"
ping_max = "30s"
auth_timeout = "10s"
idle_timeout = "60s"
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
    fn add_client_with_domain() {
        let file = write_test_config();
        let output_dir = TempDir::new().unwrap();

        let result = add_client(
            file.path(),
            output_dir.path(),
            Some("vpn.example.com"),
            "10.10.0.100",
            true,
        );
        if let Err(ref e) = result {
            eprintln!("Error: {e:?}");
        }
        assert!(result.is_ok());

        let config = load_server_config(file.path()).unwrap();
        assert_eq!(config.clients.len(), 1);
        assert_eq!(
            config.clients[0].assigned_ipv4,
            Ipv4Addr::new(10, 10, 0, 100)
        );
    }

    #[test]
    fn add_client_duplicate_ip() {
        let file = write_test_config();
        let output_dir = TempDir::new().unwrap();

        // Add first client with specific IP
        let result = add_client(
            file.path(),
            output_dir.path(),
            Some("vpn.example.com"),
            "10.10.0.50",
            true,
        );
        assert!(result.is_ok());

        // Try to add second client with same IP
        let result = add_client(
            file.path(),
            output_dir.path(),
            Some("vpn.example.com"),
            "10.10.0.50",
            true,
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("already assigned"));
    }

    #[test]
    fn add_client_invalid_ip() {
        let file = write_test_config();
        let output_dir = TempDir::new().unwrap();

        let result = add_client(
            file.path(),
            output_dir.path(),
            Some("vpn.example.com"),
            "not-an-ip",
            true,
        );
        assert!(result.is_err());
    }

    #[test]
    fn add_client_extracts_domain_from_cert() {
        let cert_pem = test_cert_pem("unused.example.com", &["vpn.example.com"]);
        let file = write_test_config_with_cert(&cert_pem);
        let output_dir = TempDir::new().unwrap();

        let result = add_client(file.path(), output_dir.path(), None, "10.10.0.101", true);
        assert!(result.is_ok());

        let client_path = fs::read_dir(output_dir.path())
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let client_toml = fs::read_to_string(client_path).unwrap();
        let client_config = ClientConfig::from_toml_str(&client_toml).unwrap();
        assert_eq!(client_config.network.hostname, "vpn.example.com");
    }

    #[test]
    fn add_client_rejects_wildcard_domain_from_cert() {
        let cert_pem = test_cert_pem("unused.example.com", &["*.example.com"]);
        let file = write_test_config_with_cert(&cert_pem);
        let output_dir = TempDir::new().unwrap();

        let result = add_client(file.path(), output_dir.path(), None, "10.10.0.102", true);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("wildcard"));
    }
}
