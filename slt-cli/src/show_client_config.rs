//! Show client config command.
//!
//! Outputs client configuration fields recoverable from server data.

use std::path::Path;

use anyhow::{Context, Result};
use serde::Serialize;
use slt_core::types::{ClientId, SharedSecret, TlsMaterial, TunConfig};

use crate::cert::extract_domain_from_cert;
use crate::client_id::parse_client_id;
use crate::config_io::{load_server_config, read_cert_content};

const DEFAULT_CLIENT_PORT: u16 = 443;

#[derive(Serialize)]
struct RecoverableClientConfig {
    network: RecoverableClientNetwork,
    tls: RecoverableClientTls,
    identity: RecoverableClientIdentity,
    tun: TunConfig,
}

#[derive(Serialize)]
struct RecoverableClientNetwork {
    hostname: String,
    port: u16,
}

#[derive(Serialize)]
struct RecoverableClientTls {
    tls_ca: TlsMaterial,
}

#[derive(Serialize)]
struct RecoverableClientIdentity {
    client_id: ClientId,
    shared_secret: SharedSecret,
    assigned_ipv4: std::net::Ipv4Addr,
}

/// Output client configuration fields recoverable from server data to stdout.
///
/// The domain is extracted from the server certificate if not provided.
/// The server certificate (not CA) is embedded for certificate pinning.
/// The client private key is intentionally omitted because the server stores
/// only the corresponding public key.
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
    let output = recoverable_client_config_output(config_path, client_id, domain)?;

    if !quiet {
        print!("{output}");
    }

    Ok(())
}

fn recoverable_client_config_output(
    config_path: &Path,
    client_id: &str,
    domain: Option<&str>,
) -> Result<String> {
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

    let recoverable = RecoverableClientConfig {
        network: RecoverableClientNetwork {
            hostname: domain,
            port: DEFAULT_CLIENT_PORT,
        },
        tls: RecoverableClientTls {
            tls_ca: TlsMaterial::Pem(cert_pem),
        },
        identity: RecoverableClientIdentity {
            client_id: client.client_id,
            shared_secret: config.server_secret,
            assigned_ipv4: client.assigned_ipv4,
        },
        tun: TunConfig {
            tun_name: config.tun.tun_name,
            tun_mtu: config.tun.tun_mtu,
            tun_ipv4: client.assigned_ipv4,
            tun_prefix: config.tun.tun_prefix,
        },
    };

    let toml =
        toml::to_string_pretty(&recoverable).context("failed to serialize recoverable fields")?;

    Ok(format!(
        "# Partial client configuration for {client_id}.\n\
         # Not runnable: the server does not store identity.privkey_ed25519.\n\
         # Restore the original client-{client_id}.toml created by add-client, or remove and re-add the client.\n\n\
         {toml}"
    ))
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
    fn show_client_config_output_omits_private_key() {
        let file = write_test_config();
        let output = recoverable_client_config_output(
            file.path(),
            "0102030405060708090a0b0c0d0e0f10",
            Some("vpn.example.com"),
        )
        .unwrap();

        assert!(output.contains("# Partial client configuration"));
        assert!(output.contains("client-0102030405060708090a0b0c0d0e0f10.toml"));
        assert!(output.contains("[identity]"));
        assert!(output.contains("[identity.shared_secret]"));
        assert!(output.contains("assigned_ipv4 = \"10.10.0.2\""));
        assert!(!output.contains("privkey_ed25519 ="));
        assert!(
            !output.contains("0000000000000000000000000000000000000000000000000000000000000000")
        );

        let err = slt_core::config::ClientConfig::from_toml_str(&output).unwrap_err();
        assert!(err.to_string().contains("privkey_ed25519"));
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
