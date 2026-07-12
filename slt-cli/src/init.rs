//! Server initialization command.
//!
//! Creates a complete server configuration with certificates and sensible defaults.

use std::fs;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;

use anyhow::{Context, Result, bail};
use slt_core::config::{
    DEFAULT_MAX_AUTH_INFLIGHT, DEFAULT_SESSION_QUEUE_SIZE, DEFAULT_TUN_MTU,
    DEFAULT_UDP_NAT_MAX_ENTRIES, ServerConfig, default_tcp_connection_cap,
};
use slt_core::types::{
    ServerNetworkConfig, ServerTimingConfig, ServerTlsConfig, ServerTransportConfig, SharedSecret,
    TlsMaterial, TunConfig,
};

use crate::config_io::save_server_config;
use crate::generate_certs;

/// Default TCP/UDP listen port.
const DEFAULT_LISTEN_PORT: u16 = 443;

/// Default nginx upstream port.
const DEFAULT_NGINX_PORT: u16 = 8080;

/// Default TUN interface name.
const DEFAULT_TUN_NAME: &str = "tun0";

/// Default server TUN IPv4 address.
const DEFAULT_TUN_IPV4: Ipv4Addr = Ipv4Addr::new(10, 10, 0, 1);

/// Default TUN overlay prefix length.
const DEFAULT_TUN_PREFIX: u8 = 24;

/// Initialize server configuration.
///
/// Creates the config directory if it doesn't exist, generates certificates,
/// and creates a `server.toml` with sensible defaults.
///
/// When `force` is `false`, refuses to overwrite an existing `server.toml` or
/// any existing certificate/key file, since re-initializing regenerates the
/// shared secret and CA and invalidates every deployed client config.
///
/// # Errors
///
/// Returns an error if:
/// - The directory cannot be created
/// - Existing files would be overwritten without `force`
/// - Certificate generation fails
/// - The config file cannot be written
pub fn init(
    config_dir: &Path,
    domain: &str,
    inline_certs: bool,
    force: bool,
    quiet: bool,
) -> Result<()> {
    if !config_dir.exists() {
        fs::create_dir_all(config_dir)
            .with_context(|| format!("failed to create directory {}", config_dir.display()))?;
        if !quiet {
            println!("Created directory: {}", config_dir.display());
        }
    }

    let config_path = config_dir.join("server.toml");
    if config_path.exists() && !force {
        bail!(
            "server config already exists at {}; re-running `slt init` regenerates the shared \
             secret, CA, and server key, invalidating every deployed client config. \
             Re-run with --force to overwrite.",
            config_path.display(),
        );
    }

    generate_certs::generate_certs(config_dir, domain, force, quiet)?;

    let mut secret_bytes = [0u8; 32];
    rand::fill(&mut secret_bytes);
    let server_secret = SharedSecret(secret_bytes);

    let (tls_cert, tls_key) = if inline_certs {
        let cert_path = config_dir.join("server.pem");
        let key_path = config_dir.join("server-key.pem");

        let cert_pem = fs::read_to_string(&cert_path)
            .with_context(|| format!("failed to read {}", cert_path.display()))?;
        let key_pem = fs::read_to_string(&key_path)
            .with_context(|| format!("failed to read {}", key_path.display()))?;

        (TlsMaterial::Pem(cert_pem), TlsMaterial::Pem(key_pem))
    } else {
        (
            TlsMaterial::File {
                file: Path::new("server.pem").to_path_buf(),
            },
            TlsMaterial::File {
                file: Path::new("server-key.pem").to_path_buf(),
            },
        )
    };

    let config = ServerConfig {
        server_secret,
        network: ServerNetworkConfig {
            listen_tcp: SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), DEFAULT_LISTEN_PORT),
            listen_udp: SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), DEFAULT_LISTEN_PORT),
            nginx_tcp_upstream: SocketAddr::new(Ipv4Addr::LOCALHOST.into(), DEFAULT_NGINX_PORT),
            nginx_udp_upstream: SocketAddr::new(Ipv4Addr::LOCALHOST.into(), DEFAULT_NGINX_PORT),
        },
        tls: ServerTlsConfig { tls_cert, tls_key },
        tun: TunConfig {
            tun_name: DEFAULT_TUN_NAME.to_string(),
            tun_mtu: DEFAULT_TUN_MTU,
            tun_ipv4: DEFAULT_TUN_IPV4,
            tun_prefix: DEFAULT_TUN_PREFIX,
        },
        timing: ServerTimingConfig::default(),
        transport: ServerTransportConfig::default(),
        udp_nat_max_entries: DEFAULT_UDP_NAT_MAX_ENTRIES,
        session_queue_size: DEFAULT_SESSION_QUEUE_SIZE,
        max_auth_inflight: DEFAULT_MAX_AUTH_INFLIGHT,
        tcp_connection_cap: default_tcp_connection_cap(),
        clients: Vec::new(),
    };

    config
        .validate()
        .context("generated config failed validation")?;

    save_server_config(&config_path, &config)?;

    if !quiet {
        println!("Generated server configuration: {}", config_path.display());
        if inline_certs {
            println!("Certificates embedded in config");
        } else {
            println!("Certificates referenced as files");
        }
        println!();
        println!("Next steps:");
        println!("  1. Review {} if needed", config_path.display());
        println!(
            "  2. Add clients with: slt add-client --config {} --output-dir <dir>",
            config_path.display()
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::TempDir;

    use super::*;

    #[test]
    fn init_creates_directory_and_files() {
        let temp_dir = TempDir::new().unwrap();
        let config_dir = temp_dir.path().join("vpn-config");

        init(&config_dir, "example.com", false, false, true).unwrap();

        assert!(config_dir.exists());
        assert!(config_dir.join("server.toml").exists());
        assert!(config_dir.join("ca.pem").exists());
        assert!(config_dir.join("server.pem").exists());
        assert!(config_dir.join("server-key.pem").exists());
    }

    #[test]
    fn init_with_inline_certs() {
        let temp_dir = TempDir::new().unwrap();
        let config_dir = temp_dir.path().join("vpn-config-inline");

        init(&config_dir, "example.com", true, false, true).unwrap();

        let config_content = fs::read_to_string(config_dir.join("server.toml")).unwrap();
        // Inline certs should contain PEM markers directly in the config
        assert!(config_content.contains("-----BEGIN CERTIFICATE-----"));
        assert!(config_content.contains("-----BEGIN PRIVATE KEY-----"));
    }

    #[test]
    fn init_with_file_refs() {
        let temp_dir = TempDir::new().unwrap();
        let config_dir = temp_dir.path().join("vpn-config-file");

        init(&config_dir, "example.com", false, false, true).unwrap();

        let config_content = fs::read_to_string(config_dir.join("server.toml")).unwrap();
        // File refs should have { file = "..." } format
        assert!(config_content.contains("file = \"server.pem\""));
        assert!(config_content.contains("file = \"server-key.pem\""));
    }

    #[test]
    fn init_creates_valid_config() {
        let temp_dir = TempDir::new().unwrap();
        let config_dir = temp_dir.path().join("vpn-config-valid");

        init(&config_dir, "example.com", false, false, true).unwrap();

        // Load and validate the config
        let config_path = config_dir.join("server.toml");
        let contents = fs::read_to_string(&config_path).unwrap();
        let config: ServerConfig = ServerConfig::from_toml_str(&contents).unwrap();

        assert!(config.validate().is_ok());
        assert!(config.clients.is_empty());
        assert_eq!(config.tun.tun_name, "tun0");
        assert_eq!(config.tun.tun_mtu, 1186);
        assert_eq!(config.session_queue_size, 1024);
    }

    #[test]
    fn init_refuses_existing_config_without_force() {
        let temp_dir = TempDir::new().unwrap();
        let config_dir = temp_dir.path().join("vpn-config-existing");

        init(&config_dir, "example.com", false, false, true).unwrap();

        // A second init without --force must bail and leave the original files intact.
        let result = init(&config_dir, "example.com", false, false, true);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("server.toml"));
        assert!(err.contains("--force"));
    }

    #[test]
    fn init_force_overwrites_existing() {
        let temp_dir = TempDir::new().unwrap();
        let config_dir = temp_dir.path().join("vpn-config-force");

        init(&config_dir, "example.com", false, false, true).unwrap();
        let before = fs::read_to_string(config_dir.join("server-key.pem")).unwrap();

        init(&config_dir, "example.com", false, true, true).unwrap();

        // --force regenerates the server key.
        let after = fs::read_to_string(config_dir.join("server-key.pem")).unwrap();
        assert_ne!(before, after);
    }
}
