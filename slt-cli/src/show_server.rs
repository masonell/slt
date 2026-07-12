//! Server configuration display command.

use std::fmt::Write as _;
use std::path::Path;

use anyhow::Result;
use slt_core::config::ServerConfig;
use slt_core::types::{ServerTimingConfig, ServerTransportConfig, ServerUdpQspCipher, TlsMaterial};

use crate::config_io::load_server_config;

/// Display server configuration summary.
///
/// Shows network, TLS, TUN, timing, transport, capacity, and client settings.
/// Secrets (`server_secret`, TLS key content) are hidden by default unless
/// `reveal_secrets` is true.
///
/// # Errors
///
/// Returns an error if the config file cannot be read or parsed.
pub fn show_server(config_path: &Path, reveal_secrets: bool) -> Result<()> {
    let config = load_server_config(config_path)?;

    print!("{}", server_summary(&config, reveal_secrets));

    Ok(())
}

fn server_summary(config: &ServerConfig, reveal_secrets: bool) -> String {
    let server_secret = if reveal_secrets {
        hex::encode(config.server_secret.as_bytes())
    } else {
        "<hidden>".to_owned()
    };
    let certificate = match &config.tls.tls_cert {
        TlsMaterial::Pem(pem) => format!("<inline, {} bytes>", pem.len()),
        TlsMaterial::File { file } => file.display().to_string(),
    };
    let private_key = match &config.tls.tls_key {
        TlsMaterial::Pem(pem) if reveal_secrets => format!("<inline, {} bytes>", pem.len()),
        TlsMaterial::Pem(_) => "<hidden>".to_owned(),
        TlsMaterial::File { file } if reveal_secrets => file.display().to_string(),
        TlsMaterial::File { file } => format!("{} <hidden>", file.display()),
    };
    let mut clients = String::new();
    if config.clients.is_empty() {
        clients.push_str("  (none)\n");
    } else {
        for client in &config.clients {
            let status = if client.enabled {
                "enabled"
            } else {
                "disabled"
            };
            writeln!(
                &mut clients,
                "  {} -> {} [{}]",
                client.client_id, client.assigned_ipv4, status
            )
            .expect("writing to a String cannot fail");
        }
    }

    format!(
        concat!(
            "Server Configuration\n",
            "====================\n",
            "\n",
            "Server Secret: {}\n",
            "\n",
            "Network:\n",
            "  Listen TCP:    {}\n",
            "  Listen UDP:    {}\n",
            "  Nginx TCP Up:  {}\n",
            "  Nginx UDP Up:  {}\n",
            "\n",
            "TLS:\n",
            "  Certificate: {}\n",
            "  Private Key:  {}\n",
            "\n",
            "TUN:\n",
            "  Interface: {}\n",
            "  MTU:       {}\n",
            "  IPv4:      {}/{}\n",
            "\n",
            "{}\n",
            "{}\n",
            "{}\n",
            "Clients ({}):\n",
            "{}",
        ),
        server_secret,
        config.network.listen_tcp,
        config.network.listen_udp,
        config.network.nginx_tcp_upstream,
        config.network.nginx_udp_upstream,
        certificate,
        private_key,
        config.tun.tun_name,
        config.tun.tun_mtu,
        config.tun.tun_ipv4,
        config.tun.tun_prefix,
        timing_summary(&config.timing),
        transport_summary(&config.transport),
        advanced_summary(config),
        config.clients.len(),
        clients,
    )
}

fn timing_summary(timing: &ServerTimingConfig) -> String {
    format!(
        concat!(
            "Timing:\n",
            "  Ping Min:       {:?}\n",
            "  Ping Max:       {:?}\n",
            "  Auth Timeout:   {:?}\n",
            "  TCP Write:      {:?}\n",
            "  UDP Liveness:   {:?}\n",
            "  Idle Timeout:   {:?}\n",
            "  Metrics Intvl:  {:?}\n",
            "  TCP Classify:   {:?}\n",
        ),
        timing.ping_min,
        timing.ping_max,
        timing.auth_timeout,
        timing.tcp_write_timeout,
        timing.udp_liveness_timeout,
        timing.idle_timeout,
        timing.metrics_interval,
        timing.tcp_classification_timeout,
    )
}

fn transport_summary(transport: &ServerTransportConfig) -> String {
    let allowed_ciphers = transport
        .udp_qsp
        .allowed_ciphers
        .iter()
        .copied()
        .map(cipher_config_name)
        .collect::<Vec<_>>()
        .join(", ");

    format!("Transport:\n  UDP-QSP Allowed Ciphers: {allowed_ciphers}\n")
}

const fn cipher_config_name(cipher: ServerUdpQspCipher) -> &'static str {
    match cipher {
        ServerUdpQspCipher::Aes128Gcm => "aes-128-gcm",
        ServerUdpQspCipher::ChaCha20Poly1305 => "chacha20-poly1305",
    }
}

fn advanced_summary(config: &ServerConfig) -> String {
    format!(
        concat!(
            "Advanced:\n",
            "  UDP NAT Entries:    {}\n",
            "  Session Queue:      {}\n",
            "  Max Auth Inflight:  {}\n",
            "  TCP Conn Cap:       {}\n",
        ),
        config.udp_nat_max_entries,
        config.session_queue_size,
        config.max_auth_inflight,
        config.tcp_connection_cap,
    )
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use slt_core::config::{
        DEFAULT_MAX_AUTH_INFLIGHT, DEFAULT_SESSION_QUEUE_SIZE, DEFAULT_UDP_NAT_MAX_ENTRIES,
        default_tcp_connection_cap,
    };
    use tempfile::NamedTempFile;

    use super::*;

    fn write_test_config() -> NamedTempFile {
        let mut file = NamedTempFile::new().unwrap();
        let config = r#"
server_secret = { hex = "0000000000000000000000000000000000000000000000000000000000000000" }

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
udp_liveness_timeout = "47s"
idle_timeout = "60s"
metrics_interval = "5m"

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
    fn server_summary_hides_secrets_by_default() {
        let file = write_test_config();
        let config = load_server_config(file.path()).unwrap();
        let summary = server_summary(&config, false);

        assert!(summary.contains("Server Secret: <hidden>"));
        assert!(summary.contains("Private Key:  server-key.pem <hidden>"));
        assert!(!summary.contains(&hex::encode(config.server_secret.as_bytes())));
    }

    #[test]
    fn server_summary_reveals_secrets_when_requested() {
        let file = write_test_config();
        let config = load_server_config(file.path()).unwrap();
        let summary = server_summary(&config, true);

        assert!(summary.contains(&format!(
            "Server Secret: {}",
            hex::encode(config.server_secret.as_bytes())
        )));
        assert!(summary.contains("Private Key:  server-key.pem\n"));
        assert!(!summary.contains("server-key.pem <hidden>"));
    }

    #[test]
    fn timing_summary_includes_udp_liveness_timeout() {
        let file = write_test_config();
        let config = load_server_config(file.path()).unwrap();

        assert!(
            timing_summary(&config.timing).contains("  UDP Liveness:   47s\n"),
            "timing summary should show the effective UDP liveness timeout"
        );
    }

    #[test]
    fn advanced_summary_includes_all_effective_capacity_settings() {
        let file = write_test_config();
        let config = load_server_config(file.path()).unwrap();

        assert_eq!(
            advanced_summary(&config),
            format!(
                concat!(
                    "Advanced:\n",
                    "  UDP NAT Entries:    {}\n",
                    "  Session Queue:      {}\n",
                    "  Max Auth Inflight:  {}\n",
                    "  TCP Conn Cap:       {}\n",
                ),
                DEFAULT_UDP_NAT_MAX_ENTRIES,
                DEFAULT_SESSION_QUEUE_SIZE,
                DEFAULT_MAX_AUTH_INFLIGHT,
                default_tcp_connection_cap(),
            )
        );
    }

    #[test]
    fn transport_summary_includes_default_cipher_allowlist() {
        let file = write_test_config();
        let config = load_server_config(file.path()).unwrap();

        assert_eq!(
            transport_summary(&config.transport),
            concat!(
                "Transport:\n",
                "  UDP-QSP Allowed Ciphers: aes-128-gcm, chacha20-poly1305\n",
            )
        );
    }

    #[test]
    fn transport_summary_includes_restricted_cipher_allowlist() {
        let file = write_test_config();
        let mut config = load_server_config(file.path()).unwrap();
        config.transport.udp_qsp.allowed_ciphers = vec![ServerUdpQspCipher::ChaCha20Poly1305];

        assert_eq!(
            transport_summary(&config.transport),
            concat!(
                "Transport:\n",
                "  UDP-QSP Allowed Ciphers: chacha20-poly1305\n",
            )
        );
    }

    #[test]
    fn show_server_fails_on_missing_file() {
        let result = show_server(Path::new("/nonexistent/path.toml"), false);
        assert!(result.is_err());
    }
}
