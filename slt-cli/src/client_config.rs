//! Client configuration builder utilities.

use std::net::Ipv4Addr;

use slt_core::config::ClientConfig;
use slt_core::types::{
    ClientIdentity, ClientNetworkConfig, ClientTimingConfig, ClientTlsConfig, PrivKeyEd25519,
    SharedSecret, TlsMaterial, TunConfig,
};

/// Default client port.
const DEFAULT_PORT: u16 = 443;

/// Build a complete client configuration.
///
/// Creates a `ClientConfig` with the given parameters. The server certificate
/// is embedded inline for certificate pinning (works with `PARTIAL_CHAIN` flag).
///
/// # Arguments
///
/// * `server_secret` - Server's shared secret for deriving client secrets
/// * `client_id` - 16-byte client identifier
/// * `privkey` - Client's Ed25519 private key
/// * `assigned_ipv4` - IP address assigned to the client's TUN interface
/// * `domain` - Server domain name
/// * `tls_server_cert_pem` - PEM-encoded server certificate (embedded for pinning)
/// * `tun_config` - TUN configuration from server
pub fn build_client_config(
    server_secret: SharedSecret,
    client_id: slt_core::types::ClientId,
    privkey: PrivKeyEd25519,
    assigned_ipv4: Ipv4Addr,
    domain: &str,
    tls_server_cert_pem: &str,
    tun_config: &TunConfig,
) -> ClientConfig {
    ClientConfig {
        network: ClientNetworkConfig {
            hostname: domain.to_string(),
            port: DEFAULT_PORT,
            ip: None,
        },
        tls: ClientTlsConfig {
            // Embed server cert inline for pinning (works with `PARTIAL_CHAIN` flag)
            tls_ca: TlsMaterial::Pem(tls_server_cert_pem.to_string()),
            quic_ca: None,
        },
        identity: ClientIdentity {
            client_id,
            shared_secret: server_secret,
            assigned_ipv4,
            privkey_ed25519: privkey,
        },
        tun: TunConfig {
            tun_name: tun_config.tun_name.clone(),
            tun_mtu: tun_config.tun_mtu,
            tun_ipv4: assigned_ipv4,
            tun_prefix: tun_config.tun_prefix,
        },
        enable_upgrade: true,
        require_udp: false,
        timing: ClientTimingConfig::default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_client_config_basic() {
        let config = build_client_config(
            SharedSecret([1u8; 32]),
            slt_core::types::ClientId([2u8; 16]),
            PrivKeyEd25519([3u8; 32]),
            "10.10.0.2".parse().unwrap(),
            "vpn.example.com",
            "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
            &TunConfig {
                tun_name: "tun0".to_string(),
                tun_mtu: 1280,
                tun_ipv4: "10.10.0.1".parse().unwrap(),
                tun_prefix: 24,
            },
        );

        assert_eq!(config.network.hostname, "vpn.example.com");
        assert_eq!(config.network.port, 443);
        assert_eq!(config.identity.assigned_ipv4.to_string(), "10.10.0.2");
        assert_eq!(config.tun.tun_name, "tun0");
        assert_eq!(config.tun.tun_ipv4.to_string(), "10.10.0.2");
        assert_eq!(config.tun.tun_prefix, 24);
    }
}
