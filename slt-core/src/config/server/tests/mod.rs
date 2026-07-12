mod redaction;
mod serde_defaults;
mod validation;

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use super::ServerConfig;
use crate::types::{
    ClientId, PubKeyEd25519, ServerClient, ServerNetworkConfig, ServerTimingConfig,
    ServerTlsConfig, ServerTransportConfig, SharedSecret, TlsMaterial, TunConfig,
};

fn test_config() -> ServerConfig {
    ServerConfig {
        server_secret: SharedSecret([0u8; 32]),
        network: ServerNetworkConfig {
            listen_tcp: SocketAddr::from(([0, 0, 0, 0], 443)),
            listen_udp: SocketAddr::from(([0, 0, 0, 0], 443)),
            nginx_tcp_upstream: SocketAddr::from(([127, 0, 0, 1], 8080)),
            nginx_udp_upstream: SocketAddr::from(([127, 0, 0, 1], 8080)),
        },
        tls: ServerTlsConfig {
            tls_cert: TlsMaterial::Pem(String::new()),
            tls_key: TlsMaterial::Pem(String::new()),
        },
        tun: TunConfig {
            tun_name: "tun0".to_string(),
            tun_mtu: 1280,
            tun_ipv4: Ipv4Addr::new(10, 10, 0, 1),
            tun_prefix: 24,
        },
        timing: ServerTimingConfig {
            ping_min: Duration::from_secs(10),
            ping_max: Duration::from_secs(20),
            auth_timeout: Duration::from_secs(10),
            tcp_write_timeout: Duration::from_secs(10),
            udp_liveness_timeout: Duration::from_secs(45),
            idle_timeout: Duration::from_mins(1),
            metrics_interval: Duration::from_mins(5),
            tcp_classification_timeout: Duration::from_secs(60),
        },
        transport: ServerTransportConfig::default(),
        udp_nat_max_entries: 1024,
        session_queue_size: 256,
        max_auth_inflight: 128,
        tcp_connection_cap: 512,
        clients: vec![ServerClient {
            client_id: ClientId([0u8; 16]),
            pubkey_ed25519: PubKeyEd25519([0u8; 32]),
            assigned_ipv4: Ipv4Addr::new(10, 10, 0, 2),
            enabled: true,
        }],
    }
}
