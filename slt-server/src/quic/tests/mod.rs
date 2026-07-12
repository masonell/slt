use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use slt_core::config::ServerConfig;
use slt_core::types::{
    CidPrefix, QUIC_DCID_PREFIX_LEN, ServerNetworkConfig, ServerTimingConfig, ServerTlsConfig,
    ServerTransportConfig, SharedSecret, TlsMaterial, TunConfig,
};

use super::{
    QuicEndpoint, TokioUpstreamSocketFactory, UpstreamSocketFactory, UpstreamSocketFuture,
};
use crate::metrics::Metrics;
use crate::registry::SessionRegistry;
use crate::sessions::SessionTx;
use crate::{AssignedIp, ClientId};

mod endpoint;
mod nat;
mod routing;
mod upstream_reader;

struct FailingUpstreamSocketFactory {
    failure_count: usize,
    attempts: AtomicUsize,
}

impl FailingUpstreamSocketFactory {
    const fn new(failure_count: usize) -> Self {
        Self {
            failure_count,
            attempts: AtomicUsize::new(0),
        }
    }

    fn attempts(&self) -> usize {
        self.attempts.load(Ordering::Relaxed)
    }
}

impl UpstreamSocketFactory for FailingUpstreamSocketFactory {
    fn create_connected(&self, upstream_addr: SocketAddr) -> UpstreamSocketFuture {
        let attempt = self.attempts.fetch_add(1, Ordering::Relaxed);
        let should_fail = attempt < self.failure_count;
        Box::pin(async move {
            if should_fail {
                return Err(io::Error::new(
                    io::ErrorKind::AddrNotAvailable,
                    "injected upstream socket setup failure",
                ));
            }
            TokioUpstreamSocketFactory
                .create_connected(upstream_addr)
                .await
        })
    }
}

fn test_config() -> ServerConfig {
    ServerConfig {
        server_secret: SharedSecret([0u8; 32]),
        network: ServerNetworkConfig {
            listen_tcp: SocketAddr::from(([127, 0, 0, 1], 0)),
            listen_udp: SocketAddr::from(([127, 0, 0, 1], 0)),
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
        clients: vec![],
    }
}

async fn make_endpoint() -> QuicEndpoint {
    let registry = Arc::new(SessionRegistry::new());
    let metrics = Arc::new(Metrics::default());
    let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
    QuicEndpoint::from_socket_for_test(
        socket,
        SocketAddr::from(([127, 0, 0, 1], 8080)),
        NonZeroUsize::new(1024).unwrap(),
        Duration::from_mins(1),
        registry,
        metrics,
    )
    .await
}

fn make_quic_short_header(dcid_prefix: &[u8; QUIC_DCID_PREFIX_LEN]) -> Vec<u8> {
    let mut buf = vec![0x40];
    buf.extend_from_slice(dcid_prefix);
    buf.extend_from_slice(&[0u8; 16]);
    buf
}

fn register_test_cid_route(
    registry: &SessionRegistry,
    dcid_prefix: [u8; QUIC_DCID_PREFIX_LEN],
    tx: SessionTx,
) {
    let client_id = ClientId([dcid_prefix[0]; 16]);
    let assigned = AssignedIp(Ipv4Addr::new(10, 0, 0, dcid_prefix[0]));
    let handle = registry.register_session(client_id, assigned, tx.clone());
    registry
        .insert_cid(
            handle.client_id,
            handle.session_id,
            CidPrefix::from(dcid_prefix),
            tx,
        )
        .unwrap();
}

fn make_quic_long_header() -> Vec<u8> {
    vec![0xC0, 0x00, 0x00, 0x00, 0x01, 0x08]
}

fn make_non_quic_packet() -> Vec<u8> {
    vec![0x00]
}
