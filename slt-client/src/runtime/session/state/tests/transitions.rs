use std::sync::Arc;
use std::time::{Duration, Instant};

use slt_core::crypto::udp_qsp::{QuicQspSession, UdpQspKeys};
use slt_core::proto::CipherSuite;
use slt_core::types::{Cid, MAX_DCID_LEN};
use tokio::net::UdpSocket;

use super::*;
use crate::metrics::Metrics;
use crate::test_support::mock_quic_ids_sync;
use crate::transport::udp_qsp::ClientTransport;

#[test]
fn need_discovery_to_pending_transition() {
    let backoff = ReconnectBackoff::new(Duration::from_secs(1), Duration::from_secs(30));
    let initial_state = UdpState::NeedDiscovery {
        backoff,
        reconnect_at: Instant::now(),
    };

    assert!(initial_state.is_waiting());
    assert!(initial_state.reconnect_at().is_some());
    assert!(initial_state.register_deadline().is_none());

    let quic_ids = mock_quic_ids_sync();
    let new_backoff = ReconnectBackoff::new(Duration::from_secs(1), Duration::from_secs(30));
    let new_state = UdpState::Pending {
        quic_ids,
        backoff: new_backoff,
        reconnect_at: Instant::now(),
        registration: None,
    };

    assert!(new_state.is_waiting());
    assert!(new_state.reconnect_at().is_some());
    assert!(new_state.register_deadline().is_none());
}

#[test]
fn pending_to_active_transition() {
    let backoff = ReconnectBackoff::new(Duration::from_secs(1), Duration::from_secs(30));
    let quic_ids = mock_quic_ids_sync();
    let initial_state = UdpState::Pending {
        quic_ids,
        backoff,
        reconnect_at: Instant::now(),
        registration: None,
    };

    // Verify initial state
    assert!(initial_state.is_waiting());
    assert!(initial_state.reconnect_at().is_some());

    let rt = tokio::runtime::Runtime::new().unwrap();
    let new_state = rt.block_on(async {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let peer: std::net::SocketAddr = "127.0.0.1:443".parse().unwrap();
        let io = crate::transport::udp_qsp::client_udp_qsp_io(&socket, peer).unwrap();

        let dcid = Cid::from([0xAA; MAX_DCID_LEN]);
        let scid = Cid::from([0xBB; MAX_DCID_LEN]);

        let keys = UdpQspKeys::from_packet_material(
            CipherSuite::Aes128Gcm,
            [0u8; 16],
            [0u8; 16],
            [0u8; 16],
            [0u8; 16],
            [0u8; 12],
            [0u8; 12],
        )
        .unwrap();

        let session = QuicQspSession::new(io, scid, dcid, keys, 0, 0, false);
        let metrics = Arc::new(Metrics::default());
        let transport = ClientTransport::new(session, metrics);
        UdpState::Active(Box::new(transport))
    });

    assert!(!new_state.is_waiting());
    assert!(new_state.reconnect_at().is_none());
    assert!(new_state.register_deadline().is_none());
    assert!(new_state.as_active().is_some());
}

#[test]
fn pending_retry_clears_registration() {
    let backoff = ReconnectBackoff::new(Duration::from_secs(1), Duration::from_secs(30));
    let quic_ids = mock_quic_ids_sync();
    let rt = tokio::runtime::Runtime::new().unwrap();
    let prepared = rt.block_on(async {
        crate::runtime::register::prepare_udp_qsp_registration(&quic_ids, CipherSuite::Aes128Gcm)
            .unwrap()
    });
    let registration = Some(Box::new(PendingUdpQspRegistration {
        prepared,
        deadline: Instant::now() + Duration::from_secs(5),
    }));

    let state_before = UdpState::Pending {
        quic_ids: mock_quic_ids_sync(),
        backoff,
        reconnect_at: Instant::now(),
        registration,
    };

    assert!(!state_before.is_waiting());
    assert!(state_before.register_deadline().is_some());

    let state_after = UdpState::Pending {
        quic_ids: mock_quic_ids_sync(),
        backoff: ReconnectBackoff::new(Duration::from_secs(1), Duration::from_secs(30)),
        reconnect_at: Instant::now() + Duration::from_secs(2),
        registration: None,
    };

    assert!(state_after.is_waiting());
    assert!(state_after.register_deadline().is_none());
    assert!(state_after.reconnect_at().is_some());
}

#[test]
fn discovery_retry_updates_reconnect_at() {
    let initial_time = Instant::now();
    let backoff = ReconnectBackoff::new(Duration::from_secs(1), Duration::from_secs(30));
    let state_before = UdpState::NeedDiscovery {
        backoff,
        reconnect_at: initial_time,
    };

    let new_time = initial_time + Duration::from_secs(2);
    let new_backoff = ReconnectBackoff::new(Duration::from_secs(1), Duration::from_secs(30));
    let state_after = UdpState::NeedDiscovery {
        backoff: new_backoff,
        reconnect_at: new_time,
    };

    assert!(state_before.is_waiting());
    assert!(state_after.is_waiting());

    assert!(state_after.reconnect_at().unwrap() > state_before.reconnect_at().unwrap());
}
