use super::*;

mod disabled_and_discovery {
    use std::time::{Duration, Instant};

    use super::*;

    #[test]
    fn disabled_is_not_waiting() {
        let state = UdpState::Disabled;
        assert!(!state.is_waiting());
    }

    #[test]
    fn disabled_has_no_reconnect_at() {
        let state = UdpState::Disabled;
        assert!(state.reconnect_at().is_none());
    }

    #[test]
    fn disabled_has_no_register_deadline() {
        let state = UdpState::Disabled;
        assert!(state.register_deadline().is_none());
    }

    #[test]
    fn disabled_has_no_active_transport() {
        let state = UdpState::Disabled;
        assert!(state.as_active().is_none());
    }

    #[test]
    fn need_discovery_is_waiting() {
        let backoff = ReconnectBackoff::new(Duration::from_secs(1), Duration::from_secs(30));
        let state = UdpState::NeedDiscovery {
            backoff,
            reconnect_at: Instant::now(),
        };
        assert!(state.is_waiting());
    }

    #[test]
    fn need_discovery_has_reconnect_at() {
        let backoff = ReconnectBackoff::new(Duration::from_secs(1), Duration::from_secs(30));
        let reconnect_at = Instant::now();
        let state = UdpState::NeedDiscovery {
            backoff,
            reconnect_at,
        };
        assert_eq!(state.reconnect_at(), Some(reconnect_at));
    }

    #[test]
    fn need_discovery_has_no_register_deadline() {
        let backoff = ReconnectBackoff::new(Duration::from_secs(1), Duration::from_secs(30));
        let state = UdpState::NeedDiscovery {
            backoff,
            reconnect_at: Instant::now(),
        };
        assert!(state.register_deadline().is_none());
    }
}

mod pending {
    use std::time::{Duration, Instant};

    use slt_core::proto::CipherSuite;

    use super::*;
    use crate::test_support::mock_quic_ids_sync;

    fn make_pending_state_without_registration() -> UdpState {
        let backoff = ReconnectBackoff::new(Duration::from_secs(1), Duration::from_secs(30));
        let quic_ids = mock_quic_ids_sync();
        UdpState::Pending {
            quic_ids,
            backoff,
            reconnect_at: Instant::now(),
            registration: None,
        }
    }

    #[test]
    fn pending_without_registration_is_waiting() {
        let state = make_pending_state_without_registration();
        assert!(state.is_waiting());
    }

    #[test]
    fn pending_without_registration_has_reconnect_at() {
        let reconnect_at = Instant::now();
        let backoff = ReconnectBackoff::new(Duration::from_secs(1), Duration::from_secs(30));
        let quic_ids = mock_quic_ids_sync();
        let state = UdpState::Pending {
            quic_ids,
            backoff,
            reconnect_at,
            registration: None,
        };
        assert_eq!(state.reconnect_at(), Some(reconnect_at));
    }

    #[test]
    fn pending_without_registration_has_no_register_deadline() {
        let state = make_pending_state_without_registration();
        assert!(state.register_deadline().is_none());
    }

    #[test]
    fn pending_without_registration_has_no_active_transport() {
        let state = make_pending_state_without_registration();
        assert!(state.as_active().is_none());
    }

    #[test]
    fn pending_with_registration_is_not_waiting() {
        let backoff = ReconnectBackoff::new(Duration::from_secs(1), Duration::from_secs(30));
        let quic_ids = mock_quic_ids_sync();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let prepared = rt.block_on(async {
            crate::runtime::register::prepare_udp_qsp_registration(
                &quic_ids,
                CipherSuite::Aes128Gcm,
            )
            .unwrap()
        });
        let registration = Some(Box::new(PendingUdpQspRegistration {
            prepared,
            deadline: Instant::now() + Duration::from_secs(5),
        }));
        let state = UdpState::Pending {
            quic_ids,
            backoff,
            reconnect_at: Instant::now(),
            registration,
        };
        assert!(!state.is_waiting());
    }

    #[test]
    fn pending_with_registration_has_no_reconnect_at() {
        let backoff = ReconnectBackoff::new(Duration::from_secs(1), Duration::from_secs(30));
        let quic_ids = mock_quic_ids_sync();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let prepared = rt.block_on(async {
            crate::runtime::register::prepare_udp_qsp_registration(
                &quic_ids,
                CipherSuite::Aes128Gcm,
            )
            .unwrap()
        });
        let registration = Some(Box::new(PendingUdpQspRegistration {
            prepared,
            deadline: Instant::now() + Duration::from_secs(5),
        }));
        let state = UdpState::Pending {
            quic_ids,
            backoff,
            reconnect_at: Instant::now(),
            registration,
        };
        assert!(state.reconnect_at().is_none());
    }

    #[test]
    fn pending_with_registration_has_register_deadline() {
        let deadline = Instant::now() + Duration::from_secs(5);
        let backoff = ReconnectBackoff::new(Duration::from_secs(1), Duration::from_secs(30));
        let quic_ids = mock_quic_ids_sync();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let prepared = rt.block_on(async {
            crate::runtime::register::prepare_udp_qsp_registration(
                &quic_ids,
                CipherSuite::Aes128Gcm,
            )
            .unwrap()
        });
        let registration = Some(Box::new(PendingUdpQspRegistration { prepared, deadline }));
        let state = UdpState::Pending {
            quic_ids,
            backoff,
            reconnect_at: Instant::now(),
            registration,
        };
        assert_eq!(state.register_deadline(), Some(deadline));
    }

    #[test]
    fn pending_with_registration_has_no_active_transport() {
        let backoff = ReconnectBackoff::new(Duration::from_secs(1), Duration::from_secs(30));
        let quic_ids = mock_quic_ids_sync();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let prepared = rt.block_on(async {
            crate::runtime::register::prepare_udp_qsp_registration(
                &quic_ids,
                CipherSuite::Aes128Gcm,
            )
            .unwrap()
        });
        let registration = Some(Box::new(PendingUdpQspRegistration {
            prepared,
            deadline: Instant::now() + Duration::from_secs(5),
        }));
        let state = UdpState::Pending {
            quic_ids,
            backoff,
            reconnect_at: Instant::now(),
            registration,
        };
        assert!(state.as_active().is_none());
    }
}

mod active {
    use std::sync::Arc;

    use slt_core::crypto::udp_qsp::{QuicQspSession, UdpQspKeys};
    use slt_core::proto::CipherSuite;
    use slt_core::types::{Cid, MAX_DCID_LEN};
    use tokio::net::UdpSocket;

    use super::*;
    use crate::metrics::Metrics;
    use crate::transport::udp_qsp::ClientTransport;

    fn make_active_state() -> UdpState {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
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
        })
    }

    #[test]
    fn active_is_not_waiting() {
        let state = make_active_state();
        assert!(!state.is_waiting());
    }

    #[test]
    fn active_has_no_reconnect_at() {
        let state = make_active_state();
        assert!(state.reconnect_at().is_none());
    }

    #[test]
    fn active_has_no_register_deadline() {
        let state = make_active_state();
        assert!(state.register_deadline().is_none());
    }

    #[test]
    fn active_has_active_transport() {
        let state = make_active_state();
        assert!(state.as_active().is_some());
    }

    #[test]
    fn active_mut_returns_mutable_transport() {
        let mut state = make_active_state();
        assert!(state.as_active_mut().is_some());
    }
}
