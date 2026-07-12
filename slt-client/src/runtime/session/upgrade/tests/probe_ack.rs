use std::time::Duration;

use super::super::*;
use super::{parkable_session, tun_channels};

mod udp_ready_tcp_write_failure {
    use std::time::Instant;

    use slt_core::proto::UpgradeProbeAckPayload;
    use tokio::time;

    use super::*;
    use crate::runtime::services::DesktopServices;
    use crate::test_support::test_config;

    #[tokio::test]
    async fn udp_ready_write_observes_tcp_write_timeout() {
        let mut config = test_config();
        config.enable_upgrade = true;
        config.timing.tcp_write_timeout = Duration::from_millis(40);
        let services = DesktopServices::new();
        let mut tun = tun_channels();
        let (mut session, _server_stream, write_gate) =
            parkable_session(&config, &mut tun, &services).await;
        let upgrade_id = 0xAA;
        let nonce = 0xBB;
        session.udp_upgrade = UdpUpgradeState::Upgrading {
            upgrade_id,
            deadline: Instant::now() + config.timing.register_timeout,
            attempts: 1,
            next_probe_at: Instant::now() + config.timing.reconnect_min,
            probe_nonce: nonce,
            probe_acked: false,
            ready_sent: false,
            probe_backoff: ReconnectBackoff::new(
                config.timing.reconnect_min,
                config.timing.reconnect_max,
            ),
        };
        let ack = UpgradeProbeAckPayload { upgrade_id, nonce };
        let mut payload = Vec::new();
        ack.encode(&mut payload);
        write_gate.park();

        let err = time::timeout(
            Duration::from_secs(1),
            session.handle_upgrade_probe_ack(&payload),
        )
        .await
        .expect("UDP_READY write deadline must fire")
        .expect_err("parked UDP_READY write must fail");

        assert!(matches!(
            &err,
            SessionError::Io(source)
                if source.kind() == std::io::ErrorKind::TimedOut
        ));
        assert_eq!(err.exit(), SessionExit::ConnectionError);
    }
}

mod probe_ack_handling {
    use std::sync::Arc;
    use std::time::Instant;

    use slt_core::crypto::udp_qsp::QuicQspSession;
    use slt_core::proto::MessageLimits;
    use slt_core::transport::tcp::TcpChannel;
    use slt_core::types::Cid;
    use tokio::net::UdpSocket;
    use tokio_util::sync::CancellationToken;

    use super::*;
    use crate::metrics::Metrics;
    use crate::runtime::services::DesktopServices;
    use crate::test_support::{make_server_keys, make_test_keys, test_config, tls_tcp_stream_pair};
    use crate::transport::tcp::{ClientKeyUpdater, TcpSession, TcpTransport};
    use crate::transport::udp_qsp::{ClientTransport, client_udp_qsp_io};

    async fn loopback_tcp_transport() -> TcpTransport {
        let metrics = Arc::new(Metrics::default());
        let updater = ClientKeyUpdater::new(metrics);
        let (client_stream, _server_stream) = tls_tcp_stream_pair().await;
        TcpChannel::with_key_updater(client_stream, updater)
    }

    async fn udp_transport_pair() -> (ClientTransport, ClientTransport) {
        let client_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let server_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let client_addr = client_socket.local_addr().unwrap();
        let server_addr = server_socket.local_addr().unwrap();
        let scid = Cid::from([0xA1; 20]);
        let dcid = Cid::from([0xB2; 20]);

        let client_io = client_udp_qsp_io(&client_socket, server_addr).unwrap();
        let client_session =
            QuicQspSession::new(client_io, scid, dcid, make_test_keys(), 0, 0, false);
        let server_io = client_udp_qsp_io(&server_socket, client_addr).unwrap();
        let server_session =
            QuicQspSession::new(server_io, dcid, scid, make_server_keys(), 0, 0, false);

        (
            ClientTransport::new(client_session, Arc::new(Metrics::default())),
            ClientTransport::new(server_session, Arc::new(Metrics::default())),
        )
    }

    async fn read_probe(transport: &mut ClientTransport) -> UpgradeProbePayload {
        let message = transport
            .read_next_message(MessageLimits::new(2048, 2048))
            .await
            .unwrap();
        let Message::UpgradeProbe { payload } = message.message() else {
            panic!("expected upgrade_probe");
        };
        UpgradeProbePayload::decode(payload).unwrap()
    }

    #[tokio::test]
    async fn delayed_probe_ack_after_retransmission_validates_udp_path() {
        let mut config = test_config();
        config.enable_upgrade = true;
        let services = DesktopServices::new();
        let mut tun = tun_channels();
        let metrics = Arc::new(Metrics::default());
        let updater = ClientKeyUpdater::new(metrics.clone());
        let (client_stream, server_stream) = tls_tcp_stream_pair().await;
        let tcp_session = TcpSession {
            transport: TcpChannel::with_key_updater(client_stream, updater),
            peer: None,
            sni: None,
        };
        let mut session = ClientSession::new(
            &config,
            tcp_session,
            &mut tun,
            CancellationToken::new(),
            metrics,
            &services,
            None,
        );
        let mut server_tcp = TcpChannel::new(server_stream);
        let (client_udp, mut server_udp) = udp_transport_pair().await;
        session.udp_state = UdpState::Active(Box::new(client_udp));

        let now = Instant::now();
        session.start_udp_upgrade_attempt(now);
        session.send_upgrade_probe(now).await.unwrap();
        let first_probe = read_probe(&mut server_udp).await;

        session
            .send_upgrade_probe(now + config.timing.reconnect_min)
            .await
            .unwrap();
        let second_probe = read_probe(&mut server_udp).await;
        assert_eq!(second_probe, first_probe);

        let ack = UpgradeProbeAckPayload {
            upgrade_id: first_probe.upgrade_id,
            nonce: first_probe.nonce,
        };
        let mut ack_payload = Vec::new();
        ack.encode(&mut ack_payload);
        server_udp
            .write_message(Message::UpgradeProbeAck {
                payload: &ack_payload,
            })
            .await
            .unwrap();
        server_udp.flush().await.unwrap();

        let ack_message = session
            .udp_state
            .as_active_mut()
            .unwrap()
            .read_next_message(MessageLimits::new(2048, 2048))
            .await
            .unwrap();
        assert_eq!(
            session.handle_udp_message(ack_message).await.unwrap(),
            SessionControl::Continue
        );

        let UdpUpgradeState::Upgrading {
            attempts,
            probe_nonce,
            probe_acked,
            ready_sent,
            ..
        } = session.udp_upgrade
        else {
            panic!("delayed ack should keep the active upgrade attempt");
        };
        assert_eq!(attempts, 2);
        assert_eq!(probe_nonce, first_probe.nonce);
        assert!(probe_acked);
        assert!(ready_sent);

        assert_ne!(server_tcp.read_more().await.unwrap(), 0);
        let ready = server_tcp.try_pop_message(session.limits).unwrap().unwrap();
        let Message::UdpReady { payload } = ready.message() else {
            panic!("expected udp_ready");
        };
        assert_eq!(
            UdpReadyPayload::decode(payload).unwrap().upgrade_id,
            first_probe.upgrade_id
        );
    }

    #[tokio::test]
    async fn probe_ack_with_mismatched_nonce_does_not_mark_probe_acked() {
        let mut config = test_config();
        config.enable_upgrade = true;
        let services = DesktopServices::new();
        let mut tun = tun_channels();
        let metrics = Arc::new(Metrics::default());
        let tcp_session = TcpSession {
            transport: loopback_tcp_transport().await,
            peer: None,
            sni: None,
        };
        let mut session = ClientSession::new(
            &config,
            tcp_session,
            &mut tun,
            CancellationToken::new(),
            metrics,
            &services,
            None,
        );

        let upgrade_id = 0xAA;
        let mismatched_nonce = 0x10;
        let probe_nonce = 0x11;
        session.udp_upgrade = UdpUpgradeState::Upgrading {
            upgrade_id,
            deadline: Instant::now() + config.timing.register_timeout,
            attempts: 2,
            next_probe_at: Instant::now() + config.timing.reconnect_min,
            probe_nonce,
            probe_acked: false,
            ready_sent: false,
            probe_backoff: ReconnectBackoff::new(
                config.timing.reconnect_min,
                config.timing.reconnect_max,
            ),
        };

        let ack = UpgradeProbeAckPayload {
            upgrade_id,
            nonce: mismatched_nonce,
        };
        let mut payload = Vec::new();
        ack.encode(&mut payload);

        let control = session.handle_upgrade_probe_ack(&payload).await.unwrap();
        assert!(
            matches!(control, SessionControl::Continue),
            "mismatched ack should be ignored, got {control:?}",
        );

        let UdpUpgradeState::Upgrading {
            probe_acked,
            ready_sent,
            probe_nonce: stored_nonce,
            ..
        } = session.udp_upgrade
        else {
            panic!("mismatched ack should leave upgrade attempt active");
        };
        assert!(
            !probe_acked,
            "mismatched ack must not validate the udp path"
        );
        assert!(!ready_sent, "mismatched ack must not send udp_ready");
        assert_eq!(stored_nonce, probe_nonce);
    }
}
