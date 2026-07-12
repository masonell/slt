use std::time::Duration;

use super::super::*;
use super::{parkable_session, tun_channels};

mod registration_and_tcp_write_failures {
    use std::time::Instant;

    use tokio::time;

    use super::*;
    use crate::runtime::services::DesktopServices;
    use crate::test_support::{mock_quic_ids, test_config};

    #[tokio::test]
    async fn register_cid_write_observes_tcp_write_timeout() {
        let mut config = test_config();
        config.enable_upgrade = true;
        config.timing.tcp_write_timeout = Duration::from_millis(40);
        let services = DesktopServices::new();
        let mut tun = tun_channels();
        let (mut session, _server_stream, write_gate) =
            parkable_session(&config, &mut tun, &services).await;
        session.udp_state = UdpState::Pending {
            quic_ids: mock_quic_ids().await,
            backoff: ReconnectBackoff::new(
                config.timing.reconnect_min,
                config.timing.reconnect_max,
            ),
            reconnect_at: Instant::now(),
            registration: None,
        };
        write_gate.park();

        let err = time::timeout(Duration::from_secs(1), session.attempt_udp_registration())
            .await
            .expect("REGISTER_CID write deadline must fire")
            .expect_err("parked REGISTER_CID write must fail");

        assert!(matches!(
            &err,
            SessionError::Io(source)
                if source.kind() == std::io::ErrorKind::TimedOut
        ));
        assert_eq!(err.exit(), SessionExit::ConnectionError);
    }

    #[tokio::test]
    async fn optional_registration_setup_failure_schedules_retry() {
        let mut config = test_config();
        config.enable_upgrade = true;
        let services = DesktopServices::new();
        let mut tun = tun_channels();
        let (mut session, _server_stream, _write_gate) =
            parkable_session(&config, &mut tun, &services).await;
        session.udp_state = UdpState::Pending {
            quic_ids: mock_quic_ids().await,
            backoff: ReconnectBackoff::new(
                config.timing.reconnect_min,
                config.timing.reconnect_max,
            ),
            reconnect_at: Instant::now(),
            registration: None,
        };
        let retry_started = Instant::now();
        let setup_error = SessionError::Io(std::io::Error::other(
            "failed to duplicate udp discovery socket",
        ));

        let control = session.handle_registration_setup_failure(&setup_error);

        assert_eq!(control, SessionControl::Continue);
        let UdpState::Pending {
            reconnect_at,
            registration,
            ..
        } = &session.udp_state
        else {
            panic!("optional setup failure must keep pending registration state");
        };
        assert!(*reconnect_at > retry_started);
        assert!(registration.is_none());
    }

    #[tokio::test]
    async fn required_registration_setup_failure_is_fatal() {
        let mut config = test_config();
        config.enable_upgrade = true;
        config.require_udp = true;
        let services = DesktopServices::new();
        let mut tun = tun_channels();
        let (mut session, _server_stream, _write_gate) =
            parkable_session(&config, &mut tun, &services).await;
        let original_reconnect_at = Instant::now();
        session.udp_state = UdpState::Pending {
            quic_ids: mock_quic_ids().await,
            backoff: ReconnectBackoff::new(
                config.timing.reconnect_min,
                config.timing.reconnect_max,
            ),
            reconnect_at: original_reconnect_at,
            registration: None,
        };
        let setup_error = SessionError::Io(std::io::Error::other(
            "failed to duplicate udp discovery socket",
        ));

        let control = session.handle_registration_setup_failure(&setup_error);

        assert_eq!(
            control,
            SessionControl::Close(SessionExit::UdpUpgradeRequired)
        );
        let UdpState::Pending { reconnect_at, .. } = &session.udp_state else {
            panic!("required setup failure must leave pending state intact");
        };
        assert_eq!(*reconnect_at, original_reconnect_at);
    }
}
