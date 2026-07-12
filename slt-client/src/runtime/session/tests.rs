use std::sync::Arc;
use std::time::{Duration, Instant};

use slt_core::config::ClientConfig;
use slt_core::crypto::udp_qsp::{QspSessionError, QuicQspSession, UdpQspKeys};
use slt_core::proto::{
    CipherSuite, CloseCode, ClosePayload, FallbackOkPayload, FallbackToTcpPayload, FrameError,
    Message, MessageError, MessageType, OwnedMessageBuf, SwitchAckPayload, SwitchOkPayload,
    SwitchToUdpPayload, decode_message, encode_message,
};
use slt_core::transport::tcp::TcpChannel;
use slt_core::types::{Cid, MAX_DCID_LEN};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time;
use tokio_boring::SslStream;
use tokio_util::sync::CancellationToken;

use super::{
    ActiveTransport, ClientSession, SessionControl, SessionError, SessionEvent, SessionExit,
    TunScheduling, UdpState, UdpUpgradeState,
};
use crate::metrics::Metrics;
use crate::runtime::ReconnectBackoff;
use crate::runtime::observer::TransportChangeReason;
use crate::runtime::services::DesktopServices;
use crate::test_support::{
    ParkableWriteStream, WriteGate, make_server_keys, make_test_keys, mock_quic_ids, test_config,
    tls_pair_with_parkable_client_writes, tls_tcp_stream_pair,
};
use crate::transport::tcp::{ClientKeyUpdater, TcpSession};
use crate::transport::udp_qsp::{ClientTransport, ClientUdpQspIo, UdpQspError, client_udp_qsp_io};
use crate::tun::TunChannels;

async fn test_session<'a>(
    config: &'a ClientConfig,
    tun: &'a mut TunChannels,
    services: &'a DesktopServices,
) -> (
    ClientSession<'a, DesktopServices>,
    SslStream<tokio::net::TcpStream>,
) {
    let metrics = Arc::new(Metrics::default());
    let updater = ClientKeyUpdater::new(metrics.clone());
    let (client_stream, server_stream) = tls_tcp_stream_pair().await;
    let tcp_session = TcpSession {
        transport: TcpChannel::with_key_updater(client_stream, updater),
        peer: None,
        sni: None,
    };
    (
        ClientSession::new(
            config,
            tcp_session,
            tun,
            CancellationToken::new(),
            metrics,
            services,
            None,
        ),
        server_stream,
    )
}

async fn parkable_test_session<'a>(
    config: &'a ClientConfig,
    tun: &'a mut TunChannels,
    services: &'a DesktopServices,
    cancel: CancellationToken,
) -> (
    ClientSession<'a, DesktopServices, ParkableWriteStream>,
    SslStream<DuplexStream>,
    Arc<WriteGate>,
) {
    let metrics = Arc::new(Metrics::default());
    let updater = ClientKeyUpdater::new(metrics.clone());
    let (client_stream, server_stream, write_gate) = tls_pair_with_parkable_client_writes().await;
    let tcp_session = TcpSession {
        transport: TcpChannel::with_key_updater(client_stream, updater),
        peer: None,
        sni: None,
    };
    (
        ClientSession::new(config, tcp_session, tun, cancel, metrics, services, None),
        server_stream,
        write_gate,
    )
}

fn data_message(packet: &[u8]) -> OwnedMessageBuf {
    let mut frame = Vec::new();
    encode_message(Message::Data { packet }, &mut frame).unwrap();
    OwnedMessageBuf::new(MessageType::Data, frame)
}

async fn test_udp_transport() -> ClientTransport {
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let peer = "127.0.0.1:443".parse().unwrap();
    let io = client_udp_qsp_io(&socket, peer).unwrap();
    let keys = UdpQspKeys::from_packet_material(
        CipherSuite::Aes128Gcm,
        [0; 16],
        [0; 16],
        [0; 16],
        [0; 16],
        [0; 12],
        [0; 12],
    )
    .unwrap();
    let session = QuicQspSession::new(
        io,
        Cid::from([0xBB; MAX_DCID_LEN]),
        Cid::from([0xAA; MAX_DCID_LEN]),
        keys,
        0,
        0,
        false,
    );
    ClientTransport::new(session, Arc::new(Metrics::default()))
}

async fn paired_udp_transports() -> (ClientTransport, QuicQspSession<ClientUdpQspIo>) {
    let client_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let server_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let client_addr = client_socket.local_addr().unwrap();
    let server_addr = server_socket.local_addr().unwrap();
    let scid = Cid::from([0xA1; 20]);
    let dcid = Cid::from([0xB2; 20]);

    let client_io = client_udp_qsp_io(&client_socket, server_addr).unwrap();
    let client_qsp = QuicQspSession::new(client_io, scid, dcid, make_test_keys(), 0, 0, false);
    let client = ClientTransport::new(client_qsp, Arc::new(Metrics::default()));

    let server_io = client_udp_qsp_io(&server_socket, client_addr).unwrap();
    let server = QuicQspSession::new(server_io, dcid, scid, make_server_keys(), 0, 0, false);
    (client, server)
}

#[test]
fn tun_scheduling_preserves_partial_udp_flush_progress() {
    assert!(!TunScheduling::UdpFlush.defer_tun(true, true, true));
    assert!(!TunScheduling::BatchablePacket.defer_tun(true, true, true));
    assert!(TunScheduling::NonBatchingTun.defer_tun(false, true, true));
    assert!(!TunScheduling::NonBatchingTun.defer_tun(false, false, true));
    assert!(TunScheduling::Unchanged.defer_tun(true, true, true));
    assert!(!TunScheduling::Unchanged.defer_tun(true, true, false));
}

#[tokio::test]
async fn udp_data_is_accepted_while_tcp_is_preferred() {
    let config = test_config();
    let services = DesktopServices::new();
    let (_tun_tx, to_session_rx) = mpsc::channel(1);
    let (to_tun_tx, mut to_tun_rx) = mpsc::channel(1);
    let mut tun = TunChannels {
        to_session_rx,
        to_tun_tx,
    };
    let (mut session, _server_stream) = test_session(&config, &mut tun, &services).await;
    let packet = b"authenticated udp data";

    assert_eq!(
        session
            .handle_udp_message(data_message(packet))
            .await
            .unwrap(),
        SessionControl::Continue
    );
    assert_eq!(session.active_transport, ActiveTransport::Tcp);
    let delivered = to_tun_rx.try_recv().unwrap();
    assert!(matches!(
        delivered.message(),
        Message::Data { packet: delivered_packet } if delivered_packet == packet
    ));
}

#[tokio::test]
async fn tcp_data_is_accepted_while_udp_is_preferred() {
    let config = test_config();
    let services = DesktopServices::new();
    let (_tun_tx, to_session_rx) = mpsc::channel(1);
    let (to_tun_tx, mut to_tun_rx) = mpsc::channel(1);
    let mut tun = TunChannels {
        to_session_rx,
        to_tun_tx,
    };
    let (mut session, mut server_stream) = test_session(&config, &mut tun, &services).await;
    session.active_transport = ActiveTransport::UdpQsp;
    let packet = b"late tcp data";
    let mut frame = Vec::new();
    encode_message(Message::Data { packet }, &mut frame).unwrap();
    server_stream.write_all(&frame).await.unwrap();

    assert_ne!(session.tcp.read_more().await.unwrap(), 0);
    assert_eq!(
        session.handle_tcp_read().await.unwrap(),
        SessionControl::Continue
    );
    assert_eq!(session.active_transport, ActiveTransport::UdpQsp);
    let delivered = to_tun_rx.try_recv().unwrap();
    assert!(matches!(
        delivered.message(),
        Message::Data { packet: delivered_packet } if delivered_packet == packet
    ));
}

#[tokio::test]
async fn fallback_request_precedes_retried_tcp_data() {
    let config = test_config();
    let services = DesktopServices::new();
    let (_tun_tx, to_session_rx) = mpsc::channel(1);
    let (to_tun_tx, _to_tun_rx) = mpsc::channel(1);
    let mut tun = TunChannels {
        to_session_rx,
        to_tun_tx,
    };
    let (mut session, server_stream) = test_session(&config, &mut tun, &services).await;
    let mut server = TcpChannel::new(server_stream);
    session.active_transport = ActiveTransport::UdpQsp;
    session
        .request_tcp_fallback(TransportChangeReason::UdpError)
        .await
        .unwrap();
    let packet = vec![0x45; 20];
    assert_eq!(
        session.handle_tun_packet(packet.clone()).await.unwrap(),
        SessionControl::Continue
    );

    assert_ne!(server.read_more().await.unwrap(), 0);
    let request = server.try_pop_message(session.limits).unwrap().unwrap();
    let Message::FallbackToTcp { payload } = request.message() else {
        panic!("expected fallback request before tcp data");
    };
    let fallback_id = FallbackToTcpPayload::decode(payload).unwrap().fallback_id;
    assert_eq!(session.pending_tcp_fallback, Some(fallback_id));

    let data = loop {
        if let Some(message) = server.try_pop_message(session.limits).unwrap() {
            break message;
        }
        assert_ne!(server.read_more().await.unwrap(), 0);
    };
    assert!(matches!(
        data.message(),
        Message::Data { packet: delivered_packet } if delivered_packet == packet
    ));
    assert_eq!(session.active_transport, ActiveTransport::Tcp);
}

#[tokio::test]
async fn duplicate_server_fallback_preserves_replacement_registration() {
    let mut config = test_config();
    config.enable_upgrade = true;
    let services = DesktopServices::new();
    let (_tun_tx, to_session_rx) = mpsc::channel(1);
    let (to_tun_tx, _to_tun_rx) = mpsc::channel(1);
    let mut tun = TunChannels {
        to_session_rx,
        to_tun_tx,
    };
    let (mut session, mut server_stream) = test_session(&config, &mut tun, &services).await;
    session.active_transport = ActiveTransport::UdpQsp;
    session.udp_state = UdpState::Active(Box::new(test_udp_transport().await));
    session
        .write_active_message(Message::Data {
            packet: b"queued udp uplink",
        })
        .await
        .unwrap();
    assert!(session.udp_state.as_active().unwrap().has_pending_flush());
    let fallback_id = 0xFA11_BACC;
    let request = FallbackToTcpPayload { fallback_id };
    let mut payload = Vec::new();
    request.encode(&mut payload);
    let mut frame = Vec::new();
    encode_message(Message::FallbackToTcp { payload: &payload }, &mut frame).unwrap();
    server_stream.write_all(&frame).await.unwrap();

    assert_ne!(session.tcp.read_more().await.unwrap(), 0);
    assert_eq!(
        session.handle_tcp_read().await.unwrap(),
        SessionControl::Continue
    );
    assert_eq!(session.active_transport, ActiveTransport::Tcp);
    assert!(matches!(session.udp_state, UdpState::NeedDiscovery { .. }));
    assert!(session.retained_udp_transport.is_some());
    assert!(session.udp_receive_transport().is_some());
    assert!(
        !session
            .retained_udp_transport
            .as_ref()
            .unwrap()
            .has_pending_flush()
    );

    let mut server = TcpChannel::new(server_stream);
    assert_ne!(server.read_more().await.unwrap(), 0);
    let ack = server.try_pop_message(session.limits).unwrap().unwrap();
    let Message::FallbackOk {
        payload: ack_payload,
    } = ack.message()
    else {
        panic!("expected fallback acknowledgement");
    };
    assert_eq!(
        FallbackOkPayload::decode(ack_payload).unwrap().fallback_id,
        fallback_id
    );
    assert_eq!(session.last_peer_fallback_id, Some(fallback_id));

    let quic_ids = mock_quic_ids().await;
    let expected_dcid = quic_ids.dcid;
    session.udp_state = UdpState::Pending {
        quic_ids,
        backoff: ReconnectBackoff::new(config.timing.reconnect_min, config.timing.reconnect_max),
        reconnect_at: Instant::now(),
        registration: None,
    };
    assert_eq!(
        session.attempt_udp_registration().await.unwrap(),
        SessionControl::Continue
    );
    let registration_deadline = session.udp_state.register_deadline().unwrap();

    let registration = loop {
        if let Some(message) = server.try_pop_message(session.limits).unwrap() {
            break message;
        }
        assert_ne!(server.read_more().await.unwrap(), 0);
    };
    assert!(matches!(
        registration.message(),
        Message::RegisterCid { .. }
    ));

    server
        .write_message(Message::FallbackToTcp { payload: &payload })
        .await
        .unwrap();
    assert_ne!(session.tcp.read_more().await.unwrap(), 0);
    assert_eq!(
        session.handle_tcp_read().await.unwrap(),
        SessionControl::Continue
    );

    let UdpState::Pending {
        quic_ids,
        registration,
        ..
    } = &session.udp_state
    else {
        panic!("duplicate fallback replaced pending registration state");
    };
    assert_eq!(quic_ids.dcid, expected_dcid);
    assert!(registration.is_some());
    assert_eq!(
        session.udp_state.register_deadline(),
        Some(registration_deadline)
    );
    assert!(session.retained_udp_transport.is_some());

    assert_ne!(server.read_more().await.unwrap(), 0);
    let duplicate_ack = server.try_pop_message(session.limits).unwrap().unwrap();
    let Message::FallbackOk { payload } = duplicate_ack.message() else {
        panic!("expected duplicate fallback acknowledgement");
    };
    assert_eq!(
        FallbackOkPayload::decode(payload).unwrap().fallback_id,
        fallback_id
    );
}

#[tokio::test]
async fn disabled_client_does_not_start_udp_discovery_after_fallback() {
    let mut config = test_config();
    config.enable_upgrade = false;
    config.require_udp = false;
    let services = DesktopServices::new();
    let (_tun_tx, to_session_rx) = mpsc::channel(1);
    let (to_tun_tx, _to_tun_rx) = mpsc::channel(1);
    let mut tun = TunChannels {
        to_session_rx,
        to_tun_tx,
    };
    let (mut session, mut server_stream) = test_session(&config, &mut tun, &services).await;
    let request = FallbackToTcpPayload { fallback_id: 42 };
    let mut payload = Vec::new();
    request.encode(&mut payload);
    let mut frame = Vec::new();
    encode_message(Message::FallbackToTcp { payload: &payload }, &mut frame).unwrap();
    server_stream.write_all(&frame).await.unwrap();

    assert_ne!(session.tcp.read_more().await.unwrap(), 0);
    assert_eq!(
        session.handle_tcp_read().await.unwrap(),
        SessionControl::Continue
    );
    assert!(matches!(session.udp_state, UdpState::Disabled));
    assert!(matches!(session.udp_upgrade, UdpUpgradeState::Disabled));
    assert!(session.retained_udp_transport.is_none());
}

#[tokio::test]
async fn retained_udp_failure_preserves_in_flight_registration() {
    let mut config = test_config();
    config.enable_upgrade = true;
    let services = DesktopServices::new();
    let (_tun_tx, to_session_rx) = mpsc::channel(1);
    let (to_tun_tx, _to_tun_rx) = mpsc::channel(1);
    let mut tun = TunChannels {
        to_session_rx,
        to_tun_tx,
    };
    let (mut session, _server_stream) = test_session(&config, &mut tun, &services).await;
    let quic_ids = mock_quic_ids().await;
    let expected_dcid = quic_ids.dcid;
    session.udp_state = UdpState::Pending {
        quic_ids,
        backoff: ReconnectBackoff::new(config.timing.reconnect_min, config.timing.reconnect_max),
        reconnect_at: Instant::now(),
        registration: None,
    };
    assert_eq!(
        session.attempt_udp_registration().await.unwrap(),
        SessionControl::Continue
    );
    session.retained_udp_transport = Some(Box::new(test_udp_transport().await));

    let error = SessionError::from(UdpQspError::from(QspSessionError::PacketNumberOverflow));
    assert!(session.handle_udp_error(&error).await.unwrap());

    assert!(session.retained_udp_transport.is_none());
    assert!(session.pending_tcp_fallback.is_none());
    let UdpState::Pending {
        quic_ids,
        registration,
        ..
    } = &session.udp_state
    else {
        panic!("retained path failure replaced pending registration state");
    };
    assert_eq!(quic_ids.dcid, expected_dcid);
    assert!(registration.is_some());
}

#[tokio::test]
async fn switch_to_udp_waits_for_switch_ok_before_committing() {
    let config = test_config();
    let services = DesktopServices::new();
    let (_tun_tx, to_session_rx) = mpsc::channel(1);
    let (to_tun_tx, _to_tun_rx) = mpsc::channel(1);
    let mut tun = TunChannels {
        to_session_rx,
        to_tun_tx,
    };
    let (mut session, server_stream) = test_session(&config, &mut tun, &services).await;
    let mut server = TcpChannel::new(server_stream);
    let upgrade_id = 0x5A17_CAFE;
    session.udp_upgrade = UdpUpgradeState::Upgrading {
        upgrade_id,
        deadline: Instant::now() + config.timing.register_timeout,
        attempts: 1,
        next_probe_at: Instant::now() + config.timing.reconnect_min,
        probe_nonce: 7,
        probe_acked: true,
        ready_sent: true,
        probe_backoff: ReconnectBackoff::new(
            config.timing.reconnect_min,
            config.timing.reconnect_max,
        ),
    };
    let switch = SwitchToUdpPayload { upgrade_id };
    let mut payload = Vec::new();
    switch.encode(&mut payload);

    assert_eq!(
        session.handle_switch_to_udp(&payload).await.unwrap(),
        SessionControl::Continue
    );
    assert_eq!(session.active_transport, ActiveTransport::Tcp);
    assert!(matches!(
        session.udp_upgrade,
        UdpUpgradeState::AwaitingSwitchOk {
            upgrade_id: pending_id,
            ..
        } if pending_id == upgrade_id
    ));

    assert_ne!(server.read_more().await.unwrap(), 0);
    let ack = server.try_pop_message(session.limits).unwrap().unwrap();
    let Message::SwitchAck {
        payload: ack_payload,
    } = ack.message()
    else {
        panic!("expected switch_ack");
    };
    assert_eq!(
        SwitchAckPayload::decode(ack_payload).unwrap().upgrade_id,
        upgrade_id
    );
    assert!(
        time::timeout(Duration::from_millis(25), server.read_more())
            .await
            .is_err(),
        "client emitted a post-ack barrier frame"
    );

    let confirmation = SwitchOkPayload { upgrade_id };
    payload.clear();
    confirmation.encode(&mut payload);
    server
        .write_message(Message::SwitchOk { payload: &payload })
        .await
        .unwrap();
    assert_ne!(session.tcp.read_more().await.unwrap(), 0);
    assert_eq!(
        session.handle_tcp_read().await.unwrap(),
        SessionControl::Continue
    );
    assert_eq!(session.active_transport, ActiveTransport::UdpQsp);
    assert!(matches!(session.udp_upgrade, UdpUpgradeState::Idle));
}

#[tokio::test]
async fn tcp_eof_before_switch_ok_reconnects_without_preferring_udp() {
    let config = test_config();
    let services = DesktopServices::new();
    let (_tun_tx, to_session_rx) = mpsc::channel(1);
    let (to_tun_tx, _to_tun_rx) = mpsc::channel(1);
    let mut tun = TunChannels {
        to_session_rx,
        to_tun_tx,
    };
    let (mut session, _server_stream) = test_session(&config, &mut tun, &services).await;
    session.udp_upgrade = UdpUpgradeState::AwaitingSwitchOk {
        upgrade_id: 17,
        deadline: Instant::now() + config.timing.register_timeout,
    };

    let mut next_ping_at = session.schedule_next_ping();
    assert_eq!(
        session
            .handle_event(SessionEvent::TcpRead(0), &mut next_ping_at)
            .await
            .unwrap(),
        SessionControl::Close(SessionExit::TcpClosed)
    );
    assert_eq!(session.active_transport, ActiveTransport::Tcp);
}

#[tokio::test]
async fn tcp_close_terminates_udp_preferred_session() {
    let config = test_config();
    let services = DesktopServices::new();
    let (_tun_tx, to_session_rx) = mpsc::channel(1);
    let (to_tun_tx, _to_tun_rx) = mpsc::channel(1);
    let mut tun = TunChannels {
        to_session_rx,
        to_tun_tx,
    };
    let (mut session, mut server_stream) = test_session(&config, &mut tun, &services).await;
    session.active_transport = ActiveTransport::UdpQsp;

    let mut close_payload = Vec::new();
    ClosePayload {
        code: CloseCode::ServerRestart,
    }
    .encode(&mut close_payload);
    let mut frame = Vec::new();
    encode_message(
        Message::Close {
            payload: &close_payload,
        },
        &mut frame,
    )
    .unwrap();
    server_stream.write_all(&frame).await.unwrap();

    assert_ne!(session.tcp.read_more().await.unwrap(), 0);
    assert_eq!(
        session.handle_tcp_read().await.unwrap(),
        SessionControl::Close(SessionExit::RemoteClose(CloseCode::ServerRestart))
    );
}

#[tokio::test]
async fn protocol_error_sends_protocol_close_before_session_exit() {
    let config = test_config();
    let services = DesktopServices::new();
    let (_tun_tx, to_session_rx) = mpsc::channel(1);
    let (to_tun_tx, _to_tun_rx) = mpsc::channel(1);
    let mut tun = TunChannels {
        to_session_rx,
        to_tun_tx,
    };
    let (mut session, mut server_stream) = test_session(&config, &mut tun, &services).await;
    server_stream.write_all(&[0xff, 0, 0, 0, 0]).await.unwrap();

    let tun_fault = CancellationToken::new();
    let outcome = time::timeout(Duration::from_secs(1), session.run(&tun_fault))
        .await
        .expect("protocol violation must terminate the session");
    assert_eq!(outcome.exit, SessionExit::ProtocolError);
    assert!(matches!(outcome.error, Some(SessionError::Message(_))));

    let mut close_frame = [0u8; 6];
    time::timeout(
        Duration::from_secs(1),
        server_stream.read_exact(&mut close_frame),
    )
    .await
    .expect("client must attempt a protocol close")
    .unwrap();
    let (message, consumed) = decode_message(&close_frame, session.limits)
        .unwrap()
        .expect("close frame must be complete");
    assert_eq!(consumed, close_frame.len());
    let Message::Close { payload } = message else {
        panic!("expected close message");
    };
    assert_eq!(
        ClosePayload::decode(payload).unwrap().code,
        CloseCode::ProtocolError
    );
}

#[tokio::test]
async fn network_change_propagates_authenticated_udp_protocol_error() {
    let mut config = test_config();
    config.timing.register_timeout = Duration::from_millis(50);
    let services = DesktopServices::new();
    let (_tun_tx, to_session_rx) = mpsc::channel(1);
    let (to_tun_tx, _to_tun_rx) = mpsc::channel(1);
    let mut tun = TunChannels {
        to_session_rx,
        to_tun_tx,
    };
    let (mut session, _server_stream) = test_session(&config, &mut tun, &services).await;

    let client_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let server_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let client_addr = client_socket.local_addr().unwrap();
    let server_addr = server_socket.local_addr().unwrap();
    let scid = Cid::from([0xA1; 20]);
    let dcid = Cid::from([0xB2; 20]);

    let client_io = client_udp_qsp_io(&client_socket, server_addr).unwrap();
    let client_qsp = QuicQspSession::new(client_io, scid, dcid, make_test_keys(), 0, 0, false);
    session.udp_state = UdpState::Active(Box::new(ClientTransport::new(
        client_qsp,
        Arc::new(Metrics::default()),
    )));
    session.active_transport = ActiveTransport::UdpQsp;

    let server_io = client_udp_qsp_io(&server_socket, client_addr).unwrap();
    let mut server_qsp =
        QuicQspSession::new(server_io, dcid, scid, make_server_keys(), 0, 0, false);
    server_qsp.send(&[0xff, 0, 0, 0, 0]).await.unwrap();
    server_qsp.flush().await.unwrap();

    let err = time::timeout(Duration::from_secs(1), session.handle_network_changed())
        .await
        .expect("authenticated protocol failure must not enter refresh recovery")
        .unwrap_err();
    assert!(matches!(
        &err,
        SessionError::Message(MessageError::Frame(FrameError::UnknownType(0xff)))
    ));
    assert_eq!(err.exit(), SessionExit::ProtocolError);
    assert_eq!(session.active_transport, ActiveTransport::UdpQsp);
    assert!(session.pending_tcp_fallback.is_none());
}

#[tokio::test]
async fn switch_ok_timeout_synchronizes_tcp_fallback() {
    let mut config = test_config();
    config.enable_upgrade = true;
    let services = DesktopServices::new();
    let (_tun_tx, to_session_rx) = mpsc::channel(1);
    let (to_tun_tx, _to_tun_rx) = mpsc::channel(1);
    let mut tun = TunChannels {
        to_session_rx,
        to_tun_tx,
    };
    let (mut session, server_stream) = test_session(&config, &mut tun, &services).await;
    let mut server = TcpChannel::new(server_stream);
    session.udp_upgrade = UdpUpgradeState::AwaitingSwitchOk {
        upgrade_id: 23,
        deadline: Instant::now() - Duration::from_millis(1),
    };

    assert_eq!(
        session.handle_udp_upgrade_tick().await.unwrap(),
        SessionControl::Continue
    );
    assert!(matches!(
        session.udp_upgrade,
        UdpUpgradeState::TcpOnlyBlockedUdp { .. }
    ));
    assert_ne!(server.read_more().await.unwrap(), 0);
    let request = server.try_pop_message(session.limits).unwrap().unwrap();
    assert!(matches!(request.message(), Message::FallbackToTcp { .. }));
}

#[tokio::test]
async fn saturated_tcp_tun_and_udp_sources_are_polled_fairly() {
    const MAX_POLLS: usize = 128;

    let config = test_config();
    let services = DesktopServices::new();
    let packet = vec![0x45; 20];
    let (tun_tx, to_session_rx) = mpsc::channel(1);
    let (to_tun_tx, _to_tun_rx) = mpsc::channel::<OwnedMessageBuf>(1);
    tun_tx.try_send(packet.clone()).unwrap();
    let mut tun = TunChannels {
        to_session_rx,
        to_tun_tx,
    };
    let (mut session, mut server_stream) = test_session(&config, &mut tun, &services).await;
    let (client_udp, mut server_udp) = paired_udp_transports().await;
    session.udp_state = UdpState::Active(Box::new(client_udp));

    let mut frame = Vec::new();
    encode_message(
        Message::Data {
            packet: packet.as_slice(),
        },
        &mut frame,
    )
    .unwrap();
    for _ in 0..16 {
        server_udp.send(&frame).await.unwrap();
    }
    server_udp.flush().await.unwrap();
    let limits = session.limits;
    session
        .udp_receive_transport_mut()
        .unwrap()
        .read_next_message(limits)
        .await
        .unwrap();
    server_stream.write_all(&frame).await.unwrap();

    let mut tcp_seen = 0;
    let mut tun_seen = 0;
    let mut udp_seen = 0;
    for _ in 0..MAX_POLLS {
        let event = time::timeout(
            Duration::from_secs(1),
            session.poll_event(Instant::now() + Duration::from_secs(60), true),
        )
        .await
        .expect("saturated source must remain ready")
        .unwrap();

        match event {
            SessionEvent::TcpRead(n) => {
                assert_ne!(n, 0);
                tcp_seen += 1;
                server_stream.write_all(&frame).await.unwrap();
            }
            SessionEvent::TunPacket(Some(received)) => {
                assert_eq!(received, packet);
                tun_seen += 1;
                tun_tx.try_send(packet.clone()).unwrap();
            }
            SessionEvent::UdpResult(Ok(_)) => {
                udp_seen += 1;
                server_udp.send(&frame).await.unwrap();
                server_udp.flush().await.unwrap();
            }
            SessionEvent::UdpResult(Err(err)) => panic!("UDP source failed: {err}"),
            _ => panic!("unexpected event while packet sources are saturated"),
        }

        if tcp_seen != 0 && tun_seen != 0 && udp_seen != 0 {
            break;
        }
    }

    assert_ne!(tcp_seen, 0, "ready TCP source was not selected");
    assert_ne!(tun_seen, 0, "ready TUN source was starved by TCP");
    assert_ne!(udp_seen, 0, "ready UDP source was starved by TCP or TUN");
}

#[tokio::test]
async fn saturated_tcp_and_udp_reads_cannot_starve_partial_udp_flush() {
    const MAX_POLLS: usize = 128;

    let config = test_config();
    let services = DesktopServices::new();
    let (tun_tx, to_session_rx) = mpsc::channel::<Vec<u8>>(1);
    let (to_tun_tx, _to_tun_rx) = mpsc::channel::<OwnedMessageBuf>(1);
    let mut tun = TunChannels {
        to_session_rx,
        to_tun_tx,
    };
    let (mut session, mut server_stream) = test_session(&config, &mut tun, &services).await;
    let (client_udp, mut server_udp) = paired_udp_transports().await;
    session.udp_state = UdpState::Active(Box::new(client_udp));
    session.active_transport = ActiveTransport::UdpQsp;

    let pending_packet = vec![0x45; 20];
    session
        .write_active_message(Message::Data {
            packet: pending_packet.as_slice(),
        })
        .await
        .unwrap();
    assert!(session.has_pending_udp_flush());

    let saturated_packet = vec![0x46; 20];
    let mut saturated_frame = Vec::new();
    encode_message(
        Message::Data {
            packet: saturated_packet.as_slice(),
        },
        &mut saturated_frame,
    )
    .unwrap();
    for _ in 0..16 {
        server_udp.send(&saturated_frame).await.unwrap();
    }
    server_udp.flush().await.unwrap();
    let limits = session.limits;
    session
        .udp_receive_transport_mut()
        .unwrap()
        .read_next_message(limits)
        .await
        .unwrap();
    server_stream.write_all(&saturated_frame).await.unwrap();

    let mut flush_seen = false;
    let mut next_ping_at = Instant::now() + Duration::from_secs(60);
    for _ in 0..MAX_POLLS {
        let event = time::timeout(
            Duration::from_secs(1),
            session.poll_event(next_ping_at, true),
        )
        .await
        .expect("saturated source must remain ready")
        .unwrap();

        match event {
            SessionEvent::TcpRead(n) => {
                assert_ne!(n, 0);
                server_stream.write_all(&saturated_frame).await.unwrap();
            }
            SessionEvent::UdpResult(Ok(_)) => {
                server_udp.send(&saturated_frame).await.unwrap();
                server_udp.flush().await.unwrap();
            }
            SessionEvent::UdpFlushReady => {
                assert_eq!(
                    session
                        .handle_event(SessionEvent::UdpFlushReady, &mut next_ping_at)
                        .await
                        .unwrap(),
                    SessionControl::Continue
                );
                flush_seen = true;
                break;
            }
            SessionEvent::UdpResult(Err(err)) => panic!("UDP source failed: {err}"),
            _ => panic!("unexpected event while reads and flush are saturated"),
        }
    }
    drop(tun_tx);

    assert!(
        flush_seen,
        "ready TCP or UDP reads starved the partial flush"
    );
    assert!(!session.has_pending_udp_flush());

    let mut packet_buf = vec![0u8; 2048];
    let opened = time::timeout(Duration::from_secs(1), server_udp.recv(&mut packet_buf))
        .await
        .expect("server must receive the flushed packet")
        .unwrap();
    let (message, consumed) = decode_message(&opened.payload, session.limits)
        .unwrap()
        .expect("flushed packet must contain a complete message");
    assert_eq!(consumed, opened.payload.len());
    assert!(matches!(
        message,
        Message::Data { packet } if packet == pending_packet
    ));
}

#[tokio::test]
async fn expired_idle_deadline_preempts_ready_tun_packet() {
    let config = test_config();
    let services = DesktopServices::new();
    let (tun_tx, to_session_rx) = mpsc::channel(1);
    let (to_tun_tx, _to_tun_rx) = mpsc::channel::<OwnedMessageBuf>(1);
    tun_tx.try_send(vec![0x45; 20]).unwrap();
    let mut tun = TunChannels {
        to_session_rx,
        to_tun_tx,
    };
    let (mut session, _server_stream) = test_session(&config, &mut tun, &services).await;
    session.last_tcp_rx = Instant::now() - config.timing.idle_timeout - Duration::from_millis(1);

    let event = session
        .poll_event(Instant::now() + Duration::from_secs(60), true)
        .await
        .unwrap();

    assert!(matches!(event, SessionEvent::IdleTimeout));
}

#[tokio::test]
async fn expired_ping_deadline_preempts_ready_tun_packet() {
    let config = test_config();
    let services = DesktopServices::new();
    let (tun_tx, to_session_rx) = mpsc::channel(1);
    let (to_tun_tx, _to_tun_rx) = mpsc::channel::<OwnedMessageBuf>(1);
    tun_tx.try_send(vec![0x45; 20]).unwrap();
    let mut tun = TunChannels {
        to_session_rx,
        to_tun_tx,
    };
    let (mut session, _server_stream) = test_session(&config, &mut tun, &services).await;

    let event = session
        .poll_event(Instant::now() - Duration::from_millis(1), true)
        .await
        .unwrap();

    assert!(matches!(event, SessionEvent::PingTick));
}

#[tokio::test]
async fn established_tcp_write_timeout_exits_for_reconnect() {
    let mut config = test_config();
    config.timing.tcp_write_timeout = Duration::from_millis(40);
    let services = DesktopServices::new();
    let (tun_tx, to_session_rx) = mpsc::channel(1);
    let (to_tun_tx, _to_tun_rx) = mpsc::channel::<OwnedMessageBuf>(1);
    tun_tx.try_send(vec![0x45; 20]).unwrap();
    let mut tun = TunChannels {
        to_session_rx,
        to_tun_tx,
    };
    let (mut session, _server_stream, write_gate) =
        parkable_test_session(&config, &mut tun, &services, CancellationToken::new()).await;
    write_gate.park();

    let tun_fault = CancellationToken::new();
    let outcome = time::timeout(Duration::from_secs(1), session.run(&tun_fault))
        .await
        .expect("parked DATA write must observe its deadline");

    assert_eq!(outcome.exit, SessionExit::ConnectionError);
    assert!(matches!(
        outcome.error,
        Some(SessionError::Io(ref source))
            if source.kind() == std::io::ErrorKind::TimedOut
    ));
    time::timeout(
        Duration::from_secs(1),
        write_gate.wait_until_write_blocked(),
    )
    .await
    .expect("DATA write reached the parked transport");
}

#[tokio::test]
async fn internal_tun_fault_cleanup_does_not_count_shutdown() {
    let config = test_config();
    let services = DesktopServices::new();
    let (_tun_tx, to_session_rx) = mpsc::channel(1);
    let (to_tun_tx, _to_tun_rx) = mpsc::channel(1);
    let mut tun = TunChannels {
        to_session_rx,
        to_tun_tx,
    };
    let metrics = Arc::new(Metrics::default());
    let updater = ClientKeyUpdater::new(metrics.clone());
    let (client_stream, _server_stream) = tls_tcp_stream_pair().await;
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
        metrics.clone(),
        &services,
        None,
    );
    let tun_fault = CancellationToken::new();
    tun_fault.cancel();

    let outcome = session.run(&tun_fault).await;

    assert_eq!(outcome.exit, SessionExit::TunFault);
    assert!(outcome.error.is_none());
    let snapshot = metrics.snapshot();
    assert_eq!(snapshot.disconnect_error, 0);
    assert_eq!(snapshot.disconnect_shutdown, 0);
}

#[tokio::test]
async fn shutdown_cancels_blocked_established_tcp_write() {
    let mut config = test_config();
    config.timing.tcp_write_timeout = Duration::from_secs(60);
    let services = DesktopServices::new();
    let cancel = CancellationToken::new();
    let (tun_tx, to_session_rx) = mpsc::channel(1);
    let (to_tun_tx, _to_tun_rx) = mpsc::channel::<OwnedMessageBuf>(1);
    tun_tx.try_send(vec![0x45; 20]).unwrap();
    let mut tun = TunChannels {
        to_session_rx,
        to_tun_tx,
    };
    let (mut session, _server_stream, write_gate) =
        parkable_test_session(&config, &mut tun, &services, cancel.clone()).await;
    write_gate.park();
    let tun_fault = CancellationToken::new();
    let run = session.run(&tun_fault);
    tokio::pin!(run);

    time::timeout(Duration::from_secs(1), async {
        tokio::select! {
            outcome = &mut run => panic!("session exited before cancellation: {:?}", outcome.exit),
            () = write_gate.wait_until_write_blocked() => {}
        }
    })
    .await
    .expect("DATA write reached the parked transport");

    // The parked write does not register a waker. Cancellation wakes the
    // outer session guard, which drops that write before sending CLOSE.
    write_gate.unpark();
    cancel.cancel();
    let outcome = time::timeout(Duration::from_secs(1), &mut run)
        .await
        .expect("shutdown must cancel the parked DATA write");

    assert_eq!(outcome.exit, SessionExit::Shutdown);
    assert!(outcome.error.is_none());
}
