use std::net::{Ipv4Addr, SocketAddr};

use slt_core::proto::{
    CipherSuite, CloseCode, ClosePayload, FallbackOkPayload, FallbackToTcpPayload, FrameError,
    Message, MessageError, PayloadError, PingPayload, PongPayload, decode_message, encode_message,
};
use slt_core::types::{Cid, MAX_DCID_LEN};
use tokio::io::AsyncWriteExt;
use tokio::time::{Duration, timeout};

use super::super::*;
use super::common::{
    complete_udp_upgrade_handshake, ipv4_packet, make_register_payload, read_close_code,
    read_message_bytes, spawn_session,
};

#[tokio::test]
async fn session_responds_to_tcp_ping() {
    let (join, mut client, tx, _tun_rx, _udp_rx, limits, _assigned, _registry) =
        spawn_session().await;
    let nonce = 0xA1B2_C3D4_E5F6_0708;
    let ping_payload = PingPayload { nonce };
    let mut ping_payload_bytes = Vec::new();
    ping_payload.encode(&mut ping_payload_bytes);
    let mut frame = Vec::new();
    encode_message(
        Message::Ping {
            payload: &ping_payload_bytes,
        },
        &mut frame,
    )
    .unwrap();
    client.write_all(&frame).await.unwrap();

    let buf = timeout(
        Duration::from_secs(1),
        read_message_bytes(&mut client, limits),
    )
    .await
    .unwrap()
    .unwrap();
    let (message, _) = decode_message(&buf, limits).unwrap().unwrap();
    match message {
        Message::Pong { payload } => {
            let response_payload = PongPayload::decode(payload).unwrap();
            assert_eq!(response_payload.nonce, nonce);
        }
        _ => panic!("expected pong"),
    }

    let _ = tx.send(SessionEvent::Shutdown).await;
    let _ = join.await.unwrap();
}

#[tokio::test]
async fn session_forwards_tcp_data_to_tun() {
    let (join, mut client, tx, mut tun_rx, _udp_rx, _limits, assigned, _registry) =
        spawn_session().await;
    let packet = ipv4_packet(assigned.addr(), Ipv4Addr::new(192, 0, 2, 1), 8);
    let mut frame = Vec::new();
    encode_message(Message::Data { packet: &packet }, &mut frame).unwrap();
    client.write_all(&frame).await.unwrap();

    let received = timeout(Duration::from_secs(1), tun_rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(received, packet);

    let _ = tx.send(SessionEvent::Shutdown).await;
    let _ = join.await.unwrap();
}

#[tokio::test]
async fn session_drops_spoofed_tcp_data() {
    let (join, mut client, tx, mut tun_rx, _udp_rx, _limits, _assigned, _registry) =
        spawn_session().await;
    let packet = ipv4_packet(Ipv4Addr::new(10, 0, 0, 99), Ipv4Addr::new(192, 0, 2, 1), 8);
    let mut frame = Vec::new();
    encode_message(Message::Data { packet: &packet }, &mut frame).unwrap();
    client.write_all(&frame).await.unwrap();

    match timeout(Duration::from_millis(200), tun_rx.recv()).await {
        Ok(Some(_)) => panic!("unexpected tunneled packet"),
        Ok(None) => panic!("tun channel closed unexpectedly"),
        Err(_) => {}
    }

    let _ = tx.send(SessionEvent::Shutdown).await;
    let _ = join.await.unwrap();
}

#[tokio::test]
async fn session_handles_close_message() {
    let (join, mut client, _tx, _tun_rx, _udp_rx, _limits, _assigned, _registry) =
        spawn_session().await;

    let close = ClosePayload {
        code: CloseCode::ProtocolError,
    };
    let mut payload = Vec::new();
    close.encode(&mut payload);
    let mut frame = Vec::new();
    encode_message(Message::Close { payload: &payload }, &mut frame).unwrap();
    client.write_all(&frame).await.unwrap();

    let result = timeout(Duration::from_secs(1), join)
        .await
        .unwrap()
        .unwrap();
    assert!(result.is_ok());
}

#[tokio::test]
async fn session_rejects_unexpected_control_message() {
    let (join, mut client, _tx, _tun_rx, _udp_rx, limits, _assigned, _registry) =
        spawn_session().await;

    let mut frame = Vec::new();
    encode_message(Message::AuthOk { payload: &[] }, &mut frame).unwrap();
    client.write_all(&frame).await.unwrap();

    assert_eq!(
        read_close_code(&mut client, limits).await,
        CloseCode::ProtocolError
    );

    let result = timeout(Duration::from_secs(1), join)
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(result, Err(SessionError::ProtocolViolation)));
}

#[tokio::test]
async fn session_sends_protocol_close_for_unknown_frame_type() {
    let (join, mut client, _tx, _tun_rx, _udp_rx, limits, _assigned, _registry) =
        spawn_session().await;

    client.write_all(&[0xFF, 0, 0, 0, 0]).await.unwrap();

    assert_eq!(
        read_close_code(&mut client, limits).await,
        CloseCode::ProtocolError
    );
    let result = timeout(Duration::from_secs(1), join)
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        result,
        Err(SessionError::Message(MessageError::Frame(
            FrameError::UnknownType(0xFF)
        )))
    ));
}

#[tokio::test]
async fn session_sends_protocol_close_for_invalid_ping_payload() {
    let (join, mut client, _tx, _tun_rx, _udp_rx, limits, _assigned, _registry) =
        spawn_session().await;

    let mut frame = Vec::new();
    encode_message(Message::Ping { payload: &[] }, &mut frame).unwrap();
    client.write_all(&frame).await.unwrap();

    assert_eq!(
        read_close_code(&mut client, limits).await,
        CloseCode::ProtocolError
    );
    let result = timeout(Duration::from_secs(1), join)
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        result,
        Err(SessionError::Payload(PayloadError::LengthMismatch {
            expected: 8,
            actual: 0
        }))
    ));
}

#[tokio::test]
async fn session_drops_oversized_tun_packet() {
    let (join, mut client, tx, _tun_rx, _udp_rx, limits, assigned, _registry) =
        spawn_session().await;

    // Create a packet larger than max_data_len
    let max_payload = limits.max_data_len - 20; // IPv4 header is 20 bytes
    let oversized_packet = ipv4_packet(
        assigned.addr(),
        Ipv4Addr::new(192, 0, 2, 1),
        max_payload + 100,
    );

    tx.send(SessionEvent::TunPacket(oversized_packet))
        .await
        .unwrap();

    // Should not forward anything to client via TCP
    if let Ok(Ok(_)) = timeout(
        Duration::from_millis(200),
        read_message_bytes(&mut client, limits),
    )
    .await
    {
        panic!("oversized packet should not be forwarded to client")
    }

    let _ = tx.send(SessionEvent::Shutdown).await;
    let _ = join.await.unwrap();
}

#[tokio::test]
async fn session_accepts_tcp_data_when_udp_is_preferred() {
    let (join, mut client, tx, mut tun_rx, mut udp_rx, limits, assigned, _registry) =
        spawn_session().await;

    // Register and activate UDP
    let dcid = Cid::from([0x71; MAX_DCID_LEN]);
    let scid = Cid::from([0x72; MAX_DCID_LEN]);
    let register = make_register_payload(dcid, scid, CipherSuite::Aes128Gcm);
    let mut reg_buf = Vec::new();
    register.encode(&mut reg_buf).unwrap();
    let mut frame = Vec::new();
    encode_message(Message::RegisterCid { payload: &reg_buf }, &mut frame).unwrap();
    client.write_all(&frame).await.unwrap();

    let buf = timeout(
        Duration::from_secs(1),
        read_message_bytes(&mut client, limits),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(matches!(
        decode_message(&buf, limits).unwrap().unwrap().0,
        Message::RegisterOk { .. }
    ));

    let peer = SocketAddr::from(([127, 0, 0, 1], 33333));
    let _ = complete_udp_upgrade_handshake(
        &mut client,
        &tx,
        &mut udp_rx,
        limits,
        &register,
        peer,
        0x1300,
    )
    .await;

    // TCP remains a valid authenticated ingress path while UDP is preferred.
    let tcp_data = ipv4_packet(assigned.addr(), Ipv4Addr::new(192, 0, 2, 21), 8);
    let mut tcp_frame = Vec::new();
    encode_message(Message::Data { packet: &tcp_data }, &mut tcp_frame).unwrap();
    client.write_all(&tcp_frame).await.unwrap();

    let received = timeout(Duration::from_secs(1), tun_rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(received, tcp_data);

    let _ = tx.send(SessionEvent::Shutdown).await;
    let _ = join.await.unwrap();
}

#[tokio::test]
async fn tcp_fallback_precedes_data_and_changes_server_egress() {
    let (join, mut client, tx, mut tun_rx, mut udp_rx, limits, assigned, _registry) =
        spawn_session().await;

    let dcid = Cid::from([0x73; MAX_DCID_LEN]);
    let scid = Cid::from([0x74; MAX_DCID_LEN]);
    let register = make_register_payload(dcid, scid, CipherSuite::Aes128Gcm);
    let mut register_payload = Vec::new();
    register.encode(&mut register_payload).unwrap();
    let mut frame = Vec::new();
    encode_message(
        Message::RegisterCid {
            payload: &register_payload,
        },
        &mut frame,
    )
    .unwrap();
    client.write_all(&frame).await.unwrap();
    let response = timeout(
        Duration::from_secs(1),
        read_message_bytes(&mut client, limits),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(matches!(
        decode_message(&response, limits).unwrap().unwrap().0,
        Message::RegisterOk { .. }
    ));

    let peer = SocketAddr::from(([127, 0, 0, 1], 33334));
    let _ = complete_udp_upgrade_handshake(
        &mut client,
        &tx,
        &mut udp_rx,
        limits,
        &register,
        peer,
        0x1400,
    )
    .await;

    let fallback_id = 0xFA11_BACC;
    let fallback = FallbackToTcpPayload { fallback_id };
    let mut fallback_payload = Vec::new();
    fallback.encode(&mut fallback_payload);
    frame.clear();
    encode_message(
        Message::FallbackToTcp {
            payload: &fallback_payload,
        },
        &mut frame,
    )
    .unwrap();
    let uplink = ipv4_packet(assigned.addr(), Ipv4Addr::new(192, 0, 2, 22), 8);
    encode_message(Message::Data { packet: &uplink }, &mut frame).unwrap();
    client.write_all(&frame).await.unwrap();

    let ack_frame = timeout(
        Duration::from_secs(1),
        read_message_bytes(&mut client, limits),
    )
    .await
    .unwrap()
    .unwrap();
    let Message::FallbackOk { payload } = decode_message(&ack_frame, limits).unwrap().unwrap().0
    else {
        panic!("expected fallback_ok");
    };
    assert_eq!(
        FallbackOkPayload::decode(payload).unwrap().fallback_id,
        fallback_id
    );

    let received = timeout(Duration::from_secs(1), tun_rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(received, uplink);

    let downlink = ipv4_packet(assigned.addr(), Ipv4Addr::new(192, 0, 2, 23), 8);
    tx.send(SessionEvent::TunPacket(downlink.clone()))
        .await
        .unwrap();
    let data_frame = timeout(
        Duration::from_secs(1),
        read_message_bytes(&mut client, limits),
    )
    .await
    .unwrap()
    .unwrap();
    match decode_message(&data_frame, limits).unwrap().unwrap().0 {
        Message::Data { packet } => assert_eq!(packet, downlink),
        other => panic!("expected tcp data after fallback, got {other:?}"),
    }
    assert!(
        timeout(Duration::from_millis(100), udp_rx.recv())
            .await
            .is_err(),
        "server kept using udp after acknowledged tcp fallback"
    );

    let _ = tx.send(SessionEvent::Shutdown).await;
    let _ = join.await.unwrap();
}
