use std::net::{Ipv4Addr, SocketAddr};

use slt_core::crypto::udp_qsp::UdpQspKeys;
use slt_core::proto::{
    CipherSuite, CloseCode, ClosePayload, Message, PingPayload, PongPayload, decode_message,
    encode_message,
};
use slt_core::types::{Cid, MAX_DCID_LEN};
use tokio::io::AsyncWriteExt;
use tokio::time::{Duration, timeout};

use super::super::*;
use super::common::{ipv4_packet, make_register_payload, read_message_bytes, spawn_session};
use crate::quic::UdpClaim;

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
    let (join, mut client, _tx, _tun_rx, _udp_rx, _limits, _assigned, _registry) =
        spawn_session().await;

    let mut frame = Vec::new();
    encode_message(Message::AuthOk { payload: &[] }, &mut frame).unwrap();
    client.write_all(&frame).await.unwrap();

    let result = timeout(Duration::from_secs(1), join)
        .await
        .unwrap()
        .unwrap();
    assert!(result.is_err());
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
    match timeout(
        Duration::from_millis(200),
        read_message_bytes(&mut client, limits),
    )
    .await
    {
        Ok(Ok(_)) => panic!("oversized packet should not be forwarded to client"),
        Ok(Err(_)) | Err(_) => {}
    }

    let _ = tx.send(SessionEvent::Shutdown).await;
    let _ = join.await.unwrap();
}

#[tokio::test]
async fn session_drops_tcp_data_when_udp_active() {
    let (join, mut client, tx, mut tun_rx, _udp_rx, limits, assigned, _registry) =
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

    let keys = UdpQspKeys::from_register(&register).unwrap();
    let peer = SocketAddr::from(([127, 0, 0, 1], 33333));
    let udp_data = ipv4_packet(assigned.addr(), Ipv4Addr::new(192, 0, 2, 20), 8);
    let mut udp_frame = Vec::new();
    encode_message(Message::Data { packet: &udp_data }, &mut udp_frame).unwrap();
    let udp_packet = keys
        .protect(
            register.client_to_server_cid.as_slice(),
            0,
            register.key_phase,
            &udp_frame,
        )
        .unwrap();
    tx.send(SessionEvent::Udp(UdpClaim {
        peer,
        dcid_prefix: register.client_to_server_cid.prefix().unwrap(),
        payload: udp_packet,
    }))
    .await
    .unwrap();
    let _ = timeout(Duration::from_secs(1), tun_rx.recv())
        .await
        .unwrap()
        .unwrap();

    // Now send data via TCP - should be dropped since UDP is active
    let tcp_data = ipv4_packet(assigned.addr(), Ipv4Addr::new(192, 0, 2, 21), 8);
    let mut tcp_frame = Vec::new();
    encode_message(Message::Data { packet: &tcp_data }, &mut tcp_frame).unwrap();
    client.write_all(&tcp_frame).await.unwrap();

    // Should NOT appear on TUN (dropped because TCP is not active transport)
    match timeout(Duration::from_millis(200), tun_rx.recv()).await {
        Ok(Some(_)) => panic!("TCP data should be dropped when UDP is active"),
        Ok(None) | Err(_) => {}
    }

    let _ = tx.send(SessionEvent::Shutdown).await;
    let _ = join.await.unwrap();
}
