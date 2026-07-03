use std::net::{Ipv4Addr, SocketAddr};

use slt_core::crypto::udp_qsp::UdpQspKeys;
use slt_core::proto::{
    CipherSuite, Message, MessageLimits, RegisterFailCode, RegisterFailPayload, decode_message,
    encode_message,
};
use slt_core::types::{Cid, MAX_DCID_LEN, ServerUdpQspCipher, ServerUdpQspConfig};
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;
use tokio::time::{Duration, timeout};

use super::super::*;
use super::common::{
    complete_udp_upgrade_handshake, ipv4_packet, make_register_payload, read_message_bytes,
    spawn_session, spawn_session_with_udp_qsp_config,
};
use crate::test_support::TlsDuplexStream;

async fn assert_register_response_fail(
    client: &mut TlsDuplexStream,
    limits: MessageLimits,
    payload: &[u8],
    code: RegisterFailCode,
) {
    let mut frame = Vec::new();
    encode_message(Message::RegisterCid { payload }, &mut frame).unwrap();
    client.write_all(&frame).await.unwrap();

    let buf = timeout(Duration::from_secs(1), read_message_bytes(client, limits))
        .await
        .unwrap()
        .unwrap();
    let (message, _) = decode_message(&buf, limits).unwrap().unwrap();
    match message {
        Message::RegisterFail { payload } => {
            let fail = RegisterFailPayload::decode(payload).unwrap();
            assert_eq!(fail.code, code);
        }
        _ => panic!("expected register fail"),
    }
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn session_registers_udp_and_forwards_data() {
    let (join, mut client, tx, _tun_rx, mut udp_rx, limits, assigned, _registry) =
        spawn_session().await;

    let dcid = Cid::from([0xAA; MAX_DCID_LEN]);
    let scid = Cid::from([0xBB; MAX_DCID_LEN]);
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
    let (message, _) = decode_message(&buf, limits).unwrap().unwrap();
    assert!(matches!(message, Message::RegisterOk { .. }));

    // Before first UDP claim, downlink traffic must stay on TCP.
    let tcp_packet = ipv4_packet(assigned.addr(), Ipv4Addr::new(192, 0, 2, 2), 12);
    tx.send(SessionEvent::TunPacket(tcp_packet.clone()))
        .await
        .unwrap();

    let buf = timeout(
        Duration::from_secs(1),
        read_message_bytes(&mut client, limits),
    )
    .await
    .unwrap()
    .unwrap();
    let (message, _) = decode_message(&buf, limits).unwrap().unwrap();
    match message {
        Message::Data { packet } => assert_eq!(packet, tcp_packet.as_slice()),
        _ => panic!("expected tcp data before first udp claim"),
    }
    assert!(
        timeout(Duration::from_millis(200), udp_rx.recv())
            .await
            .is_err(),
        "unexpected udp datagram before first udp claim"
    );

    let keys = UdpQspKeys::from_register(&register).unwrap();
    let peer = SocketAddr::from(([127, 0, 0, 1], 55555));

    let server_expected_pn = complete_udp_upgrade_handshake(
        &mut client,
        &tx,
        &mut udp_rx,
        limits,
        &register,
        peer,
        0x71,
    )
    .await;

    // Now send a TUN packet and verify it's forwarded via UDP.
    let data_packet = ipv4_packet(assigned.addr(), Ipv4Addr::new(192, 0, 2, 3), 12);
    tx.send(SessionEvent::TunPacket(data_packet.clone()))
        .await
        .unwrap();

    let packet = timeout(Duration::from_secs(1), udp_rx.recv())
        .await
        .unwrap()
        .unwrap();
    let opened = keys
        .open(
            register.client_to_server_cid.len(),
            &packet,
            server_expected_pn,
        )
        .unwrap();
    let (message, consumed) = decode_message(&opened.payload, limits).unwrap().unwrap();
    assert_eq!(consumed, opened.payload.len());
    if let Message::Data { packet } = message {
        assert_eq!(packet, data_packet.as_slice());
    } else {
        panic!("expected data message");
    }

    let _ = tx.send(SessionEvent::Shutdown).await;
    let _ = join.await.unwrap();
}

#[tokio::test]
async fn session_register_rejects_invalid_cid() {
    let (join, mut client, tx, _tun_rx, _udp_rx, limits, _assigned, _registry) =
        spawn_session().await;

    let payload = vec![1, 0xAA, 0x00];
    let mut frame = Vec::new();
    encode_message(Message::RegisterCid { payload: &payload }, &mut frame).unwrap();
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
        Message::RegisterFail { payload } => {
            let fail = RegisterFailPayload::decode(payload).unwrap();
            assert_eq!(fail.code, RegisterFailCode::InvalidCid);
        }
        _ => panic!("expected register fail"),
    }

    let _ = tx.send(SessionEvent::Shutdown).await;
    let _ = join.await.unwrap();
}

#[tokio::test]
async fn session_register_accepts_chacha20_poly1305() {
    let (join, mut client, tx, _tun_rx, _udp_rx, limits, _assigned, _registry) =
        spawn_session().await;

    let dcid = Cid::from([0xAB; MAX_DCID_LEN]);
    let scid = Cid::from([0xBC; MAX_DCID_LEN]);
    let register = make_register_payload(dcid, scid, CipherSuite::ChaCha20Poly1305);
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
    let (message, _) = decode_message(&buf, limits).unwrap().unwrap();
    assert!(matches!(message, Message::RegisterOk { .. }));

    let _ = tx.send(SessionEvent::Shutdown).await;
    let _ = join.await.unwrap();
}

#[tokio::test]
async fn session_register_rejects_disallowed_cipher() {
    let udp_qsp_config = ServerUdpQspConfig {
        allowed_ciphers: vec![ServerUdpQspCipher::Aes128Gcm],
    };
    let (join, mut client, tx, _tun_rx, _udp_rx, limits, _assigned, _registry) =
        spawn_session_with_udp_qsp_config(udp_qsp_config).await;

    let dcid = Cid::from([0xAB; MAX_DCID_LEN]);
    let scid = Cid::from([0xBC; MAX_DCID_LEN]);
    let register = make_register_payload(dcid, scid, CipherSuite::ChaCha20Poly1305);
    let mut reg_buf = Vec::new();
    register.encode(&mut reg_buf).unwrap();

    assert_register_response_fail(
        &mut client,
        limits,
        &reg_buf,
        RegisterFailCode::InvalidCipher,
    )
    .await;

    let _ = tx.send(SessionEvent::Shutdown).await;
    let _ = join.await.unwrap();
}

#[tokio::test]
async fn session_register_rejects_unknown_cipher_as_invalid_cipher() {
    let (join, mut client, tx, _tun_rx, _udp_rx, limits, _assigned, _registry) =
        spawn_session().await;

    let dcid = Cid::from([0xAB; MAX_DCID_LEN]);
    let scid = Cid::from([0xBC; MAX_DCID_LEN]);
    let register = make_register_payload(dcid, scid, CipherSuite::Aes128Gcm);
    let mut reg_buf = Vec::new();
    register.encode(&mut reg_buf).unwrap();
    let cipher_offset = 1 + MAX_DCID_LEN + 1 + MAX_DCID_LEN;
    reg_buf[cipher_offset] = 0x99;

    assert_register_response_fail(
        &mut client,
        limits,
        &reg_buf,
        RegisterFailCode::InvalidCipher,
    )
    .await;

    let _ = tx.send(SessionEvent::Shutdown).await;
    let _ = join.await.unwrap();
}

#[tokio::test]
async fn session_register_rejects_malformed_key_material_as_invalid_keys() {
    let (join, mut client, tx, _tun_rx, _udp_rx, limits, _assigned, _registry) =
        spawn_session().await;

    let dcid = Cid::from([0xAB; MAX_DCID_LEN]);
    let scid = Cid::from([0xBC; MAX_DCID_LEN]);
    let register = make_register_payload(dcid, scid, CipherSuite::Aes128Gcm);
    let mut reg_buf = Vec::new();
    register.encode(&mut reg_buf).unwrap();
    reg_buf.pop();

    assert_register_response_fail(&mut client, limits, &reg_buf, RegisterFailCode::InvalidKeys)
        .await;

    let _ = tx.send(SessionEvent::Shutdown).await;
    let _ = join.await.unwrap();
}

#[tokio::test]
async fn session_register_rejects_prefix_collision() {
    let (join, mut client, tx, _tun_rx, _udp_rx, limits, _assigned, registry) =
        spawn_session().await;

    let dcid = Cid::from([0xCD; MAX_DCID_LEN]);
    let scid = Cid::from([0xDE; MAX_DCID_LEN]);
    let (dummy_tx, _dummy_rx) = mpsc::channel(1);
    registry
        .insert_cid(999, dcid.prefix().unwrap(), dummy_tx)
        .unwrap();

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
    let (message, _) = decode_message(&buf, limits).unwrap().unwrap();
    match message {
        Message::RegisterFail { payload } => {
            let fail = RegisterFailPayload::decode(payload).unwrap();
            assert_eq!(fail.code, RegisterFailCode::InvalidCid);
        }
        _ => panic!("expected register fail"),
    }

    let _ = tx.send(SessionEvent::Shutdown).await;
    let _ = join.await.unwrap();
}
