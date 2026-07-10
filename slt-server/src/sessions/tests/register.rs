use std::net::{Ipv4Addr, SocketAddr};

use slt_core::crypto::udp_qsp::UdpQspKeys;
use slt_core::proto::{
    CipherSuite, FallbackOkPayload, FallbackToTcpPayload, Message, MessageLimits,
    RegisterCidPayload, RegisterFailCode, RegisterFailPayload, RegisterOkPayload, decode_message,
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
use crate::{AssignedIp, ClientId};

async fn register_and_activate_udp(
    client: &mut TlsDuplexStream,
    tx: &SessionTx,
    udp_rx: &mut mpsc::Receiver<Vec<u8>>,
    limits: MessageLimits,
    dcid_byte: u8,
    scid_byte: u8,
    peer_port: u16,
    upgrade_id: u64,
) -> RegisterCidPayload {
    let register = make_register_payload(
        Cid::from([dcid_byte; MAX_DCID_LEN]),
        Cid::from([scid_byte; MAX_DCID_LEN]),
        CipherSuite::Aes128Gcm,
    );
    let mut payload = Vec::new();
    register.encode(&mut payload).unwrap();
    let mut frame = Vec::new();
    encode_message(Message::RegisterCid { payload: &payload }, &mut frame).unwrap();
    client.write_all(&frame).await.unwrap();

    let response = timeout(Duration::from_secs(1), read_message_bytes(client, limits))
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        decode_message(&response, limits).unwrap().unwrap().0,
        Message::RegisterOk { .. }
    ));

    complete_udp_upgrade_handshake(
        client,
        tx,
        udp_rx,
        limits,
        &register,
        SocketAddr::from(([127, 0, 0, 1], peer_port)),
        upgrade_id,
    )
    .await;
    register
}

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

    let keys = UdpQspKeys::new(register.cipher, register.secret_rx, register.secret_tx).unwrap();
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
    let dummy_handle = registry.register_session(
        ClientId([0xCD; 16]),
        AssignedIp(Ipv4Addr::new(10, 0, 0, 10)),
        dummy_tx.clone(),
    );
    registry
        .insert_cid(
            dummy_handle.client_id,
            dummy_handle.session_id,
            dcid.prefix().unwrap(),
            dummy_tx,
        )
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

#[tokio::test]
async fn session_rejects_tcp_register_while_udp_active() {
    let (join, mut client, tx, _tun_rx, mut udp_rx, limits, _assigned, _registry) =
        spawn_session().await;
    let _active = register_and_activate_udp(
        &mut client,
        &tx,
        &mut udp_rx,
        limits,
        0xD1,
        0xD2,
        45_001,
        0xD100,
    )
    .await;

    let replacement = make_register_payload(
        Cid::from([0xD3; MAX_DCID_LEN]),
        Cid::from([0xD4; MAX_DCID_LEN]),
        CipherSuite::Aes128Gcm,
    );
    let mut payload = Vec::new();
    replacement.encode(&mut payload).unwrap();
    let mut frame = Vec::new();
    encode_message(Message::RegisterCid { payload: &payload }, &mut frame).unwrap();
    client.write_all(&frame).await.unwrap();

    let result = timeout(Duration::from_secs(1), join)
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(result, Err(SessionError::ProtocolViolation)));
    assert!(
        udp_rx.try_recv().is_err(),
        "registration response was sent over udp"
    );
}

#[tokio::test]
async fn session_registers_replacement_after_ordered_tcp_fallback() {
    let (join, mut client, tx, _tun_rx, mut udp_rx, limits, _assigned, _registry) =
        spawn_session().await;
    let _active = register_and_activate_udp(
        &mut client,
        &tx,
        &mut udp_rx,
        limits,
        0xD5,
        0xD6,
        45_002,
        0xD200,
    )
    .await;

    let replacement = make_register_payload(
        Cid::from([0xD7; MAX_DCID_LEN]),
        Cid::from([0xD8; MAX_DCID_LEN]),
        CipherSuite::Aes128Gcm,
    );
    let fallback_id = 0xD200_D200;
    let fallback = FallbackToTcpPayload { fallback_id };
    let mut fallback_payload = Vec::new();
    fallback.encode(&mut fallback_payload);
    let mut replacement_payload = Vec::new();
    replacement.encode(&mut replacement_payload).unwrap();
    let mut frame = Vec::new();
    encode_message(
        Message::FallbackToTcp {
            payload: &fallback_payload,
        },
        &mut frame,
    )
    .unwrap();
    encode_message(
        Message::RegisterCid {
            payload: &replacement_payload,
        },
        &mut frame,
    )
    .unwrap();
    client.write_all(&frame).await.unwrap();

    let fallback_response = timeout(
        Duration::from_secs(1),
        read_message_bytes(&mut client, limits),
    )
    .await
    .unwrap()
    .unwrap();
    let Message::FallbackOk { payload } = decode_message(&fallback_response, limits)
        .unwrap()
        .unwrap()
        .0
    else {
        panic!("expected fallback_ok");
    };
    assert_eq!(
        FallbackOkPayload::decode(payload).unwrap().fallback_id,
        fallback_id
    );

    let register_response = timeout(
        Duration::from_secs(1),
        read_message_bytes(&mut client, limits),
    )
    .await
    .unwrap()
    .unwrap();
    let Message::RegisterOk { payload } = decode_message(&register_response, limits)
        .unwrap()
        .unwrap()
        .0
    else {
        panic!("expected register_ok");
    };
    assert_eq!(
        RegisterOkPayload::decode(payload)
            .unwrap()
            .client_to_server_cid,
        replacement.client_to_server_cid
    );
    assert!(
        udp_rx.try_recv().is_err(),
        "registration response was sent over udp"
    );

    complete_udp_upgrade_handshake(
        &mut client,
        &tx,
        &mut udp_rx,
        limits,
        &replacement,
        SocketAddr::from(([127, 0, 0, 1], 45_003)),
        0xD201,
    )
    .await;

    let _ = tx.send(SessionEvent::Shutdown).await;
    join.await.unwrap().unwrap();
}

#[tokio::test]
async fn session_sends_malformed_register_failure_on_tcp_after_fallback() {
    let (join, mut client, tx, _tun_rx, mut udp_rx, limits, _assigned, _registry) =
        spawn_session().await;
    let _active = register_and_activate_udp(
        &mut client,
        &tx,
        &mut udp_rx,
        limits,
        0xD9,
        0xDA,
        45_004,
        0xD300,
    )
    .await;

    let fallback_id = 0xD300_D300;
    let fallback = FallbackToTcpPayload { fallback_id };
    let mut fallback_payload = Vec::new();
    fallback.encode(&mut fallback_payload);
    let malformed_payload = [1, 0xAA, 0x00];
    let mut frame = Vec::new();
    encode_message(
        Message::FallbackToTcp {
            payload: &fallback_payload,
        },
        &mut frame,
    )
    .unwrap();
    encode_message(
        Message::RegisterCid {
            payload: &malformed_payload,
        },
        &mut frame,
    )
    .unwrap();
    client.write_all(&frame).await.unwrap();

    let fallback_response = timeout(
        Duration::from_secs(1),
        read_message_bytes(&mut client, limits),
    )
    .await
    .unwrap()
    .unwrap();
    let Message::FallbackOk { payload } = decode_message(&fallback_response, limits)
        .unwrap()
        .unwrap()
        .0
    else {
        panic!("expected fallback_ok");
    };
    assert_eq!(
        FallbackOkPayload::decode(payload).unwrap().fallback_id,
        fallback_id
    );

    let register_response = timeout(
        Duration::from_secs(1),
        read_message_bytes(&mut client, limits),
    )
    .await
    .unwrap()
    .unwrap();
    let Message::RegisterFail { payload } = decode_message(&register_response, limits)
        .unwrap()
        .unwrap()
        .0
    else {
        panic!("expected register_fail");
    };
    assert_eq!(
        RegisterFailPayload::decode(payload).unwrap().code,
        RegisterFailCode::InvalidCid
    );
    assert!(
        udp_rx.try_recv().is_err(),
        "registration response was sent over udp"
    );

    let _ = tx.send(SessionEvent::Shutdown).await;
    join.await.unwrap().unwrap();
}
