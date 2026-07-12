use std::net::{Ipv4Addr, SocketAddr};

use slt_core::crypto::udp_qsp::UdpQspKeys;
use slt_core::proto::{
    CipherSuite, CloseCode, Message, MessageType, decode_message, encode_message,
};
use slt_core::types::{Cid, MAX_DCID_LEN};
use tokio::io::AsyncWriteExt;
use tokio::time::{Duration, timeout};

use super::super::*;
use super::common::{
    complete_udp_upgrade_handshake, ipv4_packet, make_register_payload, read_close_code,
    read_message_bytes, spawn_session, spawn_session_with_udp_socket,
};
use crate::quic::UdpClaim;

#[tokio::test]
async fn session_ignores_trailing_data_after_udp_message() {
    let (join, mut client, tx, mut tun_rx, mut udp_rx, limits, assigned, _registry) =
        spawn_session().await;

    // Register UDP
    let dcid = Cid::from([0x81; MAX_DCID_LEN]);
    let scid = Cid::from([0x82; MAX_DCID_LEN]);
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

    let keys = UdpQspKeys::new(register.cipher, register.secret_rx, register.secret_tx).unwrap();
    let peer = SocketAddr::from(([127, 0, 0, 1], 44444));
    let _ = complete_udp_upgrade_handshake(
        &mut client,
        &tx,
        &mut udp_rx,
        limits,
        &register,
        peer,
        0x1801,
    )
    .await;

    // Create a valid data frame then append garbage
    let uplink_packet = ipv4_packet(assigned.addr(), Ipv4Addr::new(192, 0, 2, 30), 8);
    let mut data_frame = Vec::new();
    encode_message(
        Message::Data {
            packet: &uplink_packet,
        },
        &mut data_frame,
    )
    .unwrap();
    data_frame.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]); // trailing garbage

    let udp_packet = keys
        .protect(
            register.client_to_server_cid.as_slice(),
            register.pn_start_rx + 1,
            register.key_phase,
            &data_frame,
        )
        .unwrap();
    tx.send(SessionEvent::Udp(UdpClaim {
        peer,
        dcid_prefix: register.client_to_server_cid.prefix().unwrap(),
        payload: udp_packet,
    }))
    .await
    .unwrap();

    // Should forward the decoded DATA payload and ignore trailing bytes.
    let received = timeout(Duration::from_secs(1), tun_rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(received, uplink_packet);

    let _ = join.shutdown().await.unwrap();
}

// =========================================================================
// UDP error handling tests
// =========================================================================

#[tokio::test]
async fn session_rejects_authenticated_incomplete_udp_datagrams() {
    let mut incomplete_ping = vec![u8::from(MessageType::Ping)];
    incomplete_ping.extend_from_slice(&8u32.to_be_bytes());
    incomplete_ping.extend_from_slice(&[0; 7]);

    for plaintext in [Vec::new(), incomplete_ping] {
        assert_authenticated_incomplete_udp_datagram_rejected(&plaintext).await;
    }
}

async fn assert_authenticated_incomplete_udp_datagram_rejected(plaintext: &[u8]) {
    let (join, mut client, tx, _tun_rx, _udp_rx, limits, _assigned, _registry) =
        spawn_session().await;

    let dcid = Cid::from([0x83; MAX_DCID_LEN]);
    let scid = Cid::from([0x84; MAX_DCID_LEN]);
    let register = make_register_payload(dcid, scid, CipherSuite::Aes128Gcm);
    let mut register_payload = Vec::new();
    register.encode(&mut register_payload).unwrap();
    let mut register_frame = Vec::new();
    encode_message(
        Message::RegisterCid {
            payload: &register_payload,
        },
        &mut register_frame,
    )
    .unwrap();
    client.write_all(&register_frame).await.unwrap();

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

    let keys = UdpQspKeys::new(register.cipher, register.secret_rx, register.secret_tx).unwrap();
    let protected = keys
        .protect(
            register.client_to_server_cid.as_slice(),
            register.pn_start_rx,
            register.key_phase,
            plaintext,
        )
        .unwrap();
    tx.send(SessionEvent::Udp(UdpClaim {
        peer: SocketAddr::from(([127, 0, 0, 1], 44445)),
        dcid_prefix: register.client_to_server_cid.prefix().unwrap(),
        payload: protected,
    }))
    .await
    .unwrap();

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
async fn session_drops_udp_replay_packet() {
    let (join, mut client, tx, mut tun_rx, mut udp_rx, limits, assigned, _registry) =
        spawn_session().await;

    // Register and activate UDP
    let dcid = Cid::from([0x91; MAX_DCID_LEN]);
    let scid = Cid::from([0x92; MAX_DCID_LEN]);
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

    let keys = UdpQspKeys::new(register.cipher, register.secret_rx, register.secret_tx).unwrap();
    let peer = SocketAddr::from(([127, 0, 0, 1], 12345));
    let _ = complete_udp_upgrade_handshake(
        &mut client,
        &tx,
        &mut udp_rx,
        limits,
        &register,
        peer,
        0x1500,
    )
    .await;

    // Send first valid data packet (PN=1; PN=0 was upgrade probe)
    let uplink_packet = ipv4_packet(assigned.addr(), Ipv4Addr::new(192, 0, 2, 40), 8);
    let mut data_frame = Vec::new();
    encode_message(
        Message::Data {
            packet: &uplink_packet,
        },
        &mut data_frame,
    )
    .unwrap();
    let udp_packet = keys
        .protect(
            register.client_to_server_cid.as_slice(),
            register.pn_start_rx + 1,
            register.key_phase,
            &data_frame,
        )
        .unwrap();
    tx.send(SessionEvent::Udp(UdpClaim {
        peer,
        dcid_prefix: register.client_to_server_cid.prefix().unwrap(),
        payload: udp_packet.clone(),
    }))
    .await
    .unwrap();

    let received = timeout(Duration::from_secs(1), tun_rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(received, uplink_packet);

    // Replay the same packet (same PN=1) - should be dropped
    tx.send(SessionEvent::Udp(UdpClaim {
        peer,
        dcid_prefix: register.client_to_server_cid.prefix().unwrap(),
        payload: udp_packet,
    }))
    .await
    .unwrap();

    // Should NOT receive another packet (replay dropped)
    if let Ok(Some(_)) = timeout(Duration::from_millis(200), tun_rx.recv()).await {
        panic!("replayed UDP packet should be dropped")
    }

    let _ = join.shutdown().await.unwrap();
}

#[tokio::test]
async fn session_drops_udp_packet_with_bad_crypto() {
    let (join, mut client, tx, mut tun_rx, mut udp_rx, limits, assigned, _registry) =
        spawn_session().await;

    // Register and activate UDP
    let dcid = Cid::from([0x93; MAX_DCID_LEN]);
    let scid = Cid::from([0x94; MAX_DCID_LEN]);
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

    let keys = UdpQspKeys::new(register.cipher, register.secret_rx, register.secret_tx).unwrap();
    let peer = SocketAddr::from(([127, 0, 0, 1], 12346));
    let _ = complete_udp_upgrade_handshake(
        &mut client,
        &tx,
        &mut udp_rx,
        limits,
        &register,
        peer,
        0x1501,
    )
    .await;

    // Send a valid packet first.
    let uplink_packet = ipv4_packet(assigned.addr(), Ipv4Addr::new(192, 0, 2, 41), 8);
    let mut data_frame = Vec::new();
    encode_message(
        Message::Data {
            packet: &uplink_packet,
        },
        &mut data_frame,
    )
    .unwrap();
    let udp_packet = keys
        .protect(
            register.client_to_server_cid.as_slice(),
            register.pn_start_rx + 1,
            register.key_phase,
            &data_frame,
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

    // Send garbage (wrong keys) - should be dropped
    let garbage = vec![0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE];
    tx.send(SessionEvent::Udp(UdpClaim {
        peer,
        dcid_prefix: register.client_to_server_cid.prefix().unwrap(),
        payload: garbage,
    }))
    .await
    .unwrap();

    // Should NOT receive anything (crypto failure)
    if let Ok(Some(_)) = timeout(Duration::from_millis(200), tun_rx.recv()).await {
        panic!("packet with bad crypto should be dropped")
    }

    // Session should still be alive and process valid packets
    let uplink_packet2 = ipv4_packet(assigned.addr(), Ipv4Addr::new(192, 0, 2, 42), 8);
    let mut data_frame2 = Vec::new();
    encode_message(
        Message::Data {
            packet: &uplink_packet2,
        },
        &mut data_frame2,
    )
    .unwrap();
    let udp_packet2 = keys
        .protect(
            register.client_to_server_cid.as_slice(),
            register.pn_start_rx + 2,
            register.key_phase,
            &data_frame2,
        )
        .unwrap();
    tx.send(SessionEvent::Udp(UdpClaim {
        peer,
        dcid_prefix: register.client_to_server_cid.prefix().unwrap(),
        payload: udp_packet2,
    }))
    .await
    .unwrap();

    let received = timeout(Duration::from_secs(1), tun_rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(received, uplink_packet2);

    let _ = join.shutdown().await.unwrap();
}

#[tokio::test]
async fn decrypt_garbage_from_any_peer_does_not_retire_udp() {
    let (join, mut client, tx, mut tun_rx, mut udp_rx, limits, assigned, registry) =
        spawn_session().await;

    // Register and activate UDP
    let dcid = Cid::from([0xD1; MAX_DCID_LEN]);
    let scid = Cid::from([0xD2; MAX_DCID_LEN]);
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
    assert!(registry.has_cid(register.client_to_server_cid.prefix().unwrap()));

    let keys = UdpQspKeys::new(register.cipher, register.secret_rx, register.secret_tx).unwrap();
    let peer = SocketAddr::from(([127, 0, 0, 1], 56789));
    let _ = complete_udp_upgrade_handshake(
        &mut client,
        &tx,
        &mut udp_rx,
        limits,
        &register,
        peer,
        0x1502,
    )
    .await;

    // Send a data packet after upgrade commit.
    let uplink_packet = ipv4_packet(assigned.addr(), Ipv4Addr::new(192, 0, 2, 80), 8);
    let mut data_frame = Vec::new();
    encode_message(
        Message::Data {
            packet: &uplink_packet,
        },
        &mut data_frame,
    )
    .unwrap();
    let udp_packet = keys
        .protect(
            register.client_to_server_cid.as_slice(),
            register.pn_start_rx + 1,
            register.key_phase,
            &data_frame,
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

    let unvalidated_peer = SocketAddr::from(([127, 0, 0, 1], 56788));
    for garbage_peer in [unvalidated_peer, peer] {
        for _ in 0..128 {
            tx.send(SessionEvent::Udp(UdpClaim {
                peer: garbage_peer,
                dcid_prefix: register.client_to_server_cid.prefix().unwrap(),
                payload: vec![0xBA; 32],
            }))
            .await
            .unwrap();
        }
    }

    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(registry.has_cid(register.client_to_server_cid.prefix().unwrap()));

    let later_packet = ipv4_packet(assigned.addr(), Ipv4Addr::new(192, 0, 2, 81), 8);
    let mut later_frame = Vec::new();
    encode_message(
        Message::Data {
            packet: &later_packet,
        },
        &mut later_frame,
    )
    .unwrap();
    let protected = keys
        .protect(
            register.client_to_server_cid.as_slice(),
            register.pn_start_rx + 2,
            register.key_phase,
            &later_frame,
        )
        .unwrap();
    tx.send(SessionEvent::Udp(UdpClaim {
        peer,
        dcid_prefix: register.client_to_server_cid.prefix().unwrap(),
        payload: protected,
    }))
    .await
    .unwrap();

    let received = timeout(Duration::from_secs(1), tun_rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(received, later_packet);

    let _ = join.shutdown().await.unwrap();
}

#[tokio::test]
async fn session_retries_downlink_over_tcp_after_udp_send_failure() {
    let (join, mut client, tx, mut tun_rx, mut udp_rx, limits, assigned, registry, udp) =
        spawn_session_with_udp_socket().await;

    let dcid = Cid::from([0xD3; MAX_DCID_LEN]);
    let scid = Cid::from([0xD4; MAX_DCID_LEN]);
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
    assert!(registry.has_cid(register.client_to_server_cid.prefix().unwrap()));

    let peer = SocketAddr::from(([127, 0, 0, 1], 56791));
    let _ = complete_udp_upgrade_handshake(
        &mut client,
        &tx,
        &mut udp_rx,
        limits,
        &register,
        peer,
        0x1503,
    )
    .await;

    udp.fail_next_send();
    let downlink_packet = ipv4_packet(assigned.addr(), Ipv4Addr::new(192, 0, 2, 82), 8);
    tx.send(SessionEvent::TunPacket(downlink_packet.clone()))
        .await
        .unwrap();

    let mut saw_data = false;
    for _ in 0..8 {
        let buf = timeout(
            Duration::from_secs(1),
            read_message_bytes(&mut client, limits),
        )
        .await
        .unwrap()
        .unwrap();
        let (message, _) = decode_message(&buf, limits).unwrap().unwrap();
        match message {
            Message::Data { packet } => {
                assert_eq!(packet, downlink_packet);
                saw_data = true;
                break;
            }
            Message::FallbackToTcp { .. } => {}
            other => panic!("expected tcp data after udp send failure, got {other:?}"),
        }
    }
    assert!(saw_data, "server did not retry downlink data over tcp");
    assert!(!registry.has_cid(register.client_to_server_cid.prefix().unwrap()));

    let tcp_packet = ipv4_packet(assigned.addr(), Ipv4Addr::new(192, 0, 2, 83), 8);
    let mut tcp_frame = Vec::new();
    encode_message(
        Message::Data {
            packet: &tcp_packet,
        },
        &mut tcp_frame,
    )
    .unwrap();
    client.write_all(&tcp_frame).await.unwrap();

    let received = timeout(Duration::from_secs(1), tun_rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(received, tcp_packet);

    let _ = join.shutdown().await.unwrap();
}

#[tokio::test]
async fn decrypt_garbage_does_not_close_udp_only_session() {
    let (join, mut client, tx, mut tun_rx, mut udp_rx, limits, assigned, registry) =
        spawn_session().await;

    // Register and activate UDP-QSP.
    let dcid = Cid::from([0xE1; MAX_DCID_LEN]);
    let scid = Cid::from([0xE2; MAX_DCID_LEN]);
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

    let keys = UdpQspKeys::new(register.cipher, register.secret_rx, register.secret_tx).unwrap();
    let peer = SocketAddr::from(([127, 0, 0, 1], 56790));
    let _ = complete_udp_upgrade_handshake(
        &mut client,
        &tx,
        &mut udp_rx,
        limits,
        &register,
        peer,
        0x1602,
    )
    .await;

    // Close the TCP connection (e.g. a middlebox reaped it after the upgrade).
    // The server sets tcp_alive=false and continues on UDP-QSP alone.
    drop(client);

    // Let the server observe the TCP EOF before sending unauthenticated noise.
    tokio::time::sleep(Duration::from_millis(100)).await;

    let unvalidated_peer = SocketAddr::from(([127, 0, 0, 1], 56791));
    for _ in 0..128 {
        tx.send(SessionEvent::Udp(UdpClaim {
            peer: unvalidated_peer,
            dcid_prefix: register.client_to_server_cid.prefix().unwrap(),
            payload: vec![0xBB; 32],
        }))
        .await
        .unwrap();
    }

    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(!join.is_finished());
    assert!(registry.has_cid(register.client_to_server_cid.prefix().unwrap()));

    let uplink_packet = ipv4_packet(assigned.addr(), Ipv4Addr::new(192, 0, 2, 90), 8);
    let mut data_frame = Vec::new();
    encode_message(
        Message::Data {
            packet: &uplink_packet,
        },
        &mut data_frame,
    )
    .unwrap();
    let protected = keys
        .protect(
            register.client_to_server_cid.as_slice(),
            register.pn_start_rx + 1,
            register.key_phase,
            &data_frame,
        )
        .unwrap();
    tx.send(SessionEvent::Udp(UdpClaim {
        peer,
        dcid_prefix: register.client_to_server_cid.prefix().unwrap(),
        payload: protected,
    }))
    .await
    .unwrap();

    let received = timeout(Duration::from_secs(1), tun_rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(received, uplink_packet);

    assert!(join.shutdown().await.unwrap().is_ok());
}
