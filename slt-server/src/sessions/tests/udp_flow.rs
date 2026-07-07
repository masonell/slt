use std::net::{Ipv4Addr, SocketAddr};

use slt_core::crypto::udp_qsp::UdpQspKeys;
use slt_core::proto::{
    CipherSuite, Message, PingPayload, PongPayload, decode_message, encode_message,
};
use slt_core::types::{Cid, MAX_DCID_LEN};
use tokio::io::AsyncWriteExt;
use tokio::time::{Duration, timeout};

use super::super::*;
use super::common::{
    complete_udp_upgrade_handshake, ipv4_packet, make_register_payload, read_message_bytes,
    spawn_session, spawn_session_with_peer_capture,
};
use crate::quic::UdpClaim;

#[tokio::test]
async fn session_switches_to_udp_after_switch_ack() {
    let (join, mut client, tx, mut tun_rx, mut udp_rx, limits, assigned, _registry) =
        spawn_session().await;

    let dcid = Cid::from([0xCC; MAX_DCID_LEN]);
    let scid = Cid::from([0xDD; MAX_DCID_LEN]);
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

    let keys = UdpQspKeys::new(register.cipher, register.secret_rx, register.secret_tx).unwrap();
    let peer = SocketAddr::from(([127, 0, 0, 1], 44444));

    let server_expected_pn = complete_udp_upgrade_handshake(
        &mut client,
        &tx,
        &mut udp_rx,
        limits,
        &register,
        peer,
        0x1200,
    )
    .await;

    // Valid UDP data should still forward to TUN after upgrade commit.
    let uplink_packet = ipv4_packet(assigned.addr(), Ipv4Addr::new(192, 0, 2, 44), 12);
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
    let claim = UdpClaim {
        peer,
        dcid_prefix: register.client_to_server_cid.prefix().unwrap(),
        payload: udp_packet,
    };
    tx.send(SessionEvent::Udp(claim)).await.unwrap();

    let received = timeout(Duration::from_secs(1), tun_rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(received, uplink_packet);

    let downlink_packet = ipv4_packet(assigned.addr(), Ipv4Addr::new(192, 0, 2, 45), 12);
    tx.send(SessionEvent::TunPacket(downlink_packet.clone()))
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
    match message {
        Message::Data { packet } => assert_eq!(packet, downlink_packet.as_slice()),
        _ => panic!("expected udp data after switch commit"),
    }

    let _ = tx.send(SessionEvent::Shutdown).await;
    let _ = join.await.unwrap();
}

#[tokio::test]
async fn session_switches_to_udp_with_chacha20_poly1305() {
    let (join, mut client, tx, mut tun_rx, mut udp_rx, limits, assigned, _registry) =
        spawn_session().await;

    let dcid = Cid::from([0xCE; MAX_DCID_LEN]);
    let scid = Cid::from([0xDE; MAX_DCID_LEN]);
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

    let keys = UdpQspKeys::new(register.cipher, register.secret_rx, register.secret_tx).unwrap();
    let peer = SocketAddr::from(([127, 0, 0, 1], 44445));

    let server_expected_pn = complete_udp_upgrade_handshake(
        &mut client,
        &tx,
        &mut udp_rx,
        limits,
        &register,
        peer,
        0x2200,
    )
    .await;

    // Uplink: a ChaCha20-protected DATA frame must decrypt and reach TUN.
    let uplink_packet = ipv4_packet(assigned.addr(), Ipv4Addr::new(192, 0, 2, 64), 12);
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

    let received = timeout(Duration::from_secs(1), tun_rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(received, uplink_packet);

    // Downlink: TUN egress must be protected with ChaCha20 and decrypt cleanly.
    let downlink_packet = ipv4_packet(assigned.addr(), Ipv4Addr::new(192, 0, 2, 65), 12);
    tx.send(SessionEvent::TunPacket(downlink_packet.clone()))
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
    match message {
        Message::Data { packet } => assert_eq!(packet, downlink_packet.as_slice()),
        _ => panic!("expected udp data over chacha20 transport"),
    }

    let _ = tx.send(SessionEvent::Shutdown).await;
    let _ = join.await.unwrap();
}

#[tokio::test]
async fn session_handles_udp_pong() {
    let (join, mut client, tx, mut tun_rx, mut udp_rx, limits, assigned, _registry) =
        spawn_session().await;

    // Register and complete upgrade commit.
    let dcid = Cid::from([0xA1; MAX_DCID_LEN]);
    let scid = Cid::from([0xA2; MAX_DCID_LEN]);
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
    let peer = SocketAddr::from(([127, 0, 0, 1], 23456));

    let _ = complete_udp_upgrade_handshake(
        &mut client,
        &tx,
        &mut udp_rx,
        limits,
        &register,
        peer,
        0x1201,
    )
    .await;

    // Send UDP PONG - should be handled without error
    let pong_nonce = 0x1234_5678_9ABC_DEF0u64;
    let pong_payload = pong_nonce.to_be_bytes();
    let mut pong_frame = Vec::new();
    encode_message(
        Message::Pong {
            payload: &pong_payload,
        },
        &mut pong_frame,
    )
    .unwrap();
    let udp_pong = keys
        .protect(
            register.client_to_server_cid.as_slice(),
            register.pn_start_rx + 1,
            register.key_phase,
            &pong_frame,
        )
        .unwrap();
    tx.send(SessionEvent::Udp(UdpClaim {
        peer,
        dcid_prefix: register.client_to_server_cid.prefix().unwrap(),
        payload: udp_pong,
    }))
    .await
    .unwrap();

    // PONG doesn't produce TUN output, just wait a bit for processing
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Session should still work - send another data packet
    let uplink_packet2 = ipv4_packet(assigned.addr(), Ipv4Addr::new(192, 0, 2, 51), 8);
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

    let _ = tx.send(SessionEvent::Shutdown).await;
    let _ = join.await.unwrap();
}

#[tokio::test]
async fn valid_udp_packet_from_new_peer_updates_reply_peer() {
    let (join, mut client, tx, _tun_rx, mut udp_rx, mut udp_peer_rx, limits, _assigned, _registry) =
        spawn_session_with_peer_capture().await;

    let dcid = Cid::from([0xC1; MAX_DCID_LEN]);
    let scid = Cid::from([0xC2; MAX_DCID_LEN]);
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
    let old_peer = SocketAddr::from(([127, 0, 0, 1], 45678));
    let new_peer = SocketAddr::from(([127, 0, 0, 1], 45679));

    let server_expected_pn = complete_udp_upgrade_handshake(
        &mut client,
        &tx,
        &mut udp_rx,
        limits,
        &register,
        old_peer,
        0x1203,
    )
    .await;
    let first_reply_peer = timeout(Duration::from_secs(1), udp_peer_rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(first_reply_peer, old_peer);

    let ping = PingPayload {
        nonce: 0xCAFE_BABE_1234_5678,
    };
    let mut ping_payload = Vec::with_capacity(8);
    ping.encode(&mut ping_payload);
    let mut ping_frame = Vec::new();
    encode_message(
        Message::Ping {
            payload: &ping_payload,
        },
        &mut ping_frame,
    )
    .unwrap();
    let ping_packet = keys
        .protect(
            register.client_to_server_cid.as_slice(),
            register.pn_start_rx + 1,
            register.key_phase,
            &ping_frame,
        )
        .unwrap();
    tx.send(SessionEvent::Udp(UdpClaim {
        peer: new_peer,
        dcid_prefix: register.client_to_server_cid.prefix().unwrap(),
        payload: ping_packet,
    }))
    .await
    .unwrap();

    let pong_packet = timeout(Duration::from_secs(1), udp_rx.recv())
        .await
        .unwrap()
        .unwrap();
    let reply_peer = timeout(Duration::from_secs(1), udp_peer_rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(reply_peer, new_peer);

    let opened = keys
        .open(
            register.client_to_server_cid.len(),
            &pong_packet,
            server_expected_pn,
        )
        .unwrap();
    let (message, consumed) = decode_message(&opened.payload, limits).unwrap().unwrap();
    assert_eq!(consumed, opened.payload.len());
    match message {
        Message::Pong { payload } => {
            let pong = PongPayload::decode(payload).unwrap();
            assert_eq!(pong.nonce, ping.nonce);
        }
        _ => panic!("expected pong from migrated peer refresh"),
    }

    let _ = tx.send(SessionEvent::Shutdown).await;
    let _ = join.await.unwrap();
}

#[tokio::test]
async fn session_ignores_udp_control_messages() {
    let (join, mut client, tx, mut tun_rx, mut udp_rx, limits, assigned, _registry) =
        spawn_session().await;

    // Register and complete upgrade commit.
    let dcid = Cid::from([0xB1; MAX_DCID_LEN]);
    let scid = Cid::from([0xB2; MAX_DCID_LEN]);
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
    let peer = SocketAddr::from(([127, 0, 0, 1], 34567));

    let _ = complete_udp_upgrade_handshake(
        &mut client,
        &tx,
        &mut udp_rx,
        limits,
        &register,
        peer,
        0x1202,
    )
    .await;

    // Send various control messages via UDP that should be ignored
    let control_messages = [
        Message::Auth { payload: &[] },
        Message::AuthOk { payload: &[] },
        Message::AuthFail { payload: &[] },
        Message::RegisterOk { payload: &[] },
        Message::RegisterFail { payload: &[] },
        Message::UpgradeProbeAck { payload: &[] },
        Message::UdpReady { payload: &[] },
        Message::SwitchToUdp { payload: &[] },
        Message::SwitchAck { payload: &[] },
    ];

    for (i, msg) in control_messages.into_iter().enumerate() {
        let mut ctrl_frame = Vec::new();
        encode_message(msg, &mut ctrl_frame).unwrap();
        let udp_ctrl = keys
            .protect(
                register.client_to_server_cid.as_slice(),
                register.pn_start_rx + 1 + i as u64,
                register.key_phase,
                &ctrl_frame,
            )
            .unwrap();
        tx.send(SessionEvent::Udp(UdpClaim {
            peer,
            dcid_prefix: register.client_to_server_cid.prefix().unwrap(),
            payload: udp_ctrl,
        }))
        .await
        .unwrap();
    }

    // Control messages should be silently ignored - no TUN output
    if let Ok(Some(_)) = timeout(Duration::from_millis(200), tun_rx.recv()).await {
        panic!("UDP control messages should be ignored")
    }

    // Session should still work - send a data packet
    let uplink_packet2 = ipv4_packet(assigned.addr(), Ipv4Addr::new(192, 0, 2, 61), 8);
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
            register.pn_start_rx + 1 + control_messages.len() as u64,
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

    let _ = tx.send(SessionEvent::Shutdown).await;
    let _ = join.await.unwrap();
}
