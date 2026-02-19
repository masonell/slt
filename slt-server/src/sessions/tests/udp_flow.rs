use std::net::{Ipv4Addr, SocketAddr};

use slt_core::crypto::udp_qsp::UdpQspKeys;
use slt_core::proto::{CipherSuite, Message, decode_message, encode_message};
use slt_core::types::{Cid, MAX_DCID_LEN};
use tokio::io::AsyncWriteExt;
use tokio::time::{Duration, timeout};

use super::super::*;
use super::common::{ipv4_packet, make_register_payload, read_message_bytes, spawn_session};
use crate::quic::UdpClaim;

#[tokio::test]
async fn session_switches_to_udp_after_first_valid_data_claim() {
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

    let keys = UdpQspKeys::from_register(&register).unwrap();
    let peer = SocketAddr::from(([127, 0, 0, 1], 44444));

    // First valid UDP claim is DATA; this should switch active transport to UDP.
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
            0,
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
            register.pn_start,
        )
        .unwrap();
    let (message, consumed) = decode_message(&opened.payload, limits).unwrap().unwrap();
    assert_eq!(consumed, opened.payload.len());
    match message {
        Message::Data { packet } => assert_eq!(packet, downlink_packet.as_slice()),
        _ => panic!("expected udp data after first valid udp claim"),
    }

    let _ = tx.send(SessionEvent::Shutdown).await;
    let _ = join.await.unwrap();
}

#[tokio::test]
async fn session_handles_udp_pong() {
    let (join, mut client, tx, mut tun_rx, _udp_rx, limits, assigned, _registry) =
        spawn_session().await;

    // Register and activate UDP
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

    let keys = UdpQspKeys::from_register(&register).unwrap();
    let peer = SocketAddr::from(([127, 0, 0, 1], 23456));

    // Activate UDP with a data packet
    let uplink_packet = ipv4_packet(assigned.addr(), Ipv4Addr::new(192, 0, 2, 50), 8);
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
            0,
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
            1,
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
            2,
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
async fn session_ignores_udp_control_messages() {
    let (join, mut client, tx, mut tun_rx, _udp_rx, limits, assigned, _registry) =
        spawn_session().await;

    // Register and activate UDP
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

    let keys = UdpQspKeys::from_register(&register).unwrap();
    let peer = SocketAddr::from(([127, 0, 0, 1], 34567));

    // Activate UDP with a data packet
    let uplink_packet = ipv4_packet(assigned.addr(), Ipv4Addr::new(192, 0, 2, 60), 8);
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
            0,
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

    // Send various control messages via UDP that should be ignored
    let control_messages = [
        Message::Auth { payload: &[] },
        Message::AuthOk { payload: &[] },
        Message::AuthFail { payload: &[] },
        Message::RegisterOk { payload: &[] },
        Message::RegisterFail { payload: &[] },
    ];

    for (i, msg) in control_messages.into_iter().enumerate() {
        let mut ctrl_frame = Vec::new();
        encode_message(msg, &mut ctrl_frame).unwrap();
        let udp_ctrl = keys
            .protect(
                register.client_to_server_cid.as_slice(),
                (i + 1) as u64,
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
    match timeout(Duration::from_millis(200), tun_rx.recv()).await {
        Ok(Some(_)) => panic!("UDP control messages should be ignored"),
        Ok(None) | Err(_) => {}
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
            6,
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
