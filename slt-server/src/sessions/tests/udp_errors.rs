use std::net::{Ipv4Addr, SocketAddr};

use slt_core::crypto::udp_qsp::UdpQspKeys;
use slt_core::proto::{CipherSuite, Message, decode_message, encode_message};
use slt_core::types::{Cid, MAX_DCID_LEN};
use tokio::io::AsyncWriteExt;
use tokio::time::{Duration, timeout};

use super::super::*;
use super::common::{
    complete_udp_upgrade_handshake, ipv4_packet, make_register_payload, read_message_bytes,
    spawn_session,
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

    let keys = UdpQspKeys::from_register(&register).unwrap();
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

    let _ = tx.send(SessionEvent::Shutdown).await;
    let _ = join.await.unwrap();
}

// =========================================================================
// UDP error handling tests
// =========================================================================

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

    let keys = UdpQspKeys::from_register(&register).unwrap();
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
    match timeout(Duration::from_millis(200), tun_rx.recv()).await {
        Ok(Some(_)) => panic!("replayed UDP packet should be dropped"),
        Ok(None) | Err(_) => {}
    }

    let _ = tx.send(SessionEvent::Shutdown).await;
    let _ = join.await.unwrap();
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

    let keys = UdpQspKeys::from_register(&register).unwrap();
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
    match timeout(Duration::from_millis(200), tun_rx.recv()).await {
        Ok(Some(_)) => panic!("packet with bad crypto should be dropped"),
        Ok(None) | Err(_) => {}
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

    let _ = tx.send(SessionEvent::Shutdown).await;
    let _ = join.await.unwrap();
}

#[tokio::test]
async fn session_falls_back_to_tcp_after_udp_dead_channel() {
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

    let keys = UdpQspKeys::from_register(&register).unwrap();
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

    // Send 64 garbage packets to trigger DeadChannel fallback
    // (DEAD_CHANNEL_FAILURE_THRESHOLD = 64)
    for _ in 0..64 {
        let garbage = vec![0xBA; 32];
        tx.send(SessionEvent::Udp(UdpClaim {
            peer,
            dcid_prefix: register.client_to_server_cid.prefix().unwrap(),
            payload: garbage,
        }))
        .await
        .unwrap();
    }

    // Give time for processing
    tokio::time::sleep(Duration::from_millis(100)).await;

    // CID should be removed and session should fall back to TCP
    assert!(!registry.has_cid(register.client_to_server_cid.prefix().unwrap()));

    // Session should still accept TCP data
    let tcp_packet = ipv4_packet(assigned.addr(), Ipv4Addr::new(192, 0, 2, 81), 8);
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

    let _ = tx.send(SessionEvent::Shutdown).await;
    let _ = join.await.unwrap();
}
