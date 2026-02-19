use std::net::{Ipv4Addr, SocketAddr};

use slt_core::crypto::udp_qsp::UdpQspKeys;
use slt_core::proto::{
    CipherSuite, Message, MessageLimits, PingPayload, PongPayload, RegisterCidPayload,
    SwitchAckPayload, SwitchToUdpPayload, UdpReadyPayload, UpgradeProbeAckPayload,
    UpgradeProbePayload, decode_message, encode_message,
};
use slt_core::types::{Cid, MAX_DCID_LEN};
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::time::{Duration, timeout};

use super::super::*;
use super::common::{ipv4_packet, make_register_payload, read_message_bytes, spawn_session};
use crate::quic::UdpClaim;

fn decode_single_message<'a>(payload: &'a [u8], limits: MessageLimits) -> Message<'a> {
    let (message, consumed) = decode_message(payload, limits).unwrap().unwrap();
    assert_eq!(consumed, payload.len());
    message
}

async fn write_tcp_message<S: AsyncWrite + Unpin>(stream: &mut S, message: Message<'_>) {
    let mut frame = Vec::new();
    encode_message(message, &mut frame).unwrap();
    stream.write_all(&frame).await.unwrap();
}

async fn send_udp_message(
    tx: &SessionTx,
    keys: &UdpQspKeys,
    register: &RegisterCidPayload,
    peer: SocketAddr,
    pn: u64,
    message: Message<'_>,
) {
    let mut frame = Vec::new();
    encode_message(message, &mut frame).unwrap();
    let packet = keys
        .protect(
            register.client_to_server_cid.as_slice(),
            pn,
            register.key_phase,
            &frame,
        )
        .unwrap();
    tx.send(SessionEvent::Udp(UdpClaim {
        peer,
        dcid_prefix: register.client_to_server_cid.prefix().unwrap(),
        payload: packet,
    }))
    .await
    .unwrap();
}

async fn wait_for_switch_commit_barrier(
    client: &mut crate::test_support::TlsDuplexStream,
    limits: MessageLimits,
) {
    let nonce = 0xA11C_E000_0000_0002u64;
    let ping = PingPayload { nonce };
    let mut payload = Vec::with_capacity(8);
    ping.encode(&mut payload);
    write_tcp_message(client, Message::Ping { payload: &payload }).await;

    let mut pong_received = false;
    for _ in 0..8 {
        let buf = timeout(Duration::from_secs(1), read_message_bytes(client, limits))
            .await
            .unwrap()
            .unwrap();
        let (message, _) = decode_message(&buf, limits).unwrap().unwrap();
        match message {
            Message::Pong { payload } => {
                let pong = PongPayload::decode(payload).unwrap();
                if pong.nonce == nonce {
                    pong_received = true;
                    break;
                }
            }
            Message::Ping { .. } | Message::SwitchToUdp { .. } => {}
            _ => {}
        }
    }
    assert!(pong_received, "did not observe switch-commit barrier pong");
}

#[tokio::test]
async fn session_keeps_tcp_when_udp_blackholed() {
    let (join, mut client, tx, _tun_rx, mut udp_rx, limits, assigned, _registry) =
        spawn_session().await;

    let dcid = Cid::from([0xE1; MAX_DCID_LEN]);
    let scid = Cid::from([0xE2; MAX_DCID_LEN]);
    let register = make_register_payload(dcid, scid, CipherSuite::Aes128Gcm);
    let mut reg_buf = Vec::new();
    register.encode(&mut reg_buf).unwrap();
    write_tcp_message(&mut client, Message::RegisterCid { payload: &reg_buf }).await;

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

    // Simulate UDP blackhole: no UpgradeProbe arrives from the client.
    let tcp_packet = ipv4_packet(assigned.addr(), Ipv4Addr::new(192, 0, 2, 201), 12);
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
    match decode_message(&buf, limits).unwrap().unwrap().0 {
        Message::Data { packet } => assert_eq!(packet, tcp_packet.as_slice()),
        _ => panic!("expected tcp data while udp is blackholed"),
    }

    assert!(
        timeout(Duration::from_millis(250), udp_rx.recv())
            .await
            .is_err(),
        "unexpected udp datagram without upgrade commit"
    );

    let _ = tx.send(SessionEvent::Shutdown).await;
    let _ = join.await.unwrap();
}

#[tokio::test]
async fn session_drops_udp_data_before_switch_commit() {
    let (join, mut client, tx, mut tun_rx, mut udp_rx, limits, assigned, _registry) =
        spawn_session().await;

    let dcid = Cid::from([0xE7; MAX_DCID_LEN]);
    let scid = Cid::from([0xE8; MAX_DCID_LEN]);
    let register = make_register_payload(dcid, scid, CipherSuite::Aes128Gcm);
    let mut reg_buf = Vec::new();
    register.encode(&mut reg_buf).unwrap();
    write_tcp_message(&mut client, Message::RegisterCid { payload: &reg_buf }).await;

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

    // UDP data before switch commit must not be treated as active transport.
    let keys = UdpQspKeys::from_register(&register).unwrap();
    let peer = SocketAddr::from(([127, 0, 0, 1], 56321));
    let uplink_packet = ipv4_packet(assigned.addr(), Ipv4Addr::new(192, 0, 2, 250), 12);
    send_udp_message(
        &tx,
        &keys,
        &register,
        peer,
        register.pn_start_rx,
        Message::Data {
            packet: &uplink_packet,
        },
    )
    .await;

    assert!(
        timeout(Duration::from_millis(250), tun_rx.recv())
            .await
            .is_err(),
        "udp data should be dropped before switch commit"
    );

    // TCP remains the stable active path.
    let tcp_packet = ipv4_packet(assigned.addr(), Ipv4Addr::new(192, 0, 2, 251), 12);
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
    match decode_message(&buf, limits).unwrap().unwrap().0 {
        Message::Data { packet } => assert_eq!(packet, tcp_packet.as_slice()),
        _ => panic!("expected tcp data before udp switch commit"),
    }

    assert!(
        timeout(Duration::from_millis(250), udp_rx.recv())
            .await
            .is_err(),
        "unexpected udp datagram before switch commit"
    );

    let _ = tx.send(SessionEvent::Shutdown).await;
    let _ = join.await.unwrap();
}

#[tokio::test]
async fn session_handles_udp_probe_reordering_before_ready() {
    let (join, mut client, tx, _tun_rx, mut udp_rx, limits, assigned, _registry) =
        spawn_session().await;

    let dcid = Cid::from([0xE3; MAX_DCID_LEN]);
    let scid = Cid::from([0xE4; MAX_DCID_LEN]);
    let register = make_register_payload(dcid, scid, CipherSuite::Aes128Gcm);
    let mut reg_buf = Vec::new();
    register.encode(&mut reg_buf).unwrap();
    write_tcp_message(&mut client, Message::RegisterCid { payload: &reg_buf }).await;

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
    let peer = SocketAddr::from(([127, 0, 0, 1], 54321));
    let upgrade_id = 0xD00D;

    // Reordered control: ready arrives before probe. No switch must be sent yet.
    let ready = UdpReadyPayload { upgrade_id };
    let mut ready_payload = Vec::new();
    ready.encode(&mut ready_payload);
    write_tcp_message(
        &mut client,
        Message::UdpReady {
            payload: &ready_payload,
        },
    )
    .await;
    assert!(
        timeout(
            Duration::from_millis(250),
            read_message_bytes(&mut client, limits)
        )
        .await
        .is_err(),
        "switch_to_udp sent before probe validation"
    );

    // Later probe acts like a retransmit after a lost first probe.
    let probe_nonce = 0xCAFE_BABE_0001;
    let probe = UpgradeProbePayload {
        upgrade_id,
        nonce: probe_nonce,
    };
    let mut probe_payload = Vec::new();
    probe.encode(&mut probe_payload);
    send_udp_message(
        &tx,
        &keys,
        &register,
        peer,
        register.pn_start_rx,
        Message::UpgradeProbe {
            payload: &probe_payload,
        },
    )
    .await;

    let ack_packet = timeout(Duration::from_secs(1), udp_rx.recv())
        .await
        .unwrap()
        .unwrap();
    let ack_opened = keys
        .open(
            register.client_to_server_cid.len(),
            &ack_packet,
            register.pn_start,
        )
        .unwrap();
    match decode_single_message(&ack_opened.payload, limits) {
        Message::UpgradeProbeAck { payload } => {
            let ack = UpgradeProbeAckPayload::decode(payload).unwrap();
            assert_eq!(ack.upgrade_id, upgrade_id);
            assert_eq!(ack.nonce, probe_nonce);
        }
        _ => panic!("expected upgrade_probe_ack"),
    }

    let switch_buf = timeout(
        Duration::from_secs(1),
        read_message_bytes(&mut client, limits),
    )
    .await
    .unwrap()
    .unwrap();
    match decode_message(&switch_buf, limits).unwrap().unwrap().0 {
        Message::SwitchToUdp { payload } => {
            let switch = SwitchToUdpPayload::decode(payload).unwrap();
            assert_eq!(switch.upgrade_id, upgrade_id);
        }
        _ => panic!("expected switch_to_udp"),
    }

    let switch_ack = SwitchAckPayload { upgrade_id };
    let mut switch_ack_payload = Vec::new();
    switch_ack.encode(&mut switch_ack_payload);
    write_tcp_message(
        &mut client,
        Message::SwitchAck {
            payload: &switch_ack_payload,
        },
    )
    .await;
    wait_for_switch_commit_barrier(&mut client, limits).await;

    // After commit, downlink traffic must go over UDP.
    let udp_expected_pn = ack_opened.pn + 1;
    let downlink_packet = ipv4_packet(assigned.addr(), Ipv4Addr::new(192, 0, 2, 202), 12);
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
            udp_expected_pn,
        )
        .unwrap();
    match decode_single_message(&opened.payload, limits) {
        Message::Data { packet } => assert_eq!(packet, downlink_packet.as_slice()),
        _ => panic!("expected udp data after switch commit"),
    }

    let _ = tx.send(SessionEvent::Shutdown).await;
    let _ = join.await.unwrap();
}

#[tokio::test]
async fn session_is_idempotent_for_duplicate_upgrade_controls() {
    let (join, mut client, tx, _tun_rx, mut udp_rx, limits, assigned, _registry) =
        spawn_session().await;

    let dcid = Cid::from([0xE5; MAX_DCID_LEN]);
    let scid = Cid::from([0xE6; MAX_DCID_LEN]);
    let register = make_register_payload(dcid, scid, CipherSuite::Aes128Gcm);
    let mut reg_buf = Vec::new();
    register.encode(&mut reg_buf).unwrap();
    write_tcp_message(&mut client, Message::RegisterCid { payload: &reg_buf }).await;

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
    let peer = SocketAddr::from(([127, 0, 0, 1], 55321));
    let upgrade_id = 0xD00E;

    // Out-of-order SwitchAck before commit should be ignored.
    let early_ack = SwitchAckPayload { upgrade_id };
    let mut early_ack_payload = Vec::new();
    early_ack.encode(&mut early_ack_payload);
    write_tcp_message(
        &mut client,
        Message::SwitchAck {
            payload: &early_ack_payload,
        },
    )
    .await;

    // Probe #1
    let probe1 = UpgradeProbePayload {
        upgrade_id,
        nonce: 0x1111,
    };
    let mut probe1_payload = Vec::new();
    probe1.encode(&mut probe1_payload);
    send_udp_message(
        &tx,
        &keys,
        &register,
        peer,
        register.pn_start_rx,
        Message::UpgradeProbe {
            payload: &probe1_payload,
        },
    )
    .await;
    let ack_packet_1 = timeout(Duration::from_secs(1), udp_rx.recv())
        .await
        .unwrap()
        .unwrap();
    let ack_opened_1 = keys
        .open(
            register.client_to_server_cid.len(),
            &ack_packet_1,
            register.pn_start,
        )
        .unwrap();
    assert!(matches!(
        decode_single_message(&ack_opened_1.payload, limits),
        Message::UpgradeProbeAck { .. }
    ));

    // Probe #2 (duplicate / retransmit with same upgrade_id)
    let probe2 = UpgradeProbePayload {
        upgrade_id,
        nonce: 0x2222,
    };
    let mut probe2_payload = Vec::new();
    probe2.encode(&mut probe2_payload);
    send_udp_message(
        &tx,
        &keys,
        &register,
        peer,
        register.pn_start_rx + 1,
        Message::UpgradeProbe {
            payload: &probe2_payload,
        },
    )
    .await;
    let ack_packet_2 = timeout(Duration::from_secs(1), udp_rx.recv())
        .await
        .unwrap()
        .unwrap();
    let ack_opened_2 = keys
        .open(
            register.client_to_server_cid.len(),
            &ack_packet_2,
            ack_opened_1.pn + 1,
        )
        .unwrap();
    assert!(matches!(
        decode_single_message(&ack_opened_2.payload, limits),
        Message::UpgradeProbeAck { .. }
    ));

    let ready = UdpReadyPayload { upgrade_id };
    let mut ready_payload = Vec::new();
    ready.encode(&mut ready_payload);
    write_tcp_message(
        &mut client,
        Message::UdpReady {
            payload: &ready_payload,
        },
    )
    .await;

    let switch_buf = timeout(
        Duration::from_secs(1),
        read_message_bytes(&mut client, limits),
    )
    .await
    .unwrap()
    .unwrap();
    match decode_message(&switch_buf, limits).unwrap().unwrap().0 {
        Message::SwitchToUdp { payload } => {
            let switch = SwitchToUdpPayload::decode(payload).unwrap();
            assert_eq!(switch.upgrade_id, upgrade_id);
        }
        _ => panic!("expected switch_to_udp"),
    }

    // Duplicate UdpReady must not emit another SwitchToUdp.
    write_tcp_message(
        &mut client,
        Message::UdpReady {
            payload: &ready_payload,
        },
    )
    .await;
    assert!(
        timeout(
            Duration::from_millis(250),
            read_message_bytes(&mut client, limits)
        )
        .await
        .is_err(),
        "duplicate udp_ready produced duplicate switch_to_udp"
    );

    // Commit switch and verify duplicate SwitchAck is ignored.
    let switch_ack = SwitchAckPayload { upgrade_id };
    let mut switch_ack_payload = Vec::new();
    switch_ack.encode(&mut switch_ack_payload);
    write_tcp_message(
        &mut client,
        Message::SwitchAck {
            payload: &switch_ack_payload,
        },
    )
    .await;
    write_tcp_message(
        &mut client,
        Message::SwitchAck {
            payload: &switch_ack_payload,
        },
    )
    .await;
    wait_for_switch_commit_barrier(&mut client, limits).await;

    // After duplicate controls, session should still emit UDP data.
    let udp_expected_pn = ack_opened_2.pn + 1;
    let downlink_packet = ipv4_packet(assigned.addr(), Ipv4Addr::new(192, 0, 2, 203), 12);
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
            udp_expected_pn,
        )
        .unwrap();
    match decode_single_message(&opened.payload, limits) {
        Message::Data { packet } => assert_eq!(packet, downlink_packet.as_slice()),
        _ => panic!("expected udp data after duplicate controls"),
    }

    let _ = tx.send(SessionEvent::Shutdown).await;
    let _ = join.await.unwrap();
}
