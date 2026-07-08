use std::net::{Ipv4Addr, SocketAddr};

use slt_core::crypto::udp_qsp::UdpQspKeys;
use slt_core::proto::{
    CipherSuite, CloseCode, ClosePayload, Message, PingPayload, PongPayload, decode_message,
    encode_message,
};
use slt_core::types::{Cid, MAX_DCID_LEN};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::time::{Duration, timeout};
use tokio_util::sync::CancellationToken;

use super::super::*;
use super::common::{
    complete_udp_upgrade_handshake, ipv4_packet, make_register_payload, read_message_bytes,
    spawn_session, spawn_session_with_timeouts,
};
use crate::quic::UdpClaim;
use crate::test_support::{TlsDuplexStream, default_session_timeouts};

#[tokio::test]
async fn session_idle_timeout_sends_close() {
    let mut timeouts = default_session_timeouts();
    timeouts.idle_timeout = Duration::from_millis(50);
    timeouts.ping_min = Duration::from_secs(5);
    timeouts.ping_max = Duration::from_secs(5);

    let (join, mut client, _tx, _tun_rx, _udp_rx, limits, _assigned, _registry) =
        spawn_session_with_timeouts(timeouts).await;

    tokio::time::sleep(Duration::from_millis(80)).await;

    let buf = timeout(
        Duration::from_secs(1),
        read_message_bytes(&mut client, limits),
    )
    .await
    .unwrap()
    .unwrap();
    let (message, _) = decode_message(&buf, limits).unwrap().unwrap();
    match message {
        Message::Close { payload } => {
            let close = ClosePayload::decode(payload).unwrap();
            assert_eq!(close.code, CloseCode::IdleTimeout);
        }
        _ => panic!("expected close"),
    }

    let result = timeout(Duration::from_secs(1), join)
        .await
        .unwrap()
        .unwrap();
    assert!(result.is_ok());
}

#[tokio::test]
async fn partial_tcp_frame_does_not_reset_idle_timeout() {
    let mut timeouts = default_session_timeouts();
    timeouts.idle_timeout = Duration::from_millis(300);
    timeouts.ping_min = Duration::from_secs(5);
    timeouts.ping_max = Duration::from_secs(5);

    let (join, mut client, _tx, _tun_rx, _udp_rx, limits, _assigned, _registry) =
        spawn_session_with_timeouts(timeouts).await;

    tokio::time::sleep(Duration::from_millis(220)).await;

    let mut payload = Vec::new();
    PingPayload { nonce: 0xCAFE }.encode(&mut payload);
    let mut frame = Vec::new();
    encode_message(Message::Ping { payload: &payload }, &mut frame).unwrap();
    client.write_all(&frame[..1]).await.unwrap();
    client.flush().await.unwrap();

    let buf = timeout(
        Duration::from_millis(180),
        read_message_bytes(&mut client, limits),
    )
    .await
    .expect("partial frame bytes must not extend the original idle deadline")
    .unwrap();
    let (message, _) = decode_message(&buf, limits).unwrap().unwrap();
    match message {
        Message::Close { payload } => {
            let close = ClosePayload::decode(payload).unwrap();
            assert_eq!(close.code, CloseCode::IdleTimeout);
        }
        _ => panic!("expected close"),
    }

    let result = timeout(Duration::from_secs(1), join)
        .await
        .unwrap()
        .unwrap();
    assert!(result.is_ok());
}

#[tokio::test]
async fn tun_downlink_does_not_reset_idle_timeout() {
    let mut timeouts = default_session_timeouts();
    timeouts.idle_timeout = Duration::from_millis(300);
    timeouts.ping_min = Duration::from_secs(5);
    timeouts.ping_max = Duration::from_secs(5);

    let (join, mut client, tx, _tun_rx, _udp_rx, limits, assigned, _registry) =
        spawn_session_with_timeouts(timeouts).await;

    tokio::time::sleep(Duration::from_millis(220)).await;

    let packet = ipv4_packet(Ipv4Addr::new(192, 0, 2, 10), assigned.addr(), 8);
    tx.send(SessionEvent::TunPacket(packet)).await.unwrap();

    let close_code = read_until_close_code(&mut client, limits, Duration::from_millis(180)).await;
    assert_eq!(close_code, CloseCode::IdleTimeout);

    let result = timeout(Duration::from_secs(1), join)
        .await
        .unwrap()
        .unwrap();
    assert!(result.is_ok());
}

#[tokio::test]
async fn session_sends_tcp_ping_on_schedule() {
    let mut timeouts = default_session_timeouts();
    timeouts.ping_min = Duration::from_millis(50);
    timeouts.ping_max = Duration::from_millis(50);
    timeouts.idle_timeout = Duration::from_secs(5);

    let (join, mut client, tx, _tun_rx, _udp_rx, limits, _assigned, _registry) =
        spawn_session_with_timeouts(timeouts).await;

    tokio::time::sleep(Duration::from_millis(80)).await;

    let buf = timeout(
        Duration::from_secs(1),
        read_message_bytes(&mut client, limits),
    )
    .await
    .unwrap()
    .unwrap();
    let (message, _) = decode_message(&buf, limits).unwrap().unwrap();
    assert!(matches!(message, Message::Ping { .. }));

    let _ = tx.send(SessionEvent::Shutdown).await;
    let _ = join.await.unwrap();
}

async fn read_until_close_code(
    stream: &mut TlsDuplexStream,
    limits: MessageLimits,
    duration: Duration,
) -> CloseCode {
    timeout(duration, async {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            let n = stream.read(&mut chunk).await.unwrap();
            assert_ne!(n, 0, "stream closed before close message");
            buf.extend_from_slice(&chunk[..n]);

            loop {
                let Some((message, consumed)) = decode_message(&buf, limits).unwrap() else {
                    break;
                };
                let close_code = match message {
                    Message::Close { payload } => Some(ClosePayload::decode(payload).unwrap().code),
                    _ => None,
                };
                buf.drain(..consumed);
                if let Some(code) = close_code {
                    return code;
                }
            }
        }
    })
    .await
    .expect("downlink event must not extend the original idle deadline")
}

#[tokio::test]
async fn session_sends_udp_ping_on_schedule() {
    let mut timeouts = default_session_timeouts();
    timeouts.ping_min = Duration::from_millis(200);
    timeouts.ping_max = Duration::from_millis(200);
    timeouts.idle_timeout = Duration::from_secs(5);

    let (join, mut client, tx, _tun_rx, mut udp_rx, limits, _assigned, _registry) =
        spawn_session_with_timeouts(timeouts).await;

    let dcid = Cid::from([0x41; MAX_DCID_LEN]);
    let scid = Cid::from([0x42; MAX_DCID_LEN]);
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
    let peer = SocketAddr::from(([127, 0, 0, 1], 33333));
    let mut server_expected_pn = complete_udp_upgrade_handshake(
        &mut client,
        &tx,
        &mut udp_rx,
        limits,
        &register,
        peer,
        0x1400,
    )
    .await;

    tokio::time::sleep(Duration::from_millis(250)).await;
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
    let verify_nonce = match message {
        Message::Ping { payload } => PingPayload::decode(payload).unwrap().nonce,
        _ => panic!("expected verify ping"),
    };
    server_expected_pn = opened.pn + 1;

    let pong = PongPayload {
        nonce: verify_nonce,
    };
    let mut pong_payload = Vec::new();
    pong.encode(&mut pong_payload);
    let mut pong_frame = Vec::new();
    encode_message(
        Message::Pong {
            payload: &pong_payload,
        },
        &mut pong_frame,
    )
    .unwrap();
    let packet = keys
        .protect(
            register.client_to_server_cid.as_slice(),
            register.pn_start_rx + 1,
            register.key_phase,
            &pong_frame,
        )
        .unwrap();
    let claim = UdpClaim {
        peer,
        dcid_prefix: register.client_to_server_cid.prefix().unwrap(),
        payload: packet,
    };
    tx.send(SessionEvent::Udp(claim)).await.unwrap();

    tokio::time::sleep(Duration::from_millis(250)).await;

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
    assert!(matches!(message, Message::Ping { .. }));

    let _ = tx.send(SessionEvent::Shutdown).await;
    let _ = join.await.unwrap();
}

#[tokio::test]
async fn session_cleans_registry_on_shutdown() {
    let (join, mut client, tx, _tun_rx, _udp_rx, limits, assigned, registry) =
        spawn_session().await;

    let dcid = Cid::from([0x51; MAX_DCID_LEN]);
    let scid = Cid::from([0x52; MAX_DCID_LEN]);
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
    assert!(registry.has_cid(register.client_to_server_cid.prefix().unwrap()));
    assert!(registry.lookup_ip(assigned.addr()).is_some());

    let _ = tx.send(SessionEvent::Shutdown).await;
    let _ = join.await.unwrap();

    assert!(registry.lookup_ip(assigned.addr()).is_none());
    assert!(!registry.has_cid(register.client_to_server_cid.prefix().unwrap()));
}

#[tokio::test]
async fn replacement_shutdown_exits_running_session_with_full_queue() {
    let (join, _client, tx, _tun_rx, _udp_rx, _limits, assigned, registry) = spawn_session().await;

    tokio::task::yield_now().await;

    for i in 0..8 {
        let packet = ipv4_packet(assigned.addr(), Ipv4Addr::new(192, 0, 2, 100 + i), 8);
        tx.try_send(SessionEvent::TunPacket(packet)).unwrap();
    }
    let extra_packet = ipv4_packet(assigned.addr(), Ipv4Addr::new(192, 0, 2, 200), 8);
    assert!(matches!(
        tx.try_send(SessionEvent::TunPacket(extra_packet)),
        Err(mpsc::error::TrySendError::Full(SessionEvent::TunPacket(_)))
    ));

    let client_id = ClientId([0xA5; 16]);
    let replacement_assigned = AssignedIp(Ipv4Addr::new(10, 0, 0, 10));
    let (replacement_tx, _replacement_rx) = mpsc::channel(1);
    let replacement_shutdown = CancellationToken::new();
    let (_replacement, old) = registry.register_session(
        client_id,
        replacement_assigned,
        replacement_tx,
        replacement_shutdown,
    );
    old.expect("old session must be registered")
        .shutdown
        .cancel();

    let result = timeout(Duration::from_secs(1), join)
        .await
        .unwrap()
        .unwrap();
    assert!(result.is_ok());
    assert!(registry.lookup_ip(assigned.addr()).is_none());
    assert!(registry.lookup_ip(replacement_assigned.addr()).is_some());
}

#[tokio::test]
async fn session_continues_on_udp_after_tcp_close() {
    let (join, mut client, tx, mut tun_rx, mut udp_rx, limits, assigned, _registry) =
        spawn_session().await;

    // Register UDP
    let dcid = Cid::from([0x61; MAX_DCID_LEN]);
    let scid = Cid::from([0x62; MAX_DCID_LEN]);
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
    let peer = SocketAddr::from(([127, 0, 0, 1], 22222));
    let _ = complete_udp_upgrade_handshake(
        &mut client,
        &tx,
        &mut udp_rx,
        limits,
        &register,
        peer,
        0x1401,
    )
    .await;

    // Session should still handle UDP traffic.
    let uplink_packet = ipv4_packet(assigned.addr(), Ipv4Addr::new(192, 0, 2, 10), 8);
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

    // Close TCP connection
    drop(client);

    // Session should still handle UDP traffic
    let uplink_packet2 = ipv4_packet(assigned.addr(), Ipv4Addr::new(192, 0, 2, 11), 8);
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

    let received2 = timeout(Duration::from_secs(1), tun_rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(received2, uplink_packet2);

    // Clean shutdown
    let _ = tx.send(SessionEvent::Shutdown).await;
    let _ = join.await.unwrap();
}

#[tokio::test]
async fn session_closes_via_udp_when_tcp_dead() {
    let (join, mut client, tx, _tun_rx, mut udp_rx, limits, _assigned, _registry) =
        spawn_session().await;

    // Register and complete upgrade commit.
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
    let peer = SocketAddr::from(([127, 0, 0, 1], 45678));
    let server_expected_pn = complete_udp_upgrade_handshake(
        &mut client,
        &tx,
        &mut udp_rx,
        limits,
        &register,
        peer,
        0x1402,
    )
    .await;

    // Close TCP connection
    drop(client);

    // Give session time to notice TCP close
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Session should still handle UDP and respond via UDP
    let ping_nonce = 0xFEED_FACE_CAFE_BEEFu64;
    let ping_payload = PingPayload { nonce: ping_nonce };
    let mut ping_buf = Vec::new();
    ping_payload.encode(&mut ping_buf);
    let mut ping_frame = Vec::new();
    encode_message(Message::Ping { payload: &ping_buf }, &mut ping_frame).unwrap();
    let udp_ping = keys
        .protect(
            register.client_to_server_cid.as_slice(),
            register.pn_start_rx + 1,
            register.key_phase,
            &ping_frame,
        )
        .unwrap();
    tx.send(SessionEvent::Udp(UdpClaim {
        peer,
        dcid_prefix: register.client_to_server_cid.prefix().unwrap(),
        payload: udp_ping,
    }))
    .await
    .unwrap();

    // Should receive PONG via UDP
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
        Message::Pong { payload } => {
            let pong = PongPayload::decode(payload).unwrap();
            assert_eq!(pong.nonce, ping_nonce);
        }
        _ => panic!("expected pong via UDP"),
    }

    // Clean shutdown
    let _ = tx.send(SessionEvent::Shutdown).await;
    let _ = join.await.unwrap();
}

#[tokio::test]
async fn session_ping_uses_jitter_when_range_nonzero() {
    // Test that ping scheduling uses jitter when min != max
    // We can't test exact timing, but we can verify the session works with jitter enabled
    let mut timeouts = default_session_timeouts();
    timeouts.ping_min = Duration::from_millis(50);
    timeouts.ping_max = Duration::from_millis(100); // 50ms jitter range
    timeouts.idle_timeout = Duration::from_secs(5);

    let (join, mut client, tx, _tun_rx, _udp_rx, limits, _assigned, _registry) =
        spawn_session_with_timeouts(timeouts).await;

    // Wait for at least the minimum ping interval
    tokio::time::sleep(Duration::from_millis(60)).await;

    // Should receive a ping within the jitter range
    let buf = timeout(
        Duration::from_millis(100), // Extra time for jitter
        read_message_bytes(&mut client, limits),
    )
    .await
    .unwrap()
    .unwrap();
    let (message, _) = decode_message(&buf, limits).unwrap().unwrap();
    assert!(matches!(message, Message::Ping { .. }));

    let _ = tx.send(SessionEvent::Shutdown).await;
    let _ = join.await.unwrap();
}
