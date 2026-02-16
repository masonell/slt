//! Integration tests for client session handling.

use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use slt_core::crypto::udp_qsp::UdpQspKeys;
use slt_core::proto::{
    AEAD_IV_LEN, AEAD_KEY_LEN, CipherSuite, CloseCode, ClosePayload, HP_KEY_LEN, MessageLimits,
    RegisterCidPayload, RegisterFailCode, RegisterFailPayload, decode_message, encode_message,
};
use slt_core::transport::tcp::TcpChannel;
use slt_core::types::{Cid, QUIC_DCID_PREFIX_LEN};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::sync::mpsc;
use tokio::time::{Duration, timeout};

use super::*;
use crate::test_support::{
    TestTun, TestUdpSocket, TlsDuplexStream, default_session_timeouts, tls_pair,
};

async fn spawn_session() -> (
    tokio::task::JoinHandle<io::Result<()>>,
    TlsDuplexStream,
    SessionTx,
    mpsc::Receiver<Vec<u8>>,
    mpsc::Receiver<Vec<u8>>,
    MessageLimits,
    AssignedIp,
    Arc<SessionRegistry>,
) {
    spawn_session_with_timeouts(default_session_timeouts()).await
}

async fn spawn_session_with_timeouts(
    timeouts: SessionTimeouts,
) -> (
    tokio::task::JoinHandle<io::Result<()>>,
    TlsDuplexStream,
    SessionTx,
    mpsc::Receiver<Vec<u8>>,
    mpsc::Receiver<Vec<u8>>,
    MessageLimits,
    AssignedIp,
    Arc<SessionRegistry>,
) {
    let (server_tls, client_tls) = tls_pair().await;
    let (tun, tun_rx) = TestTun::new(8);
    let (udp, udp_rx) = TestUdpSocket::new(16);
    let registry = Arc::new(SessionRegistry::new());
    let metrics = Arc::new(Metrics::default());
    let (tx, rx) = mpsc::channel(8);
    let client_id = ClientId([0xA5; 16]);
    let assigned = AssignedIp(Ipv4Addr::new(10, 0, 0, 9));
    let (handle, _old) = registry.register_session(client_id, assigned, tx.clone());
    let limits = MessageLimits::from_mtu(1500);
    let session = ClientSessionBase::<TestTun, DuplexStream, TestUdpSocket>::new(
        handle.session_id,
        client_id,
        assigned,
        TcpChannel::with_key_updater(server_tls, SessionKeyUpdater::new(metrics.clone())),
        tun,
        udp,
        registry.clone(),
        metrics,
        tx.clone(),
        rx,
        limits,
        timeouts,
    );
    let join = tokio::spawn(async move { session.run().await });
    (
        join, client_tls, tx, tun_rx, udp_rx, limits, assigned, registry,
    )
}

async fn read_message_bytes(
    stream: &mut TlsDuplexStream,
    limits: MessageLimits,
) -> io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "tls closed"));
        }
        buf.extend_from_slice(&chunk[..n]);
        match decode_message(&buf, limits) {
            Ok(Some((_msg, _))) => return Ok(buf),
            Ok(None) => {}
            Err(err) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("message error: {err:?}"),
                ));
            }
        }
    }
}

fn ipv4_packet(src: Ipv4Addr, dst: Ipv4Addr, payload_len: usize) -> Vec<u8> {
    let total_len = 20 + payload_len;
    let total_len_u16 = u16::try_from(total_len).expect("payload too large for IPv4 packet");
    let mut packet = vec![0u8; total_len];
    packet[0] = 0x45;
    let [hi, lo] = total_len_u16.to_be_bytes();
    packet[2] = hi;
    packet[3] = lo;
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&src.octets());
    packet[16..20].copy_from_slice(&dst.octets());
    if payload_len > 0 {
        packet[20] = 0xAA;
    }
    packet
}

fn make_register_payload(dcid: Cid, scid: Cid, cipher: CipherSuite) -> RegisterCidPayload {
    RegisterCidPayload {
        dcid,
        scid,
        cipher,
        hp_tx: [0x11; HP_KEY_LEN],
        hp_rx: [0x11; HP_KEY_LEN],
        aead_tx: [0x22; AEAD_KEY_LEN],
        aead_rx: [0x22; AEAD_KEY_LEN],
        iv_tx: [0x33; AEAD_IV_LEN],
        iv_rx: [0x33; AEAD_IV_LEN],
        pn_start: 0,
        pn_start_rx: 0,
        key_phase: false,
    }
}

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
#[allow(clippy::too_many_lines)]
async fn session_registers_udp_and_forwards_data() {
    let (join, mut client, tx, _tun_rx, mut udp_rx, limits, assigned, _registry) =
        spawn_session().await;

    let dcid = Cid::from([0xAA; QUIC_DCID_PREFIX_LEN]);
    let scid = Cid::from([0xBB; QUIC_DCID_PREFIX_LEN]);
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

    // Send a UDP PING to establish the peer address.
    // Server switches to UDP after this first valid claim.
    let probe_nonce = 0xA1B2_C3D4_E5F6_0708;
    let probe = PingPayload { nonce: probe_nonce };
    let mut probe_payload = Vec::new();
    probe.encode(&mut probe_payload);
    let mut probe_frame = Vec::new();
    encode_message(
        Message::Ping {
            payload: &probe_payload,
        },
        &mut probe_frame,
    )
    .unwrap();
    let packet = keys
        .protect(
            register.dcid.as_slice(),
            0,
            register.key_phase,
            &probe_frame,
        )
        .unwrap();
    let claim = UdpClaim {
        peer,
        dcid_prefix: register.dcid.prefix(),
        payload: packet,
    };
    tx.send(SessionEvent::Udp(claim)).await.unwrap();

    // Wait for PONG response (establishes peer and verifies UDP works)
    let mut server_expected_pn = register.pn_start;
    let packet = timeout(Duration::from_secs(1), udp_rx.recv())
        .await
        .unwrap()
        .unwrap();
    let opened = keys
        .open(register.dcid.len(), &packet, server_expected_pn)
        .unwrap();
    server_expected_pn = opened.pn + 1;
    let (message, consumed) = decode_message(&opened.payload, limits).unwrap().unwrap();
    assert_eq!(consumed, opened.payload.len());
    assert!(
        matches!(message, Message::Pong { .. }),
        "expected pong response"
    );

    // Now send a TUN packet and verify it's forwarded via UDP.
    let data_packet = ipv4_packet(assigned.addr(), Ipv4Addr::new(192, 0, 2, 3), 12);
    tx.send(SessionEvent::TunPacket(data_packet.clone()))
        .await
        .unwrap();

    let packet = timeout(Duration::from_millis(200), udp_rx.recv())
        .await
        .unwrap()
        .unwrap();
    let opened = keys
        .open(register.dcid.len(), &packet, server_expected_pn)
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
async fn session_switches_to_udp_after_first_valid_data_claim() {
    let (join, mut client, tx, mut tun_rx, mut udp_rx, limits, assigned, _registry) =
        spawn_session().await;

    let dcid = Cid::from([0xCC; QUIC_DCID_PREFIX_LEN]);
    let scid = Cid::from([0xDD; QUIC_DCID_PREFIX_LEN]);
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
        .protect(register.dcid.as_slice(), 0, register.key_phase, &data_frame)
        .unwrap();
    let claim = UdpClaim {
        peer,
        dcid_prefix: register.dcid.prefix(),
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
        .open(register.dcid.len(), &packet, register.pn_start)
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
async fn session_register_rejects_invalid_keys() {
    let (join, mut client, tx, _tun_rx, _udp_rx, limits, _assigned, _registry) =
        spawn_session().await;

    let dcid = Cid::from([0xAB; QUIC_DCID_PREFIX_LEN]);
    let scid = Cid::from([0xBC; QUIC_DCID_PREFIX_LEN]);
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
    match message {
        Message::RegisterFail { payload } => {
            let fail = RegisterFailPayload::decode(payload).unwrap();
            assert_eq!(fail.code, RegisterFailCode::InvalidKeys);
        }
        _ => panic!("expected register fail"),
    }

    let _ = tx.send(SessionEvent::Shutdown).await;
    let _ = join.await.unwrap();
}

#[tokio::test]
async fn session_register_rejects_prefix_collision() {
    let (join, mut client, tx, _tun_rx, _udp_rx, limits, _assigned, registry) =
        spawn_session().await;

    let dcid = Cid::from([0xCD; QUIC_DCID_PREFIX_LEN]);
    let scid = Cid::from([0xDE; QUIC_DCID_PREFIX_LEN]);
    let (dummy_tx, _dummy_rx) = mpsc::channel(1);
    registry.insert_cid(999, dcid.prefix(), dummy_tx).unwrap();

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

#[tokio::test]
async fn session_sends_udp_ping_on_schedule() {
    let mut timeouts = default_session_timeouts();
    timeouts.ping_min = Duration::from_millis(200);
    timeouts.ping_max = Duration::from_millis(200);
    timeouts.idle_timeout = Duration::from_secs(5);

    let (join, mut client, tx, _tun_rx, mut udp_rx, limits, _assigned, _registry) =
        spawn_session_with_timeouts(timeouts).await;

    let dcid = Cid::from([0x41; QUIC_DCID_PREFIX_LEN]);
    let scid = Cid::from([0x42; QUIC_DCID_PREFIX_LEN]);
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
    let peer = SocketAddr::from(([127, 0, 0, 1], 33333));

    let packet = ipv4_packet(Ipv4Addr::new(10, 0, 0, 9), Ipv4Addr::new(192, 0, 2, 4), 8);
    let mut data_frame = Vec::new();
    encode_message(Message::Data { packet: &packet }, &mut data_frame).unwrap();
    let packet = keys
        .protect(register.dcid.as_slice(), 0, register.key_phase, &data_frame)
        .unwrap();
    let claim = UdpClaim {
        peer,
        dcid_prefix: register.dcid.prefix(),
        payload: packet,
    };
    tx.send(SessionEvent::Udp(claim)).await.unwrap();

    let packet = timeout(Duration::from_secs(1), udp_rx.recv())
        .await
        .unwrap()
        .unwrap();
    let opened = keys
        .open(register.dcid.len(), &packet, register.pn_start)
        .unwrap();
    let (message, consumed) = decode_message(&opened.payload, limits).unwrap().unwrap();
    assert_eq!(consumed, opened.payload.len());
    let verify_nonce = match message {
        Message::Ping { payload } => PingPayload::decode(payload).unwrap().nonce,
        _ => panic!("expected verify ping"),
    };
    let server_expected_pn = opened.pn + 1;

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
        .protect(register.dcid.as_slice(), 1, register.key_phase, &pong_frame)
        .unwrap();
    let claim = UdpClaim {
        peer,
        dcid_prefix: register.dcid.prefix(),
        payload: packet,
    };
    tx.send(SessionEvent::Udp(claim)).await.unwrap();

    tokio::time::sleep(Duration::from_millis(250)).await;

    let packet = timeout(Duration::from_secs(1), udp_rx.recv())
        .await
        .unwrap()
        .unwrap();
    let opened = keys
        .open(register.dcid.len(), &packet, server_expected_pn)
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

    let dcid = Cid::from([0x51; QUIC_DCID_PREFIX_LEN]);
    let scid = Cid::from([0x52; QUIC_DCID_PREFIX_LEN]);
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
    assert!(registry.has_cid(register.dcid.prefix()));
    assert!(registry.lookup_ip(assigned.addr()).is_some());

    let _ = tx.send(SessionEvent::Shutdown).await;
    let _ = join.await.unwrap();

    assert!(registry.lookup_ip(assigned.addr()).is_none());
    assert!(!registry.has_cid(register.dcid.prefix()));
}

#[tokio::test]
async fn session_continues_on_udp_after_tcp_close() {
    let (join, mut client, tx, mut tun_rx, _udp_rx, limits, assigned, _registry) =
        spawn_session().await;

    // Register UDP
    let dcid = Cid::from([0x61; QUIC_DCID_PREFIX_LEN]);
    let scid = Cid::from([0x62; QUIC_DCID_PREFIX_LEN]);
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

    // Activate UDP with a data packet
    let keys = UdpQspKeys::from_register(&register).unwrap();
    let peer = SocketAddr::from(([127, 0, 0, 1], 22222));
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
        .protect(register.dcid.as_slice(), 0, register.key_phase, &data_frame)
        .unwrap();
    tx.send(SessionEvent::Udp(UdpClaim {
        peer,
        dcid_prefix: register.dcid.prefix(),
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
            register.dcid.as_slice(),
            1,
            register.key_phase,
            &data_frame2,
        )
        .unwrap();
    tx.send(SessionEvent::Udp(UdpClaim {
        peer,
        dcid_prefix: register.dcid.prefix(),
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
    let dcid = Cid::from([0x71; QUIC_DCID_PREFIX_LEN]);
    let scid = Cid::from([0x72; QUIC_DCID_PREFIX_LEN]);
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
        .protect(register.dcid.as_slice(), 0, register.key_phase, &udp_frame)
        .unwrap();
    tx.send(SessionEvent::Udp(UdpClaim {
        peer,
        dcid_prefix: register.dcid.prefix(),
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

#[tokio::test]
async fn session_drops_udp_message_with_trailing_data() {
    let (join, mut client, tx, mut tun_rx, _udp_rx, limits, assigned, _registry) =
        spawn_session().await;

    // Register UDP
    let dcid = Cid::from([0x81; QUIC_DCID_PREFIX_LEN]);
    let scid = Cid::from([0x82; QUIC_DCID_PREFIX_LEN]);
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
        .protect(register.dcid.as_slice(), 0, register.key_phase, &data_frame)
        .unwrap();
    tx.send(SessionEvent::Udp(UdpClaim {
        peer,
        dcid_prefix: register.dcid.prefix(),
        payload: udp_packet,
    }))
    .await
    .unwrap();

    // Should NOT forward to TUN (dropped due to trailing data)
    match timeout(Duration::from_millis(200), tun_rx.recv()).await {
        Ok(Some(_)) => panic!("UDP message with trailing data should be dropped"),
        Ok(None) | Err(_) => {}
    }

    let _ = tx.send(SessionEvent::Shutdown).await;
    let _ = join.await.unwrap();
}

// =========================================================================
// UDP error handling tests
// =========================================================================

#[tokio::test]
async fn session_drops_udp_replay_packet() {
    let (join, mut client, tx, mut tun_rx, _udp_rx, limits, assigned, _registry) =
        spawn_session().await;

    // Register and activate UDP
    let dcid = Cid::from([0x91; QUIC_DCID_PREFIX_LEN]);
    let scid = Cid::from([0x92; QUIC_DCID_PREFIX_LEN]);
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

    // Send first valid data packet (PN=0)
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
        .protect(register.dcid.as_slice(), 0, register.key_phase, &data_frame)
        .unwrap();
    tx.send(SessionEvent::Udp(UdpClaim {
        peer,
        dcid_prefix: register.dcid.prefix(),
        payload: udp_packet.clone(),
    }))
    .await
    .unwrap();

    let received = timeout(Duration::from_secs(1), tun_rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(received, uplink_packet);

    // Replay the same packet (same PN=0) - should be dropped
    tx.send(SessionEvent::Udp(UdpClaim {
        peer,
        dcid_prefix: register.dcid.prefix(),
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
    let (join, mut client, tx, mut tun_rx, _udp_rx, limits, assigned, _registry) =
        spawn_session().await;

    // Register and activate UDP
    let dcid = Cid::from([0x93; QUIC_DCID_PREFIX_LEN]);
    let scid = Cid::from([0x94; QUIC_DCID_PREFIX_LEN]);
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

    // Send a valid packet first to activate UDP
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
        .protect(register.dcid.as_slice(), 0, register.key_phase, &data_frame)
        .unwrap();
    tx.send(SessionEvent::Udp(UdpClaim {
        peer,
        dcid_prefix: register.dcid.prefix(),
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
        dcid_prefix: register.dcid.prefix(),
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
            register.dcid.as_slice(),
            1,
            register.key_phase,
            &data_frame2,
        )
        .unwrap();
    tx.send(SessionEvent::Udp(UdpClaim {
        peer,
        dcid_prefix: register.dcid.prefix(),
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
async fn session_handles_udp_pong() {
    let (join, mut client, tx, mut tun_rx, _udp_rx, limits, assigned, _registry) =
        spawn_session().await;

    // Register and activate UDP
    let dcid = Cid::from([0xA1; QUIC_DCID_PREFIX_LEN]);
    let scid = Cid::from([0xA2; QUIC_DCID_PREFIX_LEN]);
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
        .protect(register.dcid.as_slice(), 0, register.key_phase, &data_frame)
        .unwrap();
    tx.send(SessionEvent::Udp(UdpClaim {
        peer,
        dcid_prefix: register.dcid.prefix(),
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
        .protect(register.dcid.as_slice(), 1, register.key_phase, &pong_frame)
        .unwrap();
    tx.send(SessionEvent::Udp(UdpClaim {
        peer,
        dcid_prefix: register.dcid.prefix(),
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
            register.dcid.as_slice(),
            2,
            register.key_phase,
            &data_frame2,
        )
        .unwrap();
    tx.send(SessionEvent::Udp(UdpClaim {
        peer,
        dcid_prefix: register.dcid.prefix(),
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
    let dcid = Cid::from([0xB1; QUIC_DCID_PREFIX_LEN]);
    let scid = Cid::from([0xB2; QUIC_DCID_PREFIX_LEN]);
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
        .protect(register.dcid.as_slice(), 0, register.key_phase, &data_frame)
        .unwrap();
    tx.send(SessionEvent::Udp(UdpClaim {
        peer,
        dcid_prefix: register.dcid.prefix(),
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
                register.dcid.as_slice(),
                (i + 1) as u64,
                register.key_phase,
                &ctrl_frame,
            )
            .unwrap();
        tx.send(SessionEvent::Udp(UdpClaim {
            peer,
            dcid_prefix: register.dcid.prefix(),
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
            register.dcid.as_slice(),
            6,
            register.key_phase,
            &data_frame2,
        )
        .unwrap();
    tx.send(SessionEvent::Udp(UdpClaim {
        peer,
        dcid_prefix: register.dcid.prefix(),
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
async fn session_closes_via_udp_when_tcp_dead() {
    let (join, mut client, tx, mut tun_rx, mut udp_rx, limits, assigned, _registry) =
        spawn_session().await;

    // Register and activate UDP
    let dcid = Cid::from([0xC1; QUIC_DCID_PREFIX_LEN]);
    let scid = Cid::from([0xC2; QUIC_DCID_PREFIX_LEN]);
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
    let peer = SocketAddr::from(([127, 0, 0, 1], 45678));

    // Activate UDP with a data packet
    let uplink_packet = ipv4_packet(assigned.addr(), Ipv4Addr::new(192, 0, 2, 70), 8);
    let mut data_frame = Vec::new();
    encode_message(
        Message::Data {
            packet: &uplink_packet,
        },
        &mut data_frame,
    )
    .unwrap();
    let udp_packet = keys
        .protect(register.dcid.as_slice(), 0, register.key_phase, &data_frame)
        .unwrap();
    tx.send(SessionEvent::Udp(UdpClaim {
        peer,
        dcid_prefix: register.dcid.prefix(),
        payload: udp_packet,
    }))
    .await
    .unwrap();
    let _ = timeout(Duration::from_secs(1), tun_rx.recv())
        .await
        .unwrap()
        .unwrap();

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
        .protect(register.dcid.as_slice(), 1, register.key_phase, &ping_frame)
        .unwrap();
    tx.send(SessionEvent::Udp(UdpClaim {
        peer,
        dcid_prefix: register.dcid.prefix(),
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
        .open(register.dcid.len(), &packet, register.pn_start)
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

#[tokio::test]
async fn session_falls_back_to_tcp_after_udp_dead_channel() {
    let (join, mut client, tx, mut tun_rx, _udp_rx, limits, assigned, registry) =
        spawn_session().await;

    // Register and activate UDP
    let dcid = Cid::from([0xD1; QUIC_DCID_PREFIX_LEN]);
    let scid = Cid::from([0xD2; QUIC_DCID_PREFIX_LEN]);
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
    assert!(registry.has_cid(register.dcid.prefix()));

    let keys = UdpQspKeys::from_register(&register).unwrap();
    let peer = SocketAddr::from(([127, 0, 0, 1], 56789));

    // Activate UDP with a data packet
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
        .protect(register.dcid.as_slice(), 0, register.key_phase, &data_frame)
        .unwrap();
    tx.send(SessionEvent::Udp(UdpClaim {
        peer,
        dcid_prefix: register.dcid.prefix(),
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
            dcid_prefix: register.dcid.prefix(),
            payload: garbage,
        }))
        .await
        .unwrap();
    }

    // Give time for processing
    tokio::time::sleep(Duration::from_millis(100)).await;

    // CID should be removed and session should fall back to TCP
    assert!(!registry.has_cid(register.dcid.prefix()));

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
