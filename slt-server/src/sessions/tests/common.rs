use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use slt_core::crypto::udp_qsp::UdpQspKeys;
use slt_core::proto::{
    AEAD_IV_LEN, CipherSuite, Message, MessageLimits, PingPayload, PongPayload, RegisterCidPayload,
    SwitchAckPayload, SwitchToUdpPayload, UdpReadyPayload, UpgradeProbeAckPayload,
    UpgradeProbePayload, decode_message, encode_message,
};
use slt_core::transport::tcp::TcpChannel;
use slt_core::types::Cid;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::time::{Duration, timeout};

use super::super::*;
use crate::quic::UdpClaim;
use crate::test_support::{
    TestTun, TestUdpSocket, TlsDuplexStream, default_session_timeouts, tls_pair,
};

pub(super) type SpawnSessionResult = (
    tokio::task::JoinHandle<Result<(), SessionError>>,
    TlsDuplexStream,
    SessionTx,
    mpsc::Receiver<Vec<u8>>,
    mpsc::Receiver<Vec<u8>>,
    MessageLimits,
    AssignedIp,
    Arc<SessionRegistry>,
);

pub(super) type SpawnSessionWithPeerCaptureResult = (
    tokio::task::JoinHandle<Result<(), SessionError>>,
    TlsDuplexStream,
    SessionTx,
    mpsc::Receiver<Vec<u8>>,
    mpsc::Receiver<Vec<u8>>,
    mpsc::Receiver<SocketAddr>,
    MessageLimits,
    AssignedIp,
    Arc<SessionRegistry>,
);

pub(super) async fn spawn_session() -> SpawnSessionResult {
    spawn_session_with_timeouts(default_session_timeouts()).await
}

pub(super) async fn spawn_session_with_timeouts(timeouts: SessionTimeouts) -> SpawnSessionResult {
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
    let udp_io_factory = Arc::new(UdpIoFactory::new(udp));
    let session = ClientSessionBase::new(
        handle.session_id,
        client_id,
        assigned,
        TcpChannel::with_key_updater(server_tls, SessionKeyUpdater::new(metrics.clone())),
        tun,
        udp_io_factory,
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

pub(super) async fn spawn_session_with_peer_capture() -> SpawnSessionWithPeerCaptureResult {
    let (server_tls, client_tls) = tls_pair().await;
    let (tun, tun_rx) = TestTun::new(8);
    let (udp, udp_rx, udp_peer_rx) = TestUdpSocket::new_with_peer_capture(16);
    let registry = Arc::new(SessionRegistry::new());
    let metrics = Arc::new(Metrics::default());
    let (tx, rx) = mpsc::channel(8);
    let client_id = ClientId([0xA5; 16]);
    let assigned = AssignedIp(Ipv4Addr::new(10, 0, 0, 9));
    let (handle, _old) = registry.register_session(client_id, assigned, tx.clone());
    let limits = MessageLimits::from_mtu(1500);
    let udp_io_factory = Arc::new(UdpIoFactory::new(udp));
    let session = ClientSessionBase::new(
        handle.session_id,
        client_id,
        assigned,
        TcpChannel::with_key_updater(server_tls, SessionKeyUpdater::new(metrics.clone())),
        tun,
        udp_io_factory,
        registry.clone(),
        metrics,
        tx.clone(),
        rx,
        limits,
        default_session_timeouts(),
    );
    let join = tokio::spawn(async move { session.run().await });
    (
        join,
        client_tls,
        tx,
        tun_rx,
        udp_rx,
        udp_peer_rx,
        limits,
        assigned,
        registry,
    )
}

pub(super) async fn read_message_bytes(
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

pub(super) fn ipv4_packet(src: Ipv4Addr, dst: Ipv4Addr, payload_len: usize) -> Vec<u8> {
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

pub(super) fn make_register_payload(
    client_to_server_cid: Cid,
    server_to_client_cid: Cid,
    cipher: CipherSuite,
) -> RegisterCidPayload {
    RegisterCidPayload {
        client_to_server_cid,
        server_to_client_cid,
        cipher,
        hp_tx: vec![0x11; cipher.hp_key_len()],
        hp_rx: vec![0x11; cipher.hp_key_len()],
        aead_tx: vec![0x22; cipher.aead_key_len()],
        aead_rx: vec![0x22; cipher.aead_key_len()],
        iv_tx: [0x33; AEAD_IV_LEN],
        iv_rx: [0x33; AEAD_IV_LEN],
        pn_start: 0,
        pn_start_rx: 0,
        key_phase: false,
    }
}

pub(super) async fn complete_udp_upgrade_handshake(
    client: &mut TlsDuplexStream,
    tx: &SessionTx,
    udp_rx: &mut mpsc::Receiver<Vec<u8>>,
    limits: MessageLimits,
    register: &RegisterCidPayload,
    peer: SocketAddr,
    upgrade_id: u64,
) -> u64 {
    let keys = UdpQspKeys::from_register(register).unwrap();
    let probe_nonce = 0xDEAD_BEEF_CAFE_1234;
    let probe = UpgradeProbePayload {
        upgrade_id,
        nonce: probe_nonce,
    };
    let mut probe_payload = Vec::with_capacity(16);
    probe.encode(&mut probe_payload);
    let mut probe_frame = Vec::new();
    encode_message(
        Message::UpgradeProbe {
            payload: &probe_payload,
        },
        &mut probe_frame,
    )
    .unwrap();
    let probe_packet = keys
        .protect(
            register.client_to_server_cid.as_slice(),
            register.pn_start_rx,
            register.key_phase,
            &probe_frame,
        )
        .unwrap();
    tx.send(SessionEvent::Udp(UdpClaim {
        peer,
        dcid_prefix: register.client_to_server_cid.prefix().unwrap(),
        payload: probe_packet,
    }))
    .await
    .unwrap();

    let ack_packet = timeout(Duration::from_secs(1), udp_rx.recv())
        .await
        .unwrap()
        .unwrap();
    let opened = keys
        .open(
            register.client_to_server_cid.len(),
            &ack_packet,
            register.pn_start,
        )
        .unwrap();
    let (message, consumed) = decode_message(&opened.payload, limits).unwrap().unwrap();
    assert_eq!(consumed, opened.payload.len());
    match message {
        Message::UpgradeProbeAck { payload } => {
            let ack = UpgradeProbeAckPayload::decode(payload).unwrap();
            assert_eq!(ack.upgrade_id, upgrade_id);
            assert_eq!(ack.nonce, probe_nonce);
        }
        _ => panic!("expected upgrade probe ack"),
    }
    let next_server_pn = opened.pn + 1;

    let ready = UdpReadyPayload { upgrade_id };
    let mut ready_payload = Vec::with_capacity(8);
    ready.encode(&mut ready_payload);
    let mut ready_frame = Vec::new();
    encode_message(
        Message::UdpReady {
            payload: &ready_payload,
        },
        &mut ready_frame,
    )
    .unwrap();
    client.write_all(&ready_frame).await.unwrap();

    let mut switch_received = false;
    for _ in 0..8 {
        let buf = timeout(Duration::from_secs(1), read_message_bytes(client, limits))
            .await
            .unwrap()
            .unwrap();
        let (message, _) = decode_message(&buf, limits).unwrap().unwrap();
        match message {
            Message::SwitchToUdp { payload } => {
                let switch = SwitchToUdpPayload::decode(payload).unwrap();
                assert_eq!(switch.upgrade_id, upgrade_id);
                switch_received = true;
                break;
            }
            Message::Ping { .. } | Message::Pong { .. } => {}
            _ => panic!("expected switch_to_udp"),
        }
    }
    assert!(switch_received, "did not receive switch_to_udp");

    let switch_ack = SwitchAckPayload { upgrade_id };
    let mut switch_ack_payload = Vec::with_capacity(8);
    switch_ack.encode(&mut switch_ack_payload);
    let mut switch_ack_frame = Vec::new();
    encode_message(
        Message::SwitchAck {
            payload: &switch_ack_payload,
        },
        &mut switch_ack_frame,
    )
    .unwrap();
    client.write_all(&switch_ack_frame).await.unwrap();

    // Barrier: force server to process `SwitchAck` before returning.
    let ping_nonce = 0xA11C_E000_0000_0001u64;
    let ping = PingPayload { nonce: ping_nonce };
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
    client.write_all(&ping_frame).await.unwrap();

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
                if pong.nonce == ping_nonce {
                    pong_received = true;
                    break;
                }
            }
            Message::Ping { .. } | Message::SwitchToUdp { .. } => {}
            _ => {}
        }
    }
    assert!(pong_received, "did not observe post-switch pong barrier");

    next_server_pn
}
