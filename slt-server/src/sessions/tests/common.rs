use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;

use slt_core::crypto::udp_qsp::UdpQspKeys;
use slt_core::proto::{
    CipherSuite, Message, MessageLimits, RegisterCidPayload, SwitchAckPayload, SwitchOkPayload,
    SwitchToUdpPayload, UDP_QSP_TRAFFIC_SECRET_LEN, UdpReadyPayload, UpgradeProbeAckPayload,
    UpgradeProbePayload, decode_message, encode_message,
};
use slt_core::transport::tcp::TcpChannel;
use slt_core::types::{Cid, ServerUdpQspConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::time::{Duration, timeout};
use tokio_util::sync::CancellationToken;

use super::super::*;
use crate::quic::UdpClaim;
use crate::test_support::{
    TestTun, TestUdpSocket, TlsDuplexStream, WriteGate, default_session_timeouts, tls_pair,
    tls_pair_with_parkable_server_writes,
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

pub(super) type SpawnSessionWithShutdownResult = (
    tokio::task::JoinHandle<Result<(), SessionError>>,
    TlsDuplexStream,
    SessionTx,
    mpsc::Receiver<Vec<u8>>,
    mpsc::Receiver<Vec<u8>>,
    MessageLimits,
    AssignedIp,
    Arc<SessionRegistry>,
    CancellationToken,
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

pub(super) type SpawnSessionWithUdpSocketResult = (
    tokio::task::JoinHandle<Result<(), SessionError>>,
    TlsDuplexStream,
    SessionTx,
    mpsc::Receiver<Vec<u8>>,
    mpsc::Receiver<Vec<u8>>,
    MessageLimits,
    AssignedIp,
    Arc<SessionRegistry>,
    Arc<TestUdpSocket>,
);

pub(super) type SpawnSessionWithParkedWritesResult = (
    tokio::task::JoinHandle<Result<(), SessionError>>,
    TlsDuplexStream,
    SessionTx,
    AssignedIp,
    Arc<SessionRegistry>,
    CancellationToken,
    Arc<WriteGate>,
);

pub(super) async fn spawn_session() -> SpawnSessionResult {
    spawn_session_with_timeouts_and_udp_qsp_config(
        default_session_timeouts(),
        ServerUdpQspConfig::default(),
    )
    .await
}

pub(super) async fn spawn_session_with_timeouts(timeouts: SessionTimeouts) -> SpawnSessionResult {
    spawn_session_with_timeouts_and_udp_qsp_config(timeouts, ServerUdpQspConfig::default()).await
}

pub(super) async fn spawn_session_with_expired_idle_and_ready_packet(
    timeouts: SessionTimeouts,
) -> SpawnSessionResult {
    let (server_tls, client_tls) = tls_pair().await;
    let (tun, tun_rx) = TestTun::new(8);
    let (udp, udp_rx) = TestUdpSocket::new(16);
    let registry = Arc::new(SessionRegistry::new());
    let metrics = Arc::new(Metrics::default());
    let (tx, rx) = mpsc::channel(8);
    let shutdown = CancellationToken::new();
    let client_id = ClientId([0xA5; 16]);
    let assigned = AssignedIp(Ipv4Addr::new(10, 0, 0, 9));
    let handle = registry.register_session(client_id, assigned, tx.clone());
    let limits = MessageLimits::from_mtu(1500);
    let udp_io_factory = Arc::new(UdpIoFactory::new(udp));
    let mut session = ClientSessionBase::new(
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
        shutdown,
        limits,
        timeouts,
        ServerUdpQspConfig::default(),
    );
    session.last_activity = Instant::now() - timeouts.idle_timeout - Duration::from_millis(1);
    tx.try_send(SessionEvent::TunPacket(vec![0x45; 20]))
        .unwrap();
    let join = tokio::spawn(async move { session.run().await });
    (
        join, client_tls, tx, tun_rx, udp_rx, limits, assigned, registry,
    )
}

pub(super) async fn spawn_session_with_udp_qsp_config(
    udp_qsp_config: ServerUdpQspConfig,
) -> SpawnSessionResult {
    spawn_session_with_timeouts_and_udp_qsp_config(default_session_timeouts(), udp_qsp_config).await
}

pub(super) async fn spawn_session_with_shutdown() -> SpawnSessionWithShutdownResult {
    spawn_session_with_shutdown_and_udp_qsp_config(
        default_session_timeouts(),
        ServerUdpQspConfig::default(),
    )
    .await
}

pub(super) async fn spawn_session_with_udp_socket() -> SpawnSessionWithUdpSocketResult {
    let (server_tls, client_tls) = tls_pair().await;
    let (tun, tun_rx) = TestTun::new(8);
    let (udp, udp_rx) = TestUdpSocket::new(16);
    let registry = Arc::new(SessionRegistry::new());
    let metrics = Arc::new(Metrics::default());
    let (tx, rx) = mpsc::channel(8);
    let shutdown = CancellationToken::new();
    let client_id = ClientId([0xA5; 16]);
    let assigned = AssignedIp(Ipv4Addr::new(10, 0, 0, 9));
    let handle = registry.register_session(client_id, assigned, tx.clone());
    let limits = MessageLimits::from_mtu(1500);
    let udp_io_factory = Arc::new(UdpIoFactory::new(udp.clone()));
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
        shutdown,
        limits,
        default_session_timeouts(),
        ServerUdpQspConfig::default(),
    );
    let join = tokio::spawn(async move { session.run().await });
    (
        join, client_tls, tx, tun_rx, udp_rx, limits, assigned, registry, udp,
    )
}

pub(super) async fn spawn_session_with_parkable_server_writes(
    timeouts: SessionTimeouts,
) -> SpawnSessionWithParkedWritesResult {
    let (server_tls, client_tls, write_gate) = tls_pair_with_parkable_server_writes().await;
    let (tun, _tun_rx) = TestTun::new(8);
    let (udp, _udp_rx) = TestUdpSocket::new(16);
    let registry = Arc::new(SessionRegistry::new());
    let metrics = Arc::new(Metrics::default());
    let (tx, rx) = mpsc::channel(8);
    let shutdown = CancellationToken::new();
    let client_id = ClientId([0xA5; 16]);
    let assigned = AssignedIp(Ipv4Addr::new(10, 0, 0, 9));
    let handle = registry.register_session(client_id, assigned, tx.clone());
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
        shutdown.clone(),
        limits,
        timeouts,
        ServerUdpQspConfig::default(),
    );
    let join = tokio::spawn(async move { session.run().await });
    (
        join, client_tls, tx, assigned, registry, shutdown, write_gate,
    )
}

async fn spawn_session_with_timeouts_and_udp_qsp_config(
    timeouts: SessionTimeouts,
    udp_qsp_config: ServerUdpQspConfig,
) -> SpawnSessionResult {
    let (join, client_tls, tx, tun_rx, udp_rx, limits, assigned, registry, _shutdown) =
        spawn_session_with_shutdown_and_udp_qsp_config(timeouts, udp_qsp_config).await;
    (
        join, client_tls, tx, tun_rx, udp_rx, limits, assigned, registry,
    )
}

async fn spawn_session_with_shutdown_and_udp_qsp_config(
    timeouts: SessionTimeouts,
    udp_qsp_config: ServerUdpQspConfig,
) -> SpawnSessionWithShutdownResult {
    let (server_tls, client_tls) = tls_pair().await;
    let (tun, tun_rx) = TestTun::new(8);
    let (udp, udp_rx) = TestUdpSocket::new(16);
    let registry = Arc::new(SessionRegistry::new());
    let metrics = Arc::new(Metrics::default());
    let (tx, rx) = mpsc::channel(8);
    let shutdown = CancellationToken::new();
    let client_id = ClientId([0xA5; 16]);
    let assigned = AssignedIp(Ipv4Addr::new(10, 0, 0, 9));
    let handle = registry.register_session(client_id, assigned, tx.clone());
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
        shutdown.clone(),
        limits,
        timeouts,
        udp_qsp_config,
    );
    let join = tokio::spawn(async move { session.run().await });
    (
        join, client_tls, tx, tun_rx, udp_rx, limits, assigned, registry, shutdown,
    )
}

pub(super) async fn spawn_session_with_peer_capture() -> SpawnSessionWithPeerCaptureResult {
    let (server_tls, client_tls) = tls_pair().await;
    let (tun, tun_rx) = TestTun::new(8);
    let (udp, udp_rx, udp_peer_rx) = TestUdpSocket::new_with_peer_capture(16);
    let registry = Arc::new(SessionRegistry::new());
    let metrics = Arc::new(Metrics::default());
    let (tx, rx) = mpsc::channel(8);
    let shutdown = CancellationToken::new();
    let client_id = ClientId([0xA5; 16]);
    let assigned = AssignedIp(Ipv4Addr::new(10, 0, 0, 9));
    let handle = registry.register_session(client_id, assigned, tx.clone());
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
        shutdown,
        limits,
        default_session_timeouts(),
        ServerUdpQspConfig::default(),
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
        secret_tx: [0x11; UDP_QSP_TRAFFIC_SECRET_LEN],
        secret_rx: [0x22; UDP_QSP_TRAFFIC_SECRET_LEN],
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
    let keys = UdpQspKeys::new(register.cipher, register.secret_rx, register.secret_tx).unwrap();
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

    let mut switch_ok_received = false;
    for _ in 0..8 {
        let buf = timeout(Duration::from_secs(1), read_message_bytes(client, limits))
            .await
            .unwrap()
            .unwrap();
        let (message, _) = decode_message(&buf, limits).unwrap().unwrap();
        match message {
            Message::SwitchOk { payload } => {
                let confirmation = SwitchOkPayload::decode(payload).unwrap();
                assert_eq!(confirmation.upgrade_id, upgrade_id);
                switch_ok_received = true;
                break;
            }
            Message::Ping { .. } | Message::Pong { .. } | Message::SwitchToUdp { .. } => {}
            _ => panic!("expected switch_ok"),
        }
    }
    assert!(switch_ok_received, "did not receive switch_ok");

    next_server_pn
}
