//! Batched UDP-QSP flush driving and NAT peer-update integration tests.
//!
//! These tests use a buffering, peer-recording `SessionIo` fake in place of the
//! immediate-send `UdpIo` so that:
//! - TUN downlink data packets (sent via `send_udp_message`, which does not
//!   flush) are visibly buffered until the session lifecycle flushes them;
//! - each flushed packet records the destination peer, proving NAT/endpoint
//!   updates route subsequent downlink sends to the new peer.

use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use slt_core::crypto::udp_qsp::{PeerUpdate, QuicQspSession, SessionIo, UdpQspKeys};
use slt_core::proto::{
    CipherSuite, Message, MessageLimits, PingPayload, PongPayload, RegisterCidPayload,
    decode_message, encode_message,
};
use slt_core::transport::tcp::TcpChannel;
use slt_core::types::{Cid, MAX_DCID_LEN, ServerUdpQspConfig};
use tokio::io::AsyncWriteExt;
use tokio::sync::{mpsc, oneshot};
use tokio::time::{Duration, timeout};

use super::super::*;
use super::common::{complete_udp_upgrade_handshake, ipv4_packet, make_register_payload};
use crate::quic::UdpClaim;
use crate::test_support::{TestTun, TlsDuplexStream, default_session_timeouts, tls_pair};

/// Buffering UDP-QSP I/O fake.
///
/// `send` buffers packets (modeling the GSO send slab); `flush` releases them,
/// recording each released packet together with the destination peer it was
/// flushed to. `has_pending_flush` mirrors the non-empty slab. This lets tests
/// observe both the batching contract and the per-flush destination peer.
#[derive(Debug)]
struct BufferingUdpIo {
    peer: SocketAddr,
    pending: Vec<Vec<u8>>,
    /// Bytes-only mirror (compatible with `complete_udp_upgrade_handshake`).
    bytes_tx: mpsc::Sender<Vec<u8>>,
    /// Every flushed packet with its destination peer, for assertions.
    sent: Arc<Mutex<Vec<(Vec<u8>, SocketAddr)>>>,
    flush_failures: Arc<AtomicUsize>,
}

impl SessionIo for BufferingUdpIo {
    async fn send(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.pending.push(bytes.to_vec());
        Ok(())
    }

    async fn recv(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
        // Server-side UDP-QSP recv happens at the front door; this backend is
        // send-only, so recv is never exercised.
        Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "BufferingUdpIo recv is unused (front-door recv)",
        ))
    }

    async fn flush(&mut self) -> io::Result<()> {
        if self
            .flush_failures
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |remaining| {
                (remaining > 0).then(|| remaining - 1)
            })
            .is_ok()
        {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "injected UDP flush failure",
            ));
        }

        let drained = std::mem::take(&mut self.pending);
        let mut sent = self.sent.lock().expect("sent lock");
        for bytes in drained {
            // Best-effort: the bytes channel exists only to feed the shared
            // handshake helper; assertions read from `sent`.
            let _ = self.bytes_tx.try_send(bytes.clone());
            sent.push((bytes, self.peer));
        }
        Ok(())
    }

    fn has_pending_flush(&self) -> bool {
        !self.pending.is_empty()
    }

    fn discard_pending_send(&mut self) -> usize {
        let discarded = self.pending.len();
        self.pending.clear();
        discarded
    }
}

impl PeerUpdate for BufferingUdpIo {
    fn set_peer(&mut self, peer: SocketAddr) {
        self.peer = peer;
    }
}

impl UdpSessionIo for BufferingUdpIo {}

/// Factory producing [`BufferingUdpIo`] backends that share a bytes channel and
/// a sent-packet log with the test.
#[derive(Debug)]
struct BufferingUdpIoFactory {
    bytes_tx: mpsc::Sender<Vec<u8>>,
    sent: Arc<Mutex<Vec<(Vec<u8>, SocketAddr)>>>,
    flush_failures: Arc<AtomicUsize>,
}

impl UdpSessionIoFactory<BufferingUdpIo> for BufferingUdpIoFactory {
    fn create(&self, peer: SocketAddr) -> io::Result<BufferingUdpIo> {
        Ok(BufferingUdpIo {
            peer,
            pending: Vec::new(),
            bytes_tx: self.bytes_tx.clone(),
            sent: self.sent.clone(),
            flush_failures: self.flush_failures.clone(),
        })
    }
}

type BufferingSpawnResult = (
    tokio::task::JoinHandle<Result<(), SessionError>>,
    TlsDuplexStream,
    SessionTx,
    mpsc::Receiver<Vec<u8>>,
    Arc<Mutex<Vec<(Vec<u8>, SocketAddr)>>>,
    MessageLimits,
    AssignedIp,
    Arc<SessionRegistry>,
    Arc<AtomicUsize>,
);

/// Spawn a session backed by the buffering UDP-QSP fake.
async fn spawn_session_buffering() -> BufferingSpawnResult {
    let (server_tls, client_tls) = tls_pair().await;
    let (tun, _tun_rx) = TestTun::new(8);
    let (bytes_tx, bytes_rx) = mpsc::channel(256);
    let sent: Arc<Mutex<Vec<(Vec<u8>, SocketAddr)>>> = Arc::new(Mutex::new(Vec::new()));
    let flush_failures = Arc::new(AtomicUsize::new(0));
    let factory = BufferingUdpIoFactory {
        bytes_tx,
        sent: sent.clone(),
        flush_failures: flush_failures.clone(),
    };
    let registry = Arc::new(SessionRegistry::new());
    let metrics = Arc::new(Metrics::default());
    let (tx, rx) = mpsc::channel(8);
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let client_id = ClientId([0xA5; 16]);
    let assigned = AssignedIp(Ipv4Addr::new(10, 0, 0, 9));
    let handle = registry.register_session(client_id, assigned, tx.clone());
    let limits = MessageLimits::from_mtu(1500);
    let session = ClientSessionBase::new(
        handle.session_id,
        client_id,
        assigned,
        TcpChannel::with_key_updater(server_tls, SessionKeyUpdater::new(metrics.clone())),
        tun,
        Arc::new(factory),
        registry.clone(),
        metrics,
        tx.clone(),
        rx,
        shutdown_rx,
        limits,
        default_session_timeouts(),
        ServerUdpQspConfig::default(),
    );
    let join = tokio::spawn(async move {
        let result = session.run().await;
        drop(shutdown_tx);
        result
    });
    (
        join,
        client_tls,
        tx,
        bytes_rx,
        sent,
        limits,
        assigned,
        registry,
        flush_failures,
    )
}

/// Register a CID and complete the full UDP upgrade handshake so the session is
/// committed to UDP-QSP with `peer` as its accepted endpoint.
async fn register_and_upgrade(
    client: &mut TlsDuplexStream,
    tx: &SessionTx,
    udp_rx: &mut mpsc::Receiver<Vec<u8>>,
    limits: MessageLimits,
    dcid: Cid,
    scid: Cid,
    peer: SocketAddr,
    upgrade_id: u64,
) -> (UdpQspKeys, RegisterCidPayload) {
    let register = make_register_payload(dcid, scid, CipherSuite::Aes128Gcm);
    let mut reg_buf = Vec::new();
    register.encode(&mut reg_buf).unwrap();
    let mut frame = Vec::new();
    encode_message(Message::RegisterCid { payload: &reg_buf }, &mut frame).unwrap();
    client.write_all(&frame).await.unwrap();

    let buf = timeout(
        Duration::from_secs(1),
        super::common::read_message_bytes(client, limits),
    )
    .await
    .expect("RegisterOk within timeout")
    .expect("read ok");
    assert!(matches!(
        decode_message(&buf, limits).unwrap().unwrap().0,
        Message::RegisterOk { .. }
    ));

    let keys = UdpQspKeys::new(register.cipher, register.secret_rx, register.secret_tx).unwrap();
    let _next_server_pn =
        complete_udp_upgrade_handshake(client, tx, udp_rx, limits, &register, peer, upgrade_id)
            .await;
    (keys, register)
}

/// Returns true if `bytes` decrypts (over a small packet-number search) to a
/// `Data` message whose packet equals `expected_packet`.
fn flushed_data_matches(
    keys: &UdpQspKeys,
    scid_len: usize,
    bytes: &[u8],
    expected_packet: &[u8],
    limits: MessageLimits,
) -> bool {
    for pn in 0..64u64 {
        let Ok(opened) = keys.open(scid_len, bytes, pn) else {
            continue;
        };
        if let Ok(Some((Message::Data { packet }, _))) = decode_message(&opened.payload, limits) {
            return packet == expected_packet;
        }
    }
    false
}

/// Poll the flushed-packet log until a `Data` packet matching `expected_packet`
/// appears, returning the destination peer it was flushed to.
async fn wait_for_flushed_data_peer(
    sent: &Arc<Mutex<Vec<(Vec<u8>, SocketAddr)>>>,
    keys: &UdpQspKeys,
    scid_len: usize,
    expected_packet: &[u8],
    limits: MessageLimits,
    deadline: Duration,
) -> Option<SocketAddr> {
    let limit = tokio::time::Instant::now() + deadline;
    loop {
        let snapshot = sent.lock().expect("sent lock").clone();
        for (bytes, peer) in &snapshot {
            if flushed_data_matches(keys, scid_len, bytes, expected_packet, limits) {
                return Some(*peer);
            }
        }
        if tokio::time::Instant::now() >= limit {
            return None;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

#[tokio::test]
async fn tcp_cutover_discards_pending_udp_without_retiring_receive_state() {
    let (server_tls, _client_tls) = tls_pair().await;
    let (tun, _tun_rx) = TestTun::new(8);
    let (bytes_tx, _bytes_rx) = mpsc::channel(8);
    let sent = Arc::new(Mutex::new(Vec::new()));
    let flush_failures = Arc::new(AtomicUsize::new(0));
    let factory = Arc::new(BufferingUdpIoFactory {
        bytes_tx: bytes_tx.clone(),
        sent: sent.clone(),
        flush_failures: flush_failures.clone(),
    });
    let registry = Arc::new(SessionRegistry::new());
    let metrics = Arc::new(Metrics::default());
    let (tx, rx) = mpsc::channel(8);
    let (_shutdown_tx, shutdown_rx) = oneshot::channel();
    let client_id = ClientId([0xA5; 16]);
    let assigned = AssignedIp(Ipv4Addr::new(10, 0, 0, 9));
    let handle = registry.register_session(client_id, assigned, tx.clone());
    let mut session = ClientSessionBase::new(
        handle.session_id,
        client_id,
        assigned,
        TcpChannel::with_key_updater(server_tls, SessionKeyUpdater::new(metrics.clone())),
        tun,
        factory,
        registry,
        metrics,
        tx,
        rx,
        shutdown_rx,
        MessageLimits::from_mtu(1500),
        default_session_timeouts(),
        ServerUdpQspConfig::default(),
    );
    let register = make_register_payload(
        Cid::from([0xC8; MAX_DCID_LEN]),
        Cid::from([0xD8; MAX_DCID_LEN]),
        CipherSuite::Aes128Gcm,
    );
    let keys = UdpQspKeys::new(register.cipher, register.secret_rx, register.secret_tx).unwrap();
    let io = BufferingUdpIo {
        peer: (Ipv4Addr::LOCALHOST, 18111).into(),
        pending: Vec::new(),
        bytes_tx,
        sent: sent.clone(),
        flush_failures,
    };
    session.udp_session = Some(QuicQspSession::new(
        io,
        register.client_to_server_cid,
        register.server_to_client_cid,
        keys,
        register.pn_start,
        register.pn_start_rx,
        register.key_phase,
    ));
    session.active_transport = ActiveTransport::UdpQsp;
    session
        .udp_session
        .as_mut()
        .unwrap()
        .send(b"queued downlink")
        .await
        .unwrap();
    assert!(session.udp_session.as_ref().unwrap().has_pending_flush());

    session.set_active_transport(ActiveTransport::Tcp);

    let udp = session
        .udp_session
        .as_ref()
        .expect("tcp fallback must retain udp receive state");
    assert!(!udp.has_pending_flush());
    assert!(sent.lock().expect("sent lock").is_empty());
}

#[tokio::test]
async fn lifecycle_idle_flush_drains_buffered_data() {
    let (join, mut client, tx, mut udp_rx, sent, limits, assigned, _registry, _flush_failures) =
        spawn_session_buffering().await;

    let dcid = Cid::from([0xC1; MAX_DCID_LEN]);
    let scid = Cid::from([0xD1; MAX_DCID_LEN]);
    let peer_a: SocketAddr = (Ipv4Addr::new(127, 0, 0, 1), 11111).into();
    let (keys, register) = register_and_upgrade(
        &mut client,
        &tx,
        &mut udp_rx,
        limits,
        dcid,
        scid,
        peer_a,
        0x2100,
    )
    .await;

    // A TUN downlink packet is sent via `send_udp_message`, which only buffers;
    // only the lifecycle flush branch (or a full slab) can drain it.
    let pkt = ipv4_packet(assigned.addr(), Ipv4Addr::new(192, 0, 2, 7), 12);
    tx.send(SessionEvent::TunPacket(pkt.clone())).await.unwrap();

    let peer = wait_for_flushed_data_peer(
        &sent,
        &keys,
        register.server_to_client_cid.len(),
        &pkt,
        limits,
        Duration::from_secs(2),
    )
    .await
    .expect("buffered downlink data was flushed by the lifecycle loop");
    assert_eq!(peer, peer_a);

    let _ = tx.send(SessionEvent::Shutdown).await;
    join.await.unwrap().unwrap();
}

#[tokio::test]
async fn lifecycle_flush_failure_falls_back_to_tcp() {
    let (join, mut client, tx, mut udp_rx, _sent, limits, assigned, registry, flush_failures) =
        spawn_session_buffering().await;

    let dcid = Cid::from([0xC4; MAX_DCID_LEN]);
    let scid = Cid::from([0xD4; MAX_DCID_LEN]);
    let peer_a: SocketAddr = (Ipv4Addr::new(127, 0, 0, 1), 14111).into();
    let (_keys, register) = register_and_upgrade(
        &mut client,
        &tx,
        &mut udp_rx,
        limits,
        dcid,
        scid,
        peer_a,
        0x2400,
    )
    .await;
    assert!(registry.has_cid(register.client_to_server_cid.prefix().unwrap()));

    flush_failures.fetch_add(1, Ordering::AcqRel);
    let pkt = ipv4_packet(assigned.addr(), Ipv4Addr::new(192, 0, 2, 9), 12);
    tx.send(SessionEvent::TunPacket(pkt)).await.unwrap();

    let buf = timeout(
        Duration::from_secs(1),
        super::common::read_message_bytes(&mut client, limits),
    )
    .await
    .expect("tcp fallback request within timeout")
    .expect("read ok");
    assert!(matches!(
        decode_message(&buf, limits).unwrap().unwrap().0,
        Message::FallbackToTcp { .. }
    ));
    assert!(!registry.has_cid(register.client_to_server_cid.prefix().unwrap()));

    let nonce = 0xA11C_E000_0000_2400u64;
    let mut ping_payload = Vec::with_capacity(8);
    PingPayload { nonce }.encode(&mut ping_payload);
    let mut ping_frame = Vec::new();
    encode_message(
        Message::Ping {
            payload: &ping_payload,
        },
        &mut ping_frame,
    )
    .unwrap();
    client.write_all(&ping_frame).await.unwrap();

    let mut saw_pong = false;
    for _ in 0..8 {
        let buf = timeout(
            Duration::from_secs(1),
            super::common::read_message_bytes(&mut client, limits),
        )
        .await
        .expect("tcp pong within timeout")
        .expect("read ok");
        let (message, _) = decode_message(&buf, limits).unwrap().unwrap();
        match message {
            Message::Pong { payload } if PongPayload::decode(payload).unwrap().nonce == nonce => {
                saw_pong = true;
                break;
            }
            Message::FallbackToTcp { .. } => {}
            other => panic!("expected tcp pong after udp flush failure, got {other:?}"),
        }
    }
    assert!(
        saw_pong,
        "session did not continue on tcp after udp flush failure"
    );

    let _ = tx.send(SessionEvent::Shutdown).await;
    join.await.unwrap().unwrap();
}

#[tokio::test]
async fn shutdown_flush_drains_pending_buffered_data() {
    let (join, mut client, tx, mut udp_rx, sent, limits, assigned, _registry, _flush_failures) =
        spawn_session_buffering().await;

    let dcid = Cid::from([0xC2; MAX_DCID_LEN]);
    let scid = Cid::from([0xD2; MAX_DCID_LEN]);
    let peer_a: SocketAddr = (Ipv4Addr::new(127, 0, 0, 1), 12111).into();
    let (keys, register) = register_and_upgrade(
        &mut client,
        &tx,
        &mut udp_rx,
        limits,
        dcid,
        scid,
        peer_a,
        0x2200,
    )
    .await;

    // Buffer a downlink packet, then shut down immediately so the lifecycle
    // idle-flush has no idle window to run first. The shutdown best-effort flush
    // must still drain it rather than stranding it in the slab.
    let pkt = ipv4_packet(assigned.addr(), Ipv4Addr::new(192, 0, 2, 8), 12);
    tx.send(SessionEvent::TunPacket(pkt.clone())).await.unwrap();
    let _ = tx.send(SessionEvent::Shutdown).await;
    join.await.unwrap().unwrap();

    let peer = wait_for_flushed_data_peer(
        &sent,
        &keys,
        register.server_to_client_cid.len(),
        &pkt,
        limits,
        Duration::from_secs(1),
    )
    .await
    .expect("pending downlink data was flushed before shutdown exit");
    assert_eq!(peer, peer_a);
}

#[tokio::test]
async fn nat_peer_update_routes_downlink_to_new_peer() {
    let (join, mut client, tx, mut udp_rx, sent, limits, assigned, _registry, _flush_failures) =
        spawn_session_buffering().await;

    let dcid = Cid::from([0xC3; MAX_DCID_LEN]);
    let scid = Cid::from([0xD3; MAX_DCID_LEN]);
    let peer_a: SocketAddr = (Ipv4Addr::new(127, 0, 0, 1), 13111).into();
    let peer_b: SocketAddr = (Ipv4Addr::new(127, 0, 0, 1), 13222).into();
    let (keys, register) = register_and_upgrade(
        &mut client,
        &tx,
        &mut udp_rx,
        limits,
        dcid,
        scid,
        peer_a,
        0x2300,
    )
    .await;
    let scid_len = register.server_to_client_cid.len();

    // Downlink before any NAT change goes to the originally accepted peer.
    let pkt_a = ipv4_packet(assigned.addr(), Ipv4Addr::new(192, 0, 2, 17), 12);
    tx.send(SessionEvent::TunPacket(pkt_a.clone()))
        .await
        .unwrap();
    let peer = wait_for_flushed_data_peer(
        &sent,
        &keys,
        scid_len,
        &pkt_a,
        limits,
        Duration::from_secs(2),
    )
    .await
    .expect("first downlink flushed");
    assert_eq!(peer, peer_a, "downlink before NAT change targets peer_a");

    // A valid UDP claim arriving from a new endpoint updates the session peer.
    let mut ping_payload = Vec::with_capacity(8);
    PingPayload { nonce: 0x1 }.encode(&mut ping_payload);
    let mut ping_frame = Vec::new();
    encode_message(
        Message::Ping {
            payload: &ping_payload,
        },
        &mut ping_frame,
    )
    .unwrap();
    let claim_packet = keys
        .protect(
            register.client_to_server_cid.as_slice(),
            register.pn_start_rx + 1,
            register.key_phase,
            &ping_frame,
        )
        .unwrap();
    tx.send(SessionEvent::Udp(UdpClaim {
        peer: peer_b,
        dcid_prefix: register.client_to_server_cid.prefix().unwrap(),
        payload: claim_packet,
    }))
    .await
    .unwrap();

    // Give the claim time to update the peer before issuing the next downlink.
    tokio::time::sleep(Duration::from_millis(50)).await;

    // A subsequent downlink must now route to the new peer.
    let pkt_b = ipv4_packet(assigned.addr(), Ipv4Addr::new(192, 0, 2, 18), 12);
    tx.send(SessionEvent::TunPacket(pkt_b.clone()))
        .await
        .unwrap();
    let peer = wait_for_flushed_data_peer(
        &sent,
        &keys,
        scid_len,
        &pkt_b,
        limits,
        Duration::from_secs(2),
    )
    .await
    .expect("post-NAT downlink flushed");
    assert_eq!(peer, peer_b, "downlink after NAT change targets peer_b");

    let _ = tx.send(SessionEvent::Shutdown).await;
    join.await.unwrap().unwrap();
}
