use std::io;
use std::net::Ipv4Addr;
use std::sync::Arc;

use slt_core::proto::{
    AEAD_IV_LEN, AEAD_KEY_LEN, CipherSuite, HP_KEY_LEN, MessageLimits, RegisterCidPayload,
    decode_message,
};
use slt_core::transport::tcp::TcpChannel;
use slt_core::types::Cid;
use tokio::io::{AsyncReadExt, DuplexStream};
use tokio::sync::mpsc;

use super::super::*;
use crate::test_support::{
    TestTun, TestUdpSocket, TlsDuplexStream, default_session_timeouts, tls_pair,
};

pub(super) type SpawnSessionResult = (
    tokio::task::JoinHandle<io::Result<()>>,
    TlsDuplexStream,
    SessionTx,
    mpsc::Receiver<Vec<u8>>,
    mpsc::Receiver<Vec<u8>>,
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
