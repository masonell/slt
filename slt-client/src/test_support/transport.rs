//! Transport test utilities.
//!
//! Provides:
//! - `ChanIo`: In-memory channel I/O for testing `SessionIo` trait
//! - `mock_quic_ids`: Mock `QuicIds` without real network peers
//! - `udp_pair`: Real UDP socket pairs for testing `ClientUdpIo`

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use slt_core::crypto::udp_qsp::SessionIo;
use slt_core::types::{Cid, MAX_DCID_LEN};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use crate::transport::quic_discovery::QuicIds;

/// In-memory channel I/O for testing `SessionIo` trait.
///
/// Provides a send/receive pair backed by `mpsc` channels, useful for
/// unit tests that need to simulate network I/O without actual sockets.
pub struct ChanIo {
    /// Channel for sending packets.
    pub tx: mpsc::Sender<Vec<u8>>,
    /// Channel for receiving packets.
    pub rx: mpsc::Receiver<Vec<u8>>,
}

impl SessionIo for ChanIo {
    async fn send(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.tx
            .send(bytes.to_vec())
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "channel closed"))
    }

    async fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let packet = self
            .rx
            .recv()
            .await
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "channel closed"))?;
        if packet.len() > buf.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "packet too large",
            ));
        }
        buf[..packet.len()].copy_from_slice(&packet);
        Ok(packet.len())
    }
}

/// Create a mock `QuicIds` for testing without real network peers.
///
/// Uses:
/// - DCID: `[0xAA; 20]` (must be exactly MAX_DCID_LEN)
/// - SCID: `[]` (empty, matching Chrome behavior)
/// - Peer: `127.0.0.1:443`
/// - Socket: Bound to `127.0.0.1:0` (OS-assigned port)
pub async fn mock_quic_ids() -> QuicIds {
    let socket = Arc::new(
        UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("failed to bind test socket"),
    );
    let dcid = Cid::from([0xAA; MAX_DCID_LEN]);
    let scid = Cid::new(&[]).expect("empty CID is valid");
    let peer: SocketAddr = "127.0.0.1:443".parse().expect("valid addr");
    QuicIds {
        dcid,
        scid,
        peer,
        socket,
    }
}

/// Create a pair of bound UDP sockets that can communicate.
///
/// Returns `(socket_a, socket_b)` where `socket_a` is connected to `socket_b`'s
/// address and vice versa. Useful for testing `ClientUdpIo` with real sockets.
pub async fn udp_pair() -> (Arc<UdpSocket>, Arc<UdpSocket>) {
    let a = Arc::new(
        UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("failed to bind socket A"),
    );
    let b = Arc::new(
        UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("failed to bind socket B"),
    );

    // Connect each socket to the other's address
    a.connect(b.local_addr().expect("socket B has local addr"))
        .await
        .expect("failed to connect socket A to B");
    b.connect(a.local_addr().expect("socket A has local addr"))
        .await
        .expect("failed to connect socket B to A");

    (a, b)
}

/// Create a mock `QuicIds` for synchronous tests (non-async).
///
/// This creates a tokio runtime internally, which is less efficient than
/// `mock_quic_ids()` for async tests.
pub fn mock_quic_ids_sync() -> QuicIds {
    let rt = tokio::runtime::Runtime::new().expect("failed to create runtime");
    rt.block_on(mock_quic_ids())
}
