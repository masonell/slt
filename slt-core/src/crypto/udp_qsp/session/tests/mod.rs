mod buffering;
mod key_update;
mod peer_update;
mod replay_window;
mod send_receive;

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use tokio::sync::mpsc;

use super::*;
use crate::proto::{
    AEAD_IV_LEN, AEAD_KEY_LEN, CipherSuite, HP_KEY_LEN, Message, MessageLimits, PingPayload,
    PongPayload, UDP_QSP_TRAFFIC_SECRET_LEN, decode_message, encode_message,
};

struct ChanIo {
    tx: mpsc::Sender<Vec<u8>>,
    rx: mpsc::Receiver<Vec<u8>>,
}

impl SessionIo for ChanIo {
    async fn send(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.tx
            .send(bytes.to_vec())
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "channel closed"))
    }

    async fn recv<'a>(&'a mut self, buf: &'a mut [u8]) -> io::Result<usize> {
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

/// In-memory `SessionIo` that buffers sends until `flush`, modeling the
/// batching contract of the real UDP-QSP socket backend. Used to assert that
/// `QuicQspSession` proxies `flush`/`has_pending_flush`/`set_peer` to its
/// underlying I/O layer instead of dropping or short-circuiting them.
#[derive(Debug)]
struct BufferingIo {
    state: Arc<Mutex<BufferingIoState>>,
}

#[derive(Debug, Default)]
struct BufferingIoState {
    pending: Vec<Vec<u8>>,
    flushed: Vec<Vec<u8>>,
    last_peer: Option<SocketAddr>,
}

impl BufferingIo {
    /// Create a buffering I/O and a shared handle to observe its internal state.
    fn pair() -> (Self, Arc<Mutex<BufferingIoState>>) {
        let state = Arc::new(Mutex::new(BufferingIoState::default()));
        (
            Self {
                state: state.clone(),
            },
            state,
        )
    }
}

impl SessionIo for BufferingIo {
    async fn send(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.state
            .lock()
            .expect("BufferingIo lock")
            .pending
            .push(bytes.to_vec());
        Ok(())
    }

    async fn recv(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "BufferingIo has no recv path",
        ))
    }

    async fn flush(&mut self) -> io::Result<()> {
        {
            let mut state = self.state.lock().expect("BufferingIo lock");
            let pending = std::mem::take(&mut state.pending);
            state.flushed.extend(pending);
        }
        Ok(())
    }

    fn has_pending_flush(&self) -> bool {
        !self
            .state
            .lock()
            .expect("BufferingIo lock")
            .pending
            .is_empty()
    }

    fn discard_pending_send(&mut self) -> usize {
        let mut state = self.state.lock().expect("BufferingIo lock");
        let discarded = state.pending.len();
        state.pending.clear();
        discarded
    }
}

impl PeerUpdate for BufferingIo {
    fn set_peer(&mut self, peer: SocketAddr) {
        self.state.lock().expect("BufferingIo lock").last_peer = Some(peer);
    }
}

#[derive(Debug)]
struct QueueIo {
    sent: Arc<Mutex<Vec<Vec<u8>>>>,
    recv: VecDeque<Vec<u8>>,
}

impl QueueIo {
    fn new(recv: Vec<Vec<u8>>) -> (Self, Arc<Mutex<Vec<Vec<u8>>>>) {
        let sent = Arc::new(Mutex::new(Vec::new()));
        (
            Self {
                sent: sent.clone(),
                recv: recv.into(),
            },
            sent,
        )
    }
}

impl SessionIo for QueueIo {
    async fn send(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.sent
            .lock()
            .expect("QueueIo sent lock")
            .push(bytes.to_vec());
        Ok(())
    }

    async fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let packet = self.recv.pop_front().ok_or_else(|| {
            io::Error::new(io::ErrorKind::UnexpectedEof, "QueueIo receive queue empty")
        })?;
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

fn encode_ping_frame(nonce: u64) -> Vec<u8> {
    let payload = PingPayload { nonce };
    let mut payload_buf = Vec::new();
    payload.encode(&mut payload_buf);

    let mut frame = Vec::new();
    encode_message(
        Message::Ping {
            payload: &payload_buf,
        },
        &mut frame,
    )
    .unwrap();
    frame
}

fn encode_pong_frame(nonce: u64) -> Vec<u8> {
    let wire = nonce.to_be_bytes();
    let mut frame = Vec::new();
    encode_message(Message::Pong { payload: &wire }, &mut frame).unwrap();
    frame
}

fn decode_one(frame: &[u8], limits: MessageLimits) -> Message<'_> {
    let (message, consumed) = decode_message(frame, limits).unwrap().unwrap();
    assert_eq!(consumed, frame.len());
    message
}

fn set_rekey_policy<I: SessionIo>(
    session: &mut QuicQspSession<I>,
    interval: u64,
    late_margin: u64,
) {
    session.rekey_policy = RekeyPolicy {
        interval,
        late_margin,
    };
    session.tx_next_rekey_pn = next_rekey_after(session.next_pn, interval);
    session.rx_next_rekey_pn = next_rekey_after(session.expected_pn(), interval);
    session.previous_rx = None;
}

fn symmetric_keys() -> UdpQspKeys {
    UdpQspKeys::new(
        CipherSuite::Aes128Gcm,
        [0x11; UDP_QSP_TRAFFIC_SECRET_LEN],
        [0x11; UDP_QSP_TRAFFIC_SECRET_LEN],
    )
    .unwrap()
}

fn buffering_keys() -> UdpQspKeys {
    UdpQspKeys::new(
        CipherSuite::Aes128Gcm,
        [0x11; UDP_QSP_TRAFFIC_SECRET_LEN],
        [0x11; UDP_QSP_TRAFFIC_SECRET_LEN],
    )
    .unwrap()
}
