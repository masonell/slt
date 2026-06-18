//! Unix UDP-QSP socket backend using `quinn-udp` GRO/GSO helpers.

use std::collections::VecDeque;
use std::io::{self, IoSliceMut};
use std::net::{SocketAddr, UdpSocket};

use quinn_udp::{BATCH_SIZE, RecvMeta, Transmit, UdpSockRef, UdpSocketState};
use tokio::io::unix::AsyncFd;

use super::gro_datagram_ranges;
use crate::crypto::udp_qsp::{PeerUpdate, SessionIo};

/// Upper bound used to size each individual UDP-QSP datagram buffer.
const MAX_DATAGRAM: usize = 1500;
const MAX_UDP_GSO_PAYLOAD: usize = u16::MAX as usize;

/// Unix optimized UDP-QSP socket backend.
///
/// The backend owns a duplicated nonblocking UDP socket, batches same-sized
/// outbound datagrams into GSO transmits, and splits GRO-coalesced receives back
/// into individual datagrams before handing them to a UDP-QSP session.
#[derive(Debug)]
pub struct UdpQspIo {
    fd: AsyncFd<UdpSocket>,
    state: UdpSocketState,
    peer: SocketAddr,
    send_buf: Vec<u8>,
    send_segment_size: Option<usize>,
    send_segments: usize,
    recv: Option<RecvState>,
}

#[derive(Debug)]
struct RecvState {
    bufs: Vec<Vec<u8>>,
    meta: Vec<RecvMeta>,
    queue: VecDeque<Vec<u8>>,
}

impl RecvState {
    fn new(socket_state: &UdpSocketState) -> Self {
        let recv_buf_len = socket_state.gro_segments() * MAX_DATAGRAM;
        Self {
            bufs: (0..BATCH_SIZE).map(|_| vec![0u8; recv_buf_len]).collect(),
            meta: (0..BATCH_SIZE).map(|_| RecvMeta::default()).collect(),
            queue: VecDeque::new(),
        }
    }
}

impl UdpQspIo {
    /// Create a UDP-QSP backend over a nonblocking UDP socket and peer address.
    ///
    /// # Errors
    ///
    /// Returns an error if the socket cannot be configured for `quinn-udp` or
    /// registered with Tokio's readiness driver.
    pub fn new(socket: UdpSocket, peer: SocketAddr) -> io::Result<Self> {
        let state = UdpSocketState::new(UdpSockRef::from(&socket))?;
        let fd = AsyncFd::new(socket)?;

        Ok(Self {
            fd,
            state,
            peer,
            send_buf: Vec::with_capacity(MAX_UDP_GSO_PAYLOAD),
            send_segment_size: None,
            send_segments: 0,
            recv: None,
        })
    }

    /// Update the accepted receive peer and outbound transmit destination.
    ///
    /// Already-queued receive datagrams are kept: they matched the previously
    /// accepted peer when received and still have to pass UDP-QSP crypto/replay
    /// checks before the session accepts them.
    pub const fn set_peer(&mut self, peer: SocketAddr) {
        self.peer = peer;
    }

    async fn send_packet(&mut self, bytes: &[u8]) -> io::Result<()> {
        let segment_size = bytes.len();
        if segment_size == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "UDP-QSP packet must not be empty",
            ));
        }
        if segment_size > MAX_UDP_GSO_PAYLOAD {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "UDP-QSP packet exceeds UDP payload limit",
            ));
        }

        let max_segments = max_gso_segments_for_size(self.state.max_gso_segments(), segment_size);
        if self.must_flush_before_append(segment_size, max_segments) {
            self.flush_pending().await?;
        }

        if self.send_segments == 0 {
            self.send_segment_size = Some(segment_size);
        }
        self.send_buf.extend_from_slice(bytes);
        self.send_segments += 1;

        if self.send_segments >= max_segments {
            self.flush_pending().await?;
        }

        Ok(())
    }

    fn must_flush_before_append(&self, segment_size: usize, max_segments: usize) -> bool {
        if self.send_segments == 0 {
            return false;
        }

        self.send_segment_size != Some(segment_size) || self.send_segments >= max_segments
    }

    async fn flush_pending(&mut self) -> io::Result<()> {
        if self.send_segments == 0 {
            return Ok(());
        }

        loop {
            let mut guard = self.fd.writable().await?;
            let segment_size = self.send_segment_size.filter(|_| self.send_segments > 1);
            let transmit = Transmit {
                destination: self.peer,
                ecn: None,
                contents: &self.send_buf,
                segment_size,
                src_ip: None,
            };

            match guard.try_io(|fd| {
                self.state
                    .try_send(UdpSockRef::from(fd.get_ref()), &transmit)
            }) {
                Ok(Ok(())) => {
                    self.clear_send_slab();
                    return Ok(());
                }
                Ok(Err(e)) => return Err(e),
                Err(_would_block) => {}
            }
        }
    }

    fn clear_send_slab(&mut self) {
        self.send_buf.clear();
        self.send_segment_size = None;
        self.send_segments = 0;
    }

    async fn recv_packet(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            if let Some(recv) = self.recv.as_mut()
                && let Some(datagram) = recv.queue.pop_front()
            {
                if datagram.len() > buf.len() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "UDP-QSP datagram exceeds caller buffer",
                    ));
                }

                buf[..datagram.len()].copy_from_slice(&datagram);
                return Ok(datagram.len());
            }

            self.recv_one_batch().await?;
        }
    }

    async fn recv_one_batch(&mut self) -> io::Result<()> {
        loop {
            let mut guard = self.fd.readable().await?;
            let recv = self.recv.get_or_insert_with(|| RecvState::new(&self.state));
            let mut iovs: Vec<IoSliceMut<'_>> = recv
                .bufs
                .iter_mut()
                .map(|buf| IoSliceMut::new(buf))
                .collect();

            match guard.try_io(|fd| {
                self.state
                    .recv(UdpSockRef::from(fd.get_ref()), &mut iovs, &mut recv.meta)
            }) {
                Ok(Ok(count)) => {
                    drop(iovs);
                    queue_peer_datagrams(self.peer, recv, count);
                    return Ok(());
                }
                Ok(Err(e)) => return Err(e),
                Err(_would_block) => {}
            }
        }
    }
}

fn queue_peer_datagrams(peer: SocketAddr, recv: &mut RecvState, count: usize) {
    for i in 0..count {
        let meta = recv.meta[i];
        if meta.addr != peer {
            continue;
        }

        for (off, end) in gro_datagram_ranges(meta.len, meta.stride) {
            recv.queue.push_back(recv.bufs[i][off..end].to_vec());
        }
    }
}

impl SessionIo for UdpQspIo {
    async fn send(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.send_packet(bytes).await
    }

    async fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.recv_packet(buf).await
    }

    async fn flush(&mut self) -> io::Result<()> {
        self.flush_pending().await
    }

    fn has_pending_flush(&self) -> bool {
        self.send_segments != 0
    }
}

impl PeerUpdate for UdpQspIo {
    fn set_peer(&mut self, peer: SocketAddr) {
        Self::set_peer(self, peer);
    }
}

const fn max_gso_segments_for_size(socket_max_segments: usize, segment_size: usize) -> usize {
    let socket_max_segments = if socket_max_segments == 0 {
        1
    } else {
        socket_max_segments
    };
    let payload_max_segments = MAX_UDP_GSO_PAYLOAD / segment_size;
    if payload_max_segments < socket_max_segments {
        payload_max_segments
    } else {
        socket_max_segments
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, UdpSocket};
    use std::time::Duration;

    use tokio::time::timeout;

    use super::*;
    use crate::crypto::udp_qsp::{QuicQspSession, UdpQspKeys};
    use crate::proto::{AEAD_IV_LEN, AEAD_KEY_LEN, CipherSuite, HP_KEY_LEN};
    use crate::types::Cid;

    fn socket_pair() -> io::Result<(UdpSocket, UdpSocket)> {
        let a = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
        let b = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
        a.set_nonblocking(true)?;
        b.set_nonblocking(true)?;
        Ok((a, b))
    }

    fn client_keys() -> UdpQspKeys {
        UdpQspKeys::new(
            CipherSuite::Aes128Gcm,
            [0x11; HP_KEY_LEN],
            [0x22; HP_KEY_LEN],
            [0x33; AEAD_KEY_LEN],
            [0x44; AEAD_KEY_LEN],
            [0x55; AEAD_IV_LEN],
            [0x66; AEAD_IV_LEN],
        )
        .unwrap()
    }

    fn server_keys() -> UdpQspKeys {
        UdpQspKeys::new(
            CipherSuite::Aes128Gcm,
            [0x22; HP_KEY_LEN],
            [0x11; HP_KEY_LEN],
            [0x44; AEAD_KEY_LEN],
            [0x33; AEAD_KEY_LEN],
            [0x66; AEAD_IV_LEN],
            [0x55; AEAD_IV_LEN],
        )
        .unwrap()
    }

    #[test]
    fn max_gso_segments_caps_by_socket_and_payload() {
        assert_eq!(max_gso_segments_for_size(64, 1200), 54);
        assert_eq!(max_gso_segments_for_size(16, 1200), 16);
        assert_eq!(max_gso_segments_for_size(1, 1200), 1);
        assert_eq!(max_gso_segments_for_size(0, 1200), 1);
        assert_eq!(max_gso_segments_for_size(64, MAX_UDP_GSO_PAYLOAD), 1);
    }

    #[tokio::test]
    async fn flush_sends_one_datagram_to_peer() -> io::Result<()> {
        let (a, b) = socket_pair()?;
        let a_addr = a.local_addr()?;
        let b_addr = b.local_addr()?;
        let mut tx = UdpQspIo::new(a, b_addr)?;
        let mut rx = UdpQspIo::new(b, a_addr)?;

        tx.send(b"packet").await?;
        assert!(tx.has_pending_flush());
        tx.flush().await?;
        assert!(!tx.has_pending_flush());

        let mut buf = [0u8; 64];
        let len = timeout(Duration::from_secs(1), rx.recv(&mut buf)).await??;
        assert_eq!(&buf[..len], b"packet");
        Ok(())
    }

    #[tokio::test]
    async fn recv_buffers_are_allocated_lazily() -> io::Result<()> {
        let (a, b) = socket_pair()?;
        let a_addr = a.local_addr()?;
        let b_addr = b.local_addr()?;
        let mut tx = UdpQspIo::new(a, b_addr)?;
        let mut rx = UdpQspIo::new(b, a_addr)?;

        assert!(tx.recv.is_none());
        assert!(rx.recv.is_none());

        tx.send(b"packet").await?;
        tx.flush().await?;
        assert!(tx.recv.is_none());
        assert!(rx.recv.is_none());

        let mut buf = [0u8; 64];
        let len = timeout(Duration::from_secs(1), rx.recv(&mut buf)).await??;
        assert_eq!(&buf[..len], b"packet");
        assert!(rx.recv.is_some());
        Ok(())
    }

    #[tokio::test]
    async fn full_send_slab_flushes_inline() -> io::Result<()> {
        let (a, b) = socket_pair()?;
        let a_addr = a.local_addr()?;
        let b_addr = b.local_addr()?;
        let mut tx = UdpQspIo::new(a, b_addr)?;
        let mut rx = UdpQspIo::new(b, a_addr)?;
        let packet = vec![0xA5; 64];
        let max_segments = max_gso_segments_for_size(tx.state.max_gso_segments(), packet.len());

        for _ in 0..max_segments {
            tx.send(&packet).await?;
        }

        assert!(!tx.has_pending_flush());
        let mut buf = [0u8; 128];
        for _ in 0..max_segments {
            let len = timeout(Duration::from_secs(1), rx.recv(&mut buf)).await??;
            assert_eq!(&buf[..len], packet);
        }
        Ok(())
    }

    #[tokio::test]
    async fn segment_size_change_flushes_existing_batch() -> io::Result<()> {
        let (a, b) = socket_pair()?;
        let a_addr = a.local_addr()?;
        let b_addr = b.local_addr()?;
        let mut tx = UdpQspIo::new(a, b_addr)?;
        let mut rx = UdpQspIo::new(b, a_addr)?;
        let first = vec![0xA5; 64];
        let second = vec![0x5A; 65];
        if max_gso_segments_for_size(tx.state.max_gso_segments(), first.len()) <= 1 {
            return Ok(());
        }

        tx.send(&first).await?;
        assert!(tx.has_pending_flush());
        tx.send(&second).await?;
        assert!(tx.has_pending_flush());

        let mut buf = [0u8; 128];
        let len = timeout(Duration::from_secs(1), rx.recv(&mut buf)).await??;
        assert_eq!(&buf[..len], first);
        assert!(
            timeout(Duration::from_millis(50), rx.recv(&mut buf))
                .await
                .is_err(),
            "second packet should remain buffered until explicit flush"
        );

        tx.flush().await?;
        let len = timeout(Duration::from_secs(1), rx.recv(&mut buf)).await??;
        assert_eq!(&buf[..len], second);
        Ok(())
    }

    #[tokio::test]
    async fn recv_filters_to_current_peer() -> io::Result<()> {
        let (a, b) = socket_pair()?;
        let noise = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
        let a_addr = a.local_addr()?;
        let b_addr = b.local_addr()?;
        let mut tx = UdpQspIo::new(a, b_addr)?;
        let mut rx = UdpQspIo::new(b, a_addr)?;

        noise.send_to(b"noise", b_addr)?;
        tx.send(b"wanted").await?;
        tx.flush().await?;

        let mut buf = [0u8; 64];
        let len = timeout(Duration::from_secs(1), rx.recv(&mut buf)).await??;
        assert_eq!(&buf[..len], b"wanted");

        rx.set_peer(noise.local_addr()?);
        noise.send_to(b"updated", b_addr)?;
        let len = timeout(Duration::from_secs(1), rx.recv(&mut buf)).await??;
        assert_eq!(&buf[..len], b"updated");
        Ok(())
    }

    #[tokio::test]
    async fn recv_rejects_too_small_caller_buffer() -> io::Result<()> {
        let (a, b) = socket_pair()?;
        let a_addr = a.local_addr()?;
        let b_addr = b.local_addr()?;
        let mut tx = UdpQspIo::new(a, b_addr)?;
        let mut rx = UdpQspIo::new(b, a_addr)?;

        tx.send(b"too large").await?;
        tx.flush().await?;

        let mut buf = [0u8; 3];
        let err = timeout(Duration::from_secs(1), rx.recv(&mut buf))
            .await?
            .expect_err("small caller buffer should be rejected");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        Ok(())
    }

    #[tokio::test]
    async fn quic_qsp_session_roundtrips_over_udp_qsp_io() -> io::Result<()> {
        let (a, b) = socket_pair()?;
        let client_addr = a.local_addr()?;
        let server_addr = b.local_addr()?;
        let client_cid = Cid::from([0xA1; 20]);
        let server_cid = Cid::from([0xB2; 20]);
        let client_io = UdpQspIo::new(a, server_addr)?;
        let server_io = UdpQspIo::new(b, client_addr)?;
        let mut client = QuicQspSession::new(
            client_io,
            client_cid,
            server_cid,
            client_keys(),
            0,
            0,
            false,
        );
        let mut server = QuicQspSession::new(
            server_io,
            server_cid,
            client_cid,
            server_keys(),
            0,
            0,
            false,
        );
        let mut buf = [0u8; 2048];

        client.send(b"ping").await.unwrap();
        client.flush().await?;
        let opened = timeout(Duration::from_secs(1), server.recv(&mut buf))
            .await?
            .unwrap();
        assert_eq!(opened.payload, b"ping");

        server.send(b"pong").await.unwrap();
        server.flush().await?;
        let opened = timeout(Duration::from_secs(1), client.recv(&mut buf))
            .await?
            .unwrap();
        assert_eq!(opened.payload, b"pong");
        Ok(())
    }
}
