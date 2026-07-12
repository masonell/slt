//! Unix UDP-QSP socket backend using `quinn-udp` GRO/GSO helpers.

use std::collections::VecDeque;
use std::io::{self, IoSliceMut};
use std::net::{SocketAddr, UdpSocket};

use quinn_udp::{BATCH_SIZE, RecvMeta, Transmit, UdpSockRef, UdpSocketState};
use tokio::io::unix::AsyncFd;
use tokio::net::UdpSocket as TokioUdpSocket;

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

    /// Return the accepted receive peer and outbound transmit destination.
    #[must_use]
    pub const fn peer(&self) -> SocketAddr {
        self.peer
    }

    /// Update the accepted receive peer and outbound transmit destination.
    ///
    /// Protected datagrams in the pending send slab are retargeted because the
    /// destination is selected when the slab is flushed.
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

    fn discard_pending_send(&mut self) -> usize {
        let discarded = self.send_segments;
        self.clear_send_slab();
        discarded
    }
}

impl PeerUpdate for UdpQspIo {
    fn set_peer(&mut self, peer: SocketAddr) {
        Self::set_peer(self, peer);
    }
}

/// Plain Unix UDP-QSP socket backend without UDP GRO/GSO helpers.
///
/// The backend owns a duplicated nonblocking UDP socket and sends one UDP-QSP
/// packet per UDP datagram. Android uses this path because protected,
/// network-bound VPN sockets can fail on cellular networks when using the
/// offload-oriented `sendmsg`/`recvmsg` path.
#[derive(Debug)]
pub struct PlainUdpQspIo {
    socket: TokioUdpSocket,
    peer: SocketAddr,
    recv_buf: Vec<u8>,
}

impl PlainUdpQspIo {
    /// Create a plain UDP-QSP backend over a nonblocking UDP socket and peer address.
    ///
    /// # Errors
    ///
    /// Returns an error if the socket cannot be configured as nonblocking or
    /// registered with Tokio's readiness driver.
    pub fn new(socket: UdpSocket, peer: SocketAddr) -> io::Result<Self> {
        socket.set_nonblocking(true)?;
        let socket = TokioUdpSocket::from_std(socket)?;
        Ok(Self {
            socket,
            peer,
            recv_buf: vec![0u8; MAX_DATAGRAM],
        })
    }

    /// Return the accepted receive peer and outbound transmit destination.
    #[must_use]
    pub const fn peer(&self) -> SocketAddr {
        self.peer
    }

    /// Update the accepted receive peer and outbound transmit destination.
    pub const fn set_peer(&mut self, peer: SocketAddr) {
        self.peer = peer;
    }

    async fn send_packet(&self, bytes: &[u8]) -> io::Result<()> {
        if bytes.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "UDP-QSP packet must not be empty",
            ));
        }
        if bytes.len() > MAX_DATAGRAM {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "UDP-QSP packet exceeds datagram buffer limit",
            ));
        }

        self.socket.send_to(bytes, self.peer).await?;
        Ok(())
    }

    async fn recv_packet(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            let (len, from) = self.recv_datagram().await?;
            if from != self.peer {
                continue;
            }
            if len > buf.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "UDP-QSP datagram exceeds caller buffer",
                ));
            }
            buf[..len].copy_from_slice(&self.recv_buf[..len]);
            return Ok(len);
        }
    }

    async fn recv_datagram(&mut self) -> io::Result<(usize, SocketAddr)> {
        self.socket.recv_from(&mut self.recv_buf).await
    }
}

impl SessionIo for PlainUdpQspIo {
    async fn send(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.send_packet(bytes).await
    }

    async fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.recv_packet(buf).await
    }

    async fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }

    fn has_pending_flush(&self) -> bool {
        false
    }
}

impl PeerUpdate for PlainUdpQspIo {
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
mod tests;
