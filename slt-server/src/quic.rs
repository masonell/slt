//! QUIC front-door handling.

use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::{Duration, Instant};

use lru::LruCache;
use quinn_udp::{BATCH_SIZE, RecvMeta, UdpSockRef, UdpSocketState};
use slt_core::classifier::{QuicVerdict, classify_quic_datagram};
use slt_core::config::ServerConfig;
use slt_core::transport::gro_datagram_ranges;
use slt_core::types::CidPrefix;
use tokio::io::unix::AsyncFd;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, trace, warn};

use super::metrics::Metrics;
use super::registry::SessionRegistry;
use crate::sessions::SessionEvent;

/// Buffer size for UDP datagram reads on the passthrough upstream-reader path.
const QUIC_BUF_LEN: usize = 2 * 1024;

/// Upper bound on a single UDP datagram received by the front-door socket.
///
/// UDP-QSP packets carry one TUN frame (≈ `tun_mtu` plus a QUIC short header and
/// AEAD overhead); passthrough QUIC datagrams are bounded by the link MTU. 1500
/// (standard Ethernet) covers both. Each recv buffer is sized to
/// `MAX_DATAGRAM * gro_segments()` so a fully `UDP_GRO`-coalesced batch (up to
/// 64 datagrams on Linux) fits without truncation. Increase this if deploying on
/// jumbo-frame links.
const MAX_DATAGRAM: usize = 1500;

/// Claimed UDP-QSP datagram metadata.
///
/// Contains information about a UDP datagram that has been classified as
/// belonging to a registered VPN session, to be delivered via the session event channel.
#[derive(Debug, Clone)]
pub struct UdpClaim {
    /// Peer address.
    pub peer: SocketAddr,
    /// Destination connection ID prefix.
    pub dcid_prefix: CidPrefix,
    /// Raw datagram payload.
    pub payload: Vec<u8>,
}

/// NAT entry for a single UDP peer.
///
/// Tracks the upstream socket, last activity timestamp, reader task handle,
/// and unique token for a single peer connection in the QUIC NAT.
#[derive(Debug)]
struct PeerEntry {
    socket: Arc<UdpSocket>,
    last_seen: Instant,
    task: tokio::task::JoinHandle<()>,
    token: u64,
}

/// QUIC NAT state managing per-peer upstream sockets.
///
/// Maintains an LRU cache of peer connections, each with its own upstream socket
/// to preserve 4-tuple state. Tracks reader task completion via token-based signaling.
struct QuicNatState {
    peers: LruCache<SocketAddr, PeerEntry>,
    done_rx: mpsc::UnboundedReceiver<(SocketAddr, u64)>,
    done_tx: mpsc::UnboundedSender<(SocketAddr, u64)>,
    next_token: u64,
}

/// Batched receive state for the QUIC front-door socket.
///
/// Owns the duplicated file descriptor of the bound UDP socket wrapped in tokio's
/// `AsyncFd` for readiness notifications, the quinn-udp `UdpSocketState` that drives
/// `recvmmsg` + `UDP_GRO`, and the per-batch receive buffers / metadata scratch space.
///
/// The underlying kernel socket is shared (via `dup`) with the [`QuicEndpoint::socket`]
/// field used for sends; packets sent through either file descriptor leave from the same
/// local 4-tuple and replies arrive on the shared socket and can be drained here.
struct QuicRecv {
    fd: AsyncFd<std::net::UdpSocket>,
    state: UdpSocketState,
    bufs: Vec<Vec<u8>>,
    meta: Vec<RecvMeta>,
}

impl QuicRecv {
    /// Builds a new batched-recv state over a nonblocking, bound socket.
    ///
    /// # Errors
    ///
    /// Returns an error if quinn-udp fails to initialize its per-socket state
    /// (e.g. kernel `UDP_GRO` probing fails).
    fn new(socket: std::net::UdpSocket) -> io::Result<Self> {
        let state = UdpSocketState::new(UdpSockRef::from(&socket))?;
        // With `UDP_GRO`, one recv buffer can hold up to `gro_segments()` coalesced
        // datagrams (64 on Linux), so size each buffer to hold a full batch.
        // quinn-udp's own benchmark uses SEGMENT_SIZE * gro_segments for the same
        // reason; undersizing here truncates/drops datagrams under a GRO burst.
        let buf_len = state.gro_segments() * MAX_DATAGRAM;
        let bufs = (0..BATCH_SIZE).map(|_| vec![0u8; buf_len]).collect();
        let meta = (0..BATCH_SIZE).map(|_| RecvMeta::default()).collect();
        let fd = AsyncFd::new(socket)?;
        Ok(Self {
            fd,
            state,
            bufs,
            meta,
        })
    }
}

/// QUIC endpoint for UDP front-door handling.
///
/// Wraps a UDP socket that receives datagrams, classifies them as VPN traffic
/// or passthrough, and forwards to either session handlers or nginx upstream.
/// Maintains per-peer NAT state for passthrough traffic.
///
/// The socket is held in two forms sharing one kernel socket: `socket` (a tokio
/// `UdpSocket`) is used for sends (VPN replies via `SessionManager` and passthrough
/// replies from upstream-reader tasks), and `recv` drives the batched receive path
/// (`recvmmsg` + `UDP_GRO`) via an `AsyncFd` over a duplicated descriptor.
pub struct QuicEndpoint {
    socket: Arc<UdpSocket>,
    recv: QuicRecv,
    nginx_upstream: SocketAddr,
    max_lru_entries: NonZeroUsize,
    idle_timeout: Duration,
    registry: Arc<SessionRegistry>,
    metrics: Arc<Metrics>,
}

impl QuicEndpoint {
    /// Bind a UDP socket.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `udp_nat_max_entries` is zero
    /// - `idle_timeout` is zero
    /// - UDP socket binding fails
    pub fn bind(
        config: &ServerConfig,
        registry: Arc<SessionRegistry>,
        metrics: Arc<Metrics>,
    ) -> io::Result<Self> {
        let max_lru_entries = NonZeroUsize::new(config.udp_nat_max_entries).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "udp_nat_max_entries must be non-zero",
            )
        })?;

        if config.timing.idle_timeout.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "idle_timeout must be non-zero",
            ));
        }
        // Bind a blocking std socket, then duplicate the descriptor so the same
        // kernel socket backs both the send path (tokio `UdpSocket`) and the
        // batched recv path (`AsyncFd` + quinn-udp). Both fds share the local
        // 4-tuple, so passthrough / VPN-reply sends and GRO recv are coherent.
        let std_socket = std::net::UdpSocket::bind(config.network.listen_udp)?;
        let recv_socket = std_socket.try_clone()?;
        recv_socket.set_nonblocking(true)?;
        let recv = QuicRecv::new(recv_socket)?;

        std_socket.set_nonblocking(true)?;
        let socket = UdpSocket::from_std(std_socket)?;
        debug!(
            listen_addr = %config.network.listen_udp,
            upstream_addr = %config.network.nginx_udp_upstream,
            max_lru_entries = max_lru_entries.get(),
            idle_timeout_ms = config.timing.idle_timeout.as_millis(),
            gro_segments = recv.state.gro_segments(),
            batch_size = BATCH_SIZE,
            "QUIC endpoint bound"
        );
        Ok(Self {
            socket: Arc::new(socket),
            recv,
            nginx_upstream: config.network.nginx_udp_upstream,
            max_lru_entries,
            idle_timeout: config.timing.idle_timeout,
            registry,
            metrics,
        })
    }

    /// Returns the underlying UDP socket.
    #[must_use]
    pub const fn socket(&self) -> &Arc<UdpSocket> {
        &self.socket
    }

    /// Build an endpoint directly from a pre-bound tokio socket (tests only).
    ///
    /// Duplicates the underlying file descriptor so the returned endpoint shares
    /// one kernel socket between the tokio send path and the batched recv path,
    /// mirroring the construction performed by [`QuicEndpoint::bind`].
    ///
    /// # Panics
    ///
    /// Panics if the file descriptor cannot be duplicated, set non-blocking, or
    /// wrapped in quinn-udp's per-socket state. Tests are abort-on-infra-failure.
    #[cfg(test)]
    async fn from_socket_for_test(
        socket: Arc<UdpSocket>,
        nginx_upstream: SocketAddr,
        max_lru_entries: NonZeroUsize,
        idle_timeout: Duration,
        registry: Arc<SessionRegistry>,
        metrics: Arc<Metrics>,
    ) -> Self {
        let std_socket: std::net::UdpSocket = socket2::SockRef::from(&*socket)
            .try_clone()
            .expect("dup socket fd")
            .into();
        std_socket.set_nonblocking(true).expect("set_nonblocking");
        let recv = QuicRecv::new(std_socket).expect("QuicRecv::new");
        Self {
            socket,
            recv,
            nginx_upstream,
            max_lru_entries,
            idle_timeout,
            registry,
            metrics,
        }
    }

    /// Run the UDP accept loop and forward traffic to the nginx upstream.
    ///
    /// Each client gets a dedicated upstream socket to preserve 4-tuple state.
    /// The loop exits once `cancel` is canceled.
    ///
    /// # Errors
    ///
    /// Returns an error if receiving from the UDP socket fails.
    pub async fn run(&mut self, cancel: CancellationToken) -> io::Result<()> {
        debug!("Starting QUIC endpoint accept loop");
        let mut state = QuicNatState::new(self.max_lru_entries);
        let mut sweep = tokio::time::interval(self.idle_timeout);

        loop {
            tokio::select! {
                () = cancel.cancelled() => {
                    debug!("QUIC endpoint accept loop cancelled");
                    return Ok(());
                }
                Some((peer, token)) = state.done_rx.recv() => {
                    state.handle_reader_done(peer, token);
                }
                _ = sweep.tick() => {
                    state.sweep_idle(self.idle_timeout);
                }
                guard = self.recv.fd.readable() => {
                    let mut guard = guard?;
                    // One recvmmsg batch per readiness edge. `try_io` clears the
                    // AsyncFd readiness flag only when `recv` returns WouldBlock
                    // (socket drained); on success it stays set, so the next
                    // `readable().await` returns immediately and the next batch
                    // drains on the following outer-select iteration - which also
                    // gives `cancel` / `done_rx` / `sweep` a turn between batches.
                    match guard.try_io(|fd| {
                        let mut iovs: Vec<IoSliceMut> =
                            self.recv.bufs.iter_mut().map(|b| IoSliceMut::new(b)).collect();
                        self.recv.state.recv(
                            UdpSockRef::from(fd.get_ref()),
                            &mut iovs,
                            &mut self.recv.meta,
                        )
                    }) {
                        Ok(Ok(m)) => self.dispatch_recv_batch(&mut state, &cancel, m).await?,
                        Ok(Err(e)) => return Err(e), // fatal recv error
                        Err(_) => {} // WouldBlock: readiness auto-cleared (Ok(0) never happens on Linux)
                    }
                }
            }
        }
    }

    /// Dispatch one `recvmmsg` batch: stride-split each (possibly `UDP_GRO`
    /// coalesced) [`RecvMeta`] into individual datagrams and route each through
    /// `handle_datagram`.
    ///
    /// Only reads `recv.meta` / `recv.bufs` (the batch was filled by the `recv`
    /// call in `run`), so this takes `&self` and can run while the `AsyncFd`
    /// readiness guard - which borrows `recv.fd` - is still held.
    async fn dispatch_recv_batch(
        &self,
        nat_state: &mut QuicNatState,
        cancel: &CancellationToken,
        count: usize,
    ) -> io::Result<()> {
        for i in 0..count {
            let len = self.recv.meta[i].len;
            let stride = self.recv.meta[i].stride;
            let peer = self.recv.meta[i].addr;
            // GRO stride-split: one RecvMeta may hold K coalesced datagrams of
            // size `stride` (the last may be shorter). Classify each one.
            for (off, end) in gro_datagram_ranges(len, stride) {
                // Copy the datagram out of the reused recv buffer - the single
                // allocation on the recv->session path - so it can be owned
                // across the session channel.
                let payload = self.recv.bufs[i][off..end].to_vec();
                trace!(peer = %peer, len = payload.len(), "Received UDP datagram");
                self.metrics.inc_udp_accepted();
                self.handle_datagram(nat_state, cancel.clone(), peer, payload)
                    .await?;
            }
        }
        Ok(())
    }

    /// Handle a single UDP datagram.
    ///
    /// Classifies the datagram and routes it appropriately:
    /// - Drops invalid packets
    /// - Forwards passthrough traffic to nginx upstream
    /// - Delivers claimed UDP-QSP traffic to registered sessions
    ///
    /// # Errors
    ///
    /// Returns an error if sending to the upstream socket fails.
    async fn handle_datagram(
        &self,
        state: &mut QuicNatState,
        cancel: CancellationToken,
        peer: SocketAddr,
        payload: Vec<u8>,
    ) -> io::Result<()> {
        let verdict = classify_quic_datagram(&payload);
        trace!(peer = %peer, verdict = ?verdict, payload_len = payload.len(), "QUIC datagram verdict");

        match verdict {
            QuicVerdict::Drop => {
                debug!(peer = %peer, payload_len = payload.len(), "QUIC datagram dropped");
                self.metrics.inc_dropped();
                return Ok(());
            }
            QuicVerdict::Pass => {
                debug!(peer = %peer, payload_len = payload.len(), "QUIC datagram passed to upstream");
                self.metrics.inc_passed();
                let upstream_socket = state
                    .get_or_create_upstream(self.socket.clone(), self.nginx_upstream, peer, cancel)
                    .await?;
                match upstream_socket.send(&payload).await {
                    Ok(sent) => {
                        trace!(peer = %peer, sent = sent, "Sent datagram to upstream");
                    }
                    Err(e) => {
                        self.metrics.inc_upstream_send_failures();
                        warn!(peer = %peer, error = %e, "Failed to send datagram to upstream");
                    }
                }
            }
            QuicVerdict::Short { dcid_prefix } => {
                if let Some(tx) = self.registry.lookup_cid(dcid_prefix) {
                    debug!(
                        peer = %peer,
                        dcid_prefix = ?dcid_prefix,
                        payload_len = payload.len(),
                        "QUIC datagram claimed by session"
                    );
                    self.metrics.inc_claimed();
                    match tx.try_send(SessionEvent::Udp(UdpClaim {
                        peer,
                        dcid_prefix,
                        payload,
                    })) {
                        Ok(()) => {
                            trace!(peer = %peer, dcid_prefix = ?dcid_prefix, "Sent claimed datagram to session");
                        }
                        Err(_) => {
                            warn!(peer = %peer, dcid_prefix = ?dcid_prefix, "Failed to send claimed datagram to session (channel full/closed)");
                        }
                    }
                } else {
                    debug!(
                        peer = %peer,
                        dcid_prefix = ?dcid_prefix,
                        payload_len = payload.len(),
                        "QUIC datagram passed to upstream (no session claim)"
                    );
                    self.metrics.inc_passed();
                    let upstream_socket = state
                        .get_or_create_upstream(
                            self.socket.clone(),
                            self.nginx_upstream,
                            peer,
                            cancel,
                        )
                        .await?;
                    match upstream_socket.send(&payload).await {
                        Ok(sent) => {
                            trace!(peer = %peer, sent = sent, dcid_prefix = ?dcid_prefix, "Sent datagram to upstream");
                        }
                        Err(e) => {
                            self.metrics.inc_upstream_send_failures();
                            warn!(peer = %peer, error = %e, dcid_prefix = ?dcid_prefix, "Failed to send datagram to upstream");
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Spawn a task that reads from upstream and forwards to the peer.
    ///
    /// Creates a reader task that continuously receives datagrams from the
    /// upstream socket and forwards them to the downstream peer. Sends a
    /// completion notification via `done_tx` when the task exits.
    ///
    /// # Arguments
    ///
    /// * `upstream` - Socket connected to nginx upstream
    /// * `downstream` - Server's UDP socket for sending to peers
    /// * `peer` - Client address to forward data to
    /// * `token` - Unique identifier for this reader task
    /// * `cancel` - Token to signal task shutdown
    /// * `done_tx` - Channel for sending completion notification
    ///
    /// # Returns
    ///
    /// A join handle for the spawned reader task.
    fn spawn_upstream_reader(
        upstream: Arc<UdpSocket>,
        downstream: Arc<UdpSocket>,
        peer: SocketAddr,
        token: u64,
        cancel: CancellationToken,
        done_tx: mpsc::UnboundedSender<(SocketAddr, u64)>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            debug!(peer = %peer, token = token, "Starting upstream reader task");
            let mut buf = vec![0u8; QUIC_BUF_LEN];
            loop {
                let len = tokio::select! {
                    () = cancel.cancelled() => break,
                    res = upstream.recv(&mut buf) => match res {
                        Ok(len) => len,
                        Err(e) => {
                            warn!(peer = %peer, error = %e, "Upstream recv error, terminating reader task");
                            break;
                        }
                    },
                };

                if len == 0 {
                    continue;
                }

                trace!(peer = %peer, len = len, "Received data from upstream");
                match downstream.send_to(&buf[..len], peer).await {
                    Ok(sent) => {
                        trace!(peer = %peer, sent = sent, "Sent data to downstream peer");
                    }
                    Err(e) => {
                        warn!(peer = %peer, error = %e, "Failed to send data to downstream peer");
                    }
                }
            }

            trace!(peer = %peer, token = token, "Upstream reader task completed");
            let _ = done_tx.send((peer, token));
        })
    }
}

impl QuicNatState {
    fn new(lru_size: NonZeroUsize) -> Self {
        let (done_tx, done_rx) = mpsc::unbounded_channel();
        debug!(lru_size = lru_size.get(), "QuicNatState initialized");
        Self {
            peers: LruCache::new(lru_size),
            done_rx,
            done_tx,
            next_token: 0,
        }
    }
    /// Handle completion notification from an upstream reader task.
    ///
    /// Removes the peer entry from the NAT state if the token matches,
    /// ensuring only the most recent task's completion is processed.
    /// Restores the entry if tokens don't match (stale notification).
    fn handle_reader_done(&mut self, peer: SocketAddr, token: u64) {
        if let Some(entry) = self.peers.pop(&peer) {
            if entry.token == token {
                trace!(peer = %peer, token = token, "Removed completed reader from NAT state");
            } else {
                trace!(peer = %peer, expected_token = entry.token, received_token = token, "Reader token mismatch, restoring entry");
                self.peers.put(peer, entry);
            }
        }
    }

    fn sweep_idle(&mut self, idle_timeout: Duration) {
        let now = Instant::now();
        let mut stale = Vec::new();
        for (peer, entry) in &self.peers {
            if now.duration_since(entry.last_seen) >= idle_timeout {
                stale.push(*peer);
            }
        }
        for peer in stale {
            if let Some(entry) = self.peers.pop(&peer) {
                debug!(peer = %peer, idle_since_ms = now.duration_since(entry.last_seen).as_millis(), "Evicting idle peer from NAT");
                entry.task.abort();
            }
        }
    }

    /// Get an existing upstream socket for the peer or create a new one.
    ///
    /// Reuses existing NAT entries to preserve the 4-tuple. Creates a new
    /// connected socket and reader task if no entry exists. Evicts LRU
    /// entries when capacity is exceeded.
    ///
    /// # Arguments
    ///
    /// * `downstream` - Server's UDP socket for forwarding responses
    /// * `upstream_addr` - Nginx upstream address to connect to
    /// * `peer` - Client peer address
    /// * `cancel` - Cancellation token for reader tasks
    ///
    /// # Returns
    ///
    /// The upstream socket connected to nginx.
    ///
    /// # Errors
    ///
    /// Returns an error if socket binding or connection fails.
    async fn get_or_create_upstream(
        &mut self,
        downstream: Arc<UdpSocket>,
        upstream_addr: SocketAddr,
        peer: SocketAddr,
        cancel: CancellationToken,
    ) -> io::Result<Arc<UdpSocket>> {
        let now = Instant::now();
        if let Some(entry) = self.peers.get_mut(&peer) {
            entry.last_seen = now;
            trace!(peer = %peer, "Reusing existing upstream socket");
            return Ok(entry.socket.clone());
        }

        let bind_addr = match upstream_addr {
            SocketAddr::V4(_) => SocketAddr::from(([0u8; 4], 0)),
            SocketAddr::V6(_) => SocketAddr::from(([0u16; 8], 0)),
        };
        let socket = UdpSocket::bind(bind_addr).await?;
        let local_addr = socket.local_addr()?;
        socket.connect(upstream_addr).await?;
        let socket = Arc::new(socket);

        debug!(
            peer = %peer,
            local_addr = %local_addr,
            upstream_addr = %upstream_addr,
            "Created new upstream socket for NAT peer"
        );

        let token = self.next_token;
        self.next_token = self.next_token.wrapping_add(1);
        let task = QuicEndpoint::spawn_upstream_reader(
            socket.clone(),
            downstream,
            peer,
            token,
            cancel,
            self.done_tx.clone(),
        );

        let entry = PeerEntry {
            socket: socket.clone(),
            last_seen: now,
            task,
            token,
        };

        if let Some(evicted) = self.peers.put(peer, entry) {
            let fallback_addr = if upstream_addr.is_ipv6() {
                SocketAddr::new(std::net::Ipv6Addr::UNSPECIFIED.into(), 0)
            } else {
                SocketAddr::new(std::net::Ipv4Addr::UNSPECIFIED.into(), 0)
            };
            info!(evicted_peer = %evicted.socket.peer_addr().unwrap_or(fallback_addr), "Evicted peer from NAT LRU cache");
            evicted.task.abort();
        }

        Ok(socket)
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};
    use std::num::NonZeroUsize;
    use std::sync::Arc;
    use std::time::Duration;

    use slt_core::config::ServerConfig;
    use slt_core::transport::gro_datagram_ranges;
    use slt_core::types::{
        QUIC_DCID_PREFIX_LEN, ServerNetworkConfig, ServerTimingConfig, ServerTlsConfig,
        SharedSecret, TlsMaterial, TunConfig,
    };
    use tokio::sync::mpsc;
    use tokio::time::{Instant, timeout, timeout_at};
    use tokio_util::sync::CancellationToken;

    use super::{PeerEntry, QuicEndpoint, QuicNatState};
    use crate::metrics::Metrics;
    use crate::registry::SessionRegistry;
    use crate::sessions::SessionEvent;

    /// The GRO stride-split math must produce one range per coalesced datagram,
    /// with the last range clipped to `len`, and never panic/infinite-loop on a
    /// malformed `stride == 0`.
    #[test]
    fn gro_datagram_ranges_splits_coalesced_buffer() {
        // Equal-sized coalesced datagrams.
        let eq: Vec<_> = gro_datagram_ranges(4096, 1024).collect();
        assert_eq!(
            eq,
            vec![(0, 1024), (1024, 2048), (2048, 3072), (3072, 4096)]
        );

        // Last datagram shorter than stride.
        let partial: Vec<_> = gro_datagram_ranges(2500, 1024).collect();
        assert_eq!(partial, vec![(0, 1024), (1024, 2048), (2048, 2500)]);

        // No coalescing: stride == len yields a single datagram (quinn-udp's non-GRO default).
        let single: Vec<_> = gro_datagram_ranges(1406, 1406).collect();
        assert_eq!(single, vec![(0, 1406)]);

        // stride == 0 is defensive: clamped to 1, no infinite loop or panic.
        let zero: Vec<_> = gro_datagram_ranges(3, 0).collect();
        assert_eq!(zero, vec![(0, 1), (1, 2), (2, 3)]);

        // Empty buffer yields nothing.
        assert!(gro_datagram_ranges(0, 1406).next().is_none());
    }

    fn test_config() -> ServerConfig {
        ServerConfig {
            server_secret: SharedSecret([0u8; 32]),
            network: ServerNetworkConfig {
                listen_tcp: SocketAddr::from(([127, 0, 0, 1], 0)),
                listen_udp: SocketAddr::from(([127, 0, 0, 1], 0)),
                nginx_tcp_upstream: SocketAddr::from(([127, 0, 0, 1], 8080)),
                nginx_udp_upstream: SocketAddr::from(([127, 0, 0, 1], 8080)),
            },
            tls: ServerTlsConfig {
                tls_cert: TlsMaterial::Pem(String::new()),
                tls_key: TlsMaterial::Pem(String::new()),
            },
            tun: TunConfig {
                tun_name: "tun0".to_string(),
                tun_mtu: 1280,
                tun_ipv4: Ipv4Addr::new(10, 10, 0, 1),
                tun_prefix: 24,
            },
            timing: ServerTimingConfig {
                ping_min: Duration::from_secs(10),
                ping_max: Duration::from_secs(20),
                auth_timeout: Duration::from_secs(10),
                idle_timeout: Duration::from_mins(1),
                metrics_interval: Duration::from_mins(5),
            },
            udp_nat_max_entries: 1024,
            session_queue_size: 256,
            clients: vec![],
        }
    }

    async fn make_endpoint() -> QuicEndpoint {
        let registry = Arc::new(SessionRegistry::new());
        let metrics = Arc::new(Metrics::default());
        let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        QuicEndpoint::from_socket_for_test(
            socket,
            SocketAddr::from(([127, 0, 0, 1], 8080)),
            NonZeroUsize::new(1024).unwrap(),
            Duration::from_mins(1),
            registry,
            metrics,
        )
        .await
    }

    fn make_quic_short_header(dcid_prefix: &[u8; QUIC_DCID_PREFIX_LEN]) -> Vec<u8> {
        let mut buf = vec![0x40]; // short header + fixed bit
        buf.extend_from_slice(dcid_prefix);
        buf.extend_from_slice(&[0u8; 16]); // some payload
        buf
    }

    fn make_quic_long_header() -> Vec<u8> {
        vec![0xC0, 0x00, 0x00, 0x00, 0x01, 0x08] // long header + fixed bit
    }

    fn make_non_quic_packet() -> Vec<u8> {
        vec![0x00] // no fixed bit
    }

    #[tokio::test]
    async fn bind_rejects_zero_udp_nat_max_entries() {
        let mut config = test_config();
        config.udp_nat_max_entries = 0;
        let registry = Arc::new(SessionRegistry::new());
        let metrics = Arc::new(Metrics::default());

        let result = QuicEndpoint::bind(&config, registry, metrics);
        assert!(result.is_err());
        if let Err(err) = result {
            assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
            assert!(
                err.to_string()
                    .contains("udp_nat_max_entries must be non-zero")
            );
        }
    }

    #[tokio::test]
    async fn bind_rejects_zero_idle_timeout() {
        let mut config = test_config();
        config.timing.idle_timeout = Duration::ZERO;
        let registry = Arc::new(SessionRegistry::new());
        let metrics = Arc::new(Metrics::default());

        let result = QuicEndpoint::bind(&config, registry, metrics);
        assert!(result.is_err());
        if let Err(err) = result {
            assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
            assert!(err.to_string().contains("idle_timeout must be non-zero"));
        }
    }

    #[tokio::test]
    async fn bind_binds_udp_socket_on_listen_addr() {
        let config = test_config();
        let registry = Arc::new(SessionRegistry::new());
        let metrics = Arc::new(Metrics::default());

        let endpoint = QuicEndpoint::bind(&config, registry, metrics);
        assert!(endpoint.is_ok());
        let endpoint = endpoint.unwrap();
        let local_addr = endpoint.socket().local_addr().unwrap();
        assert!(local_addr.port() > 0);
        assert!(local_addr.ip().is_loopback());
    }

    #[tokio::test]
    async fn run_exits_on_cancellation() {
        let mut endpoint = make_endpoint().await;
        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();

        let handle = tokio::spawn(async move { endpoint.run(cancel_clone).await });

        // Give the run loop a moment to start
        tokio::time::sleep(Duration::from_millis(10)).await;
        cancel.cancel();

        let result = timeout(Duration::from_secs(1), handle).await;
        assert!(result.is_ok());
        let inner = result.unwrap();
        assert!(inner.is_ok());
        assert!(inner.unwrap().is_ok());
    }

    #[tokio::test]
    async fn run_forwards_pass_datagrams_and_counts_udp_accepted_and_passed() {
        let upstream_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_socket.local_addr().unwrap();

        let mut config = test_config();
        config.network.nginx_udp_upstream = upstream_addr;
        config.timing.idle_timeout = Duration::from_millis(200);

        let registry = Arc::new(SessionRegistry::new());
        let metrics = Arc::new(Metrics::default());
        let mut endpoint = QuicEndpoint::bind(&config, registry, metrics.clone()).unwrap();
        let listen_addr = endpoint.socket().local_addr().unwrap();

        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();
        let run_task = tokio::spawn(async move { endpoint.run(cancel_clone).await });

        let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let payload = make_quic_long_header();
        peer.send_to(&payload, listen_addr).await.unwrap();

        let mut buf = [0u8; 256];
        let (len, _) = timeout(Duration::from_secs(1), upstream_socket.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(len, payload.len());

        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            let snap = metrics.snapshot();
            if snap.udp_accepted == 1 && snap.passed == 1 {
                break;
            }
            assert!(Instant::now() < deadline, "metrics did not update in time");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        cancel.cancel();
        let run_result = timeout(Duration::from_secs(1), run_task).await.unwrap();
        assert!(run_result.unwrap().is_ok());
    }

    #[tokio::test]
    async fn run_sweep_idle_recreates_nat_socket_after_timeout() {
        let upstream_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_socket.local_addr().unwrap();

        let mut config = test_config();
        config.network.nginx_udp_upstream = upstream_addr;
        config.timing.idle_timeout = Duration::from_millis(50);

        let registry = Arc::new(SessionRegistry::new());
        let metrics = Arc::new(Metrics::default());
        let mut endpoint = QuicEndpoint::bind(&config, registry, metrics).unwrap();
        let listen_addr = endpoint.socket().local_addr().unwrap();

        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();
        let run_task = tokio::spawn(async move { endpoint.run(cancel_clone).await });

        let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let payload = make_quic_long_header();

        peer.send_to(&payload, listen_addr).await.unwrap();
        let mut buf = [0u8; 256];
        let (_, first_src) = timeout(Duration::from_secs(1), upstream_socket.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();

        // Wait for idle sweep to evict the first NAT entry.
        tokio::time::sleep(Duration::from_millis(220)).await;

        peer.send_to(&payload, listen_addr).await.unwrap();
        let (_, second_src) = timeout(Duration::from_secs(1), upstream_socket.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();

        assert_ne!(
            first_src.port(),
            second_src.port(),
            "idle eviction should recreate upstream socket with a new local port"
        );

        cancel.cancel();
        let run_result = timeout(Duration::from_secs(1), run_task).await.unwrap();
        assert!(run_result.unwrap().is_ok());
    }

    #[tokio::test]
    async fn handle_datagram_drop_increments_dropped_metric() {
        let endpoint = make_endpoint().await;
        let mut state = QuicNatState::new(NonZeroUsize::new(1024).unwrap());
        let cancel = CancellationToken::new();
        let peer = SocketAddr::from(([127, 0, 0, 1], 12345));
        let payload = make_non_quic_packet();

        let before = endpoint.metrics.snapshot().dropped;
        let result = endpoint
            .handle_datagram(&mut state, cancel, peer, payload)
            .await;
        assert!(result.is_ok());
        let after = endpoint.metrics.snapshot().dropped;
        assert_eq!(after, before + 1);
    }

    #[tokio::test]
    async fn handle_datagram_pass_forwards_to_upstream_and_increments_passed() {
        // Create an upstream server to receive forwarded packets
        let upstream_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_socket.local_addr().unwrap();

        let registry = Arc::new(SessionRegistry::new());
        let metrics = Arc::new(Metrics::default());
        let downstream = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());

        let endpoint = QuicEndpoint::from_socket_for_test(
            downstream.clone(),
            upstream_addr,
            NonZeroUsize::new(1024).unwrap(),
            Duration::from_mins(1),
            registry,
            metrics,
        )
        .await;

        let mut state = QuicNatState::new(NonZeroUsize::new(1024).unwrap());
        let cancel = CancellationToken::new();
        let peer = SocketAddr::from(([127, 0, 0, 1], 12345));
        let payload = make_quic_long_header();

        let before = endpoint.metrics.snapshot().passed;
        let result = endpoint
            .handle_datagram(&mut state, cancel.clone(), peer, payload.clone())
            .await;
        assert!(result.is_ok());

        // Receive the forwarded packet
        let mut buf = vec![0u8; 256];
        let recv_result = timeout(
            Duration::from_millis(500),
            upstream_socket.recv_from(&mut buf),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(recv_result.0, payload.len());

        let after = endpoint.metrics.snapshot().passed;
        assert_eq!(after, before + 1);
    }

    #[tokio::test]
    async fn handle_datagram_pass_with_unconnected_upstream_socket_is_non_fatal() {
        let registry = Arc::new(SessionRegistry::new());
        let metrics = Arc::new(Metrics::default());
        let downstream = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());

        let endpoint = QuicEndpoint::from_socket_for_test(
            downstream,
            SocketAddr::from(([127, 0, 0, 1], 8080)),
            NonZeroUsize::new(1024).unwrap(),
            Duration::from_mins(1),
            registry,
            metrics.clone(),
        )
        .await;

        let mut state = QuicNatState::new(NonZeroUsize::new(1024).unwrap());
        let cancel = CancellationToken::new();
        let peer = SocketAddr::from(([127, 0, 0, 1], 12345));
        let payload = make_quic_long_header();
        let upstream_socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());

        // Seed NAT with an unconnected socket so send() fails with NotConnected.
        state.peers.put(
            peer,
            PeerEntry {
                socket: upstream_socket,
                last_seen: std::time::Instant::now(),
                task: tokio::spawn(async {}),
                token: 1,
            },
        );

        let before = metrics.snapshot();
        let result = endpoint
            .handle_datagram(&mut state, cancel, peer, payload)
            .await;
        assert!(result.is_ok());
        let after = metrics.snapshot();
        assert_eq!(after.passed, before.passed + 1);
        assert_eq!(
            after.upstream_send_failures,
            before.upstream_send_failures + 1
        );
    }

    #[tokio::test]
    async fn handle_datagram_short_with_registered_cid_sends_session_event() {
        let registry = Arc::new(SessionRegistry::new());
        let metrics = Arc::new(Metrics::default());
        let downstream = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());

        let endpoint = QuicEndpoint::from_socket_for_test(
            downstream.clone(),
            SocketAddr::from(([127, 0, 0, 1], 8080)),
            NonZeroUsize::new(1024).unwrap(),
            Duration::from_mins(1),
            registry.clone(),
            metrics,
        )
        .await;

        // Register a CID prefix
        let dcid_prefix = [0xAA; QUIC_DCID_PREFIX_LEN];
        let (tx, mut rx) = mpsc::channel(1);
        registry
            .insert_cid(1, slt_core::types::CidPrefix::from(dcid_prefix), tx)
            .unwrap();

        let mut state = QuicNatState::new(NonZeroUsize::new(1024).unwrap());
        let cancel = CancellationToken::new();
        let peer = SocketAddr::from(([127, 0, 0, 1], 12345));
        let payload = make_quic_short_header(&dcid_prefix);

        let before = endpoint.metrics.snapshot().claimed;
        let result = endpoint
            .handle_datagram(&mut state, cancel, peer, payload)
            .await;
        assert!(result.is_ok());

        // Check that the session event was sent
        let event = timeout(Duration::from_millis(100), rx.recv())
            .await
            .unwrap()
            .unwrap();
        match event {
            SessionEvent::Udp(claim) => {
                assert_eq!(claim.peer, peer);
                assert_eq!(claim.dcid_prefix.as_bytes(), &dcid_prefix);
                assert!(!claim.payload.is_empty());
            }
            _ => panic!("expected Udp event"),
        }

        let after = endpoint.metrics.snapshot().claimed;
        assert_eq!(after, before + 1);
    }

    #[tokio::test]
    async fn handle_datagram_short_with_missing_cid_passes_to_upstream() {
        let upstream_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_socket.local_addr().unwrap();

        let registry = Arc::new(SessionRegistry::new());
        let metrics = Arc::new(Metrics::default());
        let downstream = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());

        let endpoint = QuicEndpoint::from_socket_for_test(
            downstream.clone(),
            upstream_addr,
            NonZeroUsize::new(1024).unwrap(),
            Duration::from_mins(1),
            registry,
            metrics,
        )
        .await;

        let mut state = QuicNatState::new(NonZeroUsize::new(1024).unwrap());
        let cancel = CancellationToken::new();
        let peer = SocketAddr::from(([127, 0, 0, 1], 12345));
        // Use a CID prefix that's not registered
        let dcid_prefix = [0xBB; QUIC_DCID_PREFIX_LEN];
        let payload = make_quic_short_header(&dcid_prefix);

        let before = endpoint.metrics.snapshot().passed;
        let result = endpoint
            .handle_datagram(&mut state, cancel.clone(), peer, payload.clone())
            .await;
        assert!(result.is_ok());

        // Should be forwarded to upstream
        let mut buf = vec![0u8; 256];
        let recv_result = timeout(
            Duration::from_millis(500),
            upstream_socket.recv_from(&mut buf),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(recv_result.0, payload.len());

        let after = endpoint.metrics.snapshot().passed;
        assert_eq!(after, before + 1);
    }

    #[tokio::test]
    async fn handle_datagram_short_with_missing_cid_and_unconnected_upstream_is_non_fatal() {
        let registry = Arc::new(SessionRegistry::new());
        let metrics = Arc::new(Metrics::default());
        let downstream = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());

        let endpoint = QuicEndpoint::from_socket_for_test(
            downstream,
            SocketAddr::from(([127, 0, 0, 1], 8080)),
            NonZeroUsize::new(1024).unwrap(),
            Duration::from_mins(1),
            registry,
            metrics.clone(),
        )
        .await;

        let mut state = QuicNatState::new(NonZeroUsize::new(1024).unwrap());
        let cancel = CancellationToken::new();
        let peer = SocketAddr::from(([127, 0, 0, 1], 12345));
        let dcid_prefix = [0xBD; QUIC_DCID_PREFIX_LEN];
        let payload = make_quic_short_header(&dcid_prefix);
        let upstream_socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());

        // Seed NAT with an unconnected socket so send() fails with NotConnected.
        state.peers.put(
            peer,
            PeerEntry {
                socket: upstream_socket,
                last_seen: std::time::Instant::now(),
                task: tokio::spawn(async {}),
                token: 1,
            },
        );

        let before = metrics.snapshot();
        let result = endpoint
            .handle_datagram(&mut state, cancel, peer, payload)
            .await;
        assert!(result.is_ok());
        let after = metrics.snapshot();
        assert_eq!(after.passed, before.passed + 1);
        assert_eq!(
            after.upstream_send_failures,
            before.upstream_send_failures + 1
        );
    }

    #[tokio::test]
    async fn handle_datagram_claim_channel_closed_logs_and_continues() {
        let registry = Arc::new(SessionRegistry::new());
        let metrics = Arc::new(Metrics::default());
        let downstream = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());

        let endpoint = QuicEndpoint::from_socket_for_test(
            downstream.clone(),
            SocketAddr::from(([127, 0, 0, 1], 8080)),
            NonZeroUsize::new(1024).unwrap(),
            Duration::from_mins(1),
            registry.clone(),
            metrics,
        )
        .await;

        // Register a CID prefix with a channel, then close it
        let dcid_prefix = [0xCC; QUIC_DCID_PREFIX_LEN];
        let (tx, rx) = mpsc::channel(1);
        drop(rx); // Close the receiver to make try_send fail
        registry
            .insert_cid(1, slt_core::types::CidPrefix::from(dcid_prefix), tx)
            .unwrap();

        let mut state = QuicNatState::new(NonZeroUsize::new(1024).unwrap());
        let cancel = CancellationToken::new();
        let peer = SocketAddr::from(([127, 0, 0, 1], 12345));
        let payload = make_quic_short_header(&dcid_prefix);

        // Should not error even when channel is closed (try_send fails gracefully)
        let result = endpoint
            .handle_datagram(&mut state, cancel, peer, payload)
            .await;
        assert!(result.is_ok());

        // Metric should still be incremented (we tried to claim)
        let snapshot = endpoint.metrics.snapshot();
        assert!(snapshot.claimed > 0);
    }

    #[tokio::test]
    async fn get_or_create_upstream_reuses_socket_for_same_peer() {
        let downstream = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let upstream_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_socket.local_addr().unwrap();

        let mut state = QuicNatState::new(NonZeroUsize::new(1024).unwrap());
        let cancel = CancellationToken::new();
        let peer = SocketAddr::from(([127, 0, 0, 1], 12345));

        let socket1 = state
            .get_or_create_upstream(downstream.clone(), upstream_addr, peer, cancel.clone())
            .await
            .unwrap();
        let socket2 = state
            .get_or_create_upstream(downstream, upstream_addr, peer, cancel)
            .await
            .unwrap();

        // Should return the same Arc (same socket)
        assert!(Arc::ptr_eq(&socket1, &socket2));
    }

    #[tokio::test]
    async fn get_or_create_upstream_creates_distinct_sockets_per_peer() {
        let downstream = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let upstream_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_socket.local_addr().unwrap();

        let mut state = QuicNatState::new(NonZeroUsize::new(1024).unwrap());
        let cancel = CancellationToken::new();
        let peer1 = SocketAddr::from(([127, 0, 0, 1], 12345));
        let peer2 = SocketAddr::from(([127, 0, 0, 1], 12346));

        let socket1 = state
            .get_or_create_upstream(downstream.clone(), upstream_addr, peer1, cancel.clone())
            .await
            .unwrap();
        let socket2 = state
            .get_or_create_upstream(downstream, upstream_addr, peer2, cancel)
            .await
            .unwrap();

        // Should return different Arcs (different sockets)
        assert!(!Arc::ptr_eq(&socket1, &socket2));

        // Verify they have different local addresses
        let addr1 = socket1.local_addr().unwrap();
        let addr2 = socket2.local_addr().unwrap();
        assert_ne!(addr1.port(), addr2.port());
    }

    #[tokio::test]
    async fn get_or_create_upstream_evicts_lru_and_aborts_old_task() {
        let downstream = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let upstream_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_socket.local_addr().unwrap();

        // Create state with LRU size of 2
        let mut state = QuicNatState::new(NonZeroUsize::new(2).unwrap());
        let cancel = CancellationToken::new();

        let peer1 = SocketAddr::from(([127, 0, 0, 1], 12345));
        let peer2 = SocketAddr::from(([127, 0, 0, 1], 12346));
        let peer3 = SocketAddr::from(([127, 0, 0, 1], 12347));

        // Create entries for peer1 and peer2 (fills LRU)
        let _socket1 = state
            .get_or_create_upstream(downstream.clone(), upstream_addr, peer1, cancel.clone())
            .await
            .unwrap();
        let _socket2 = state
            .get_or_create_upstream(downstream.clone(), upstream_addr, peer2, cancel.clone())
            .await
            .unwrap();

        // Create entry for peer3 (should evict peer1)
        let _socket3 = state
            .get_or_create_upstream(downstream, upstream_addr, peer3, cancel)
            .await
            .unwrap();

        // peer1's socket should no longer be in the LRU (evicted)
        // peer2 and peer3 should still be there
        assert!(state.peers.contains(&peer2));
        assert!(state.peers.contains(&peer3));
        assert!(!state.peers.contains(&peer1));
    }

    #[tokio::test]
    async fn handle_reader_done_removes_matching_token() {
        let mut state = QuicNatState::new(NonZeroUsize::new(1024).unwrap());
        let peer = SocketAddr::from(([127, 0, 0, 1], 12345));
        let token = 42u64;

        // Manually insert a peer entry
        let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let entry = PeerEntry {
            socket,
            last_seen: std::time::Instant::now(),
            task: tokio::spawn(async {}),
            token,
        };
        state.peers.put(peer, entry);

        assert!(state.peers.contains(&peer));

        // Remove with matching token
        state.handle_reader_done(peer, token);

        assert!(!state.peers.contains(&peer));
    }

    #[tokio::test]
    async fn handle_reader_done_ignores_stale_token() {
        let mut state = QuicNatState::new(NonZeroUsize::new(1024).unwrap());
        let peer = SocketAddr::from(([127, 0, 0, 1], 12345));
        let correct_token = 42u64;
        let stale_token = 99u64;

        // Manually insert a peer entry
        let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let entry = PeerEntry {
            socket,
            last_seen: std::time::Instant::now(),
            task: tokio::spawn(async {}),
            token: correct_token,
        };
        state.peers.put(peer, entry);

        // Try to remove with wrong token
        state.handle_reader_done(peer, stale_token);

        // Entry should still exist (was restored)
        assert!(state.peers.contains(&peer));
    }

    #[tokio::test]
    async fn sweep_idle_evicts_stale_peers() {
        let mut state = QuicNatState::new(NonZeroUsize::new(1024).unwrap());
        let peer = SocketAddr::from(([127, 0, 0, 1], 12345));
        let idle_timeout = Duration::from_mins(1);

        // Manually insert a peer entry with old last_seen
        let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let old_time = std::time::Instant::now()
            .checked_sub(idle_timeout + Duration::from_secs(1))
            .unwrap();
        let entry = PeerEntry {
            socket,
            last_seen: old_time,
            task: tokio::spawn(async {}),
            token: 1,
        };
        state.peers.put(peer, entry);

        assert!(state.peers.contains(&peer));

        state.sweep_idle(idle_timeout);

        assert!(!state.peers.contains(&peer));
    }

    #[tokio::test]
    async fn sweep_idle_keeps_recent_peers() {
        let mut state = QuicNatState::new(NonZeroUsize::new(1024).unwrap());
        let peer = SocketAddr::from(([127, 0, 0, 1], 12345));
        let idle_timeout = Duration::from_mins(1);

        // Manually insert a peer entry with recent last_seen
        let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let entry = PeerEntry {
            socket,
            last_seen: std::time::Instant::now(),
            task: tokio::spawn(async {}),
            token: 1,
        };
        state.peers.put(peer, entry);

        assert!(state.peers.contains(&peer));

        state.sweep_idle(idle_timeout);

        assert!(state.peers.contains(&peer));
    }

    #[tokio::test]
    async fn spawn_upstream_reader_forwards_packets_and_reports_done() {
        // Create the "peer" socket that will receive forwarded packets from downstream
        let peer_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer = peer_socket.local_addr().unwrap();

        // Create the downstream socket (the server's UDP socket)
        let downstream = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let downstream_addr = downstream.local_addr().unwrap();

        // Create the mock "upstream server"
        let upstream_server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_server_addr = upstream_server.local_addr().unwrap();

        // Create the upstream client socket (this is the NAT socket)
        let upstream_client = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());

        // Connect the upstream_client to the upstream_server
        upstream_client.connect(upstream_server_addr).await.unwrap();

        let token = 123u64;
        let cancel = CancellationToken::new();
        let (done_tx, mut done_rx) = mpsc::unbounded_channel();

        // Spawn the upstream reader
        // It will read from upstream_client, then send to peer via downstream
        let handle = QuicEndpoint::spawn_upstream_reader(
            upstream_client.clone(),
            downstream.clone(),
            peer,
            token,
            cancel.clone(),
            done_tx,
        );

        // Give the task a moment to start
        tokio::time::sleep(Duration::from_millis(20)).await;

        // To test packet forwarding:
        // 1. upstream_client is connected to upstream_server
        // 2. upstream_server sends to upstream_client's address
        // 3. upstream_client receives and spawn_upstream_reader forwards to peer via downstream

        // Server sends data to the client's bound address
        let test_data = b"hello from upstream";
        upstream_server
            .send_to(test_data, upstream_client.local_addr().unwrap())
            .await
            .unwrap();

        // The peer_socket should receive the forwarded packet (from downstream_addr)
        let mut buf = vec![0u8; 256];
        let deadline = Instant::now() + Duration::from_millis(500);
        let (recv_len, from_addr) = timeout_at(deadline, peer_socket.recv_from(&mut buf))
            .await
            .expect("should receive forwarded packet")
            .expect("recv_from should succeed");
        assert_eq!(recv_len, test_data.len());
        assert_eq!(&buf[..recv_len], test_data);
        // Packet comes from downstream socket
        assert_eq!(from_addr, downstream_addr);

        // Cancel and verify done notification
        cancel.cancel();
        handle.await.unwrap();

        // Should receive the done notification
        let done_msg = timeout(Duration::from_millis(100), done_rx.recv())
            .await
            .expect("should receive done notification")
            .expect("done channel should have message");
        assert_eq!(done_msg.0, peer);
        assert_eq!(done_msg.1, token);
    }

    #[tokio::test]
    async fn spawn_upstream_reader_handles_downstream_send_error_and_reports_done() {
        let downstream = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let upstream_server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_server_addr = upstream_server.local_addr().unwrap();
        let upstream_client = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        upstream_client.connect(upstream_server_addr).await.unwrap();

        // Force send_to() error in reader by using IPv6 peer with IPv4 downstream socket.
        let peer = SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], 12345));

        let token = 321u64;
        let cancel = CancellationToken::new();
        let (done_tx, mut done_rx) = mpsc::unbounded_channel();
        let handle = QuicEndpoint::spawn_upstream_reader(
            upstream_client.clone(),
            downstream,
            peer,
            token,
            cancel.clone(),
            done_tx,
        );

        upstream_server
            .send_to(
                b"trigger send_to error",
                upstream_client.local_addr().unwrap(),
            )
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(30)).await;

        cancel.cancel();
        handle.await.unwrap();

        let done_msg = timeout(Duration::from_millis(200), done_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(done_msg.0, peer);
        assert_eq!(done_msg.1, token);
    }
}
