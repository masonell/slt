//! QUIC front-door handling.

use std::future::Future;
use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::pin::Pin;
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

type UpstreamSocketFuture = Pin<Box<dyn Future<Output = io::Result<UdpSocket>> + Send + 'static>>;

trait UpstreamSocketFactory: Send + Sync {
    fn create_connected(&self, upstream_addr: SocketAddr) -> UpstreamSocketFuture;
}

struct TokioUpstreamSocketFactory;

impl UpstreamSocketFactory for TokioUpstreamSocketFactory {
    fn create_connected(&self, upstream_addr: SocketAddr) -> UpstreamSocketFuture {
        Box::pin(async move {
            let bind_addr = match upstream_addr {
                SocketAddr::V4(_) => SocketAddr::from(([0u8; 4], 0)),
                SocketAddr::V6(_) => SocketAddr::from(([0u16; 8], 0)),
            };
            let socket = UdpSocket::bind(bind_addr).await?;
            socket.connect(upstream_addr).await?;
            Ok(socket)
        })
    }
}

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
    upstream_socket_factory: Arc<dyn UpstreamSocketFactory>,
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
            upstream_socket_factory: Arc::new(TokioUpstreamSocketFactory),
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
            upstream_socket_factory: Arc::new(TokioUpstreamSocketFactory),
            max_lru_entries,
            idle_timeout,
            registry,
            metrics,
        }
    }

    #[cfg(test)]
    fn with_upstream_socket_factory(mut self, factory: Arc<dyn UpstreamSocketFactory>) -> Self {
        self.upstream_socket_factory = factory;
        self
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
                        Ok(Ok(m)) => self.dispatch_recv_batch(&mut state, &cancel, m).await,
                        Ok(Err(e)) => return Err(e),
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
    ) {
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
                    .await;
            }
        }
    }

    /// Handle a single UDP datagram.
    ///
    /// Classifies the datagram and routes it appropriately:
    /// - Drops invalid packets
    /// - Forwards passthrough traffic to nginx upstream
    /// - Delivers claimed UDP-QSP traffic to registered sessions
    ///
    async fn handle_datagram(
        &self,
        state: &mut QuicNatState,
        cancel: CancellationToken,
        peer: SocketAddr,
        payload: Vec<u8>,
    ) {
        let verdict = classify_quic_datagram(&payload);
        trace!(peer = %peer, verdict = ?verdict, payload_len = payload.len(), "QUIC datagram verdict");

        match verdict {
            QuicVerdict::Drop => {
                debug!(peer = %peer, payload_len = payload.len(), "QUIC datagram dropped");
                self.metrics.inc_dropped();
            }
            QuicVerdict::Pass => {
                debug!(peer = %peer, payload_len = payload.len(), "QUIC datagram passed to upstream");
                self.forward_to_upstream(state, cancel, peer, &payload)
                    .await;
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
                    if tx
                        .try_send(SessionEvent::Udp(UdpClaim {
                            peer,
                            dcid_prefix,
                            payload,
                        }))
                        .is_ok()
                    {
                        trace!(peer = %peer, dcid_prefix = ?dcid_prefix, "Sent claimed datagram to session");
                    } else {
                        self.metrics.inc_udp_claim_channel_full_drops();
                        debug!(peer = %peer, dcid_prefix = ?dcid_prefix, "Claimed datagram dropped (session queue full/closed)");
                    }
                } else {
                    debug!(
                        peer = %peer,
                        dcid_prefix = ?dcid_prefix,
                        payload_len = payload.len(),
                        "QUIC datagram passed to upstream (no session claim)"
                    );
                    self.forward_to_upstream(state, cancel, peer, &payload)
                        .await;
                }
            }
        }
    }

    async fn forward_to_upstream(
        &self,
        state: &mut QuicNatState,
        cancel: CancellationToken,
        peer: SocketAddr,
        payload: &[u8],
    ) {
        self.metrics.inc_passed();
        let upstream_socket = match state
            .get_or_create_upstream(
                self.upstream_socket_factory.as_ref(),
                self.socket.clone(),
                self.nginx_upstream,
                peer,
                cancel,
            )
            .await
        {
            Ok(socket) => socket,
            Err(error) => {
                self.metrics.inc_udp_upstream_setup_failure_drops();
                warn!(
                    peer = %peer,
                    upstream_addr = %self.nginx_upstream,
                    error = %error,
                    "Failed to set up UDP upstream socket, dropping datagram"
                );
                return;
            }
        };

        match upstream_socket.send(payload).await {
            Ok(sent) => {
                trace!(peer = %peer, sent, "Sent datagram to upstream");
            }
            Err(error) => {
                self.metrics.inc_upstream_send_failures();
                warn!(peer = %peer, error = %error, "Failed to send datagram to upstream");
            }
        }
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
        upstream_socket_factory: &dyn UpstreamSocketFactory,
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

        let socket = upstream_socket_factory
            .create_connected(upstream_addr)
            .await?;
        let socket = Arc::new(socket);

        debug!(
            peer = %peer,
            local_addr = ?socket.local_addr().ok(),
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
            info!(
                evicted_peer = %evicted
                    .socket
                    .peer_addr()
                    .expect("NAT upstream sockets are connected before cache insertion"),
                "Evicted peer from NAT LRU cache"
            );
            evicted.task.abort();
        }

        Ok(socket)
    }
}

#[cfg(test)]
mod tests;
