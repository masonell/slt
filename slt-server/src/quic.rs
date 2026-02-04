//! QUIC front-door handling.

use std::io;
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::metrics::Metrics;
use super::registry::SessionRegistry;
use crate::sessions::SessionEvent;
use lru::LruCache;
use slt_core::classifier::{QuicVerdict, classify_quic_datagram};
use slt_core::config::ServerConfig;
use slt_core::types::CidPrefix;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, trace, warn};

const QUIC_BUF_LEN: usize = 2 * 1024;

/// Claimed UDP-QSP datagram metadata.
#[derive(Debug, Clone)]
pub struct UdpClaim {
    /// Peer address.
    pub peer: SocketAddr,
    /// Destination connection ID prefix.
    pub dcid_prefix: CidPrefix,
    /// Raw datagram payload.
    pub payload: Vec<u8>,
}

#[derive(Debug)]
struct PeerEntry {
    socket: Arc<UdpSocket>,
    last_seen: Instant,
    task: tokio::task::JoinHandle<()>,
    token: u64,
}

struct QuicNatState {
    peers: LruCache<SocketAddr, PeerEntry>,
    done_rx: mpsc::UnboundedReceiver<(SocketAddr, u64)>,
    done_tx: mpsc::UnboundedSender<(SocketAddr, u64)>,
    next_token: u64,
}

/// QUIC endpoint wrapper.
pub struct QuicEndpoint {
    socket: Arc<UdpSocket>,
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
    pub async fn bind(
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

        if config.idle_timeout.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "idle_timeout must be non-zero",
            ));
        }
        let socket = UdpSocket::bind(config.listen_udp).await?;
        debug!(
            listen_addr = %config.listen_udp,
            upstream_addr = %config.nginx_udp_upstream,
            max_lru_entries = max_lru_entries.get(),
            idle_timeout_ms = config.idle_timeout.as_millis(),
            "QUIC endpoint bound"
        );
        Ok(Self {
            socket: Arc::new(socket),
            nginx_upstream: config.nginx_udp_upstream,
            max_lru_entries,
            idle_timeout: config.idle_timeout,
            registry,
            metrics,
        })
    }

    /// Returns the underlying UDP socket.
    #[must_use]
    pub const fn socket(&self) -> &Arc<UdpSocket> {
        &self.socket
    }

    /// Run the UDP accept loop and forward traffic to the nginx upstream.
    ///
    /// Each client gets a dedicated upstream socket to preserve 4-tuple state.
    /// The loop exits once `cancel` is canceled.
    ///
    /// # Errors
    ///
    /// Returns an error if receiving from the UDP socket fails.
    pub async fn run(&self, cancel: CancellationToken) -> io::Result<()> {
        debug!("Starting QUIC endpoint accept loop");
        let mut buf = vec![0u8; QUIC_BUF_LEN];
        let mut state = QuicNatState::new(self.max_lru_entries);
        let mut sweep = tokio::time::interval(self.idle_timeout);

        loop {
            let (len, peer) = tokio::select! {
                () = cancel.cancelled() => {
                    debug!("QUIC endpoint accept loop cancelled");
                    return Ok(());
                }
                Some((peer, token)) = state.done_rx.recv() => {
                    state.handle_reader_done(peer, token);
                    continue;
                }
                _ = sweep.tick() => {
                    state.sweep_idle(self.idle_timeout);
                    continue;
                }
                res = self.socket.recv_from(&mut buf) => res?,
            };
            trace!(peer = %peer, len = len, "Received UDP datagram");
            self.metrics.inc_udp_accepted();
            self.handle_datagram(&mut state, cancel.clone(), peer, &buf[..len])
                .await?;
        }
    }

    async fn handle_datagram(
        &self,
        state: &mut QuicNatState,
        cancel: CancellationToken,
        peer: SocketAddr,
        payload: &[u8],
    ) -> io::Result<()> {
        let verdict = classify_quic_datagram(payload);
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
                match upstream_socket.send(payload).await {
                    Ok(sent) => {
                        trace!(peer = %peer, sent = sent, "Sent datagram to upstream");
                    }
                    Err(e) => {
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
                        payload: payload.to_vec(),
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
                    match upstream_socket.send(payload).await {
                        Ok(sent) => {
                            trace!(peer = %peer, sent = sent, dcid_prefix = ?dcid_prefix, "Sent datagram to upstream");
                        }
                        Err(e) => {
                            warn!(peer = %peer, error = %e, dcid_prefix = ?dcid_prefix, "Failed to send datagram to upstream");
                        }
                    }
                }
            }
        }
        Ok(())
    }

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
    fn handle_reader_done(&mut self, peer: SocketAddr, token: u64) {
        if let Some(entry) = self.peers.pop(&peer)
            && entry.token != token
        {
            trace!(peer = %peer, expected_token = entry.token, received_token = token, "Reader token mismatch, restoring entry");
            self.peers.put(peer, entry);
        } else if self.peers.pop(&peer).is_some() {
            trace!(peer = %peer, token = token, "Removed completed reader from NAT state");
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
