//! QUIC front-door handling.

use std::io;
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::udp_qsp::CidMap;
use crate::classifier::{QuicVerdict, classify_quic_datagram};
use crate::config::ServerConfig;
use lru::LruCache;
use tokio::net::UdpSocket;
use tokio::sync::RwLock;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

const QUIC_BUF_LEN: usize = 2 * 1024;

/// Claimed UDP-QSP datagram metadata.
#[derive(Debug, Clone)]
pub struct UdpClaim {
    /// Peer address.
    pub peer: SocketAddr,
    /// Destination connection ID.
    pub dcid: Vec<u8>,
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
    cid_map: Arc<RwLock<CidMap>>,
}

impl QuicEndpoint {
    /// Bind a UDP socket.
    pub async fn bind(config: &ServerConfig) -> io::Result<Self> {
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
        Ok(Self {
            socket: Arc::new(socket),
            nginx_upstream: config.nginx_udp_upstream,
            max_lru_entries,
            idle_timeout: config.idle_timeout,
            cid_map: Arc::new(RwLock::new(CidMap::new())),
        })
    }

    /// Returns the underlying UDP socket.
    #[must_use]
    pub fn socket(&self) -> &Arc<UdpSocket> {
        &self.socket
    }

    /// Returns the CID map shared with the UDP-QSP handler.
    #[must_use]
    pub fn cid_map(&self) -> Arc<RwLock<CidMap>> {
        self.cid_map.clone()
    }

    /// Run the UDP accept loop and forward traffic to the nginx upstream.
    ///
    /// Each client gets a dedicated upstream socket to preserve 4-tuple state.
    /// The loop exits once `cancel` is canceled.
    pub async fn run(
        &self,
        cancel: CancellationToken,
        claim_handler: impl Fn(UdpClaim) + Send + Sync + 'static,
    ) -> io::Result<()> {
        let mut buf = vec![0u8; QUIC_BUF_LEN];
        let mut state = QuicNatState::new(self.max_lru_entries);
        let mut sweep = tokio::time::interval(self.idle_timeout);
        let claim_handler: Arc<dyn Fn(UdpClaim) + Send + Sync + 'static> = Arc::new(claim_handler);

        loop {
            let (len, peer) = tokio::select! {
                _ = cancel.cancelled() => return Ok(()),
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
            self.handle_datagram(
                &mut state,
                cancel.clone(),
                peer,
                &buf[..len],
                &claim_handler,
            )
            .await?;
        }
    }

    async fn handle_datagram(
        &self,
        state: &mut QuicNatState,
        cancel: CancellationToken,
        peer: SocketAddr,
        payload: &[u8],
        claim_handler: &Arc<dyn Fn(UdpClaim) + Send + Sync + 'static>,
    ) -> io::Result<()> {
        match classify_quic_datagram(payload) {
            QuicVerdict::Drop => return Ok(()),
            QuicVerdict::Pass => {
                let upstream_socket = state
                    .get_or_create_upstream(self.socket.clone(), self.nginx_upstream, peer, cancel)
                    .await?;
                let _ = upstream_socket.send(payload).await;
            }
            QuicVerdict::Short { dcid } => {
                let claimed = {
                    let map = self.cid_map.read().await;
                    map.get(dcid).is_some()
                };
                if claimed {
                    (claim_handler)(UdpClaim {
                        peer,
                        dcid: dcid.to_vec(),
                        payload: payload.to_vec(),
                    });
                } else {
                    let upstream_socket = state
                        .get_or_create_upstream(
                            self.socket.clone(),
                            self.nginx_upstream,
                            peer,
                            cancel,
                        )
                        .await?;
                    let _ = upstream_socket.send(payload).await;
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
            let mut buf = vec![0u8; QUIC_BUF_LEN];
            loop {
                let len = tokio::select! {
                    _ = cancel.cancelled() => break,
                    res = upstream.recv(&mut buf) => match res {
                        Ok(len) => len,
                        Err(_) => break,
                    },
                };

                if len == 0 {
                    continue;
                }

                let _ = downstream.send_to(&buf[..len], peer).await;
            }

            let _ = done_tx.send((peer, token));
        })
    }
}

impl QuicNatState {
    fn new(lru_size: NonZeroUsize) -> Self {
        let (done_tx, done_rx) = mpsc::unbounded_channel();
        QuicNatState {
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
            self.peers.put(peer, entry);
        }
    }

    fn sweep_idle(&mut self, idle_timeout: Duration) {
        let now = Instant::now();
        let mut stale = Vec::new();
        for (peer, entry) in self.peers.iter() {
            if now.duration_since(entry.last_seen) >= idle_timeout {
                stale.push(*peer);
            }
        }
        for peer in stale {
            if let Some(entry) = self.peers.pop(&peer) {
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
            return Ok(entry.socket.clone());
        }

        let bind_addr = match upstream_addr {
            SocketAddr::V4(_) => SocketAddr::from(([0u8; 4], 0)),
            SocketAddr::V6(_) => SocketAddr::from(([0u16; 8], 0)),
        };
        let socket = UdpSocket::bind(bind_addr).await?;
        socket.connect(upstream_addr).await?;
        let socket = Arc::new(socket);

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
            evicted.task.abort();
        }

        Ok(socket)
    }
}
