use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket as StdUdpSocket};
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::time::{Duration, Instant};

use slt_core::config::ClientConfig;
use slt_core::crypto::quic_client_chrome_config_with_ca;
use slt_core::types::cid::CidError;
use slt_core::types::{Cid, MAX_DCID_LEN};
use tokio::net::UdpSocket;
use tokio::time;
use tokio_util::sync::CancellationToken;
use tracing::{debug, trace};

use crate::transport::host_resolver::HostResolver;
use crate::transport::socket_protector::{SocketKind, SocketProtector};

const QUIC_MAX_DATAGRAM: usize = 1350;
const QUIC_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

/// A failure from QUIC DCID discovery (the client's UDP-QSP registration
/// precursor).
///
/// The variant is the source of truth and preserves the original error via
/// `#[source]`/`#[from]`. This replaces the old `map_quic_error`/`map_cid_error`
/// flattening to `io::ErrorKind::InvalidData`, which destroyed the `quiche::Error`
/// code and `CidError` detail before they reached the caller.
///
/// The discovery path's public surface stays `io::Result` because its callers
/// (the session layer's discovery task) treat discovery as opaque pass/fail and
/// do not branch on the inner variant — but within the discovery module the
/// typed error carries the structured source, and [`Self::into_io`] re-encodes
/// it to `io::Error` exactly once at the module boundary rather than flattening
/// it piecemeal at every call site.
#[derive(Debug, thiserror::Error)]
pub enum QuicDiscoveryError {
    /// QUIC handshake / config failure from `quiche`, preserved via `#[from]`.
    #[error("quic error: {0}")]
    Quiche(#[from] quiche::Error),

    /// Connection-ID construction failure, preserved via `#[from]`.
    #[error("cid error: {0}")]
    Cid(#[from] CidError),

    /// Network-level I/O error from socket bind/protect/send/recv. Preserved.
    #[error(transparent)]
    Io(#[from] io::Error),

    /// QUIC handshake did not complete within the discovery timeout.
    #[error("quic handshake timed out")]
    Timeout,

    /// QUIC connection closed before the server DCID could be discovered.
    #[error("quic connection closed")]
    ConnectionClosed,

    /// Discovery was cancelled before completing.
    #[error("quic discovery cancelled")]
    Cancelled,

    /// No peers were available to attempt discovery against (e.g. empty
    /// resolution result with no per-peer error).
    #[error("no quic peers available")]
    NoPeers,

    /// Client configuration has an empty hostname.
    #[error("hostname is empty")]
    EmptyHostname,
}

impl QuicDiscoveryError {
    /// Re-encode the typed discovery error to `io::Error` at the module
    /// boundary.
    ///
    /// The discovery callers do not branch on the variant, so the typed error is
    /// collapsed to `io::Error` here — once, preserving the original via the
    /// `Display` message — rather than being flattened piecemeal at every call
    /// site by the deleted `map_quic_error`/`map_cid_error`. An `Io` source
    /// round-trips unchanged.
    #[must_use]
    pub fn into_io(self) -> io::Error {
        match self {
            Self::Io(err) => err,
            Self::Timeout => io::Error::new(io::ErrorKind::TimedOut, self),
            Self::ConnectionClosed => io::Error::new(io::ErrorKind::ConnectionAborted, self),
            Self::Cancelled => io::Error::new(io::ErrorKind::Interrupted, self),
            Self::NoPeers => io::Error::new(io::ErrorKind::NotFound, self),
            Self::EmptyHostname => io::Error::new(io::ErrorKind::InvalidInput, self),
            Self::Quiche(_) | Self::Cid(_) => io::Error::new(io::ErrorKind::InvalidData, self),
        }
    }
}

/// QUIC connection IDs needed for UDP-QSP registration.
#[derive(Debug, Clone)]
pub struct QuicIds {
    /// Destination connection ID for client->server packets (must be 20 bytes).
    pub dcid: Cid,
    /// Destination connection ID for server->client packets (can be 0..=20 bytes).
    pub scid: Cid,
    /// Peer address used for QUIC discovery.
    pub peer: SocketAddr,
    /// UDP socket used for QUIC discovery and UDP-QSP traffic.
    pub socket: Arc<UdpSocket>,
}

/// Perform a QUIC handshake to discover the server DCID.
///
/// Establishes a real QUIC connection to the server using Chrome-compatible settings
/// to obtain the server's destination connection ID (DCID) for UDP-QSP registration.
/// The discovered connection IDs and UDP socket are returned for subsequent UDP-QSP use.
///
/// # Errors
///
/// Returns an error if:
/// - Hostname configuration is empty
/// - DNS resolution fails or returns no addresses
/// - UDP socket bind fails
/// - QUIC handshake fails, times out (5s), or is cancelled
/// - Connection ID generation fails
pub async fn discover_quic_ids<SP, HR>(
    config: &ClientConfig,
    cancel: &CancellationToken,
    peer_override: Option<SocketAddr>,
    socket_protector: &SP,
    host_resolver: &HR,
) -> io::Result<QuicIds>
where
    SP: SocketProtector,
    HR: HostResolver,
{
    if config.network.hostname.is_empty() {
        return Err(QuicDiscoveryError::EmptyHostname.into_io());
    }

    let peers = resolve_peers(config, peer_override, host_resolver).await?;
    let mut last_err = None;
    for peer in peers {
        match Box::pin(discover_quic_ids_for_peer(
            config,
            cancel,
            peer,
            socket_protector,
        ))
        .await
        {
            Ok(ids) => return Ok(ids),
            Err(err) => {
                debug!(peer = %peer, error = %err, "quic discovery failed for peer");
                last_err = Some(err);
            }
        }
    }

    Err(last_err.unwrap_or(QuicDiscoveryError::NoPeers).into_io())
}

async fn resolve_peers<HR>(
    config: &ClientConfig,
    peer_override: Option<SocketAddr>,
    host_resolver: &HR,
) -> io::Result<Vec<SocketAddr>>
where
    HR: HostResolver,
{
    if let Some(peer) = peer_override {
        return Ok(vec![peer]);
    }

    if let Some(ip) = config.network.ip {
        return Ok(vec![SocketAddr::new(ip, config.network.port)]);
    }

    host_resolver
        .resolve(config.network.hostname.as_str(), config.network.port)
        .await
}

async fn discover_quic_ids_for_peer<SP>(
    config: &ClientConfig,
    cancel: &CancellationToken,
    peer: SocketAddr,
    socket_protector: &SP,
) -> Result<QuicIds, QuicDiscoveryError>
where
    SP: SocketProtector,
{
    let socket = Arc::new(bind_protected_udp_socket(peer, socket_protector)?);
    let local = socket.local_addr()?;

    let mut quic_config = quic_client_chrome_config_with_ca(config.tls.quic_ca.as_ref())?;
    quic_config.verify_peer(true);

    // Use empty SCID (Chrome behavior)
    let scid_conn = quiche::ConnectionId::from_ref(&[]);

    let mut conn = quiche::connect(
        Some(config.network.hostname.as_str()),
        &scid_conn,
        local,
        peer,
        &mut quic_config,
    )?;

    let mut recv_buf = vec![0u8; 65535];
    let mut out_buf = vec![0u8; QUIC_MAX_DATAGRAM];
    let deadline = Instant::now() + QUIC_HANDSHAKE_TIMEOUT;
    let mut discovered_ids: Option<QuicIds> = None;

    loop {
        while let Ok((write, send_info)) = conn.send(&mut out_buf) {
            socket.send_to(&out_buf[..write], send_info.to).await?;
        }

        if conn.is_established() && discovered_ids.is_none() {
            // Pad DCID to MAX_DCID_LEN if shorter (nginx should use 20 bytes already)
            let dcid_bytes = conn.destination_id().to_vec();
            let dcid = if dcid_bytes.len() < MAX_DCID_LEN {
                let mut padded = [0u8; MAX_DCID_LEN];
                padded[..dcid_bytes.len()].copy_from_slice(&dcid_bytes);
                fill_random(&mut padded[dcid_bytes.len()..]);
                Cid::new(&padded)?
            } else {
                Cid::new(&dcid_bytes)?
            };
            let scid = Cid::new(conn.source_id().as_ref())?;
            discovered_ids = Some(QuicIds {
                dcid,
                scid,
                peer,
                socket: socket.clone(),
            });
            let _ = conn.close(true, 0x00, b"");
        }

        if conn.is_closed() {
            return discovered_ids.ok_or(QuicDiscoveryError::ConnectionClosed);
        }

        let now = Instant::now();
        if now >= deadline {
            return Err(QuicDiscoveryError::Timeout);
        }

        let timeout = conn.timeout().unwrap_or(Duration::from_millis(50));
        let sleep_until = deadline.min(now + timeout);

        tokio::select! {
            () = cancel.cancelled() => {
                return Err(QuicDiscoveryError::Cancelled);
            }
            res = socket.recv_from(&mut recv_buf) => {
                let (len, from) = res?;
                if from != peer {
                    trace!(expected = %peer, received = %from, "ignoring quic datagram from unexpected peer");
                    continue;
                }
                let recv_info = quiche::RecvInfo { to: local, from };
                match conn.recv(&mut recv_buf[..len], recv_info) {
                    Ok(_) | Err(quiche::Error::Done) => {}
                    Err(err) => {
                        debug!(error = ?err, "quic recv failed");
                    }
                }
            }
            () = time::sleep_until(sleep_until.into()) => {
                conn.on_timeout();
            }
        }
    }
}

/// Bind a UDP socket for `peer`, apply platform socket protection, and make it nonblocking.
///
/// The socket is protected before conversion to Tokio so Android can both
/// exclude it from the VPN route and bind it to the active underlying network
/// before any packet is sent.
///
/// # Errors
///
/// Returns an error if binding, platform socket protection, nonblocking setup,
/// or Tokio conversion fails.
pub fn bind_protected_udp_socket<SP>(
    peer: SocketAddr,
    socket_protector: &SP,
) -> io::Result<UdpSocket>
where
    SP: SocketProtector,
{
    let bind_addr = match peer {
        SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    };
    let socket = StdUdpSocket::bind(bind_addr)?;
    socket_protector.protect(socket.as_raw_fd(), SocketKind::Udp)?;
    socket.set_nonblocking(true)?;
    UdpSocket::from_std(socket)
}

fn fill_random(buf: &mut [u8]) {
    let mut offset = 0;
    while offset < buf.len() {
        let chunk = fastrand::u64(..).to_be_bytes();
        let take = (buf.len() - offset).min(chunk.len());
        buf[offset..offset + take].copy_from_slice(&chunk[..take]);
        offset += take;
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    #[derive(Default)]
    struct RecordingProtector {
        calls: Mutex<Vec<(i32, SocketKind)>>,
        fail: bool,
    }

    impl SocketProtector for RecordingProtector {
        fn protect(&self, fd: i32, kind: SocketKind) -> io::Result<()> {
            self.calls.lock().unwrap().push((fd, kind));
            if self.fail {
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "test protection failure",
                ))
            } else {
                Ok(())
            }
        }
    }

    #[tokio::test]
    async fn bind_protected_udp_socket_protects_socket_before_use() {
        let peer: SocketAddr = "127.0.0.1:443".parse().unwrap();
        let protector = RecordingProtector::default();

        let socket = bind_protected_udp_socket(peer, &protector).unwrap();
        assert!(socket.local_addr().unwrap().is_ipv4());

        let calls = protector.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].1, SocketKind::Udp);
        assert!(calls[0].0 >= 0);
    }

    #[tokio::test]
    async fn bind_protected_udp_socket_returns_permission_denied_when_protection_fails() {
        let peer: SocketAddr = "127.0.0.1:443".parse().unwrap();
        let protector = RecordingProtector {
            fail: true,
            ..RecordingProtector::default()
        };

        let err = bind_protected_udp_socket(peer, &protector).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);

        let calls = protector.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].1, SocketKind::Udp);
    }
}
