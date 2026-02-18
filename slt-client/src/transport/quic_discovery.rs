use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use slt_core::config::ClientConfig;
use slt_core::crypto::quic_client_chrome_config_with_ca;
use slt_core::types::cid::CidError;
use slt_core::types::{Cid, QUIC_DCID_PREFIX_LEN};
use tokio::net::{UdpSocket, lookup_host};
use tokio::time;
use tokio_util::sync::CancellationToken;
use tracing::{debug, trace};

const QUIC_MAX_DATAGRAM: usize = 1350;
const QUIC_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

/// QUIC connection IDs needed for UDP-QSP registration.
#[derive(Debug, Clone)]
pub struct QuicIds {
    /// Destination connection ID for client->server packets.
    pub dcid: Cid,
    /// Destination connection ID for server->client packets.
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
pub async fn discover_quic_ids(
    config: &ClientConfig,
    cancel: &CancellationToken,
    peer_override: Option<SocketAddr>,
) -> io::Result<QuicIds> {
    if config.network.hostname.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "hostname is empty",
        ));
    }

    let peers = resolve_peers(config, peer_override).await?;
    let mut last_err = None;
    for peer in peers {
        match Box::pin(discover_quic_ids_for_peer(config, cancel, peer)).await {
            Ok(ids) => return Ok(ids),
            Err(err) => {
                debug!(peer = %peer, error = %err, "quic discovery failed for peer");
                last_err = Some(err);
            }
        }
    }

    Err(last_err
        .unwrap_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no quic peers available")))
}

async fn resolve_peers(
    config: &ClientConfig,
    peer_override: Option<SocketAddr>,
) -> io::Result<Vec<SocketAddr>> {
    if let Some(peer) = peer_override {
        return Ok(vec![peer]);
    }

    if let Some(ip) = config.network.ip {
        return Ok(vec![SocketAddr::new(ip, config.network.port)]);
    }

    let addrs: Vec<SocketAddr> =
        lookup_host((config.network.hostname.as_str(), config.network.port))
            .await?
            .collect();
    if addrs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "dns lookup returned no addresses",
        ));
    }
    Ok(addrs)
}

async fn discover_quic_ids_for_peer(
    config: &ClientConfig,
    cancel: &CancellationToken,
    peer: SocketAddr,
) -> io::Result<QuicIds> {
    let bind_addr = match peer {
        SocketAddr::V4(_) => "0.0.0.0:0",
        SocketAddr::V6(_) => "[::]:0",
    };
    let socket = Arc::new(UdpSocket::bind(bind_addr).await?);
    let local = socket.local_addr()?;

    let mut quic_config =
        quic_client_chrome_config_with_ca(config.tls.quic_ca.as_ref()).map_err(map_quic_error)?;
    quic_config.verify_peer(true);

    let scid_bytes = build_scid();
    let scid_conn = quiche::ConnectionId::from_ref(&scid_bytes);

    let mut conn = quiche::connect(
        Some(config.network.hostname.as_str()),
        &scid_conn,
        local,
        peer,
        &mut quic_config,
    )
    .map_err(map_quic_error)?;

    let mut recv_buf = vec![0u8; 65535];
    let mut out_buf = vec![0u8; QUIC_MAX_DATAGRAM];
    let deadline = Instant::now() + QUIC_HANDSHAKE_TIMEOUT;
    let mut discovered_ids: Option<QuicIds> = None;

    loop {
        while let Ok((write, send_info)) = conn.send(&mut out_buf) {
            socket.send_to(&out_buf[..write], send_info.to).await?;
        }

        if conn.is_established() && discovered_ids.is_none() {
            let dcid = Cid::new(conn.destination_id().as_ref()).map_err(map_cid_error)?;
            let scid = Cid::new(conn.source_id().as_ref()).map_err(map_cid_error)?;
            discovered_ids = Some(QuicIds {
                dcid,
                scid,
                peer,
                socket: socket.clone(),
            });
            let _ = conn.close(true, 0x00, b"");
        }

        if conn.is_closed() {
            return discovered_ids.ok_or_else(|| {
                io::Error::new(io::ErrorKind::ConnectionAborted, "quic connection closed")
            });
        }

        let now = Instant::now();
        if now >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "quic handshake timed out",
            ));
        }

        let timeout = conn.timeout().unwrap_or(Duration::from_millis(50));
        let sleep_until = deadline.min(now + timeout);

        tokio::select! {
            () = cancel.cancelled() => {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "quic discovery cancelled",
                ));
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

fn build_scid() -> [u8; QUIC_DCID_PREFIX_LEN] {
    let mut bytes = [0u8; QUIC_DCID_PREFIX_LEN];
    fill_random(&mut bytes);
    bytes
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

fn map_quic_error(err: quiche::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("quic error: {err:?}"))
}

fn map_cid_error(err: CidError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, err.to_string())
}
