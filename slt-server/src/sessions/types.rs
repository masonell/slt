//! Session type definitions and aliases.

use std::io;
use std::sync::Arc;
use std::time::Duration;

use boring::ssl::SslRef;
use slt_core::transport::tcp::{
    IntervalKeyUpdater, KeyUpdater, TcpChannel, default_interval_key_updater,
};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tracing::trace;

use crate::metrics::Metrics;
use crate::quic::UdpClaim;

/// Indicates which transport is preferred for a client session's outbound data.
///
/// The session can send data over either TLS-over-TCP or UDP-QSP at any given time.
/// The preferred transport determines which underlying network connection is
/// used for outgoing messages. Authenticated inbound DATA remains valid on
/// either live transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActiveTransport {
    /// TLS-over-TCP transport.
    Tcp,
    /// UDP-QSP transport.
    UdpQsp,
}

/// Events that can be delivered to a running client session.
///
/// These events are sent via the session's event channel and processed
/// by the session's event loop in `run_inner`.
#[derive(Debug)]
pub enum SessionEvent {
    /// Claimed UDP-QSP datagram destined for this session.
    Udp(UdpClaim),
    /// IP packet read from TUN destined for the client.
    TunPacket(Vec<u8>),
    /// Request that the session shut down.
    Shutdown,
}

/// Channel sender for delivering events to a session.
///
/// Used by other server components (TUN reader, UDP router, etc.) to send
/// events to the session's event loop.
pub type SessionTx = mpsc::Sender<SessionEvent>;

/// Channel receiver for session events.
///
/// Owned by the session's event loop and consumed during `run_inner`.
pub type SessionRx = mpsc::Receiver<SessionEvent>;

/// Metrics-aware TLS key updater used by server session channels.
#[derive(Debug, Clone)]
pub struct SessionKeyUpdater {
    inner: IntervalKeyUpdater,
    metrics: Arc<Metrics>,
}

impl SessionKeyUpdater {
    /// Create a metrics-aware key updater with default interval policy.
    #[must_use]
    pub const fn new(metrics: Arc<Metrics>) -> Self {
        Self {
            inner: default_interval_key_updater(),
            metrics,
        }
    }
}

impl KeyUpdater for SessionKeyUpdater {
    fn maybe_request_key_update(&mut self, ssl: &mut SslRef) -> io::Result<()> {
        let will_update = self.inner.messages_until_update() == 1;
        let request_peer_update = self.inner.requests_peer_update();
        if will_update {
            self.metrics.inc_tls_key_update_requested();
        }
        self.inner.maybe_request_key_update(ssl)?;
        if will_update {
            self.metrics.inc_tls_key_update_applied();
            trace!(
                request_peer_update,
                "server TCP TLS key update applied before outbound message"
            );
        }
        Ok(())
    }
}

/// Session TCP channel with interval-based TLS key updates.
pub type SessionTcpChannel<S = TcpStream> = TcpChannel<S, SessionKeyUpdater>;

/// Control flow return value for session message handlers.
///
/// Indicates whether the session should continue processing messages
/// or initiate a graceful shutdown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionControl {
    Continue,
    Close,
}

/// Timeout configuration for a client session.
///
/// Controls keepalive ping scheduling and session idle timeout.
///
/// # Fields
///
/// * `ping_min` - Minimum interval between keepalive pings
/// * `ping_max` - Maximum interval between keepalive pings (actual interval is randomized)
/// * `udp_liveness_timeout` - Maximum time without authenticated UDP-QSP ingress
/// * `idle_timeout` - Maximum idle time before the session is terminated
/// * `tcp_write_timeout` - Maximum time for one TCP message write
#[derive(Debug, Clone, Copy)]
pub struct SessionTimeouts {
    /// Minimum interval between keepalive pings.
    pub ping_min: Duration,
    /// Maximum interval between keepalive pings.
    pub ping_max: Duration,
    /// Time without authenticated UDP-QSP ingress before TCP fallback.
    pub udp_liveness_timeout: Duration,
    /// Idle timeout for the session.
    pub idle_timeout: Duration,
    /// Timeout for one TCP message write.
    pub tcp_write_timeout: Duration,
}
