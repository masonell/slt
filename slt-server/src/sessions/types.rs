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

/// Active transport for a client session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActiveTransport {
    /// TLS-over-TCP transport.
    Tcp,
    /// UDP-QSP transport.
    UdpQsp,
}

/// Inbound events delivered to a `ClientSession`.
#[derive(Debug)]
pub enum SessionEvent {
    /// Claimed UDP-QSP datagram destined for this session.
    Udp(UdpClaim),
    /// IP packet read from TUN destined for the client.
    TunPacket(Vec<u8>),
    /// Request that the session shut down.
    Shutdown,
}

/// Sender for delivering events to a session.
pub type SessionTx = mpsc::Sender<SessionEvent>;
/// Receiver for session events.
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

/// Session-internal control flow indicator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionControl {
    Continue,
    Close,
}

/// Configurable timeouts for a client session.
#[derive(Debug, Clone, Copy)]
pub struct SessionTimeouts {
    /// Minimum interval between keepalive pings.
    pub ping_min: Duration,
    /// Maximum interval between keepalive pings.
    pub ping_max: Duration,
    /// Idle timeout for the session.
    pub idle_timeout: Duration,
}
