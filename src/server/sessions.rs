//! Client session tracking and lifecycle helpers.

use std::time::Instant;

use super::{AssignedIp, ClientId};

/// Active transport for a client session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActiveTransport {
    /// TLS-over-TCP transport.
    Tcp,
    /// UDP-QSP transport.
    UdpQsp,
}

/// A single authenticated client session.
#[derive(Debug, Clone)]
pub struct ClientSession {
    /// Client identifier.
    pub client_id: ClientId,
    /// Assigned VPN IPv4 address.
    pub assigned_ipv4: AssignedIp,
    /// Session creation timestamp.
    pub created_at: Instant,
    /// Last activity timestamp.
    pub last_activity: Instant,
    /// Active data transport.
    pub active_transport: ActiveTransport,
    /// Whether UDP-QSP is verified for this session.
    pub udp_verified: bool,
    /// Whether the TCP control channel is still open.
    pub tcp_open: bool,
}

/// Session store backing type (typically wrapped in `Arc<RwLock<...>>`).
pub type ClientSessionMap = std::collections::HashMap<ClientId, ClientSession>;

impl ClientSession {
    /// Create a new client session with TCP active.
    #[allow(clippy::missing_const_for_fn)]
    #[must_use]
    pub fn new(client_id: ClientId, assigned_ipv4: AssignedIp, now: Instant) -> Self {
        Self {
            client_id,
            assigned_ipv4,
            created_at: now,
            last_activity: now,
            active_transport: ActiveTransport::Tcp,
            udp_verified: false,
            tcp_open: true,
        }
    }
}
