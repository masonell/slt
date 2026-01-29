//! Server-side abstractions and entry points.

pub mod auth;
pub mod metrics;
pub mod quic;
pub mod router;
pub mod sessions;
pub mod tcp;
pub mod tls;
pub mod tun;
pub mod udp_qsp;

use std::net::Ipv4Addr;

// Re-export common types
pub use crate::types::ClientId;

/// Assigned VPN IPv4 address wrapper.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AssignedIp(pub Ipv4Addr);

impl AssignedIp {
    /// Returns the inner IPv4 address.
    #[must_use]
    pub const fn addr(&self) -> Ipv4Addr {
        self.0
    }
}
