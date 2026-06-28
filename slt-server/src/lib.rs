//! Server-side abstractions and entry points.

// Test code is exempt from clippy's code-quality groups (`style`, `complexity`,
// `perf`, `pedantic`, `nursery`); the bug-catching `correctness`/`suspicious`
// groups stay enforced under `#[cfg(test)]`.
#![cfg_attr(
    test,
    allow(
        clippy::style,
        clippy::complexity,
        clippy::perf,
        clippy::pedantic,
        clippy::nursery,
    )
)]

pub mod auth;
pub mod metrics;
pub mod quic;
pub mod registry;
pub mod router;
pub mod sessions;
pub mod tcp;
pub mod tun;
pub mod udp_qsp;

#[cfg(test)]
mod test_support;

use std::fmt;
use std::net::Ipv4Addr;

// Re-export common types from slt-core
pub use slt_core::types::ClientId;

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

impl fmt::Display for AssignedIp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
