//! Packet routing and spoofing checks.

use std::net::Ipv4Addr;

use tokio::io::{AsyncRead, AsyncWrite};
use tracing::{debug, trace, warn};

use crate::sessions::{ClientSessionBase, UdpSessionIo};
use crate::tun::TunDeviceIo;

/// Routes packets between TUN and sessions.
///
/// Provides packet validation to prevent IP spoofing by enforcing that
/// packets from a session must have the session's assigned IPv4 address
/// as their source.
#[derive(Debug, Default)]
pub struct PacketRouter;

/// Minimal session metadata needed for packet validation.
///
/// Abstraction over session types to access the assigned IPv4 address
/// for source validation without requiring the full session type.
pub trait SessionMeta {
    /// Returns the assigned IPv4 address for the session.
    fn assigned_ipv4(&self) -> Ipv4Addr;
}

impl<T, S, I> SessionMeta for ClientSessionBase<T, S, I>
where
    T: TunDeviceIo,
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    I: UdpSessionIo,
{
    fn assigned_ipv4(&self) -> Ipv4Addr {
        self.assigned_ipv4.addr()
    }
}

impl PacketRouter {
    /// Create a new packet router.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Enforce `src_ip == assigned_ipv4` for a session.
    #[must_use]
    pub fn validate_src_ipv4<S: SessionMeta>(session: &S, src_ip: Ipv4Addr) -> bool {
        let assigned = session.assigned_ipv4();
        let is_valid = assigned == src_ip;

        if is_valid {
            trace!(src_ip = %src_ip, assigned_ip = %assigned, "Source IP validation passed");
        } else {
            warn!(
                src_ip = %src_ip,
                assigned_ip = %assigned,
                "Dropping packet due to source IP mismatch: spoofing detected"
            );
        }

        is_valid
    }

    /// Validate an IPv4 packet against the session's assigned address.
    #[must_use]
    pub fn validate_packet_src<S: SessionMeta>(session: &S, packet: &[u8]) -> bool {
        let assigned = session.assigned_ipv4();
        debug!(assigned_ip = %assigned, packet_len = packet.len(), "Validating packet source");

        slt_core::packet::extract_src_ipv4(packet).map_or_else(
            || {
                trace!("Failed to extract source IP from packet");
                false
            },
            |src_ip| {
                let is_valid = Self::validate_src_ipv4(session, src_ip);
                if !is_valid {
                    warn!(
                        src_ip = %src_ip,
                        assigned_ip = %assigned,
                        "Packet validation failed: source IP does not match assigned address"
                    );
                }
                is_valid
            },
        )
    }
}
