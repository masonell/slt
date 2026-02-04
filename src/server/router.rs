//! Packet routing and spoofing checks.

use std::net::Ipv4Addr;

use super::sessions::{ClientSessionBase, UdpSocketIo};
use super::tun::TunDeviceIo;
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::{debug, trace, warn};

/// Routes packets between TUN and sessions.
#[derive(Debug, Default)]
pub struct PacketRouter;

/// Minimal session metadata needed for packet validation.
pub trait SessionMeta {
    /// Returns the assigned IPv4 address for the session.
    fn assigned_ipv4(&self) -> Ipv4Addr;
}

impl<T, S, U> SessionMeta for ClientSessionBase<T, S, U>
where
    T: TunDeviceIo,
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    U: UdpSocketIo,
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

    /// Extract the source IPv4 address from an inner packet.
    #[must_use]
    pub fn extract_src_ipv4(packet: &[u8]) -> Option<Ipv4Addr> {
        trace!(
            packet_len = packet.len(),
            "Extracting source IPv4 from packet"
        );

        if packet.len() < 20 {
            trace!("Packet too short to contain IPv4 header (< 20 bytes)");
            return None;
        }

        let version = packet[0] >> 4;
        if version != 4 {
            trace!(version, "Packet is not IPv4");
            return None;
        }

        let ihl = (packet[0] & 0x0f) as usize * 4;
        if ihl < 20 || packet.len() < ihl {
            trace!(
                ihl,
                packet_len = packet.len(),
                "Invalid IHL or packet shorter than IHL"
            );
            return None;
        }

        let src_ip = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
        trace!(src_ip = %src_ip, "Extracted source IPv4 address");
        Some(src_ip)
    }

    /// Extract the destination IPv4 address from an inner packet.
    #[must_use]
    pub fn extract_dst_ipv4(packet: &[u8]) -> Option<Ipv4Addr> {
        trace!(
            packet_len = packet.len(),
            "Extracting destination IPv4 from packet"
        );

        if packet.len() < 20 {
            trace!("Packet too short to contain IPv4 header (< 20 bytes)");
            return None;
        }

        let version = packet[0] >> 4;
        if version != 4 {
            trace!(version, "Packet is not IPv4");
            return None;
        }

        let ihl = (packet[0] & 0x0f) as usize * 4;
        if ihl < 20 || packet.len() < ihl {
            trace!(
                ihl,
                packet_len = packet.len(),
                "Invalid IHL or packet shorter than IHL"
            );
            return None;
        }

        let dst_ip = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
        trace!(dst_ip = %dst_ip, "Extracted destination IPv4 address");
        Some(dst_ip)
    }

    /// Validate an IPv4 packet against the session's assigned address.
    #[must_use]
    pub fn validate_packet_src<S: SessionMeta>(session: &S, packet: &[u8]) -> bool {
        let assigned = session.assigned_ipv4();
        debug!(assigned_ip = %assigned, packet_len = packet.len(), "Validating packet source");

        Self::extract_src_ipv4(packet).map_or_else(
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
