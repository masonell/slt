//! Packet routing and spoofing checks.

use std::net::Ipv4Addr;

use super::sessions::{ClientSessionBase, UdpSocketIo};
use super::tun::TunDeviceIo;
use tokio::io::{AsyncRead, AsyncWrite};

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
        session.assigned_ipv4() == src_ip
    }

    /// Extract the source IPv4 address from an inner packet.
    #[must_use]
    pub fn extract_src_ipv4(packet: &[u8]) -> Option<Ipv4Addr> {
        if packet.len() < 20 {
            return None;
        }

        let version = packet[0] >> 4;
        if version != 4 {
            return None;
        }

        let ihl = (packet[0] & 0x0f) as usize * 4;
        if ihl < 20 || packet.len() < ihl {
            return None;
        }

        Some(Ipv4Addr::new(
            packet[12], packet[13], packet[14], packet[15],
        ))
    }

    /// Extract the destination IPv4 address from an inner packet.
    #[must_use]
    pub fn extract_dst_ipv4(packet: &[u8]) -> Option<Ipv4Addr> {
        if packet.len() < 20 {
            return None;
        }

        let version = packet[0] >> 4;
        if version != 4 {
            return None;
        }

        let ihl = (packet[0] & 0x0f) as usize * 4;
        if ihl < 20 || packet.len() < ihl {
            return None;
        }

        Some(Ipv4Addr::new(
            packet[16], packet[17], packet[18], packet[19],
        ))
    }

    /// Validate an IPv4 packet against the session's assigned address.
    #[must_use]
    pub fn validate_packet_src<S: SessionMeta>(session: &S, packet: &[u8]) -> bool {
        Self::extract_src_ipv4(packet).is_some_and(|src| Self::validate_src_ipv4(session, src))
    }
}
