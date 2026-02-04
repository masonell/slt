//! IPv4 packet parsing utilities.

use std::net::Ipv4Addr;
use tracing::trace;

/// Extract the source IPv4 address from an IPv4 packet.
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

/// Extract the destination IPv4 address from an IPv4 packet.
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
