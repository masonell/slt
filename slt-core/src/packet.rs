//! IPv4 packet parsing utilities.

use std::net::Ipv4Addr;

use tracing::trace;

const IPV4_MIN_HEADER_LEN: usize = 20;
const IPV4_ADDR_LEN: usize = 4;
const IPV4_SRC_ADDR_OFFSET: usize = 12;
const IPV4_DST_ADDR_OFFSET: usize = 16;

/// Extract the source IPv4 address from an IPv4 packet.
#[must_use]
pub fn extract_src_ipv4(packet: &[u8]) -> Option<Ipv4Addr> {
    trace!(
        packet_len = packet.len(),
        "Extracting source IPv4 from packet"
    );

    let src_ip = extract_addr(packet, IPV4_SRC_ADDR_OFFSET)?;
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

    let dst_ip = extract_addr(packet, IPV4_DST_ADDR_OFFSET)?;
    trace!(dst_ip = %dst_ip, "Extracted destination IPv4 address");
    Some(dst_ip)
}

fn extract_addr(packet: &[u8], offset: usize) -> Option<Ipv4Addr> {
    if packet.len() < IPV4_MIN_HEADER_LEN {
        trace!("Packet too short to contain IPv4 header (< 20 bytes)");
        return None;
    }

    let version = packet[0] >> 4;
    if version != 4 {
        trace!(version, "Packet is not IPv4");
        return None;
    }

    let ihl = (packet[0] & 0x0f) as usize * 4;
    if ihl < IPV4_MIN_HEADER_LEN || packet.len() < ihl {
        trace!(
            ihl,
            packet_len = packet.len(),
            "Invalid IHL or packet shorter than IHL"
        );
        return None;
    }

    let octets: [u8; IPV4_ADDR_LEN] = packet
        .get(offset..offset + IPV4_ADDR_LEN)?
        .try_into()
        .ok()?;
    Some(Ipv4Addr::from(octets))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a minimal valid IPv4 header (20 bytes) with given src/dst addresses.
    fn minimal_ipv4_header(src: Ipv4Addr, dst: Ipv4Addr) -> [u8; 20] {
        let mut header = [0u8; 20];
        // Byte 0: version 4 (high nibble) | IHL 5 (low nibble, meaning 20 bytes)
        header[0] = 0x45;
        // Bytes 1-11: zeroed (ToS, Total Length, ID, Flags, Fragment Offset, TTL, Protocol, Checksum)
        // Bytes 12-15: source IP
        header[12..16].copy_from_slice(&src.octets());
        // Bytes 16-19: destination IP
        header[16..20].copy_from_slice(&dst.octets());
        header
    }

    #[test]
    fn extracts_source_address() {
        let src = Ipv4Addr::new(10, 0, 0, 1);
        let dst = Ipv4Addr::new(192, 168, 1, 1);
        let packet = minimal_ipv4_header(src, dst);

        assert_eq!(extract_src_ipv4(&packet), Some(src));
    }

    #[test]
    fn extracts_destination_address() {
        let src = Ipv4Addr::new(10, 0, 0, 1);
        let dst = Ipv4Addr::new(192, 168, 1, 1);
        let packet = minimal_ipv4_header(src, dst);

        assert_eq!(extract_dst_ipv4(&packet), Some(dst));
    }

    #[test]
    fn extracts_both_addresses() {
        let src = Ipv4Addr::new(172, 16, 0, 1);
        let dst = Ipv4Addr::new(8, 8, 8, 8);
        let packet = minimal_ipv4_header(src, dst);

        assert_eq!(extract_src_ipv4(&packet), Some(src));
        assert_eq!(extract_dst_ipv4(&packet), Some(dst));
    }

    #[test]
    fn rejects_truncated_packet_19_bytes() {
        let truncated = [0u8; 19];
        assert_eq!(extract_src_ipv4(&truncated), None);
        assert_eq!(extract_dst_ipv4(&truncated), None);
    }

    #[test]
    fn accepts_minimum_20_byte_packet() {
        let src = Ipv4Addr::new(1, 2, 3, 4);
        let dst = Ipv4Addr::new(5, 6, 7, 8);
        let packet = minimal_ipv4_header(src, dst);

        assert_eq!(extract_src_ipv4(&packet), Some(src));
        assert_eq!(extract_dst_ipv4(&packet), Some(dst));
    }

    #[test]
    fn rejects_invalid_version() {
        let mut packet = minimal_ipv4_header(Ipv4Addr::LOCALHOST, Ipv4Addr::LOCALHOST);
        // Set version to 6 (IPv6)
        packet[0] = 0x65; // version 6, IHL 5

        assert_eq!(extract_src_ipv4(&packet), None);
        assert_eq!(extract_dst_ipv4(&packet), None);
    }

    #[test]
    fn rejects_version_0() {
        let mut packet = minimal_ipv4_header(Ipv4Addr::LOCALHOST, Ipv4Addr::LOCALHOST);
        // Set version to 0
        packet[0] = 0x05; // version 0, IHL 5

        assert_eq!(extract_src_ipv4(&packet), None);
        assert_eq!(extract_dst_ipv4(&packet), None);
    }

    #[test]
    fn rejects_invalid_ihl_too_small() {
        let mut packet = minimal_ipv4_header(Ipv4Addr::LOCALHOST, Ipv4Addr::LOCALHOST);
        // IHL = 4 means 16 bytes header, which is invalid (minimum is 20)
        packet[0] = 0x44;

        assert_eq!(extract_src_ipv4(&packet), None);
        assert_eq!(extract_dst_ipv4(&packet), None);
    }

    #[test]
    fn rejects_ihl_exceeding_packet_length() {
        let mut packet = minimal_ipv4_header(Ipv4Addr::LOCALHOST, Ipv4Addr::LOCALHOST);
        // IHL = 6 means 24 bytes header, but packet is only 20 bytes
        packet[0] = 0x46;

        assert_eq!(extract_src_ipv4(&packet), None);
        assert_eq!(extract_dst_ipv4(&packet), None);
    }

    #[test]
    fn accepts_packet_with_ip_options() {
        // Build a packet with IHL=6 (24 byte header, includes 4 bytes of options)
        let src = Ipv4Addr::new(10, 0, 0, 1);
        let dst = Ipv4Addr::new(192, 168, 1, 1);
        let mut packet = [0u8; 24];
        packet[0] = 0x46; // version 4, IHL 6 (24 bytes)
        packet[12..16].copy_from_slice(&src.octets());
        packet[16..20].copy_from_slice(&dst.octets());
        // Bytes 20-23 are options (left as zero)

        assert_eq!(extract_src_ipv4(&packet), Some(src));
        assert_eq!(extract_dst_ipv4(&packet), Some(dst));
    }

    #[test]
    fn handles_all_zero_addresses() {
        let src = Ipv4Addr::UNSPECIFIED;
        let dst = Ipv4Addr::UNSPECIFIED;
        let packet = minimal_ipv4_header(src, dst);

        assert_eq!(extract_src_ipv4(&packet), Some(src));
        assert_eq!(extract_dst_ipv4(&packet), Some(dst));
    }

    #[test]
    fn handles_broadcast_address() {
        let src = Ipv4Addr::BROADCAST;
        let dst = Ipv4Addr::BROADCAST;
        let packet = minimal_ipv4_header(src, dst);

        assert_eq!(extract_src_ipv4(&packet), Some(src));
        assert_eq!(extract_dst_ipv4(&packet), Some(dst));
    }

    #[test]
    fn handles_multicast_range() {
        let src = Ipv4Addr::new(224, 0, 0, 1);
        let dst = Ipv4Addr::new(239, 255, 255, 255);
        let packet = minimal_ipv4_header(src, dst);

        assert_eq!(extract_src_ipv4(&packet), Some(src));
        assert_eq!(extract_dst_ipv4(&packet), Some(dst));
    }

    #[test]
    fn empty_packet() {
        let empty: &[u8] = &[];
        assert_eq!(extract_src_ipv4(empty), None);
        assert_eq!(extract_dst_ipv4(empty), None);
    }

    #[test]
    fn single_byte_packet() {
        let single = [0x45u8; 1];
        assert_eq!(extract_src_ipv4(&single), None);
        assert_eq!(extract_dst_ipv4(&single), None);
    }
}
