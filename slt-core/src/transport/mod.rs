/// TCP framed channel over an established TLS stream.
pub mod tcp;
/// Shared helpers for TUN device configuration and batching.
pub mod tun;
/// Unix UDP-QSP socket backend with GRO/GSO support.
#[cfg(all(unix, feature = "udp-io"))]
pub mod udp_qsp_io;

#[cfg(all(unix, feature = "udp-io"))]
pub use udp_qsp_io::UdpQspIo;

/// Byte ranges of individual datagrams within a GRO-coalesced receive buffer.
///
/// Splits `[0, len)` into ranges of at most `stride` bytes. `stride` is clamped
/// to at least 1, so malformed metadata with `stride == 0` cannot panic in
/// `step_by`.
pub fn gro_datagram_ranges(len: usize, stride: usize) -> impl Iterator<Item = (usize, usize)> {
    let stride = stride.max(1);
    (0..len)
        .step_by(stride)
        .map(move |off| (off, (off + stride).min(len)))
}

#[cfg(test)]
mod tests {
    use super::gro_datagram_ranges;

    /// The GRO stride-split math must produce one range per coalesced datagram,
    /// with the last range clipped to `len`, and never panic/infinite-loop on a
    /// malformed `stride == 0`.
    #[test]
    fn gro_datagram_ranges_splits_coalesced_buffer() {
        let eq: Vec<_> = gro_datagram_ranges(4096, 1024).collect();
        assert_eq!(
            eq,
            vec![(0, 1024), (1024, 2048), (2048, 3072), (3072, 4096)]
        );

        let partial: Vec<_> = gro_datagram_ranges(2500, 1024).collect();
        assert_eq!(partial, vec![(0, 1024), (1024, 2048), (2048, 2500)]);

        let single: Vec<_> = gro_datagram_ranges(1406, 1406).collect();
        assert_eq!(single, vec![(0, 1406)]);

        let zero: Vec<_> = gro_datagram_ranges(3, 0).collect();
        assert_eq!(zero, vec![(0, 1), (1, 2), (2, 3)]);

        assert!(gro_datagram_ranges(0, 1406).next().is_none());
    }
}
