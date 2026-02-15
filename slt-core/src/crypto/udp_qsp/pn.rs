//! Packet number helpers.

/// Maximum packet number length in bytes on the wire (per QUIC short header spec).
pub(super) const MAX_WIRE_PN_LEN: usize = 4;

/// Compute the minimum packet number length for `pn`.
#[inline]
pub(super) const fn packet_number_len(pn: u64) -> usize {
    if pn <= 0xff {
        1
    } else if pn <= 0xffff {
        2
    } else if pn <= 0xff_ffff {
        3
    } else {
        4
    }
}

/// Reconstruct a full packet number from a truncated value.
///
/// `expected_pn` should be the next packet number you expect to receive
/// (typically `largest_pn + 1`).
#[inline]
#[must_use]
pub const fn reconstruct_packet_number(truncated_pn: u64, expected_pn: u64, pn_len: usize) -> u64 {
    if pn_len == 0 || pn_len > MAX_WIRE_PN_LEN {
        return truncated_pn;
    }

    let pn_window = 1u64 << (pn_len * 8);
    let pn_half_window = pn_window / 2;
    let pn_mask = pn_window - 1;

    let mut candidate = (expected_pn & !pn_mask) | truncated_pn;
    if let Some(sum) = candidate.checked_add(pn_half_window)
        && sum <= expected_pn
        && let Some(advanced) = candidate.checked_add(pn_window)
    {
        candidate = advanced;
    }

    if let Some(expected_limit) = expected_pn.checked_add(pn_half_window)
        && candidate > expected_limit
        && candidate >= pn_window
    {
        candidate -= pn_window;
    }

    candidate
}

#[cfg(test)]
mod tests {
    use super::reconstruct_packet_number;

    #[test]
    fn reconstruct_packet_number_wraps_forward() {
        let expected = 0x00AB_CDEF;
        let truncated = 0x1234;
        let pn = reconstruct_packet_number(truncated, expected, 2);
        assert_eq!(pn, 0x00AC_1234);
    }

    #[test]
    fn reconstruct_packet_number_wraps_backward() {
        let expected = 0x0100_1000;
        let truncated = 0xFF00;
        let pn = reconstruct_packet_number(truncated, expected, 2);
        assert_eq!(pn, 0x00FF_FF00);
    }
}
