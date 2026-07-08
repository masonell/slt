//! Packet header helpers and decoded packet metadata.

use super::pn::{MAX_WIRE_PN_LEN, packet_number_len};
use super::{AEAD_TAG_LEN, HP_MASK_LEN, HP_SAMPLE_LEN, QspCryptoError};

const FIXED_BIT: u8 = 0x40;
const KEY_PHASE_BIT: u8 = 0x04;
const RESERVED_MASK: u8 = 0x18;
const PN_LEN_MASK: u8 = 0x03;

/// Decrypted UDP-QSP packet metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenedPacket {
    /// Reconstructed packet number.
    pub pn: u64,
    /// Length of the truncated packet number in bytes.
    pub pn_len: usize,
    /// Key phase bit.
    pub key_phase: bool,
    /// Decrypted UDP-QSP plaintext.
    ///
    /// VPN message packets can include trailing zero padding added for
    /// header-protection sampling. Decode with
    /// [`crate::proto::decode_padded_message`] when exact frame bytes are
    /// required.
    pub payload: Vec<u8>,
}

/// Borrowed UDP-QSP packet metadata with payload slice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpenedPacketRef<'a> {
    /// Reconstructed packet number.
    pub pn: u64,
    /// Length of the truncated packet number in bytes.
    pub pn_len: usize,
    /// Key phase bit.
    pub key_phase: bool,
    /// Decrypted UDP-QSP plaintext.
    ///
    /// VPN message packets can include trailing zero padding added for
    /// header-protection sampling. Decode with
    /// [`crate::proto::decode_padded_message`] when exact frame bytes are
    /// required.
    pub payload: &'a [u8],
}

pub(super) struct BuiltHeader {
    pub pn_len: usize,
    pub pn_offset: usize,
}

pub(super) struct ParsedHeader {
    pub pn: u64,
    pub pn_len: usize,
    pub key_phase: bool,
    pub header: Vec<u8>,
}

pub(super) fn build_header(
    dcid: &[u8],
    pn: u64,
    key_phase: bool,
    out: &mut Vec<u8>,
) -> Result<BuiltHeader, QspCryptoError> {
    let pn_len = packet_number_len(pn);
    if pn_len == 0 || pn_len > MAX_WIRE_PN_LEN {
        return Err(QspCryptoError::InvalidPacketNumber);
    }

    let pn_offset = 1 + dcid.len();
    out.reserve(pn_offset + pn_len);

    let pn_len_u8 = u8::try_from(pn_len).map_err(|_| QspCryptoError::InvalidPacketNumber)?;
    let mut first = FIXED_BIT | ((pn_len_u8 - 1) & PN_LEN_MASK);
    if key_phase {
        first |= KEY_PHASE_BIT;
    }

    out.push(first);
    out.extend_from_slice(dcid);
    out.extend_from_slice(&pn.to_be_bytes()[8 - pn_len..]);

    Ok(BuiltHeader { pn_len, pn_offset })
}

pub(super) fn parse_header(
    dcid_len: usize,
    packet: &[u8],
    mask: [u8; HP_MASK_LEN],
) -> Result<ParsedHeader, QspCryptoError> {
    let pn_offset = 1 + dcid_len;

    let first = packet[0] ^ (mask[0] & 0x1f);
    if first & FIXED_BIT == 0 || first & 0x80 != 0 {
        return Err(QspCryptoError::InvalidHeader);
    }
    if (first & RESERVED_MASK) != 0 {
        return Err(QspCryptoError::InvalidHeader);
    }

    let pn_len = ((first & PN_LEN_MASK) + 1) as usize;
    if pn_len == 0 || pn_len > MAX_WIRE_PN_LEN {
        return Err(QspCryptoError::InvalidPacketNumber);
    }
    if packet.len() < pn_offset + pn_len + AEAD_TAG_LEN {
        return Err(QspCryptoError::PacketTooShort);
    }

    let mut pn_bytes = [0u8; MAX_WIRE_PN_LEN];
    for i in 0..pn_len {
        pn_bytes[MAX_WIRE_PN_LEN - pn_len + i] = packet[pn_offset + i] ^ mask[1 + i];
    }
    let pn = u64::from(u32::from_be_bytes(pn_bytes));

    let key_phase = (first & KEY_PHASE_BIT) != 0;
    let mut header = Vec::with_capacity(pn_offset + pn_len);
    header.push(first);
    header.extend_from_slice(&packet[1..pn_offset]);
    header.extend_from_slice(&pn_bytes[MAX_WIRE_PN_LEN - pn_len..]);

    Ok(ParsedHeader {
        pn,
        pn_len,
        key_phase,
        header,
    })
}

pub(super) fn apply_header_protection(
    packet: &mut [u8],
    pn_offset: usize,
    pn_len: usize,
    mask: [u8; HP_MASK_LEN],
) -> Result<(), QspCryptoError> {
    if pn_len == 0 || pn_len > MAX_WIRE_PN_LEN {
        return Err(QspCryptoError::InvalidPacketNumber);
    }
    if packet.len() < pn_offset + pn_len {
        return Err(QspCryptoError::PacketTooShort);
    }

    packet[0] ^= mask[0] & 0x1f;
    for i in 0..pn_len {
        packet[pn_offset + i] ^= mask[1 + i];
    }

    Ok(())
}

pub(super) const fn sample_offset(dcid_len: usize) -> usize {
    1 + dcid_len + 4
}

pub(super) const fn require_hp_sample(
    packet: &[u8],
    dcid_len: usize,
) -> Result<(), QspCryptoError> {
    let offset = sample_offset(dcid_len);
    if packet.len() < offset + HP_SAMPLE_LEN {
        return Err(QspCryptoError::PacketTooShort);
    }
    Ok(())
}

pub(super) const fn hp_sample_range(dcid_len: usize) -> std::ops::Range<usize> {
    let offset = sample_offset(dcid_len);
    offset..(offset + HP_SAMPLE_LEN)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DCID: &[u8] = &[0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x9A];

    fn zero_mask() -> [u8; HP_MASK_LEN] {
        [0u8; HP_MASK_LEN]
    }

    #[test]
    fn build_header_small_packet_number() {
        let mut out = Vec::new();
        let built = build_header(DCID, 0x12, false, &mut out).unwrap();

        assert_eq!(built.pn_len, 1);
        assert_eq!(built.pn_offset, 1 + DCID.len());
        assert_eq!(out.len(), 1 + DCID.len() + 1);
        // First byte: FIXED_BIT (0x40) | (pn_len - 1) = 0x40 | 0 = 0x40
        assert_eq!(out[0], 0x40);
        // DCID follows
        assert_eq!(&out[1..9], DCID);
        // PN is last byte
        assert_eq!(out[9], 0x12);
    }

    #[test]
    fn build_header_two_byte_packet_number() {
        let mut out = Vec::new();
        let built = build_header(DCID, 0x1234, false, &mut out).unwrap();

        assert_eq!(built.pn_len, 2);
        assert_eq!(out.len(), 1 + DCID.len() + 2);
        // First byte: FIXED_BIT (0x40) | (pn_len - 1) = 0x40 | 1 = 0x41
        assert_eq!(out[0], 0x41);
        // PN bytes
        assert_eq!(&out[9..11], &[0x12, 0x34]);
    }

    #[test]
    fn build_header_three_byte_packet_number() {
        let mut out = Vec::new();
        let built = build_header(DCID, 0x12_3456, false, &mut out).unwrap();

        assert_eq!(built.pn_len, 3);
        // First byte: 0x40 | 2 = 0x42
        assert_eq!(out[0], 0x42);
        // PN bytes
        assert_eq!(&out[9..12], &[0x12, 0x34, 0x56]);
    }

    #[test]
    fn build_header_four_byte_packet_number() {
        let mut out = Vec::new();
        let built = build_header(DCID, 0x1234_5678, false, &mut out).unwrap();

        assert_eq!(built.pn_len, 4);
        // First byte: 0x40 | 3 = 0x43
        assert_eq!(out[0], 0x43);
        // PN bytes
        assert_eq!(&out[9..13], &[0x12, 0x34, 0x56, 0x78]);
    }

    #[test]
    fn build_header_key_phase_set() {
        let mut out = Vec::new();
        let _ = build_header(DCID, 1, true, &mut out).unwrap();

        // First byte: FIXED_BIT | KEY_PHASE_BIT | 0 = 0x40 | 0x04 = 0x44
        assert_eq!(out[0], 0x44);
    }

    #[test]
    fn build_header_key_phase_clear() {
        let mut out = Vec::new();
        let _ = build_header(DCID, 1, false, &mut out).unwrap();

        // First byte: FIXED_BIT | 0 = 0x40
        assert_eq!(out[0], 0x40);
    }

    #[test]
    fn parse_header_extracts_packet_number() {
        let mut header = Vec::new();
        let _ = build_header(DCID, 0x1234, false, &mut header).unwrap();
        // parse_header requires at least header + AEAD_TAG_LEN bytes
        header.extend_from_slice(&[0u8; AEAD_TAG_LEN]);

        let parsed = parse_header(DCID.len(), &header, zero_mask()).unwrap();
        assert_eq!(parsed.pn, 0x1234);
        assert_eq!(parsed.pn_len, 2);
        assert!(!parsed.key_phase);
    }

    #[test]
    fn parse_header_extracts_key_phase() {
        let mut header = Vec::new();
        let _ = build_header(DCID, 1, true, &mut header).unwrap();
        header.extend_from_slice(&[0u8; AEAD_TAG_LEN]);

        let parsed = parse_header(DCID.len(), &header, zero_mask()).unwrap();
        assert!(parsed.key_phase);
    }

    #[test]
    fn parse_header_reconstructs_header_bytes() {
        let mut header = Vec::new();
        let _ = build_header(DCID, 0xABCD, false, &mut header).unwrap();
        let original_header = header.clone();
        header.extend_from_slice(&[0u8; AEAD_TAG_LEN]);

        let parsed = parse_header(DCID.len(), &header, zero_mask()).unwrap();
        // The reconstructed header should match the original unprotected header
        assert_eq!(parsed.header, original_header);
    }

    #[test]
    fn apply_header_protection_xors_first_byte() {
        let mut packet = vec![0x40, 0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x9A, 0x01];
        let mask: [u8; HP_MASK_LEN] = [0x1F, 0x00, 0x00, 0x00, 0x00];

        apply_header_protection(&mut packet, 9, 1, mask).unwrap();

        // First byte should be XORed with mask[0] & 0x1f
        assert_eq!(packet[0], 0x40 ^ 0x1F);
    }

    #[test]
    fn apply_header_protection_xors_packet_number() {
        let mut packet = vec![
            0x40, 0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x9A, 0x12, 0x34,
        ];
        let mask: [u8; HP_MASK_LEN] = [0x00, 0xFF, 0xFF, 0x00, 0x00];

        apply_header_protection(&mut packet, 9, 2, mask).unwrap();

        // PN bytes should be XORed with mask[1..3]
        assert_eq!(packet[9], 0x12 ^ 0xFF);
        assert_eq!(packet[10], 0x34 ^ 0xFF);
    }

    #[test]
    fn header_protection_roundtrip() {
        let mut packet = Vec::new();
        let built = build_header(DCID, 0x5678, false, &mut packet).unwrap();

        // Add some payload and tag for realism
        packet.extend_from_slice(&[0xAA; 16]); // payload
        packet.extend_from_slice(&[0xBB; 16]); // AEAD tag

        let original = packet.clone();
        let mask: [u8; HP_MASK_LEN] = [0x1F, 0xAA, 0xBB, 0xCC, 0xDD];

        // Apply protection
        apply_header_protection(&mut packet, built.pn_offset, built.pn_len, mask).unwrap();

        // Verify protection was applied
        assert_ne!(packet[0], original[0]);
        assert_ne!(packet[built.pn_offset], original[built.pn_offset]);

        // Remove protection (XOR again with same mask)
        apply_header_protection(&mut packet, built.pn_offset, built.pn_len, mask).unwrap();

        // Should match original
        assert_eq!(packet, original);
    }

    #[test]
    fn sample_offset_calculation() {
        // For 8-byte DCID: 1 + 8 + 4 = 13
        assert_eq!(sample_offset(8), 13);
        // For 0-byte DCID: 1 + 0 + 4 = 5
        assert_eq!(sample_offset(0), 5);
    }

    #[test]
    fn hp_sample_range_correct() {
        let range = hp_sample_range(8);
        assert_eq!(range, 13..(13 + HP_SAMPLE_LEN));
        assert_eq!(range.len(), HP_SAMPLE_LEN);
    }

    #[test]
    fn require_hp_sample_accepts_valid_packet() {
        let dcid_len = 8;
        let min_len = sample_offset(dcid_len) + HP_SAMPLE_LEN;
        let packet = vec![0u8; min_len];

        assert!(require_hp_sample(&packet, dcid_len).is_ok());
    }

    #[test]
    fn require_hp_sample_rejects_truncated_packet() {
        let dcid_len = 8;
        let min_len = sample_offset(dcid_len) + HP_SAMPLE_LEN;
        let packet = vec![0u8; min_len - 1];

        assert_eq!(
            require_hp_sample(&packet, dcid_len),
            Err(QspCryptoError::PacketTooShort)
        );
    }

    #[test]
    fn parse_header_rejects_truncated_packet() {
        let short_packet = vec![0x40, 0xAB]; // Only 2 bytes, need at least 1 + dcid_len + pn_len + tag

        let result = parse_header(8, &short_packet, zero_mask());
        assert!(matches!(result, Err(QspCryptoError::PacketTooShort)));
    }

    #[test]
    fn parse_header_rejects_missing_fixed_bit() {
        // Create a header without FIXED_BIT set
        let mut packet = vec![0x00]; // No fixed bit
        packet.extend_from_slice(DCID);
        packet.extend_from_slice(&[0x00, 0x01]);
        packet.extend_from_slice(&[0u8; AEAD_TAG_LEN]);

        let result = parse_header(DCID.len(), &packet, zero_mask());
        assert!(matches!(result, Err(QspCryptoError::InvalidHeader)));
    }

    #[test]
    fn parse_header_rejects_long_header_bit() {
        // Create a header with bit 7 set (long header)
        let mut packet = vec![0x80 | 0x40]; // Long header + fixed bit
        packet.extend_from_slice(DCID);
        packet.extend_from_slice(&[0x00, 0x01]);
        packet.extend_from_slice(&[0u8; AEAD_TAG_LEN]);

        let result = parse_header(DCID.len(), &packet, zero_mask());
        assert!(matches!(result, Err(QspCryptoError::InvalidHeader)));
    }

    #[test]
    fn parse_header_rejects_reserved_bits_set() {
        // Create a header with reserved bits set (bits 3,4)
        let mut packet = vec![0x40 | 0x08]; // Fixed bit + reserved bit
        packet.extend_from_slice(DCID);
        packet.extend_from_slice(&[0x00, 0x01]);
        packet.extend_from_slice(&[0u8; AEAD_TAG_LEN]);

        let result = parse_header(DCID.len(), &packet, zero_mask());
        assert!(matches!(result, Err(QspCryptoError::InvalidHeader)));
    }

    #[test]
    fn parse_header_with_mask_removes_protection() {
        let mut packet = Vec::new();
        let _ = build_header(DCID, 0x42, false, &mut packet).unwrap();
        packet.extend_from_slice(&[0u8; AEAD_TAG_LEN]);

        let mask: [u8; HP_MASK_LEN] = [0x15, 0x01, 0x02, 0x03, 0x04];

        // Apply protection
        apply_header_protection(&mut packet, 9, 1, mask).unwrap();

        // Parse with the same mask to remove protection
        let parsed = parse_header(DCID.len(), &packet, mask).unwrap();

        assert_eq!(parsed.pn, 0x42);
        assert!(!parsed.key_phase);
    }

    #[test]
    fn apply_header_protection_invalid_pn_len() {
        let mut packet = vec![0x40; 20];
        let mask = zero_mask();

        // pn_len = 0 is invalid
        assert_eq!(
            apply_header_protection(&mut packet, 9, 0, mask),
            Err(QspCryptoError::InvalidPacketNumber)
        );

        // pn_len > 4 is invalid
        assert_eq!(
            apply_header_protection(&mut packet, 9, 5, mask),
            Err(QspCryptoError::InvalidPacketNumber)
        );
    }

    #[test]
    fn apply_header_protection_packet_too_short() {
        let mut packet = vec![0x40; 5]; // Too short for pn_offset=9, pn_len=1
        let mask = zero_mask();

        assert_eq!(
            apply_header_protection(&mut packet, 9, 1, mask),
            Err(QspCryptoError::PacketTooShort)
        );
    }
}
