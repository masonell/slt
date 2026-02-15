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
    /// Decrypted payload.
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
    /// Decrypted payload.
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
