//! UDP-QSP packet protection helpers.

mod keys;
mod packet;
mod pn;
mod session;

pub use keys::UdpQspKeys;
pub use packet::{OpenedPacket, OpenedPacketRef};
pub use pn::reconstruct_packet_number;
pub use session::{
    PN_REPLAY_WINDOW, QspSessionError, QuicQspSession, ReplayError, ReplayWindow, SessionIo,
};

/// Length of the header protection mask.
pub const HP_MASK_LEN: usize = 5;
/// Header protection sample length.
pub const HP_SAMPLE_LEN: usize = 16;
/// AEAD authentication tag length.
pub const AEAD_TAG_LEN: usize = 16;

/// Errors returned by UDP-QSP crypto helpers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum QspCryptoError {
    /// Unsupported cipher suite for this build.
    #[error("unsupported cipher suite")]
    UnsupportedCipher,
    /// Packet is too short to parse.
    #[error("packet too short")]
    PacketTooShort,
    /// Packet header is invalid.
    #[error("invalid packet header")]
    InvalidHeader,
    /// Packet number length is invalid.
    #[error("invalid packet number")]
    InvalidPacketNumber,
    /// Crypto operation failed.
    #[error("crypto operation failed")]
    CryptoFail,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{AEAD_IV_LEN, AEAD_KEY_LEN, CipherSuite, HP_KEY_LEN};

    #[test]
    fn udp_qsp_roundtrip() {
        let keys = UdpQspKeys::new(
            CipherSuite::Aes128Gcm,
            [0x11; HP_KEY_LEN],
            [0x11; HP_KEY_LEN],
            [0x33; AEAD_KEY_LEN],
            [0x33; AEAD_KEY_LEN],
            [0x55; AEAD_IV_LEN],
            [0x55; AEAD_IV_LEN],
        )
        .unwrap();

        let dcid = [0xAB; 8];
        let payload = vec![0xCD; 32];
        let packet = keys.protect(&dcid, 1, false, &payload).unwrap();
        let opened = keys.open(dcid.len(), &packet, 1).unwrap();

        assert_eq!(opened.pn, 1);
        assert_eq!(opened.pn_len, 1);
        assert!(!opened.key_phase);
        assert_eq!(opened.payload, payload);
    }

    #[test]
    fn udp_qsp_roundtrip_into() {
        let keys = UdpQspKeys::new(
            CipherSuite::Aes128Gcm,
            [0x11; HP_KEY_LEN],
            [0x11; HP_KEY_LEN],
            [0x33; AEAD_KEY_LEN],
            [0x33; AEAD_KEY_LEN],
            [0x55; AEAD_IV_LEN],
            [0x55; AEAD_IV_LEN],
        )
        .unwrap();

        let dcid = [0xAB; 8];
        let payload = vec![0xCD; 32];
        let mut packet = Vec::new();
        keys.protect_into(&dcid, 7, true, &payload, &mut packet)
            .unwrap();

        let mut out = Vec::new();
        let opened = keys.open_into(dcid.len(), &packet, 7, &mut out).unwrap();

        assert_eq!(opened.pn, 7);
        assert_eq!(opened.pn_len, 1);
        assert!(opened.key_phase);
        assert_eq!(opened.payload, payload.as_slice());
    }

    #[test]
    fn udp_qsp_accepts_large_packet_number() {
        let keys = UdpQspKeys::new(
            CipherSuite::Aes128Gcm,
            [0x11; HP_KEY_LEN],
            [0x11; HP_KEY_LEN],
            [0x33; AEAD_KEY_LEN],
            [0x33; AEAD_KEY_LEN],
            [0x55; AEAD_IV_LEN],
            [0x55; AEAD_IV_LEN],
        )
        .unwrap();

        let dcid = [0xAB; 8];
        let payload = vec![0xCD; 32];
        let pn = u64::from(u32::MAX) + 1;
        let packet = keys.protect(&dcid, pn, false, &payload).unwrap();
        let opened = keys.open(dcid.len(), &packet, pn).unwrap();
        assert_eq!(opened.pn, pn);
    }

    #[test]
    fn udp_qsp_rejects_short_packet() {
        let keys = UdpQspKeys::new(
            CipherSuite::Aes128Gcm,
            [0x11; HP_KEY_LEN],
            [0x11; HP_KEY_LEN],
            [0x33; AEAD_KEY_LEN],
            [0x33; AEAD_KEY_LEN],
            [0x55; AEAD_IV_LEN],
            [0x55; AEAD_IV_LEN],
        )
        .unwrap();

        let packet = vec![0u8; 10];
        assert_eq!(
            keys.open(8, &packet, 0),
            Err(QspCryptoError::PacketTooShort)
        );
    }

    #[test]
    fn udp_qsp_rejects_invalid_fixed_bit() {
        let keys = UdpQspKeys::new(
            CipherSuite::Aes128Gcm,
            [0x11; HP_KEY_LEN],
            [0x11; HP_KEY_LEN],
            [0x33; AEAD_KEY_LEN],
            [0x33; AEAD_KEY_LEN],
            [0x55; AEAD_IV_LEN],
            [0x55; AEAD_IV_LEN],
        )
        .unwrap();

        let dcid = [0xAB; 8];
        let payload = vec![0xCD; 32];
        let mut packet = keys.protect(&dcid, 1, false, &payload).unwrap();
        packet[0] &= !0x40;

        assert_eq!(
            keys.open(dcid.len(), &packet, 1),
            Err(QspCryptoError::InvalidHeader)
        );
    }

    #[test]
    fn udp_qsp_rejects_long_header_bit() {
        let keys = UdpQspKeys::new(
            CipherSuite::Aes128Gcm,
            [0x11; HP_KEY_LEN],
            [0x11; HP_KEY_LEN],
            [0x33; AEAD_KEY_LEN],
            [0x33; AEAD_KEY_LEN],
            [0x55; AEAD_IV_LEN],
            [0x55; AEAD_IV_LEN],
        )
        .unwrap();

        let dcid = [0xAB; 8];
        let payload = vec![0xCD; 32];
        let mut packet = keys.protect(&dcid, 1, false, &payload).unwrap();
        packet[0] |= 0x80;

        assert_eq!(
            keys.open(dcid.len(), &packet, 1),
            Err(QspCryptoError::InvalidHeader)
        );
    }

    #[test]
    fn udp_qsp_rejects_reserved_bits() {
        let keys = UdpQspKeys::new(
            CipherSuite::Aes128Gcm,
            [0x11; HP_KEY_LEN],
            [0x11; HP_KEY_LEN],
            [0x33; AEAD_KEY_LEN],
            [0x33; AEAD_KEY_LEN],
            [0x55; AEAD_IV_LEN],
            [0x55; AEAD_IV_LEN],
        )
        .unwrap();

        let dcid = [0xAB; 8];
        let payload = vec![0xCD; 32];
        let mut packet = keys.protect(&dcid, 1, false, &payload).unwrap();
        packet[0] ^= 0x08;

        assert_eq!(
            keys.open(dcid.len(), &packet, 1),
            Err(QspCryptoError::InvalidHeader)
        );
    }

    #[test]
    fn udp_qsp_rejects_tampered_payload() {
        let keys = UdpQspKeys::new(
            CipherSuite::Aes128Gcm,
            [0x11; HP_KEY_LEN],
            [0x11; HP_KEY_LEN],
            [0x33; AEAD_KEY_LEN],
            [0x33; AEAD_KEY_LEN],
            [0x55; AEAD_IV_LEN],
            [0x55; AEAD_IV_LEN],
        )
        .unwrap();

        let dcid = [0xAB; 8];
        let payload = vec![0xCD; 32];
        let mut packet = keys.protect(&dcid, 1, false, &payload).unwrap();
        let last = packet.len() - 1;
        packet[last] ^= 0xFF;

        assert_eq!(
            keys.open(dcid.len(), &packet, 1),
            Err(QspCryptoError::CryptoFail)
        );
    }

    #[test]
    fn udp_qsp_roundtrip_small_payload_has_zero_padding() {
        let keys = UdpQspKeys::new(
            CipherSuite::Aes128Gcm,
            [0x11; HP_KEY_LEN],
            [0x11; HP_KEY_LEN],
            [0x33; AEAD_KEY_LEN],
            [0x33; AEAD_KEY_LEN],
            [0x55; AEAD_IV_LEN],
            [0x55; AEAD_IV_LEN],
        )
        .unwrap();

        let dcid = [0xAB; 8];
        let payload = vec![0xCD; 1];
        let packet = keys.protect(&dcid, 1, false, &payload).unwrap();
        let opened = keys.open(dcid.len(), &packet, 1).unwrap();

        assert!(opened.payload.len() >= payload.len());
        assert_eq!(&opened.payload[..payload.len()], &payload[..]);
        assert!(opened.payload[payload.len()..].iter().all(|b| *b == 0));
    }
}
