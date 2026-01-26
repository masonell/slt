//! UDP-QSP packet protection helpers.

use boring::symm::{Cipher, Crypter, Mode, decrypt_aead, encrypt_aead};

use crate::proto::{AEAD_IV_LEN, AEAD_KEY_LEN, CipherSuite, HP_KEY_LEN, RegisterCidPayload};

/// Length of the header protection mask.
pub const HP_MASK_LEN: usize = 5;
/// Header protection sample length.
pub const HP_SAMPLE_LEN: usize = 16;
/// AEAD authentication tag length.
pub const AEAD_TAG_LEN: usize = 16;

const FIXED_BIT: u8 = 0x40;
const KEY_PHASE_BIT: u8 = 0x04;
const RESERVED_MASK: u8 = 0x18;
const PN_LEN_MASK: u8 = 0x03;
const MAX_PN_LEN: usize = 4;

/// Errors returned by UDP-QSP crypto helpers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QspCryptoError {
    /// Unsupported cipher suite for this build.
    UnsupportedCipher,
    /// Packet is too short to parse.
    PacketTooShort,
    /// Packet header is invalid.
    InvalidHeader,
    /// Packet number length is invalid.
    InvalidPacketNumber,
    /// Crypto operation failed.
    CryptoFail,
}

/// Decrypted UDP-QSP packet metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenedPacket {
    /// Packet number.
    pub pn: u64,
    /// Key phase bit.
    pub key_phase: bool,
    /// Decrypted payload.
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone)]
struct HeaderProtectionKey {
    key: [u8; HP_KEY_LEN],
}

impl HeaderProtectionKey {
    fn new(key: [u8; HP_KEY_LEN]) -> Self {
        Self { key }
    }

    fn mask(&self, sample: &[u8]) -> Result<[u8; HP_MASK_LEN], QspCryptoError> {
        if sample.len() != HP_SAMPLE_LEN {
            return Err(QspCryptoError::PacketTooShort);
        }

        let cipher = Cipher::aes_128_ecb();
        let mut crypter = Crypter::new(cipher, Mode::Encrypt, &self.key, None)
            .map_err(|_| QspCryptoError::CryptoFail)?;
        crypter.pad(false);

        let mut out = [0u8; 32];
        let count = crypter
            .update(sample, &mut out)
            .map_err(|_| QspCryptoError::CryptoFail)?;
        let rest = crypter
            .finalize(&mut out[count..])
            .map_err(|_| QspCryptoError::CryptoFail)?;

        let total = count + rest;
        if total < HP_SAMPLE_LEN {
            return Err(QspCryptoError::CryptoFail);
        }

        let mut mask = [0u8; HP_MASK_LEN];
        mask.copy_from_slice(&out[..HP_MASK_LEN]);
        Ok(mask)
    }
}

#[derive(Debug, Clone)]
struct PacketKey {
    key: [u8; AEAD_KEY_LEN],
    iv: [u8; AEAD_IV_LEN],
}

impl PacketKey {
    fn new(key: [u8; AEAD_KEY_LEN], iv: [u8; AEAD_IV_LEN]) -> Self {
        Self { key, iv }
    }

    fn seal(
        &self,
        pn: u64,
        ad: &[u8],
        plaintext: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), QspCryptoError> {
        let nonce = make_nonce(&self.iv, pn);
        let mut tag = [0u8; AEAD_TAG_LEN];
        let ciphertext = encrypt_aead(
            Cipher::aes_128_gcm(),
            &self.key,
            Some(&nonce),
            ad,
            plaintext,
            &mut tag,
        )
        .map_err(|_| QspCryptoError::CryptoFail)?;
        out.extend_from_slice(&ciphertext);
        out.extend_from_slice(&tag);
        Ok(())
    }

    fn open(&self, pn: u64, ad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, QspCryptoError> {
        if ciphertext.len() < AEAD_TAG_LEN {
            return Err(QspCryptoError::PacketTooShort);
        }
        let (ct, tag) = ciphertext.split_at(ciphertext.len() - AEAD_TAG_LEN);
        let nonce = make_nonce(&self.iv, pn);
        decrypt_aead(Cipher::aes_128_gcm(), &self.key, Some(&nonce), ad, ct, tag)
            .map_err(|_| QspCryptoError::CryptoFail)
    }
}

#[derive(Debug, Clone)]
struct DirectionKeys {
    hp: HeaderProtectionKey,
    aead: PacketKey,
}

/// UDP-QSP key material for header and payload protection.
#[derive(Debug, Clone)]
pub struct UdpQspKeys {
    cipher: CipherSuite,
    tx: DirectionKeys,
    rx: DirectionKeys,
}

impl UdpQspKeys {
    /// Build UDP-QSP keys from raw key material.
    pub fn new(
        cipher: CipherSuite,
        hp_tx: [u8; HP_KEY_LEN],
        hp_rx: [u8; HP_KEY_LEN],
        aead_tx: [u8; AEAD_KEY_LEN],
        aead_rx: [u8; AEAD_KEY_LEN],
        iv_tx: [u8; AEAD_IV_LEN],
        iv_rx: [u8; AEAD_IV_LEN],
    ) -> Result<Self, QspCryptoError> {
        if cipher != CipherSuite::Aes128Gcm {
            return Err(QspCryptoError::UnsupportedCipher);
        }

        Ok(Self {
            cipher,
            tx: DirectionKeys {
                hp: HeaderProtectionKey::new(hp_tx),
                aead: PacketKey::new(aead_tx, iv_tx),
            },
            rx: DirectionKeys {
                hp: HeaderProtectionKey::new(hp_rx),
                aead: PacketKey::new(aead_rx, iv_rx),
            },
        })
    }

    /// Build UDP-QSP keys from a REGISTER_CID payload.
    pub fn from_register(payload: &RegisterCidPayload<'_>) -> Result<Self, QspCryptoError> {
        Self::new(
            payload.cipher,
            payload.hp_tx,
            payload.hp_rx,
            payload.aead_tx,
            payload.aead_rx,
            payload.iv_tx,
            payload.iv_rx,
        )
    }

    /// Protect a UDP-QSP payload into a QUIC short-header packet.
    pub fn protect(
        &self,
        dcid: &[u8],
        pn: u64,
        key_phase: bool,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, QspCryptoError> {
        if self.cipher != CipherSuite::Aes128Gcm {
            return Err(QspCryptoError::UnsupportedCipher);
        }

        if pn > u32::MAX as u64 {
            return Err(QspCryptoError::InvalidPacketNumber);
        }

        let pn_len = packet_number_len(pn);
        if pn_len == 0 || pn_len > MAX_PN_LEN {
            return Err(QspCryptoError::InvalidPacketNumber);
        }

        let mut header = Vec::with_capacity(1 + dcid.len() + pn_len);
        let mut first = FIXED_BIT | ((pn_len - 1) as u8 & PN_LEN_MASK);
        if key_phase {
            first |= KEY_PHASE_BIT;
        }
        header.push(first);
        header.extend_from_slice(dcid);
        header.extend_from_slice(&pn.to_be_bytes()[8 - pn_len..]);

        let pn_offset = 1 + dcid.len();
        let header_len = header.len();
        let min_cipher_len = (pn_offset + 4 + HP_SAMPLE_LEN).saturating_sub(header_len);
        let mut padded = Vec::from(plaintext);
        if padded.len() + AEAD_TAG_LEN < min_cipher_len {
            let pad_len = min_cipher_len - (padded.len() + AEAD_TAG_LEN);
            padded.extend(std::iter::repeat_n(0u8, pad_len));
        }

        let mut packet = header;
        let ad = packet.clone();
        self.tx.aead.seal(pn, &ad, &padded, &mut packet)?;

        let sample_offset = pn_offset + 4;
        if packet.len() < sample_offset + HP_SAMPLE_LEN {
            return Err(QspCryptoError::PacketTooShort);
        }
        let mask = self
            .tx
            .hp
            .mask(&packet[sample_offset..sample_offset + HP_SAMPLE_LEN])?;

        packet[0] ^= mask[0] & 0x1f;
        for i in 0..pn_len {
            packet[pn_offset + i] ^= mask[1 + i];
        }

        Ok(packet)
    }

    /// Unprotect a UDP-QSP short-header packet and return its plaintext.
    pub fn open(&self, dcid_len: usize, packet: &[u8]) -> Result<OpenedPacket, QspCryptoError> {
        if self.cipher != CipherSuite::Aes128Gcm {
            return Err(QspCryptoError::UnsupportedCipher);
        }

        let pn_offset = 1 + dcid_len;
        let sample_offset = pn_offset + 4;
        if packet.len() < sample_offset + HP_SAMPLE_LEN {
            return Err(QspCryptoError::PacketTooShort);
        }

        let mask = self
            .rx
            .hp
            .mask(&packet[sample_offset..sample_offset + HP_SAMPLE_LEN])?;
        let first = packet[0] ^ (mask[0] & 0x1f);

        if first & FIXED_BIT == 0 || first & 0x80 != 0 {
            return Err(QspCryptoError::InvalidHeader);
        }
        if (first & RESERVED_MASK) != 0 {
            return Err(QspCryptoError::InvalidHeader);
        }

        let pn_len = ((first & PN_LEN_MASK) + 1) as usize;
        if pn_len == 0 || pn_len > MAX_PN_LEN {
            return Err(QspCryptoError::InvalidPacketNumber);
        }
        if packet.len() < pn_offset + pn_len + AEAD_TAG_LEN {
            return Err(QspCryptoError::PacketTooShort);
        }

        let mut pn_bytes = [0u8; MAX_PN_LEN];
        for i in 0..pn_len {
            pn_bytes[MAX_PN_LEN - pn_len + i] = packet[pn_offset + i] ^ mask[1 + i];
        }
        let pn = u32::from_be_bytes(pn_bytes) as u64;

        let key_phase = (first & KEY_PHASE_BIT) != 0;
        let mut header = Vec::with_capacity(pn_offset + pn_len);
        header.push(first);
        header.extend_from_slice(&packet[1..pn_offset]);
        header.extend_from_slice(&pn_bytes[MAX_PN_LEN - pn_len..]);

        let plaintext = self.rx.aead.open(pn, &header, &packet[header.len()..])?;

        Ok(OpenedPacket {
            pn,
            key_phase,
            payload: plaintext,
        })
    }
}

fn packet_number_len(pn: u64) -> usize {
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

fn make_nonce(iv: &[u8; AEAD_IV_LEN], counter: u64) -> [u8; AEAD_IV_LEN] {
    let mut nonce = *iv;
    for (a, b) in nonce[4..].iter_mut().zip(counter.to_be_bytes().iter()) {
        *a ^= b;
    }
    nonce
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let opened = keys.open(dcid.len(), &packet).unwrap();

        assert_eq!(opened.pn, 1);
        assert!(!opened.key_phase);
        assert_eq!(opened.payload, payload);
    }

    #[test]
    fn udp_qsp_rejects_large_packet_number() {
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
        let pn = (u32::MAX as u64) + 1;
        assert_eq!(
            keys.protect(&dcid, pn, false, &payload),
            Err(QspCryptoError::InvalidPacketNumber)
        );
    }
}
