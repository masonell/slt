//! Packet protection keys and helpers.

use std::borrow::Cow;
use std::fmt;

use boring::symm::{Cipher, Crypter, Mode};

use super::packet::{
    OpenedPacket, OpenedPacketRef, apply_header_protection, build_header, hp_sample_range,
    parse_header, require_hp_sample,
};
use super::pn::{packet_number_len, reconstruct_packet_number};
use super::{AEAD_TAG_LEN, HP_MASK_LEN, HP_SAMPLE_LEN, QspCryptoError};
use crate::proto::{AEAD_IV_LEN, AEAD_KEY_LEN, CipherSuite, HP_KEY_LEN, RegisterCidPayload};

#[derive(Clone, Copy)]
struct CipherConfig {
    aead: Cipher,
    hp: Cipher,
}

impl CipherConfig {
    fn for_suite(cipher: CipherSuite) -> Result<Self, QspCryptoError> {
        match cipher {
            CipherSuite::Aes128Gcm => Ok(Self {
                aead: Cipher::aes_128_gcm(),
                hp: Cipher::aes_128_ecb(),
            }),
            CipherSuite::ChaCha20Poly1305 => Err(QspCryptoError::UnsupportedCipher),
        }
    }
}

#[derive(Clone)]
struct HeaderProtectionKey {
    key: [u8; HP_KEY_LEN],
    cipher: Cipher,
}

impl HeaderProtectionKey {
    #[inline]
    const fn new(key: [u8; HP_KEY_LEN], cipher: Cipher) -> Self {
        Self { key, cipher }
    }

    fn mask(&self, sample: &[u8]) -> Result<[u8; HP_MASK_LEN], QspCryptoError> {
        if sample.len() != HP_SAMPLE_LEN {
            return Err(QspCryptoError::PacketTooShort);
        }

        let mut crypter = Crypter::new(self.cipher, Mode::Encrypt, &self.key, None)
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

#[derive(Clone)]
struct PacketKey {
    key: [u8; AEAD_KEY_LEN],
    iv: [u8; AEAD_IV_LEN],
    cipher: Cipher,
}

impl PacketKey {
    #[inline]
    const fn new(key: [u8; AEAD_KEY_LEN], iv: [u8; AEAD_IV_LEN], cipher: Cipher) -> Self {
        Self { key, iv, cipher }
    }

    #[inline]
    fn block_size(&self) -> usize {
        self.cipher.block_size()
    }

    fn seal_into(
        &self,
        pn: u64,
        ad_len: usize,
        plaintext: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), QspCryptoError> {
        let nonce = make_nonce(&self.iv, pn);
        let mut crypter = Crypter::new(self.cipher, Mode::Encrypt, &self.key, Some(&nonce))
            .map_err(|_| QspCryptoError::CryptoFail)?;

        {
            let ad = &out[..ad_len];
            crypter
                .aad_update(ad)
                .map_err(|_| QspCryptoError::CryptoFail)?;
        }

        let start = out.len();
        let block_size = self.cipher.block_size();
        out.resize(start + plaintext.len() + block_size, 0);

        let count = crypter
            .update(plaintext, &mut out[start..])
            .map_err(|_| QspCryptoError::CryptoFail)?;
        let rest = crypter
            .finalize(&mut out[start + count..])
            .map_err(|_| QspCryptoError::CryptoFail)?;

        out.truncate(start + count + rest);

        let mut tag = [0u8; AEAD_TAG_LEN];
        crypter
            .get_tag(&mut tag)
            .map_err(|_| QspCryptoError::CryptoFail)?;
        out.extend_from_slice(&tag);

        Ok(())
    }

    fn open_into(
        &self,
        pn: u64,
        ad: &[u8],
        ciphertext: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), QspCryptoError> {
        if ciphertext.len() < AEAD_TAG_LEN {
            return Err(QspCryptoError::PacketTooShort);
        }

        let (ct, tag) = ciphertext.split_at(ciphertext.len() - AEAD_TAG_LEN);
        let nonce = make_nonce(&self.iv, pn);
        let mut crypter = Crypter::new(self.cipher, Mode::Decrypt, &self.key, Some(&nonce))
            .map_err(|_| QspCryptoError::CryptoFail)?;

        crypter
            .aad_update(ad)
            .map_err(|_| QspCryptoError::CryptoFail)?;

        let block_size = self.cipher.block_size();
        out.clear();
        out.resize(ct.len() + block_size, 0);

        let count = crypter
            .update(ct, &mut out[..])
            .map_err(|_| QspCryptoError::CryptoFail)?;

        crypter
            .set_tag(tag)
            .map_err(|_| QspCryptoError::CryptoFail)?;

        let rest = crypter
            .finalize(&mut out[count..])
            .map_err(|_| QspCryptoError::CryptoFail)?;

        out.truncate(count + rest);
        Ok(())
    }
}

#[derive(Clone)]
struct DirectionKeys {
    hp: HeaderProtectionKey,
    aead: PacketKey,
}

/// UDP-QSP key material for header and payload protection.
#[derive(Clone)]
pub struct UdpQspKeys {
    cipher: CipherSuite,
    tx: DirectionKeys,
    rx: DirectionKeys,
}

impl fmt::Debug for UdpQspKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UdpQspKeys")
            .field("cipher", &self.cipher)
            .field("tx", &"<redacted>")
            .field("rx", &"<redacted>")
            .finish()
    }
}

impl UdpQspKeys {
    /// Build UDP-QSP keys from raw key material.
    ///
    /// # Errors
    ///
    /// Returns `QspCryptoError::UnsupportedCipher` if the cipher suite is not
    /// `Aes128Gcm`.
    pub fn new(
        cipher: CipherSuite,
        hp_tx: [u8; HP_KEY_LEN],
        hp_rx: [u8; HP_KEY_LEN],
        aead_tx: [u8; AEAD_KEY_LEN],
        aead_rx: [u8; AEAD_KEY_LEN],
        iv_tx: [u8; AEAD_IV_LEN],
        iv_rx: [u8; AEAD_IV_LEN],
    ) -> Result<Self, QspCryptoError> {
        let config = CipherConfig::for_suite(cipher)?;

        Ok(Self {
            cipher,
            tx: DirectionKeys {
                hp: HeaderProtectionKey::new(hp_tx, config.hp),
                aead: PacketKey::new(aead_tx, iv_tx, config.aead),
            },
            rx: DirectionKeys {
                hp: HeaderProtectionKey::new(hp_rx, config.hp),
                aead: PacketKey::new(aead_rx, iv_rx, config.aead),
            },
        })
    }

    /// Build UDP-QSP keys from a `REGISTER_CID` payload.
    ///
    /// # Errors
    ///
    /// Returns `QspCryptoError::UnsupportedCipher` if the cipher suite is not
    /// `Aes128Gcm`.
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
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The packet is too short for header protection sampling
    /// - AEAD encryption fails
    pub fn protect(
        &self,
        dcid: &[u8],
        pn: u64,
        key_phase: bool,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, QspCryptoError> {
        let mut out = Vec::new();
        self.protect_into(dcid, pn, key_phase, plaintext, &mut out)?;
        Ok(out)
    }

    /// Protect a UDP-QSP payload into the provided buffer.
    ///
    /// The output buffer is cleared and reused for the packet bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The packet is too short for header protection sampling
    /// - AEAD encryption fails
    pub fn protect_into(
        &self,
        dcid: &[u8],
        pn: u64,
        key_phase: bool,
        plaintext: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), QspCryptoError> {
        out.clear();

        let pn_len = packet_number_len(pn);
        let header_len = 1 + dcid.len() + pn_len;
        let min_cipher_len = hp_sample_range(dcid.len()).end.saturating_sub(header_len);
        let pad_len = min_cipher_len.saturating_sub(plaintext.len() + AEAD_TAG_LEN);
        let padded_len = plaintext.len() + pad_len;
        let target_len = header_len + padded_len + AEAD_TAG_LEN;
        let needed_capacity = target_len + self.tx.aead.block_size();
        if out.capacity() < needed_capacity {
            out.reserve_exact(needed_capacity - out.capacity());
        }

        let header = build_header(dcid, pn, key_phase, out)?;
        let header_len = out.len();

        let padded = if pad_len == 0 {
            Cow::Borrowed(plaintext)
        } else {
            let mut buf = Vec::with_capacity(plaintext.len() + pad_len);
            buf.extend_from_slice(plaintext);
            buf.extend(std::iter::repeat_n(0u8, pad_len));
            Cow::Owned(buf)
        };

        self.tx.aead.seal_into(pn, header_len, &padded, out)?;

        require_hp_sample(out, dcid.len())?;
        let mask = self.tx.hp.mask(&out[hp_sample_range(dcid.len())])?;
        apply_header_protection(out, header.pn_offset, header.pn_len, mask)?;

        Ok(())
    }

    /// Unprotect a UDP-QSP short-header packet and return its plaintext.
    ///
    /// `expected_pn` should be the next packet number you expect to receive
    /// (typically `largest_pn + 1`) to allow packet number reconstruction.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The packet is too short for header protection sampling
    /// - AEAD decryption fails (authentication failure)
    /// - The packet number length is invalid
    pub fn open(
        &self,
        dcid_len: usize,
        packet: &[u8],
        expected_pn: u64,
    ) -> Result<OpenedPacket, QspCryptoError> {
        let mut payload = Vec::new();
        let meta = self.open_into_inner(dcid_len, packet, expected_pn, &mut payload)?;
        Ok(OpenedPacket {
            pn: meta.pn,
            pn_len: meta.pn_len,
            key_phase: meta.key_phase,
            payload,
        })
    }

    /// Unprotect a UDP-QSP short-header packet into the provided buffer.
    ///
    /// The output buffer is cleared and reused for the decrypted payload.
    ///
    /// `expected_pn` should be the next packet number you expect to receive
    /// (typically `largest_pn + 1`) to allow packet number reconstruction.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The packet is too short for header protection sampling
    /// - AEAD decryption fails (authentication failure)
    /// - The packet number length is invalid
    pub fn open_into<'a>(
        &self,
        dcid_len: usize,
        packet: &[u8],
        expected_pn: u64,
        out: &'a mut Vec<u8>,
    ) -> Result<OpenedPacketRef<'a>, QspCryptoError> {
        let meta = self.open_into_inner(dcid_len, packet, expected_pn, out)?;
        Ok(OpenedPacketRef {
            pn: meta.pn,
            pn_len: meta.pn_len,
            key_phase: meta.key_phase,
            payload: out.as_slice(),
        })
    }

    fn open_into_inner(
        &self,
        dcid_len: usize,
        packet: &[u8],
        expected_pn: u64,
        out: &mut Vec<u8>,
    ) -> Result<OpenedPacketMeta, QspCryptoError> {
        require_hp_sample(packet, dcid_len)?;
        let sample = hp_sample_range(dcid_len);
        let mask = self.rx.hp.mask(&packet[sample])?;
        let parsed = parse_header(dcid_len, packet, mask)?;

        let pn = reconstruct_packet_number(parsed.pn, expected_pn, parsed.pn_len);
        let plaintext_len = packet.len() - parsed.header.len() - AEAD_TAG_LEN;
        let needed_capacity = plaintext_len + self.rx.aead.block_size();
        if out.capacity() < needed_capacity {
            out.reserve_exact(needed_capacity - out.capacity());
        }

        self.rx
            .aead
            .open_into(pn, &parsed.header, &packet[parsed.header.len()..], out)?;

        Ok(OpenedPacketMeta {
            pn,
            pn_len: parsed.pn_len,
            key_phase: parsed.key_phase,
        })
    }
}

struct OpenedPacketMeta {
    pn: u64,
    pn_len: usize,
    key_phase: bool,
}

#[inline]
fn make_nonce(iv: &[u8; AEAD_IV_LEN], counter: u64) -> [u8; AEAD_IV_LEN] {
    let mut nonce = *iv;
    for (a, b) in nonce[4..].iter_mut().zip(counter.to_be_bytes().iter()) {
        *a ^= b;
    }
    nonce
}
