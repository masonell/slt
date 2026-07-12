//! UDP-QSP packet protection key facade.

mod backend;
mod derivation;
mod schedule;

#[cfg(test)]
mod tests;

use std::borrow::Cow;
use std::fmt;

use self::backend::CipherConfig;
use self::schedule::DirectionKeys;
use super::packet::{
    OpenedPacket, OpenedPacketRef, apply_header_protection, build_header, hp_sample_range,
    parse_header, require_hp_sample,
};
use super::pn::{packet_number_len, reconstruct_packet_number};
use super::{AEAD_TAG_LEN, QspCryptoError};
use crate::proto::{CipherSuite, RegisterCidPayload};

/// UDP-QSP key material for header and payload protection.
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
    /// Build UDP-QSP keys from directional traffic secrets.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The cipher suite is unsupported
    /// - Secret material lengths do not match `UDP_QSP_TRAFFIC_SECRET_LEN`
    /// - Crypto key initialization fails
    pub fn new(
        cipher: CipherSuite,
        secret_tx: impl AsRef<[u8]>,
        secret_rx: impl AsRef<[u8]>,
    ) -> Result<Self, QspCryptoError> {
        let config = CipherConfig::for_suite(cipher);

        Ok(Self {
            cipher,
            tx: DirectionKeys::from_secret(secret_tx.as_ref(), config)?,
            rx: DirectionKeys::from_secret(secret_rx.as_ref(), config)?,
        })
    }

    /// Build UDP-QSP keys from raw packet material.
    ///
    /// This is retained for tests that need exact packet keys. Rekeying from
    /// this state uses an all-zero synthetic traffic secret, so production
    /// registration should use [`Self::new`] or [`Self::from_register`] instead.
    ///
    /// # Errors
    ///
    /// Returns an error if key or IV material lengths do not match the cipher
    /// suite, or crypto key initialization fails.
    #[cfg(any(test, feature = "testing"))]
    pub fn from_packet_material(
        cipher: CipherSuite,
        hp_tx: impl AsRef<[u8]>,
        hp_rx: impl AsRef<[u8]>,
        aead_tx: impl AsRef<[u8]>,
        aead_rx: impl AsRef<[u8]>,
        iv_tx: impl AsRef<[u8]>,
        iv_rx: impl AsRef<[u8]>,
    ) -> Result<Self, QspCryptoError> {
        let config = CipherConfig::for_suite(cipher);
        Ok(Self {
            cipher,
            tx: DirectionKeys::from_packet_material(
                config,
                hp_tx.as_ref(),
                aead_tx.as_ref(),
                iv_tx.as_ref(),
            )?,
            rx: DirectionKeys::from_packet_material(
                config,
                hp_rx.as_ref(),
                aead_rx.as_ref(),
                iv_rx.as_ref(),
            )?,
        })
    }

    /// Build UDP-QSP keys from a `REGISTER_CID` payload.
    ///
    /// # Errors
    ///
    /// Returns an error if the cipher suite is unsupported or crypto key
    /// initialization fails.
    pub fn from_register(payload: &RegisterCidPayload) -> Result<Self, QspCryptoError> {
        Self::new(payload.cipher, payload.secret_tx, payload.secret_rx)
    }

    pub(crate) fn try_clone(&self) -> Result<Self, QspCryptoError> {
        Ok(Self {
            cipher: self.cipher,
            tx: self.tx.try_clone()?,
            rx: self.rx.try_clone()?,
        })
    }

    pub(crate) fn with_next_tx_keys(&self) -> Result<Self, QspCryptoError> {
        let config = CipherConfig::for_suite(self.cipher);
        Ok(Self {
            cipher: self.cipher,
            tx: self.tx.next_generation(config)?,
            rx: self.rx.try_clone()?,
        })
    }

    pub(crate) fn with_next_rx_keys(&self) -> Result<Self, QspCryptoError> {
        let config = CipherConfig::for_suite(self.cipher);
        Ok(Self {
            cipher: self.cipher,
            tx: self.tx.try_clone()?,
            rx: self.rx.next_generation(config)?,
        })
    }

    /// Protect a UDP-QSP payload into a QUIC short-header packet.
    ///
    /// Short plaintexts are padded with zero bytes before encryption so the
    /// protected packet has enough ciphertext for header-protection sampling.
    /// [`open`](Self::open) returns that full plaintext, including padding.
    ///
    /// `pn` becomes the AEAD nonce, so it must be unique for the lifetime of
    /// the current TX key. Reusing a `(key, pn)` pair is catastrophic AEAD
    /// nonce reuse: it leaks plaintext and enables forgery. Rotating the TX
    /// key (`with_next_tx_keys`) starts a fresh key under which the
    /// packet-number space resets.
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
    /// `pn` must be unique for the lifetime of the current TX key — see
    /// [`protect`](Self::protect) for the nonce-reuse constraint.
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
        if out.capacity() < target_len {
            out.reserve_exact(target_len - out.capacity());
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
    /// The returned payload is the full AEAD plaintext. It can include trailing
    /// zero padding added for header-protection sampling; VPN message callers
    /// should decode it with [`crate::proto::decode_padded_message`].
    ///
    /// `expected_pn` should be the next packet number you expect to receive
    /// (typically `largest_pn + 1`) to allow packet number reconstruction.
    /// The reconstructed packet number reproduces the sender's AEAD nonce;
    /// uniqueness is the sender's obligation (see [`protect`](Self::protect)).
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
        let meta = Self::open_into_inner(&self.rx, dcid_len, packet, expected_pn, &mut payload)?;
        Ok(OpenedPacket {
            pn: meta.pn,
            pn_len: meta.pn_len,
            key_phase: meta.key_phase,
            payload,
        })
    }

    /// Unprotect a UDP-QSP short-header packet into the provided buffer.
    ///
    /// The output buffer is cleared and reused for the full AEAD plaintext.
    /// It can include trailing zero padding added for header-protection
    /// sampling; VPN message callers should decode it with
    /// [`crate::proto::decode_padded_message`].
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
        let meta = Self::open_into_inner(&self.rx, dcid_len, packet, expected_pn, out)?;
        Ok(OpenedPacketRef {
            pn: meta.pn,
            pn_len: meta.pn_len,
            key_phase: meta.key_phase,
            payload: out.as_slice(),
        })
    }

    fn open_into_inner(
        rx: &DirectionKeys,
        dcid_len: usize,
        packet: &[u8],
        expected_pn: u64,
        out: &mut Vec<u8>,
    ) -> Result<OpenedPacketMeta, QspCryptoError> {
        require_hp_sample(packet, dcid_len)?;
        let sample = hp_sample_range(dcid_len);
        let mask = rx.hp.mask(&packet[sample])?;
        let parsed = parse_header(dcid_len, packet, mask)?;

        // parse_header guarantees packet.len() >= parsed.header.len() + AEAD_TAG_LEN,
        // so this guard is never expected to fire; it restates the bound locally so
        // the subtraction and slice below are safe by inspection instead of relying
        // on that cross-function invariant on the untrusted UDP receive path.
        if packet.len() < parsed.header.len() + AEAD_TAG_LEN {
            return Err(QspCryptoError::PacketTooShort);
        }

        let pn = reconstruct_packet_number(parsed.pn, expected_pn, parsed.pn_len);
        let plaintext_len = packet.len() - parsed.header.len() - AEAD_TAG_LEN;
        if out.capacity() < plaintext_len {
            out.reserve_exact(plaintext_len - out.capacity());
        }

        rx.aead
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
