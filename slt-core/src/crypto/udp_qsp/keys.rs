//! Packet protection keys and helpers.

use std::borrow::Cow;
use std::fmt;
use std::mem::MaybeUninit;

use boring::hash::hmac_sha256;
use boring_sys as ffi;

use super::packet::{
    OpenedPacket, OpenedPacketRef, apply_header_protection, build_header, hp_sample_range,
    parse_header, require_hp_sample,
};
use super::pn::{packet_number_len, reconstruct_packet_number};
use super::{AEAD_TAG_LEN, HP_MASK_LEN, HP_SAMPLE_LEN, QspCryptoError};
use crate::proto::{
    AEAD_IV_LEN, AEAD_KEY_LEN, CHACHA20_POLY1305_KEY_LEN, CipherSuite, HP_KEY_LEN,
    RegisterCidPayload,
};

#[derive(Clone, Copy)]
struct CipherConfig {
    hp: HeaderProtectionKind,
    aead: AeadKind,
    iv_len: usize,
}

#[derive(Clone, Copy)]
enum AeadKind {
    Aes128Gcm,
    ChaCha20Poly1305,
}

#[derive(Clone, Copy)]
enum HeaderProtectionKind {
    Aes128,
    ChaCha20,
}

impl AeadKind {
    #[inline]
    fn as_ptr(self) -> *const ffi::EVP_AEAD {
        match self {
            Self::Aes128Gcm => unsafe {
                // SAFETY: BoringSSL returns a process-global algorithm descriptor.
                ffi::EVP_aead_aes_128_gcm()
            },
            Self::ChaCha20Poly1305 => unsafe {
                // SAFETY: BoringSSL returns a process-global algorithm descriptor.
                ffi::EVP_aead_chacha20_poly1305()
            },
        }
    }

    const fn key_len(self) -> usize {
        match self {
            Self::Aes128Gcm => AEAD_KEY_LEN,
            Self::ChaCha20Poly1305 => CHACHA20_POLY1305_KEY_LEN,
        }
    }
}

impl HeaderProtectionKind {
    const fn key_len(self) -> usize {
        match self {
            Self::Aes128 => HP_KEY_LEN,
            Self::ChaCha20 => CHACHA20_POLY1305_KEY_LEN,
        }
    }
}

impl CipherConfig {
    const fn for_suite(cipher: CipherSuite) -> Self {
        match cipher {
            CipherSuite::Aes128Gcm => Self {
                hp: HeaderProtectionKind::Aes128,
                aead: AeadKind::Aes128Gcm,
                iv_len: AEAD_IV_LEN,
            },
            CipherSuite::ChaCha20Poly1305 => Self {
                hp: HeaderProtectionKind::ChaCha20,
                aead: AeadKind::ChaCha20Poly1305,
                iv_len: AEAD_IV_LEN,
            },
        }
    }

    const fn hp_key_len(self) -> usize {
        self.hp.key_len()
    }

    const fn aead_key_len(self) -> usize {
        self.aead.key_len()
    }

    const fn iv_len(self) -> usize {
        self.iv_len
    }
}

enum HeaderProtectionKey {
    Aes128 {
        key: Vec<u8>,
        encrypt_key: Box<ffi::AES_KEY>,
    },
    ChaCha20 {
        key: Vec<u8>,
    },
}

impl HeaderProtectionKey {
    fn new(kind: HeaderProtectionKind, key: &[u8]) -> Result<Self, QspCryptoError> {
        if key.len() != kind.key_len() {
            return Err(QspCryptoError::CryptoFail);
        }

        match kind {
            HeaderProtectionKind::Aes128 => {
                let mut encrypt_key = MaybeUninit::<ffi::AES_KEY>::zeroed();
                let key_bits =
                    u32::try_from(key.len() * 8).map_err(|_| QspCryptoError::CryptoFail)?;
                let rc = unsafe {
                    // SAFETY: `key` is exactly 128 bits and `encrypt_key` points to valid writable memory.
                    ffi::AES_set_encrypt_key(key.as_ptr(), key_bits, encrypt_key.as_mut_ptr())
                };
                if rc != 0 {
                    return Err(QspCryptoError::CryptoFail);
                }

                Ok(Self::Aes128 {
                    key: key.to_vec(),
                    encrypt_key: Box::new(unsafe {
                        // SAFETY: `AES_set_encrypt_key` returned success and initialized the key schedule.
                        encrypt_key.assume_init()
                    }),
                })
            }
            HeaderProtectionKind::ChaCha20 => Ok(Self::ChaCha20 { key: key.to_vec() }),
        }
    }

    fn mask(&self, sample: &[u8]) -> Result<[u8; HP_MASK_LEN], QspCryptoError> {
        if sample.len() != HP_SAMPLE_LEN {
            return Err(QspCryptoError::PacketTooShort);
        }

        match self {
            Self::Aes128 { encrypt_key, .. } => {
                let mut out = [0u8; HP_SAMPLE_LEN];
                unsafe {
                    // SAFETY: input and output are each 16-byte blocks and key schedule is initialized.
                    ffi::AES_encrypt(sample.as_ptr(), out.as_mut_ptr(), encrypt_key.as_ref());
                }

                let mut mask = [0u8; HP_MASK_LEN];
                mask.copy_from_slice(&out[..HP_MASK_LEN]);
                Ok(mask)
            }
            Self::ChaCha20 { key } => {
                let counter = u32::from_le_bytes(
                    sample[..4]
                        .try_into()
                        .map_err(|_| QspCryptoError::PacketTooShort)?,
                );
                let plaintext = [0u8; HP_MASK_LEN];
                let mut mask = [0u8; HP_MASK_LEN];
                unsafe {
                    // SAFETY: output/input are valid for 5 bytes, key is 32 bytes, and nonce is the
                    // remaining 12 bytes of the 16-byte HP sample.
                    ffi::CRYPTO_chacha_20(
                        mask.as_mut_ptr(),
                        plaintext.as_ptr(),
                        plaintext.len(),
                        key.as_ptr(),
                        sample[4..].as_ptr(),
                        counter,
                    );
                }
                Ok(mask)
            }
        }
    }

    fn key_material(&self) -> &[u8] {
        match self {
            Self::Aes128 { key, .. } | Self::ChaCha20 { key } => key,
        }
    }
}

impl Clone for HeaderProtectionKey {
    fn clone(&self) -> Self {
        match self {
            Self::Aes128 { key, .. } => Self::new(HeaderProtectionKind::Aes128, key),
            Self::ChaCha20 { key } => Self::new(HeaderProtectionKind::ChaCha20, key),
        }
        .expect("HP key material must remain valid")
    }
}

struct PacketKey {
    key: Vec<u8>,
    iv: [u8; AEAD_IV_LEN],
    aead: AeadKind,
    ctx: AeadContext,
}

impl PacketKey {
    fn new(key: &[u8], iv: &[u8], aead: AeadKind) -> Result<Self, QspCryptoError> {
        if iv.len() != AEAD_IV_LEN {
            return Err(QspCryptoError::CryptoFail);
        }
        let iv = iv.try_into().map_err(|_| QspCryptoError::CryptoFail)?;
        let ctx = AeadContext::new(aead, key)?;
        Ok(Self {
            key: key.to_vec(),
            iv,
            aead,
            ctx,
        })
    }

    fn seal_into(
        &self,
        pn: u64,
        ad_len: usize,
        plaintext: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), QspCryptoError> {
        let nonce = make_nonce(&self.iv, pn);
        let start = out.len();
        let max_out_len = plaintext.len() + AEAD_TAG_LEN;
        out.resize(start + max_out_len, 0);
        let (ad_and_prefix, ciphertext_out) = out.split_at_mut(start);
        let produced = self.ctx.seal(
            &nonce,
            &ad_and_prefix[..ad_len],
            plaintext,
            &mut ciphertext_out[..max_out_len],
        )?;
        out.truncate(start + produced);

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

        let ct = ciphertext;
        let nonce = make_nonce(&self.iv, pn);
        out.clear();
        out.resize(ct.len(), 0);
        let produced = self.ctx.open(&nonce, ad, ct, out)?;
        out.truncate(produced);
        Ok(())
    }
}

impl Clone for PacketKey {
    fn clone(&self) -> Self {
        Self::new(&self.key, &self.iv, self.aead)
            .expect("AEAD key material must remain valid for cloned PacketKey")
    }
}

#[derive(Clone)]
struct DirectionKeys {
    hp: HeaderProtectionKey,
    aead: PacketKey,
}

struct AeadContext {
    raw: *mut ffi::EVP_AEAD_CTX,
}

// SAFETY: `AeadContext` owns an `EVP_AEAD_CTX` pointer with stable allocation
// and no thread affinity. We never alias mutable Rust references to the same
// object, and BoringSSL's seal/open APIs take `const EVP_AEAD_CTX*`.
unsafe impl Send for AeadContext {}
// SAFETY: Operations use immutable pointers and are safe to call from shared
// references for stateless AEADs such as AES-128-GCM.
unsafe impl Sync for AeadContext {}

impl AeadContext {
    fn new(aead: AeadKind, key: &[u8]) -> Result<Self, QspCryptoError> {
        if key.len() != aead.key_len() {
            return Err(QspCryptoError::CryptoFail);
        }

        let aead_ptr = aead.as_ptr();
        if aead_ptr.is_null() {
            return Err(QspCryptoError::CryptoFail);
        }

        let raw = unsafe {
            // SAFETY: The AEAD algorithm pointer is valid and key buffer lives for this call.
            ffi::EVP_AEAD_CTX_new(aead_ptr, key.as_ptr(), key.len(), AEAD_TAG_LEN)
        };
        if raw.is_null() {
            return Err(QspCryptoError::CryptoFail);
        }

        Ok(Self { raw })
    }

    fn seal(
        &self,
        nonce: &[u8; AEAD_IV_LEN],
        ad: &[u8],
        plaintext: &[u8],
        out: &mut [u8],
    ) -> Result<usize, QspCryptoError> {
        let mut out_len = 0usize;
        let ok = unsafe {
            // SAFETY: `self.raw` is a live AEAD context and all pointers are valid for their lengths.
            ffi::EVP_AEAD_CTX_seal(
                self.raw,
                out.as_mut_ptr(),
                &raw mut out_len,
                out.len(),
                nonce.as_ptr(),
                nonce.len(),
                plaintext.as_ptr(),
                plaintext.len(),
                ad.as_ptr(),
                ad.len(),
            )
        };
        if ok != 1 {
            return Err(QspCryptoError::CryptoFail);
        }
        Ok(out_len)
    }

    fn open(
        &self,
        nonce: &[u8; AEAD_IV_LEN],
        ad: &[u8],
        ciphertext: &[u8],
        out: &mut [u8],
    ) -> Result<usize, QspCryptoError> {
        let mut out_len = 0usize;
        let ok = unsafe {
            // SAFETY: `self.raw` is a live AEAD context and all pointers are valid for their lengths.
            ffi::EVP_AEAD_CTX_open(
                self.raw,
                out.as_mut_ptr(),
                &raw mut out_len,
                out.len(),
                nonce.as_ptr(),
                nonce.len(),
                ciphertext.as_ptr(),
                ciphertext.len(),
                ad.as_ptr(),
                ad.len(),
            )
        };
        if ok != 1 {
            return Err(QspCryptoError::CryptoFail);
        }
        Ok(out_len)
    }
}

impl Drop for AeadContext {
    fn drop(&mut self) {
        unsafe {
            // SAFETY: `raw` comes from `EVP_AEAD_CTX_new` and may be null only if construction failed.
            ffi::EVP_AEAD_CTX_free(self.raw);
        }
    }
}

const KEY_UPDATE_CONTEXT: &[u8] = b"slt-udp-qsp/key-update-v1";
const KEY_UPDATE_HP_INFO: &[u8] = b"slt-udp-qsp/key-update-v1/hp";
const KEY_UPDATE_AEAD_INFO: &[u8] = b"slt-udp-qsp/key-update-v1/aead";
const KEY_UPDATE_IV_INFO: &[u8] = b"slt-udp-qsp/key-update-v1/iv";

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
    /// Build UDP-QSP keys from raw key material slices.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The cipher suite is unsupported
    /// - Key or IV material lengths do not match the cipher suite
    /// - Crypto key initialization fails
    pub fn new(
        cipher: CipherSuite,
        hp_tx: impl AsRef<[u8]>,
        hp_rx: impl AsRef<[u8]>,
        aead_tx: impl AsRef<[u8]>,
        aead_rx: impl AsRef<[u8]>,
        iv_tx: impl AsRef<[u8]>,
        iv_rx: impl AsRef<[u8]>,
    ) -> Result<Self, QspCryptoError> {
        let config = CipherConfig::for_suite(cipher);
        let hp_tx = hp_tx.as_ref();
        let hp_rx = hp_rx.as_ref();
        let aead_tx = aead_tx.as_ref();
        let aead_rx = aead_rx.as_ref();
        let iv_tx = iv_tx.as_ref();
        let iv_rx = iv_rx.as_ref();

        Ok(Self {
            cipher,
            tx: DirectionKeys {
                hp: HeaderProtectionKey::new(config.hp, hp_tx)?,
                aead: PacketKey::new(aead_tx, iv_tx, config.aead)?,
            },
            rx: DirectionKeys {
                hp: HeaderProtectionKey::new(config.hp, hp_rx)?,
                aead: PacketKey::new(aead_rx, iv_rx, config.aead)?,
            },
        })
    }

    /// Build UDP-QSP keys from a `REGISTER_CID` payload.
    ///
    /// # Errors
    ///
    /// Returns an error if the cipher suite is unsupported or crypto key
    /// initialization fails.
    pub fn from_register(payload: &RegisterCidPayload) -> Result<Self, QspCryptoError> {
        Self::new(
            payload.cipher,
            &payload.hp_tx,
            &payload.hp_rx,
            &payload.aead_tx,
            &payload.aead_rx,
            payload.iv_tx,
            payload.iv_rx,
        )
    }

    pub(crate) fn with_next_tx_keys(&self) -> Result<Self, QspCryptoError> {
        let config = CipherConfig::for_suite(self.cipher);
        Ok(Self {
            cipher: self.cipher,
            tx: derive_direction_keys(&self.tx, config)?,
            rx: self.rx.clone(),
        })
    }

    pub(crate) fn with_next_rx_keys(&self) -> Result<Self, QspCryptoError> {
        let config = CipherConfig::for_suite(self.cipher);
        Ok(Self {
            cipher: self.cipher,
            tx: self.tx.clone(),
            rx: derive_direction_keys(&self.rx, config)?,
        })
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
        let needed_capacity = target_len;
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

        let pn = reconstruct_packet_number(parsed.pn, expected_pn, parsed.pn_len);
        let plaintext_len = packet.len() - parsed.header.len() - AEAD_TAG_LEN;
        let needed_capacity = plaintext_len;
        if out.capacity() < needed_capacity {
            out.reserve_exact(needed_capacity - out.capacity());
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

#[inline]
fn make_nonce(iv: &[u8; AEAD_IV_LEN], counter: u64) -> [u8; AEAD_IV_LEN] {
    let mut nonce = *iv;
    for (a, b) in nonce[4..].iter_mut().zip(counter.to_be_bytes().iter()) {
        *a ^= b;
    }
    nonce
}

fn derive_direction_keys(
    current: &DirectionKeys,
    config: CipherConfig,
) -> Result<DirectionKeys, QspCryptoError> {
    let mut ikm = Vec::with_capacity(config.hp_key_len() + config.aead_key_len() + config.iv_len());
    ikm.extend_from_slice(current.hp.key_material());
    ikm.extend_from_slice(&current.aead.key);
    ikm.extend_from_slice(&current.aead.iv);

    let mut extract_input = Vec::with_capacity(KEY_UPDATE_CONTEXT.len() + ikm.len());
    extract_input.extend_from_slice(KEY_UPDATE_CONTEXT);
    extract_input.extend_from_slice(&ikm);
    let prk = hkdf_extract_sha256(&current.aead.iv, &extract_input)?;

    let next_iv = hkdf_expand_sha256_vec(&prk, KEY_UPDATE_IV_INFO, config.iv_len())?;
    Ok(DirectionKeys {
        hp: HeaderProtectionKey::new(
            config.hp,
            &hkdf_expand_sha256_vec(&prk, KEY_UPDATE_HP_INFO, config.hp_key_len())?,
        )?,
        aead: PacketKey::new(
            &hkdf_expand_sha256_vec(&prk, KEY_UPDATE_AEAD_INFO, config.aead_key_len())?,
            &next_iv,
            config.aead,
        )?,
    })
}

fn hkdf_extract_sha256(salt: &[u8], ikm: &[u8]) -> Result<[u8; 32], QspCryptoError> {
    hmac_sha256(salt, ikm).map_err(|_| QspCryptoError::CryptoFail)
}

fn hkdf_expand_sha256_vec(
    prk: &[u8; 32],
    info: &[u8],
    len: usize,
) -> Result<Vec<u8>, QspCryptoError> {
    if len == 0 {
        return Ok(Vec::new());
    }

    let mut out = Vec::with_capacity(len);
    let mut prev = [0u8; 32];
    let mut prev_len = 0usize;
    let mut counter = 1u8;

    while out.len() < len {
        let mut input = Vec::with_capacity(prev_len + info.len() + 1);
        if prev_len != 0 {
            input.extend_from_slice(&prev[..prev_len]);
        }
        input.extend_from_slice(info);
        input.push(counter);

        prev = hmac_sha256(prk, &input).map_err(|_| QspCryptoError::CryptoFail)?;
        prev_len = prev.len();

        let remaining = len - out.len();
        let take = remaining.min(prev_len);
        out.extend_from_slice(&prev[..take]);

        counter = counter.checked_add(1).ok_or(QspCryptoError::CryptoFail)?;
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{
        AEAD_IV_LEN, AEAD_KEY_LEN, CHACHA20_POLY1305_KEY_LEN, CipherSuite, HP_KEY_LEN,
    };

    /// Create keys where TX == RX for self-contained roundtrip tests.
    fn make_symmetric_keys() -> UdpQspKeys {
        UdpQspKeys::new(
            CipherSuite::Aes128Gcm,
            [0xAA; HP_KEY_LEN], // hp_tx == hp_rx
            [0xAA; HP_KEY_LEN],
            [0xBB; AEAD_KEY_LEN], // aead_tx == aead_rx
            [0xBB; AEAD_KEY_LEN],
            [0xCC; AEAD_IV_LEN], // iv_tx == iv_rx
            [0xCC; AEAD_IV_LEN],
        )
        .unwrap()
    }

    /// Create keys with distinct TX/RX for direction-specific tests.
    fn make_directional_keys() -> UdpQspKeys {
        UdpQspKeys::new(
            CipherSuite::Aes128Gcm,
            [0x11; HP_KEY_LEN],   // hp_tx
            [0x22; HP_KEY_LEN],   // hp_rx
            [0x33; AEAD_KEY_LEN], // aead_tx
            [0x44; AEAD_KEY_LEN], // aead_rx
            [0x55; AEAD_IV_LEN],  // iv_tx
            [0x66; AEAD_IV_LEN],  // iv_rx
        )
        .unwrap()
    }

    /// Create ChaCha20-Poly1305 keys where TX == RX for self-contained roundtrip tests.
    fn make_symmetric_chacha_keys() -> UdpQspKeys {
        UdpQspKeys::new(
            CipherSuite::ChaCha20Poly1305,
            &[0xAA; CHACHA20_POLY1305_KEY_LEN],
            &[0xAA; CHACHA20_POLY1305_KEY_LEN],
            &[0xBB; CHACHA20_POLY1305_KEY_LEN],
            &[0xBB; CHACHA20_POLY1305_KEY_LEN],
            &[0xCC; AEAD_IV_LEN],
            &[0xCC; AEAD_IV_LEN],
        )
        .unwrap()
    }

    /// Create ChaCha20-Poly1305 keys with distinct TX/RX for direction-specific tests.
    fn make_directional_chacha_keys() -> UdpQspKeys {
        UdpQspKeys::new(
            CipherSuite::ChaCha20Poly1305,
            &[0x11; CHACHA20_POLY1305_KEY_LEN],
            &[0x22; CHACHA20_POLY1305_KEY_LEN],
            &[0x33; CHACHA20_POLY1305_KEY_LEN],
            &[0x44; CHACHA20_POLY1305_KEY_LEN],
            &[0x55; AEAD_IV_LEN],
            &[0x66; AEAD_IV_LEN],
        )
        .unwrap()
    }

    #[test]
    fn new_keys_with_aes128gcm_succeeds() {
        let keys = UdpQspKeys::new(
            CipherSuite::Aes128Gcm,
            [0u8; HP_KEY_LEN],
            [0u8; HP_KEY_LEN],
            [0u8; AEAD_KEY_LEN],
            [0u8; AEAD_KEY_LEN],
            [0u8; AEAD_IV_LEN],
            [0u8; AEAD_IV_LEN],
        );
        assert!(keys.is_ok());
    }

    #[test]
    fn new_keys_with_chacha20_poly1305_succeeds() {
        let keys = UdpQspKeys::new(
            CipherSuite::ChaCha20Poly1305,
            &[0u8; CHACHA20_POLY1305_KEY_LEN],
            &[0u8; CHACHA20_POLY1305_KEY_LEN],
            &[0u8; CHACHA20_POLY1305_KEY_LEN],
            &[0u8; CHACHA20_POLY1305_KEY_LEN],
            &[0u8; AEAD_IV_LEN],
            &[0u8; AEAD_IV_LEN],
        );
        assert!(keys.is_ok());
    }

    #[test]
    fn chacha20_poly1305_protect_and_open_roundtrip() {
        let dcid = [0xAB; 8];
        let plaintext = b"hello with chacha20-poly1305";
        let pn = 7;

        let keys = make_symmetric_chacha_keys();
        let protected = keys.protect(&dcid, pn, true, plaintext).unwrap();

        let opened = keys.open(dcid.len(), &protected, pn).unwrap();
        assert_eq!(opened.pn, pn);
        assert!(opened.key_phase);
        assert_eq!(opened.payload, plaintext);
    }

    #[test]
    fn chacha20_poly1305_rejects_wrong_key_lengths() {
        let keys = UdpQspKeys::new(
            CipherSuite::ChaCha20Poly1305,
            &[0u8; HP_KEY_LEN],
            &[0u8; CHACHA20_POLY1305_KEY_LEN],
            &[0u8; CHACHA20_POLY1305_KEY_LEN],
            &[0u8; CHACHA20_POLY1305_KEY_LEN],
            &[0u8; AEAD_IV_LEN],
            &[0u8; AEAD_IV_LEN],
        );
        assert!(matches!(keys, Err(QspCryptoError::CryptoFail)));
    }

    #[test]
    fn with_next_tx_keys_produces_valid_keys() {
        let keys = make_directional_keys();
        let next = keys.with_next_tx_keys();
        assert!(next.is_ok());
    }

    #[test]
    fn with_next_rx_keys_produces_valid_keys() {
        let keys = make_directional_keys();
        let next = keys.with_next_rx_keys();
        assert!(next.is_ok());
    }

    #[test]
    fn tx_key_rotation_changes_encrypt_keys() {
        let dcid = [0xAB; 8];
        let plaintext = b"test payload";
        let pn = 42;

        let keys = make_directional_keys();
        let next_keys = keys.with_next_tx_keys().unwrap();

        // Encrypt with original keys
        let packet_original = keys.protect(&dcid, pn, false, plaintext).unwrap();

        // Encrypt with rotated keys
        let packet_rotated = next_keys.protect(&dcid, pn, false, plaintext).unwrap();

        // Different keys should produce different ciphertext
        assert_ne!(
            packet_original, packet_rotated,
            "rotated TX keys should produce different ciphertext"
        );
    }

    #[test]
    fn rx_key_rotation_changes_decrypt_keys() {
        let dcid = [0xAB; 8];
        let plaintext = b"test payload";
        let pn = 42;

        // Use symmetric keys so original keys can protect AND open
        let keys = make_symmetric_keys();
        let next_keys = keys.with_next_rx_keys().unwrap();

        // Encrypt with original keys (TX)
        let packet = keys.protect(&dcid, pn, false, plaintext).unwrap();

        // Original keys can decrypt (RX == TX in symmetric)
        let opened = keys.open(dcid.len(), &packet, pn);
        assert!(opened.is_ok());

        // Rotated RX keys cannot decrypt (different RX keys)
        let opened_rotated = next_keys.open(dcid.len(), &packet, pn);
        assert!(
            opened_rotated.is_err(),
            "rotated RX keys should not decrypt packets from original keys"
        );
    }

    #[test]
    fn tx_rotation_rx_keys_match_after_rotation() {
        // Test that RX keys are unchanged after TX rotation by using two key sets
        // that share the same RX direction (simulating client/server)
        let dcid = [0xAB; 8];
        let plaintext = b"test payload";
        let pn = 42;

        // Create "server" keys where TX and RX are distinct
        let server_tx = [0x33; AEAD_KEY_LEN];
        let server_rx = [0x44; AEAD_KEY_LEN];
        let server_iv_tx = [0x55; AEAD_IV_LEN];
        let server_iv_rx = [0x66; AEAD_IV_LEN];
        let server_hp_tx = [0x11; HP_KEY_LEN];
        let server_hp_rx = [0x22; HP_KEY_LEN];

        // Server keys
        let server_keys = UdpQspKeys::new(
            CipherSuite::Aes128Gcm,
            server_hp_tx,
            server_hp_rx,
            server_tx,
            server_rx,
            server_iv_tx,
            server_iv_rx,
        )
        .unwrap();

        // Rotate server's TX keys - RX should stay the same
        let server_next = server_keys.with_next_tx_keys().unwrap();

        // Create a "peer" that has TX=server's RX and RX=server's original TX
        // This simulates the other party in the communication
        let peer_keys = UdpQspKeys::new(
            CipherSuite::Aes128Gcm,
            server_hp_rx, // peer's hp_tx = server's hp_rx
            server_hp_tx, // peer's hp_rx = server's hp_tx
            server_rx,    // peer's aead_tx = server's aead_rx
            server_tx,    // peer's aead_rx = server's aead_tx
            server_iv_rx, // peer's iv_tx = server's iv_rx
            server_iv_tx, // peer's iv_rx = server's iv_tx
        )
        .unwrap();

        // Peer encrypts with its TX (which is server's original RX)
        let packet = peer_keys.protect(&dcid, pn, false, plaintext).unwrap();

        // Both server_keys and server_next should be able to decrypt
        // because RX keys are preserved after TX rotation
        let opened_orig = server_keys.open(dcid.len(), &packet, pn);
        let opened_next = server_next.open(dcid.len(), &packet, pn);

        assert!(opened_orig.is_ok(), "original server RX should decrypt");
        assert!(
            opened_next.is_ok(),
            "rotated server RX should still decrypt (RX unchanged)"
        );
        assert_eq!(opened_orig.unwrap().payload, plaintext);
        assert_eq!(opened_next.unwrap().payload, plaintext);
    }

    #[test]
    fn rx_rotation_preserves_tx_keys() {
        let dcid = [0xAB; 8];
        let plaintext = b"test payload";
        let pn = 42;

        let keys = make_directional_keys();
        let next_rx = keys.with_next_rx_keys().unwrap();

        // Both can encrypt (same TX keys)
        let packet_orig = keys.protect(&dcid, pn, false, plaintext).unwrap();
        let packet_next = next_rx.protect(&dcid, pn, false, plaintext).unwrap();

        // Same TX keys should produce same ciphertext
        assert_eq!(
            packet_orig, packet_next,
            "same TX keys should produce identical ciphertext"
        );
    }

    #[test]
    fn chacha20_poly1305_tx_key_rotation_changes_encrypt_keys() {
        let dcid = [0xAB; 8];
        let plaintext = b"test payload";
        let pn = 42;

        let keys = make_directional_chacha_keys();
        let next_keys = keys.with_next_tx_keys().unwrap();

        let packet_original = keys.protect(&dcid, pn, false, plaintext).unwrap();
        let packet_rotated = next_keys.protect(&dcid, pn, true, plaintext).unwrap();

        assert_ne!(
            packet_original, packet_rotated,
            "rotated ChaCha TX keys should produce different ciphertext"
        );
    }

    #[test]
    fn chacha20_poly1305_rx_key_rotation_derives_working_next_keys() {
        let dcid = [0xAB; 8];
        let plaintext = b"test payload";
        let pn = 42;

        let keys = make_symmetric_chacha_keys();
        let tx_next = keys.with_next_tx_keys().unwrap();
        let rx_next = keys.with_next_rx_keys().unwrap();
        let packet = tx_next.protect(&dcid, pn, true, plaintext).unwrap();

        let opened = rx_next.open(dcid.len(), &packet, pn).unwrap();
        assert_eq!(opened.payload, plaintext);
        assert!(opened.key_phase);
    }

    #[test]
    fn chacha20_poly1305_old_and_new_phase_packets_use_matching_keys() {
        let dcid = [0xAB; 8];
        let plaintext = b"test payload";
        let pn = 42;

        let keys = make_symmetric_chacha_keys();
        let tx_next = keys.with_next_tx_keys().unwrap();
        let rx_next = keys.with_next_rx_keys().unwrap();

        let old_phase = keys.protect(&dcid, pn, false, plaintext).unwrap();
        let new_phase = tx_next.protect(&dcid, pn, true, plaintext).unwrap();

        let opened_old = keys.open(dcid.len(), &old_phase, pn).unwrap();
        let opened_new = rx_next.open(dcid.len(), &new_phase, pn).unwrap();
        assert_eq!(opened_old.payload, plaintext);
        assert!(!opened_old.key_phase);
        assert_eq!(opened_new.payload, plaintext);
        assert!(opened_new.key_phase);

        assert!(keys.open(dcid.len(), &new_phase, pn).is_err());
        assert!(rx_next.open(dcid.len(), &old_phase, pn).is_err());
    }

    #[test]
    fn multiple_tx_rotations_produce_different_keys() {
        let dcid = [0xAB; 8];
        let plaintext = b"test payload";
        let pn = 42;

        let keys = make_directional_keys();
        let keys1 = keys.with_next_tx_keys().unwrap();
        let keys2 = keys1.with_next_tx_keys().unwrap();
        let keys3 = keys2.with_next_tx_keys().unwrap();

        let p0 = keys.protect(&dcid, pn, false, plaintext).unwrap();
        let p1 = keys1.protect(&dcid, pn, true, plaintext).unwrap();
        let p2 = keys2.protect(&dcid, pn, false, plaintext).unwrap();
        let p3 = keys3.protect(&dcid, pn, true, plaintext).unwrap();

        // Each rotation should produce different output
        assert_ne!(p0, p1);
        assert_ne!(p1, p2);
        assert_ne!(p2, p3);
        assert_ne!(p0, p2);
        assert_ne!(p1, p3);
    }

    #[test]
    fn multiple_rx_rotations_produce_different_keys() {
        let dcid = [0xAB; 8];
        let plaintext = b"test payload";
        let pn = 42;

        // Use symmetric keys as the base
        let keys = make_symmetric_keys();

        // Rotate RX multiple times
        let rx1 = keys.with_next_rx_keys().unwrap();
        let rx2 = rx1.with_next_rx_keys().unwrap();
        let rx3 = rx2.with_next_rx_keys().unwrap();

        // Rotate TX the same number of times to create matching keys
        let tx1 = keys.with_next_tx_keys().unwrap();
        let tx2 = tx1.with_next_tx_keys().unwrap();
        let tx3 = tx2.with_next_tx_keys().unwrap();

        // Encrypt with each TX generation (these are symmetric)
        let p1 = tx1.protect(&dcid, pn, true, plaintext).unwrap();
        let p2 = tx2.protect(&dcid, pn, false, plaintext).unwrap();
        let p3 = tx3.protect(&dcid, pn, true, plaintext).unwrap();

        // Each RX generation should only decrypt its matching TX generation
        assert!(rx1.open(dcid.len(), &p1, pn).is_ok(), "rx1 should open p1");
        assert!(rx2.open(dcid.len(), &p2, pn).is_ok(), "rx2 should open p2");
        assert!(rx3.open(dcid.len(), &p3, pn).is_ok(), "rx3 should open p3");

        // Cross-decryption should fail
        assert!(
            rx1.open(dcid.len(), &p2, pn).is_err(),
            "rx1 should not open p2"
        );
        assert!(
            rx2.open(dcid.len(), &p3, pn).is_err(),
            "rx2 should not open p3"
        );
        assert!(
            rx3.open(dcid.len(), &p1, pn).is_err(),
            "rx3 should not open p1"
        );
    }

    #[test]
    fn hkdf_expand_produces_expected_length() {
        // Test the HKDF expand function produces correct output lengths
        let prk = [0x42u8; 32];
        let info = b"test info";

        // Test various output lengths
        let out16 = hkdf_expand_sha256_vec(&prk, info, 16).unwrap();
        assert_eq!(out16.len(), 16);

        let out32 = hkdf_expand_sha256_vec(&prk, info, 32).unwrap();
        assert_eq!(out32.len(), 32);

        let out64 = hkdf_expand_sha256_vec(&prk, info, 64).unwrap();
        assert_eq!(out64.len(), 64);
    }

    #[test]
    fn hkdf_expand_deterministic() {
        let prk = [0x42u8; 32];
        let info = b"test info";

        let out1 = hkdf_expand_sha256_vec(&prk, info, 32).unwrap();
        let out2 = hkdf_expand_sha256_vec(&prk, info, 32).unwrap();

        assert_eq!(out1, out2, "HKDF expand should be deterministic");
    }

    #[test]
    fn hkdf_expand_different_info_produces_different_output() {
        let prk = [0x42u8; 32];

        let out1 = hkdf_expand_sha256_vec(&prk, b"info 1", 32).unwrap();
        let out2 = hkdf_expand_sha256_vec(&prk, b"info 2", 32).unwrap();

        assert_ne!(out1, out2, "different info should produce different output");
    }

    #[test]
    fn hkdf_expand_different_prk_produces_different_output() {
        let prk1 = [0x42u8; 32];
        let prk2 = [0x24u8; 32];
        let info = b"test info";

        let out1 = hkdf_expand_sha256_vec(&prk1, info, 32).unwrap();
        let out2 = hkdf_expand_sha256_vec(&prk2, info, 32).unwrap();

        assert_ne!(out1, out2, "different PRK should produce different output");
    }

    #[test]
    fn hkdf_extract_produces_32_bytes() {
        let salt = [0x01u8; 12];
        let ikm = b"input key material";

        let prk = hkdf_extract_sha256(&salt, ikm);
        assert!(prk.is_ok());
        assert_eq!(prk.unwrap().len(), 32);
    }

    #[test]
    fn hkdf_extract_deterministic() {
        let salt = [0x01u8; 12];
        let ikm = b"input key material";

        let prk1 = hkdf_extract_sha256(&salt, ikm).unwrap();
        let prk2 = hkdf_extract_sha256(&salt, ikm).unwrap();

        assert_eq!(prk1, prk2, "HKDF extract should be deterministic");
    }

    #[test]
    fn hkdf_extract_different_salt_different_output() {
        let salt1 = [0x01u8; 12];
        let salt2 = [0x02u8; 12];
        let ikm = b"input key material";

        let prk1 = hkdf_extract_sha256(&salt1, ikm).unwrap();
        let prk2 = hkdf_extract_sha256(&salt2, ikm).unwrap();

        assert_ne!(prk1, prk2, "different salt should produce different PRK");
    }

    #[test]
    fn protect_and_open_roundtrip() {
        let dcid = [0xAB; 8];
        let plaintext = b"hello, world!";
        let pn = 1;

        let keys = make_symmetric_keys();
        let protected = keys.protect(&dcid, pn, false, plaintext).unwrap();

        let opened = keys.open(dcid.len(), &protected, pn).unwrap();
        assert_eq!(opened.pn, pn);
        assert!(!opened.key_phase);
        assert_eq!(opened.payload, plaintext);
    }

    #[test]
    fn protect_and_open_with_different_dcids() {
        let dcid1 = [0x01; 8];
        let dcid2 = [0x02; 8];
        let plaintext = b"hello";
        let pn = 1;

        let keys = make_symmetric_keys();
        let protected1 = keys.protect(&dcid1, pn, false, plaintext).unwrap();
        let protected2 = keys.protect(&dcid2, pn, false, plaintext).unwrap();

        // Different DCIDs should produce different packets
        assert_ne!(protected1, protected2);

        // Each should decrypt with its respective DCID length
        let opened1 = keys.open(dcid1.len(), &protected1, pn).unwrap();
        assert_eq!(opened1.payload, plaintext);

        let opened2 = keys.open(dcid2.len(), &protected2, pn).unwrap();
        assert_eq!(opened2.payload, plaintext);
    }

    #[test]
    fn debug_redacts_key_material() {
        let keys = make_directional_keys();
        let debug_str = format!("{keys:?}");

        assert!(debug_str.contains("UdpQspKeys"));
        assert!(debug_str.contains("cipher"));
        assert!(debug_str.contains("<redacted>"));
        assert!(!debug_str.contains("0x11")); // The actual key bytes shouldn't appear
    }
}
