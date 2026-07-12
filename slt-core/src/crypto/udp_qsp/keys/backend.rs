//! BoringSSL-backed header and packet protection primitives.

use std::mem::MaybeUninit;

use boring_sys as ffi;

use super::super::{AEAD_TAG_LEN, HP_MASK_LEN, HP_SAMPLE_LEN, QspCryptoError};
use crate::proto::{AEAD_IV_LEN, AEAD_KEY_LEN, CHACHA20_POLY1305_KEY_LEN, CipherSuite, HP_KEY_LEN};

#[derive(Clone, Copy)]
pub(super) struct CipherConfig {
    hp: HeaderProtectionKind,
    aead: AeadKind,
    iv_len: usize,
}

#[derive(Clone, Copy)]
pub(super) enum AeadKind {
    Aes128Gcm,
    ChaCha20Poly1305,
}

#[derive(Clone, Copy)]
pub(super) enum HeaderProtectionKind {
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
    pub(super) const fn for_suite(cipher: CipherSuite) -> Self {
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

    pub(super) const fn header_protection_kind(self) -> HeaderProtectionKind {
        self.hp
    }

    pub(super) const fn aead_kind(self) -> AeadKind {
        self.aead
    }

    pub(super) const fn hp_key_len(self) -> usize {
        self.hp.key_len()
    }

    pub(super) const fn aead_key_len(self) -> usize {
        self.aead.key_len()
    }

    pub(super) const fn iv_len(self) -> usize {
        self.iv_len
    }
}

pub(super) enum HeaderProtectionKey {
    Aes128 {
        key: Vec<u8>,
        encrypt_key: Box<ffi::AES_KEY>,
    },
    ChaCha20 {
        key: Vec<u8>,
    },
}

impl HeaderProtectionKey {
    pub(super) fn new(kind: HeaderProtectionKind, key: &[u8]) -> Result<Self, QspCryptoError> {
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

    pub(super) fn mask(&self, sample: &[u8]) -> Result<[u8; HP_MASK_LEN], QspCryptoError> {
        if sample.len() != HP_SAMPLE_LEN {
            return Err(QspCryptoError::PacketTooShort);
        }

        match self {
            Self::Aes128 { encrypt_key, .. } => {
                // RFC 9001 Section 5.4.3: the mask is the first 5 bytes of a
                // single-block AES-ECB encryption of the sample.
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
                // RFC 9001 Section 5.4.4: the mask is ChaCha20 encryption of 5
                // zero bytes under the header-protection key, with sample[0..4]
                // as the little-endian block counter and sample[4..16] as the
                // 12-byte nonce.
                let counter = u32::from_le_bytes(
                    sample[..4]
                        .try_into()
                        .map_err(|_| QspCryptoError::PacketTooShort)?,
                );
                let plaintext = [0u8; HP_MASK_LEN];
                let mut mask = [0u8; HP_MASK_LEN];
                unsafe {
                    // SAFETY: output/input buffers are valid for 5 bytes, key is 32
                    // bytes, and the nonce slice is valid for 12 bytes.
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

    pub(super) fn try_clone(&self) -> Result<Self, QspCryptoError> {
        match self {
            Self::Aes128 { key, .. } => Self::new(HeaderProtectionKind::Aes128, key),
            Self::ChaCha20 { key } => Self::new(HeaderProtectionKind::ChaCha20, key),
        }
    }

    #[cfg(test)]
    pub(super) fn key_bytes(&self) -> &[u8] {
        match self {
            Self::Aes128 { key, .. } | Self::ChaCha20 { key } => key,
        }
    }
}

pub(super) struct PacketKey {
    key: Vec<u8>,
    iv: [u8; AEAD_IV_LEN],
    aead: AeadKind,
    ctx: AeadContext,
}

impl PacketKey {
    pub(super) fn new(key: &[u8], iv: &[u8], aead: AeadKind) -> Result<Self, QspCryptoError> {
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

    pub(super) fn seal_into(
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

    pub(super) fn open_into(
        &self,
        pn: u64,
        ad: &[u8],
        ciphertext: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), QspCryptoError> {
        if ciphertext.len() < AEAD_TAG_LEN {
            return Err(QspCryptoError::PacketTooShort);
        }

        let nonce = make_nonce(&self.iv, pn);
        out.clear();
        out.resize(ciphertext.len(), 0);
        let produced = self.ctx.open(&nonce, ad, ciphertext, out)?;
        out.truncate(produced);
        Ok(())
    }

    pub(super) fn try_clone(&self) -> Result<Self, QspCryptoError> {
        Self::new(&self.key, &self.iv, self.aead)
    }

    #[cfg(test)]
    pub(super) fn key_bytes(&self) -> &[u8] {
        &self.key
    }

    #[cfg(test)]
    pub(super) const fn iv(&self) -> &[u8; AEAD_IV_LEN] {
        &self.iv
    }
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
            // SAFETY: `raw` comes from `EVP_AEAD_CTX_new` and is valid after successful construction.
            ffi::EVP_AEAD_CTX_free(self.raw);
        }
    }
}

/// QUIC per-packet AEAD nonce (RFC 9001 Section 5.3): the IV with its low 8 bytes
/// XOR'd against the big-endian packet number. AEAD security requires that
/// `(key, counter)` never repeat for a given key — callers must pass a
/// monotonically unique packet number.
#[inline]
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
    fn chacha20_poly1305_rejects_wrong_key_lengths() {
        assert!(matches!(
            HeaderProtectionKey::new(HeaderProtectionKind::ChaCha20, &[0u8; HP_KEY_LEN]),
            Err(QspCryptoError::CryptoFail)
        ));
        assert!(matches!(
            PacketKey::new(
                &[0u8; AEAD_KEY_LEN],
                &[0u8; AEAD_IV_LEN],
                AeadKind::ChaCha20Poly1305,
            ),
            Err(QspCryptoError::CryptoFail)
        ));
    }

    #[test]
    fn packet_key_open_accepts_tag_only_ciphertext() {
        let key = PacketKey::new(
            &[0xBB; AEAD_KEY_LEN],
            &[0xCC; AEAD_IV_LEN],
            AeadKind::Aes128Gcm,
        )
        .unwrap();
        let ad = b"associated data";
        let mut sealed = ad.to_vec();
        key.seal_into(7, ad.len(), b"", &mut sealed).unwrap();
        let tag_only = &sealed[ad.len()..];
        assert_eq!(tag_only.len(), AEAD_TAG_LEN);

        let mut opened = Vec::new();
        key.open_into(7, ad, tag_only, &mut opened).unwrap();
        assert!(opened.is_empty());
    }
}
