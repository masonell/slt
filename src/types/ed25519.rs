use serde::{Deserialize, Serialize};

/// Ed25519 public key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(transparent)]
#[serde(transparent)]
pub struct PubKeyEd25519(#[serde(with = "crate::types::serde::hex")] pub [u8; 32]);

impl PubKeyEd25519 {
    /// Returns the raw public key bytes.
    #[inline]
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Ed25519 private key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(transparent)]
#[serde(transparent)]
pub struct PrivKeyEd25519(#[serde(with = "crate::types::serde::secret")] pub [u8; 32]);

impl PrivKeyEd25519 {
    /// Returns the raw private key bytes.
    #[inline]
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}
