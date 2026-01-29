use serde::{Deserialize, Serialize};

/// Stable 16-byte client identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(transparent)]
#[serde(transparent)]
pub struct ClientId(#[serde(with = "crate::types::serde::hex")] pub [u8; 16]);

impl ClientId {
    /// Returns the raw client id bytes.
    #[inline]
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}
