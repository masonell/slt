use serde::{Deserialize, Serialize};

/// Pre-shared secret for `ClientHello` classification.
///
/// Used by both client and server to generate/verify the `legacy_session_id`
/// in TLS `ClientHello` packets via HMAC-SHA256.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(transparent)]
#[serde(transparent)]
pub struct SharedSecret(#[serde(with = "crate::types::serde::secret")] pub [u8; 32]);

impl SharedSecret {
    /// Returns the raw secret bytes.
    #[inline]
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}
