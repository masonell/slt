use std::fmt;

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

impl fmt::Display for ClientId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Display as hex string (32 lowercase hex characters)
        for byte in &self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}
