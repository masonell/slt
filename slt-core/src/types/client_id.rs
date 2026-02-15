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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_outputs_lowercase_hex() {
        let id = ClientId([
            0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0x9A, 0xBC, 0xDE, 0xF0, 0x12, 0x34,
            0x56, 0x78,
        ]);
        let displayed = format!("{id}");
        assert_eq!(displayed.len(), 32);
        assert!(
            displayed
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        );
        assert_eq!(displayed, "abcdef01234567899abcdef012345678");
    }

    #[test]
    fn display_round_trip_is_stable() {
        let original_bytes = [
            0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0x9A, 0xBC, 0xDE, 0xF0, 0x12, 0x34,
            0x56, 0x78,
        ];
        let id = ClientId(original_bytes);

        // Display to hex string
        let hex_string = format!("{id}");

        // Parse hex back to bytes
        let parsed_bytes: [u8; 16] = (0..16)
            .map(|i| u8::from_str_radix(&hex_string[i * 2..i * 2 + 2], 16).unwrap())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        // Create new ClientId and display again
        let parsed_id = ClientId(parsed_bytes);
        let round_trip_hex = format!("{parsed_id}");

        // Verify stability
        assert_eq!(hex_string, round_trip_hex);
        assert_eq!(original_bytes, parsed_bytes);
    }
}
