//! Client ID parsing utilities.
//!
//! Provides shared functionality for parsing 16-byte client IDs from hex strings.

use anyhow::{Context, Result, bail};

/// Parse a 16-byte client ID from a hex string.
///
/// Accepts optional `0x` prefix. The input must be exactly 32 hex characters
/// representing 16 bytes.
///
/// # Errors
///
/// Returns an error if:
/// - The string contains invalid hex characters
/// - The decoded length is not exactly 16 bytes
///
/// # Examples
///
/// ```
/// # use slt_cli::client_id::parse_client_id;
/// let id = parse_client_id("0102030405060708090a0b0c0d0e0f10").unwrap();
/// assert_eq!(id.len(), 16);
/// ```
pub fn parse_client_id(s: &str) -> Result<[u8; 16]> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(s).context("invalid client ID: expected 32 hex characters")?;
    if bytes.len() != 16 {
        bail!(
            "invalid client ID: expected 16 bytes (32 hex chars), got {} bytes",
            bytes.len()
        );
    }
    let mut arr = [0u8; 16];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_client_id() {
        let result = parse_client_id("0102030405060708090a0b0c0d0e0f10");
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap(),
            [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]
        );
    }

    #[test]
    fn parse_with_0x_prefix() {
        let result = parse_client_id("0x0102030405060708090a0b0c0d0e0f10");
        assert!(result.is_ok());
    }

    #[test]
    fn parse_too_short() {
        let result = parse_client_id("01020304");
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("expected 16 bytes")
        );
    }

    #[test]
    fn parse_invalid_hex() {
        let result = parse_client_id("not-valid-hex!");
        assert!(result.is_err());
    }
}
