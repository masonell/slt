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

#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};

    use super::*;

    #[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
    struct SecretWrapper {
        #[serde(with = "crate::types::serde::secret")]
        secret: [u8; 32],
    }

    #[test]
    fn construction_and_as_bytes() {
        let bytes = [0x42; 32];
        let secret = SharedSecret(bytes);
        assert_eq!(secret.as_bytes(), &bytes);
    }

    #[test]
    fn serde_roundtrip() {
        let original = SecretWrapper { secret: [0xAB; 32] };
        let toml_str = toml::to_string(&original).unwrap();
        let parsed: SecretWrapper = toml::from_str(&toml_str).unwrap();
        assert_eq!(original.secret, parsed.secret);
    }

    #[test]
    fn equality_comparison() {
        let secret1 = SharedSecret([0x11; 32]);
        let secret2 = SharedSecret([0x11; 32]);
        let secret3 = SharedSecret([0x22; 32]);

        assert_eq!(secret1, secret2);
        assert_ne!(secret1, secret3);
    }

    #[test]
    fn rejects_wrong_length_hex() {
        let short_hex = "secret = { hex = \"abcdef\" }";
        let result: Result<SecretWrapper, _> = toml::from_str(short_hex);
        assert!(result.is_err());
    }

    #[test]
    fn rejects_invalid_hex_chars() {
        let invalid_hex = "secret = { hex = \
                           \"gg00000000000000000000000000000000000000000000000000000000000000gg\" }";
        let result: Result<SecretWrapper, _> = toml::from_str(invalid_hex);
        assert!(result.is_err());
    }
}
