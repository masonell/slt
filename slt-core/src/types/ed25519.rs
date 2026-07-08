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
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(transparent)]
#[serde(transparent)]
pub struct PrivKeyEd25519(#[serde(with = "crate::types::serde::secret")] pub [u8; 32]);

impl std::fmt::Debug for PrivKeyEd25519 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PrivKeyEd25519(<redacted>)")
    }
}

impl PrivKeyEd25519 {
    /// Returns the raw private key bytes.
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
    struct PubKeyWrapper {
        #[serde(with = "crate::types::serde::hex")]
        key: [u8; 32],
    }

    #[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
    struct PrivKeyWrapper {
        #[serde(with = "crate::types::serde::secret")]
        key: [u8; 32],
    }

    #[test]
    fn pubkey_as_bytes_returns_correct_slice() {
        let bytes = [0xAA; 32];
        let key = PubKeyEd25519(bytes);
        assert_eq!(key.as_bytes(), &bytes);
    }

    #[test]
    fn privkey_as_bytes_returns_correct_slice() {
        let bytes = [0xBB; 32];
        let key = PrivKeyEd25519(bytes);
        assert_eq!(key.as_bytes(), &bytes);
    }

    #[test]
    fn privkey_debug_redacts_key_bytes() {
        let bytes = [0xBC; 32];
        let key = PrivKeyEd25519(bytes);
        let rendered = format!("{key:?}");

        assert_eq!(rendered, "PrivKeyEd25519(<redacted>)");
        assert!(!rendered.contains(&format!("{bytes:?}")));
        assert!(!rendered.contains(&hex::encode(bytes)));
    }

    #[test]
    fn pubkey_serde_roundtrip() {
        let original = PubKeyWrapper { key: [0xAA; 32] };
        let toml_str = toml::to_string(&original).unwrap();
        let parsed: PubKeyWrapper = toml::from_str(&toml_str).unwrap();
        assert_eq!(original.key, parsed.key);
    }

    #[test]
    fn privkey_serde_roundtrip() {
        let original = PrivKeyWrapper { key: [0xBB; 32] };
        let toml_str = toml::to_string(&original).unwrap();
        let parsed: PrivKeyWrapper = toml::from_str(&toml_str).unwrap();
        assert_eq!(original.key, parsed.key);
    }

    #[test]
    fn pubkey_rejects_wrong_length_hex() {
        let short_hex = "key = \"abcdef\""; // 3 bytes instead of 32
        let result: Result<PubKeyWrapper, _> = toml::from_str(short_hex);
        assert!(result.is_err());
    }

    #[test]
    fn privkey_rejects_wrong_length_hex() {
        let short_hex = "key = { hex = \"abcdef\" }";
        let result: Result<PrivKeyWrapper, _> = toml::from_str(short_hex);
        assert!(result.is_err());
    }

    #[test]
    fn pubkey_rejects_invalid_hex_chars() {
        let invalid_hex =
            "key = \"gg00000000000000000000000000000000000000000000000000000000000000gg\"";
        let result: Result<PubKeyWrapper, _> = toml::from_str(invalid_hex);
        assert!(result.is_err());
    }

    #[test]
    fn privkey_rejects_invalid_hex_chars() {
        let invalid_hex = "key = { hex = \
                           \"gg00000000000000000000000000000000000000000000000000000000000000gg\" }";
        let result: Result<PrivKeyWrapper, _> = toml::from_str(invalid_hex);
        assert!(result.is_err());
    }
}
