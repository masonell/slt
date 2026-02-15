use serde::{Deserialize, Deserializer, Serializer, de};

/// Serialize a fixed-size byte array as lowercase hex.
///
/// # Errors
///
/// Returns the serializer's error if the string cannot be serialized.
pub fn serialize<const N: usize, S>(bytes: &[u8; N], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&hex::encode(bytes))
}

/// Decode a hex string (optionally prefixed with `0x`) to a fixed-size byte array.
///
/// # Errors
///
/// Returns an error if the hex is invalid or the decoded length doesn't match `N`.
pub fn decode_hex<const N: usize>(input: &str) -> Result<[u8; N], String> {
    let s = input.trim();
    let s = s.strip_prefix("0x").unwrap_or(s);
    let decoded = hex::decode(s).map_err(|e| e.to_string())?;
    if decoded.len() != N {
        return Err(format!("expected {N} bytes, got {}", decoded.len()));
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&decoded);
    Ok(out)
}

/// Deserialize a fixed-size byte array from hex (optionally prefixed with 0x).
///
/// # Errors
///
/// Returns the deserializer's error if the input is not a valid string or contains invalid hex.
pub fn deserialize<'de, const N: usize, D>(deserializer: D) -> Result<[u8; N], D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    decode_hex::<N>(&s).map_err(de::Error::custom)
}

#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
    struct Wrapper {
        #[serde(with = "super")]
        bytes: [u8; 16],
    }

    #[test]
    fn roundtrip_hex() {
        let bytes = [0xAB; 16];
        let input = Wrapper { bytes };
        let encoded = toml::to_string(&input).unwrap();

        let expected = hex::encode(bytes);
        assert!(encoded.contains(&format!("bytes = \"{expected}\"")));

        let decoded: Wrapper = toml::from_str(&encoded).unwrap();
        assert_eq!(decoded, input);
    }

    #[test]
    fn accepts_0x_prefix() {
        let bytes = [0x11; 16];
        let encoded = format!("bytes = \"0x{}\"", hex::encode(bytes));
        let decoded: Wrapper = toml::from_str(&encoded).unwrap();
        assert_eq!(decoded.bytes, bytes);
    }

    #[test]
    fn rejects_invalid_hex_characters() {
        let encoded = "bytes = \"not valid hex!!!\"";
        let result: Result<Wrapper, _> = toml::from_str(encoded);
        assert!(result.is_err());
    }

    #[test]
    fn rejects_wrong_length() {
        // Too short
        let encoded = "bytes = \"aabbcc\"";
        let result: Result<Wrapper, _> = toml::from_str(encoded);
        assert!(result.is_err());

        // Too long
        let encoded =
            "bytes = \"aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabb\"";
        let result: Result<Wrapper, _> = toml::from_str(encoded);
        assert!(result.is_err());
    }

    #[test]
    fn rejects_empty_string() {
        let encoded = "bytes = \"\"";
        let result: Result<Wrapper, _> = toml::from_str(encoded);
        assert!(result.is_err());
    }

    #[test]
    fn rejects_0x_prefix_only() {
        let encoded = "bytes = \"0x\"";
        let result: Result<Wrapper, _> = toml::from_str(encoded);
        assert!(result.is_err());
    }

    #[test]
    fn accepts_mixed_case() {
        let bytes = [
            0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45,
            0x67, 0x89,
        ];
        let encoded = "bytes = \"AbCdEf0123456789AbCdEf0123456789\"";
        let decoded: Wrapper = toml::from_str(encoded).unwrap();
        assert_eq!(decoded.bytes, bytes);
    }

    #[test]
    fn accepts_whitespace_surrounding() {
        let bytes = [0xAB; 16];
        let encoded = format!("bytes = \"  0x{}  \"", hex::encode(bytes));
        let decoded: Wrapper = toml::from_str(&encoded).unwrap();
        assert_eq!(decoded.bytes, bytes);
    }
}
