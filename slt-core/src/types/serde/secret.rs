use std::path::{Path, PathBuf};

use serde::{Deserialize, Deserializer, Serializer, de};

#[derive(Deserialize)]
#[serde(untagged)]
enum SecretRef {
    Hex(String),
    File { file: PathBuf },
}

/// Serialize the secret as lowercase hex.
///
/// # Errors
///
/// Returns the serializer's error if the string cannot be serialized.
pub fn serialize<const N: usize, S>(bytes: &[u8; N], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    crate::types::serde::hex::serialize(bytes, serializer)
}

/// Deserialize the secret from hex or a file reference.
///
/// # Errors
///
/// Returns the deserializer's error if the input is not a valid hex string or a valid file reference.
pub fn deserialize<'de, const N: usize, D>(deserializer: D) -> Result<[u8; N], D::Error>
where
    D: Deserializer<'de>,
{
    let secret = SecretRef::deserialize(deserializer)?;
    match secret {
        SecretRef::Hex(s) => {
            crate::types::serde::hex::decode_hex::<N>(&s).map_err(de::Error::custom)
        }
        SecretRef::File { file } => read_secret_file::<N>(&file).map_err(de::Error::custom),
    }
}

fn read_secret_file<const N: usize>(path: &Path) -> Result<[u8; N], String> {
    let bytes = std::fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    if bytes.len() == N {
        let mut out = [0u8; N];
        out.copy_from_slice(&bytes);
        return Ok(out);
    }

    let text = std::str::from_utf8(&bytes).map_err(|e| format!("utf-8 {}: {e}", path.display()))?;
    crate::types::serde::hex::decode_hex::<N>(text)
}

/// Newtype wrapper for serializing secrets as hex or file references.
pub struct SerdeSecret<const N: usize>(pub [u8; N]);

impl<const N: usize> serde::Serialize for SerdeSecret<N> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serialize(&self.0, serializer)
    }
}

impl<'de, const N: usize> serde::Deserialize<'de> for SerdeSecret<N> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize(deserializer).map(SerdeSecret)
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use serde::Deserialize;

    use super::*;

    #[derive(Debug, Deserialize)]
    struct Wrapper {
        #[serde(with = "super")]
        secret: [u8; 32],
    }

    fn temp_path(suffix: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time went backwards")
            .as_nanos();
        let pid = std::process::id();
        path.push(format!("slt_secret_{pid}_{nanos}_{suffix}"));
        path
    }

    fn toml_path(path: &Path) -> String {
        path.to_string_lossy().replace('\\', "\\\\")
    }

    #[test]
    fn parses_hex_secret() {
        let secret = [0x22; 32];
        let encoded = format!("secret = \"{}\"", hex::encode(secret));
        let decoded: Wrapper = toml::from_str(&encoded).unwrap();
        assert_eq!(decoded.secret, secret);
    }

    #[test]
    fn parses_secret_file_raw_bytes() {
        let secret = [0xAA; 32];
        let path = temp_path("raw");
        fs::write(&path, secret).unwrap();

        let encoded = format!("secret = {{ file = \"{}\" }}", toml_path(&path));
        let decoded: Wrapper = toml::from_str(&encoded).unwrap();
        assert_eq!(decoded.secret, secret);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn parses_secret_file_hex_text() {
        let secret = [0xCC; 32];
        let path = temp_path("hex");
        fs::write(&path, format!("{}\n", hex::encode(secret))).unwrap();

        let encoded = format!("secret = {{ file = \"{}\" }}", toml_path(&path));
        let decoded: Wrapper = toml::from_str(&encoded).unwrap();
        assert_eq!(decoded.secret, secret);

        let _ = fs::remove_file(path);
    }
}
