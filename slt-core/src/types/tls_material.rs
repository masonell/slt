//! TLS certificate/key material for configuration.

use std::path::PathBuf;

use serde::ser::SerializeMap;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// TLS material provided inline as PEM or loaded from a file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlsMaterial {
    /// PEM-encoded data embedded directly in the config.
    Pem(String),
    /// Path to a PEM-encoded file on disk.
    File { file: PathBuf },
}

#[derive(Deserialize)]
#[serde(untagged)]
enum TlsMaterialRef {
    Pem(String),
    PemMap { pem: String },
    File { file: PathBuf },
}

impl Serialize for TlsMaterial {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Pem(pem) => serializer.serialize_str(pem),
            Self::File { file } => {
                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry("file", file)?;
                map.end()
            }
        }
    }
}

impl<'de> Deserialize<'de> for TlsMaterial {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let material = TlsMaterialRef::deserialize(deserializer)?;
        match material {
            TlsMaterialRef::Pem(pem) | TlsMaterialRef::PemMap { pem } => Ok(Self::Pem(pem)),
            TlsMaterialRef::File { file } => Ok(Self::File { file }),
        }
    }
}

impl TlsMaterial {
    /// Returns true if the material is inline PEM.
    #[must_use]
    pub const fn is_pem(&self) -> bool {
        matches!(self, Self::Pem(_))
    }

    /// Returns true if the material references a file.
    #[must_use]
    pub const fn is_file(&self) -> bool {
        matches!(self, Self::File { .. })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Deserialize)]
    struct Config {
        cert: TlsMaterial,
    }

    #[derive(Debug, Serialize)]
    struct ConfigRef<'a> {
        cert: &'a TlsMaterial,
    }

    // Simple PEM-like string without newlines for TOML compatibility
    const PEM_DATA: &str = "-----BEGIN CERTIFICATE----- MIIBIjAN -----END CERTIFICATE-----";

    #[test]
    fn deserialize_pem_string_directly() {
        let config: Config = toml::from_str(&format!("cert = \"{PEM_DATA}\"")).unwrap();
        assert!(config.cert.is_pem());
        assert!(matches!(config.cert, TlsMaterial::Pem(s) if s == PEM_DATA));
    }

    #[test]
    fn deserialize_pem_via_map() {
        let config: Config = toml::from_str(&format!("cert = {{ pem = \"{PEM_DATA}\" }}")).unwrap();
        assert!(config.cert.is_pem());
        assert!(matches!(config.cert, TlsMaterial::Pem(s) if s == PEM_DATA));
    }

    #[test]
    fn deserialize_file_reference() {
        let config: Config = toml::from_str("cert = { file = \"/path/to/cert.pem\" }").unwrap();
        assert!(config.cert.is_file());
        assert!(matches!(config.cert, TlsMaterial::File { file } if file == *"/path/to/cert.pem"));
    }

    #[test]
    fn serialize_pem_as_string() {
        let material = TlsMaterial::Pem(PEM_DATA.to_string());
        let wrapper = ConfigRef { cert: &material };
        let toml_str = toml::to_string(&wrapper).unwrap();
        assert!(toml_str.contains(PEM_DATA));
        assert!(!toml_str.contains("pem ="));
    }

    #[test]
    fn serialize_file_as_map() {
        let material = TlsMaterial::File {
            file: PathBuf::from("/path/to/cert.pem"),
        };
        let wrapper = ConfigRef { cert: &material };
        let toml_str = toml::to_string(&wrapper).unwrap();
        assert!(toml_str.contains("file = \"/path/to/cert.pem\""));
    }

    #[test]
    fn is_pem_returns_true_for_pem_variant() {
        let material = TlsMaterial::Pem("data".to_string());
        assert!(material.is_pem());
        assert!(!material.is_file());
    }

    #[test]
    fn is_file_returns_true_for_file_variant() {
        let material = TlsMaterial::File {
            file: PathBuf::from("/path"),
        };
        assert!(material.is_file());
        assert!(!material.is_pem());
    }
}
