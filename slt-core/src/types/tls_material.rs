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
