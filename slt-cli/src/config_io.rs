//! Configuration file I/O utilities.

#![allow(dead_code)] // Functions will be used in subsequent phases

use std::path::Path;

use anyhow::{Context, Result};
use slt_core::config::{ClientConfig, ServerConfig};

/// Load a server config from a file.
///
/// # Errors
///
/// Returns an error if the file cannot be read, parsed, or validated.
pub fn load_server_config(path: &Path) -> Result<ServerConfig> {
    let contents = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read server config from {}", path.display()))?;

    ServerConfig::from_toml_str(&contents)
        .with_context(|| format!("failed to parse server config from {}", path.display()))
}

/// Save a server config to a file.
///
/// # Errors
///
/// Returns an error if the config cannot be serialized or written.
pub fn save_server_config(path: &Path, config: &ServerConfig) -> Result<()> {
    let contents = toml::to_string_pretty(config).context("failed to serialize server config")?;

    std::fs::write(path, contents)
        .with_context(|| format!("failed to write server config to {}", path.display()))
}

/// Load a client config from a file.
///
/// # Errors
///
/// Returns an error if the file cannot be read, parsed, or validated.
pub fn load_client_config(path: &Path) -> Result<ClientConfig> {
    let contents = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read client config from {}", path.display()))?;

    ClientConfig::from_toml_str(&contents)
        .with_context(|| format!("failed to parse client config from {}", path.display()))
}

/// Save a client config to a file.
///
/// # Errors
///
/// Returns an error if the config cannot be serialized or written.
pub fn save_client_config(path: &Path, config: &ClientConfig) -> Result<()> {
    let contents = toml::to_string_pretty(config).context("failed to serialize client config")?;

    std::fs::write(path, contents)
        .with_context(|| format!("failed to write client config to {}", path.display()))
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use tempfile::NamedTempFile;

    use super::*;

    #[test]
    fn load_server_config_file_not_found() {
        let result = load_server_config(Path::new("/nonexistent/path.toml"));
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("failed to read server config"));
    }

    #[test]
    fn load_server_config_invalid_toml() {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(b"not valid toml[").unwrap();

        let result = load_server_config(file.path());
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("failed to parse server config"));
    }

    #[test]
    fn load_client_config_file_not_found() {
        let result = load_client_config(Path::new("/nonexistent/path.toml"));
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("failed to read client config"));
    }

    #[test]
    fn load_client_config_invalid_toml() {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(b"not valid toml[").unwrap();

        let result = load_client_config(file.path());
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("failed to parse client config"));
    }
}
