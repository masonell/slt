//! Configuration file I/O utilities.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use slt_core::config::{ClientConfig, ServerConfig};
use slt_core::types::TlsMaterial;

/// Resolve a path relative to a config file's directory.
///
/// If the path is absolute, returns it unchanged.
/// If the path is relative, resolves it relative to the config file's parent directory.
pub fn resolve_path(config_path: &Path, file_path: &Path) -> PathBuf {
    if file_path.is_absolute() {
        file_path.to_path_buf()
    } else {
        config_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(file_path)
    }
}

/// Read TLS certificate content from either inline PEM or file reference.
///
/// # Errors
///
/// Returns an error if the certificate file cannot be read.
pub fn read_cert_content(config_path: &Path, tls_cert: &TlsMaterial) -> Result<String> {
    match tls_cert {
        TlsMaterial::Pem(pem) => Ok(pem.clone()),
        TlsMaterial::File { file } => {
            let cert_path = resolve_path(config_path, Path::new(file));
            std::fs::read_to_string(&cert_path).with_context(|| {
                format!("failed to read certificate file: {}", cert_path.display())
            })
        }
    }
}

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
#[allow(dead_code)] // Utility for future use
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
