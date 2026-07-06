//! Configuration file I/O utilities.

use std::fs::{self, OpenOptions, Permissions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
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
    write_restricted(path, &contents, "server config")
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
    write_restricted(path, &contents, "client config")
}

/// Write `contents` to `path` with owner-only (`0600`) permissions.
///
/// Server and client configs embed secret material — the classification
/// `server_secret`, per-client shared secrets, and the Ed25519 private key —
/// so they are written with the same restricted permissions as `server-key.pem`
/// instead of the process umask default (typically `0644`).
///
/// # Errors
///
/// Returns an error if the file cannot be opened, written, or have its
/// permissions set.
fn write_restricted(path: &Path, contents: &str, label: &str) -> Result<()> {
    OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .and_then(|mut f| f.write_all(contents.as_bytes()))
        .with_context(|| format!("failed to write {label} to {}", path.display()))?;

    // `.mode()` applies only at creation; overwriting an existing file inherits
    // its prior mode, so re-pin `0600` to cover the overwrite path.
    fs::set_permissions(path, Permissions::from_mode(0o600))
        .with_context(|| format!("failed to set permissions on {}", path.display()))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;

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

    #[test]
    fn write_restricted_sets_owner_only_permissions() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("secret.toml");

        write_restricted(&path, "secret = true", "test config").unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "secret = true");
    }

    #[test]
    fn write_restricted_repins_mode_when_overwriting_world_readable_file() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("secret.toml");

        // Seed a world-readable file, simulating an existing config from before
        // the restricted-permission write existed.
        std::fs::write(&path, "old").unwrap();
        fs::set_permissions(&path, Permissions::from_mode(0o644)).unwrap();

        write_restricted(&path, "new", "test config").unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "new");
    }
}
