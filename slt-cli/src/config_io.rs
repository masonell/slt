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
/// The write is staged to a sibling `<path>.tmp` file and committed with an
/// atomic `rename`, so an interrupt or crash between the write and the commit
/// leaves any existing config intact rather than truncating it. The temp file
/// is a sibling so the `rename` stays on one filesystem, where it is atomic.
///
/// # Errors
///
/// Returns an error if the temp file cannot be opened, written, or renamed
/// onto `path`.
fn write_restricted(path: &Path, contents: &str, label: &str) -> Result<()> {
    let tmp_path = tmp_path_for(path);
    let result = write_temp_and_rename(&tmp_path, path, contents);
    if result.is_err() {
        // Avoid leaving a truncated temp file behind after a failed commit.
        let _ = fs::remove_file(&tmp_path);
    }
    result.with_context(|| format!("failed to write {label} to {}", path.display()))
}

/// Build the sibling `<path>.tmp` staging path used for an atomic write.
fn tmp_path_for(path: &Path) -> PathBuf {
    let mut tmp = path.as_os_str().to_os_string();
    tmp.push(".tmp");
    PathBuf::from(tmp)
}

/// Write `contents` to `tmp_path` with mode `0600`, then atomically rename it
/// onto `final_path`.
///
/// # Errors
///
/// Returns the underlying I/O error if any step fails.
fn write_temp_and_rename(
    tmp_path: &Path,
    final_path: &Path,
    contents: &str,
) -> std::io::Result<()> {
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(tmp_path)?;

    // `.mode()` only applies when the file is created, so a stale temp file left
    // behind by a crashed prior write keeps its old (possibly world-readable)
    // mode. The file is still empty here, so clamp it to `0600` before writing
    // any secret bytes: a local reader never sees secret content in a readable
    // window, and a chmod failure aborts before the secret is written at all.
    fs::set_permissions(tmp_path, Permissions::from_mode(0o600))?;

    file.write_all(contents.as_bytes())?;
    fs::rename(tmp_path, final_path)
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

    #[test]
    fn write_restricted_renames_away_temp_on_success() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("secret.toml");
        let tmp_path = PathBuf::from(format!("{}.tmp", path.display()));

        write_restricted(&path, "secret = true", "test config").unwrap();

        assert!(!tmp_path.exists(), "temp file should be renamed away");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "secret = true");
    }

    #[test]
    fn write_restricted_clamps_stale_world_readable_temp_file() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("secret.toml");
        let tmp_path = PathBuf::from(format!("{}.tmp", path.display()));

        // Simulate a stale, world-readable temp file left by a crashed prior run.
        std::fs::write(&tmp_path, "stale").unwrap();
        fs::set_permissions(&tmp_path, Permissions::from_mode(0o644)).unwrap();

        write_restricted(&path, "secret = true", "test config").unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "secret = true");
    }
}
