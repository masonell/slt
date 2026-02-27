//! Configuration validation command.

use std::path::Path;

use anyhow::{Context, Result, bail};
use slt_core::config::{ClientConfig, ServerConfig};

/// Config type detected during validation.
enum ConfigType {
    Server,
    Client,
}

/// Validate a configuration file.
///
/// Attempts to parse the file as both server and client config.
/// Returns Ok with the detected type on success, or Err with both
/// parse errors on failure.
///
/// # Errors
///
/// Returns an error if the file cannot be parsed as either config type.
pub fn validate(path: &Path, verbose: bool) -> Result<()> {
    let contents = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read {}", path.display()))?;

    let config_type = match try_parse_server(&contents) {
        Ok(()) => ConfigType::Server,
        Err(server_err) => match try_parse_client(&contents) {
            Ok(()) => ConfigType::Client,
            Err(client_err) => {
                bail!(
                    "not a valid server or client config:\n  server: {server_err}\n  client: {client_err}"
                );
            }
        },
    };

    if verbose {
        let type_name = match config_type {
            ConfigType::Server => "server",
            ConfigType::Client => "client",
        };
        println!("{}: valid {} config", path.display(), type_name);
    }

    Ok(())
}

/// Try to parse contents as a server config.
fn try_parse_server(contents: &str) -> Result<()> {
    ServerConfig::from_toml_str(contents)?;
    Ok(())
}

/// Try to parse contents as a client config.
fn try_parse_client(contents: &str) -> Result<()> {
    ClientConfig::from_toml_str(contents)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use tempfile::NamedTempFile;

    use super::*;

    fn write_temp_file(contents: &[u8]) -> NamedTempFile {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(contents).unwrap();
        file
    }

    #[test]
    fn validate_file_not_found() {
        let result = validate(Path::new("/nonexistent/path.toml"), false);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("failed to read"));
    }

    #[test]
    fn validate_invalid_toml() {
        let file = write_temp_file(b"not valid toml[");
        let result = validate(file.path(), false);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("not a valid server or client config")
        );
    }

    #[test]
    fn validate_invalid_config() {
        let file = write_temp_file(b"[some_section]\nkey = \"value\"");
        let result = validate(file.path(), false);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("not a valid server or client config")
        );
    }

    #[test]
    fn validate_quiet_mode() {
        let file = write_temp_file(b"invalid");
        let result = validate(file.path(), true);
        assert!(result.is_err());
    }
}
