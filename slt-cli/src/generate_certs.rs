//! Certificate generation command.
//!
//! Generates CA and server certificates using ECDSA P-256 for compatibility
//! with Chrome's TLS signature algorithms (which don't include Ed25519).

use std::fs::{self, OpenOptions, Permissions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

use anyhow::{Context, Result, bail};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, SanType,
};
use time::{Duration, OffsetDateTime};

/// Default certificate validity period (10 years).
const CERT_VALIDITY_YEARS: i64 = 10;

/// Generate CA and server certificates.
///
/// Creates three files in the config directory:
/// - `ca.pem`: CA certificate (for client trust store)
/// - `server.pem`: Server certificate signed by CA
/// - `server-key.pem`: Server private key
///
/// When `force` is `false`, refuses to overwrite any existing certificate or
/// key file, since regenerating the CA and server key invalidates every
/// deployed client config.
///
/// # Errors
///
/// Returns an error if the directory doesn't exist, existing material would be
/// overwritten without `force`, or file writing fails.
pub fn generate_certs(config_dir: &Path, domain: &str, force: bool, quiet: bool) -> Result<()> {
    if !config_dir.exists() {
        bail!("config directory does not exist: {}", config_dir.display());
    }

    let ca_path = config_dir.join("ca.pem");
    let server_path = config_dir.join("server.pem");
    let key_path = config_dir.join("server-key.pem");

    if !force {
        let existing: Vec<&str> = [
            ("ca.pem", ca_path.exists()),
            ("server.pem", server_path.exists()),
            ("server-key.pem", key_path.exists()),
        ]
        .into_iter()
        .filter(|(_, exists)| *exists)
        .map(|(name, _)| name)
        .collect();
        if !existing.is_empty() {
            bail!(
                "existing certificate material found in {}: {}; \
                 regenerating the CA and server key invalidates every deployed client config. \
                 Re-run with --force to overwrite.",
                config_dir.display(),
                existing.join(", "),
            );
        }
    }

    let (ca_cert_pem, server_cert_pem, server_key_pem) = generate_cert_chain(domain)?;

    std::fs::write(&ca_path, &ca_cert_pem)
        .with_context(|| format!("failed to write {}", ca_path.display()))?;
    std::fs::write(&server_path, &server_cert_pem)
        .with_context(|| format!("failed to write {}", server_path.display()))?;

    // Write private key with restricted permissions (owner read/write only)
    OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(&key_path)
        .and_then(|mut f| f.write_all(server_key_pem.as_bytes()))
        .with_context(|| format!("failed to write {}", key_path.display()))?;

    // Ensure permissions are exactly 0600 (umask may have restricted further)
    fs::set_permissions(&key_path, Permissions::from_mode(0o600))
        .with_context(|| format!("failed to set permissions on {}", key_path.display()))?;

    if !quiet {
        println!("Generated certificates for domain: {domain}");
        println!("  CA certificate: {}", ca_path.display());
        println!("  Server certificate: {}", server_path.display());
        println!("  Server key: {}", key_path.display());
    }

    Ok(())
}

/// Generate a CA certificate and server certificate chain.
///
/// The server certificate includes an Authority Key Identifier (AKID) that
/// references the CA's Subject Key Identifier (SKID).
///
/// Returns (CA cert PEM, server cert PEM, server key PEM).
fn generate_cert_chain(domain: &str) -> Result<(String, String, String)> {
    let now = OffsetDateTime::now_utc();
    let not_before = now - Duration::hours(1); // Allow for clock skew
    let not_after = now + Duration::days(CERT_VALIDITY_YEARS * 365);

    // Generate CA key and certificate
    let ca_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .context("failed to generate CA key pair")?;

    let mut ca_params = CertificateParams::default();
    ca_params
        .distinguished_name
        .push(DnType::CommonName, format!("{domain} CA"));
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    ca_params.not_before = not_before;
    ca_params.not_after = not_after;

    let ca_cert = ca_params
        .self_signed(&ca_key)
        .context("failed to self-sign CA certificate")?;
    let ca_issuer = Issuer::from_params(&ca_params, &ca_key);

    // Generate server key and certificate
    let server_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .context("failed to generate server key pair")?;

    let mut server_params = CertificateParams::default();
    server_params
        .distinguished_name
        .push(DnType::CommonName, domain);
    server_params.is_ca = IsCa::NoCa;
    server_params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    server_params.subject_alt_names = vec![SanType::DnsName(
        domain.try_into().context("invalid domain for SAN")?,
    )];
    server_params.not_before = not_before;
    server_params.not_after = not_after;
    server_params.use_authority_key_identifier_extension = true;

    let server_cert = server_params
        .signed_by(&server_key, &ca_issuer)
        .context("failed to sign server certificate with CA")?;

    Ok((ca_cert.pem(), server_cert.pem(), server_key.serialize_pem()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_cert_chain_works() {
        let (ca_pem, server_pem, key_pem) = generate_cert_chain("localhost").unwrap();

        // Check that we got valid PEM data
        assert!(ca_pem.contains("-----BEGIN CERTIFICATE-----"));
        assert!(server_pem.contains("-----BEGIN CERTIFICATE-----"));
        // PKCS#8 format for private key
        assert!(key_pem.contains("-----BEGIN PRIVATE KEY-----"));
    }

    #[test]
    fn generate_certs_fails_on_missing_dir() {
        let result = generate_certs(Path::new("/nonexistent/path"), "localhost", false, true);
        assert!(result.is_err());
    }

    #[test]
    fn generate_certs_refuses_to_overwrite_without_force() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let config_dir = temp_dir.path();

        std::fs::write(config_dir.join("server-key.pem"), "preexisting key").unwrap();

        let result = generate_certs(config_dir, "localhost", false, true);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("server-key.pem"));
        assert!(err.contains("--force"));

        // Unchanged: not overwritten when the call refuses.
        assert_eq!(
            std::fs::read_to_string(config_dir.join("server-key.pem")).unwrap(),
            "preexisting key"
        );
    }

    #[test]
    fn generate_certs_overwrites_with_force() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let config_dir = temp_dir.path();

        std::fs::write(config_dir.join("ca.pem"), "preexisting ca").unwrap();

        generate_certs(config_dir, "localhost", true, true).unwrap();

        let ca = std::fs::read_to_string(config_dir.join("ca.pem")).unwrap();
        assert!(ca.contains("-----BEGIN CERTIFICATE-----"));
    }
}
