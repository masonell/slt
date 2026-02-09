use boring::x509::X509;
use std::path::PathBuf;

/// Configures a `BoringSSL` context builder to trust the provided CA material.
pub fn configure_boring_ca_store(
    ctx: &mut boring::ssl::SslContextBuilder,
    tls_ca: &slt_core::types::TlsMaterial,
) -> Result<(), boring::error::ErrorStack> {
    match tls_ca {
        slt_core::types::TlsMaterial::File { file } => ctx.set_ca_file(file),
        slt_core::types::TlsMaterial::Pem(pem) => {
            let certs = X509::stack_from_pem(pem.as_bytes())?;
            for cert in certs {
                ctx.cert_store_mut().add_cert(cert)?;
            }
            Ok(())
        }
    }
}

/// Configures a `quiche::Config` to trust the provided CA material.
///
/// Quiche loads verification roots from a file path, so inline PEM material is written to a
/// temporary file for the duration of the call and removed afterwards.
pub fn configure_quiche_ca_store(
    config: &mut quiche::Config,
    tls_ca: &slt_core::types::TlsMaterial,
) -> std::io::Result<()> {
    match tls_ca {
        slt_core::types::TlsMaterial::File { file } => {
            config
                .load_verify_locations_from_file(file.to_string_lossy().as_ref())
                .map_err(map_quiche_error)?;
            Ok(())
        }
        slt_core::types::TlsMaterial::Pem(pem) => {
            let path = write_temp_pem(pem)?;
            let result = config
                .load_verify_locations_from_file(path.to_string_lossy().as_ref())
                .map_err(map_quiche_error);
            let _ = std::fs::remove_file(&path);
            result
        }
    }
}

fn write_temp_pem(pem: &str) -> std::io::Result<PathBuf> {
    let mut path = std::env::temp_dir();
    let name = format!("slt-quic-ca-{id}.pem", id = fastrand::u64(..));
    path.push(name);
    std::fs::write(&path, pem)?;
    Ok(path)
}

fn map_quiche_error(err: quiche::Error) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        format!("quic error: {err:?}"),
    )
}
