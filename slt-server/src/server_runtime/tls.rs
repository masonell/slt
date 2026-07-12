use std::error::Error;
use std::io;

use boring::error::ErrorStack;
use boring::pkey::PKey;
use boring::ssl::{SslAcceptor, SslAcceptorBuilder, SslFiletype, SslMethod};
use boring::x509::X509;
use slt_core::config::ServerConfig;
use slt_core::crypto::configure_tcp_tls13_only;
use slt_core::types::TlsMaterial;
use tracing::{debug, trace};

pub(super) fn build_acceptor(config: &ServerConfig) -> Result<SslAcceptor, Box<dyn Error>> {
    let mut builder = tls13_acceptor_builder()?;

    match &config.tls.tls_cert {
        TlsMaterial::File { file } => {
            debug!(source = "file", path = %file.display(), "loading tls certificate");
            builder.set_certificate_chain_file(file)?;
        }
        TlsMaterial::Pem(pem) => {
            debug!(
                source = "pem",
                pem_length = pem.len(),
                "loading tls certificate"
            );
            let mut certs = X509::stack_from_pem(pem.as_bytes())?;
            let leaf = certs
                .drain(..1)
                .next()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "tls_cert is empty"))?;
            builder.set_certificate(&leaf)?;
            for cert in certs {
                builder.add_extra_chain_cert(cert)?;
            }
        }
    }

    match &config.tls.tls_key {
        TlsMaterial::File { file } => {
            debug!(source = "file", path = %file.display(), "loading tls private key");
            builder.set_private_key_file(file, SslFiletype::PEM)?;
        }
        TlsMaterial::Pem(pem) => {
            debug!(
                source = "pem",
                pem_length = pem.len(),
                "loading tls private key"
            );
            let key = PKey::private_key_from_pem(pem.as_bytes())?;
            builder.set_private_key(&key)?;
        }
    }

    builder.check_private_key()?;
    trace!("tls acceptor built successfully");
    Ok(builder.build())
}

fn tls13_acceptor_builder() -> Result<SslAcceptorBuilder, ErrorStack> {
    let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls())?;
    configure_tcp_tls13_only(&mut builder)?;
    Ok(builder)
}

#[cfg(test)]
mod tests {
    use boring::ssl::SslVersion;

    use super::tls13_acceptor_builder;

    #[test]
    fn vpn_tls_acceptor_is_tls13_only() {
        let mut builder = tls13_acceptor_builder().unwrap();

        assert_eq!(builder.min_proto_version(), Some(SslVersion::TLS1_3));
        assert_eq!(builder.max_proto_version(), Some(SslVersion::TLS1_3));
    }
}
