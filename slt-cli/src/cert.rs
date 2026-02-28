//! Certificate parsing utilities.

use anyhow::{Context, Result, bail};
use x509_parser::pem::parse_x509_pem;
use x509_parser::prelude::*;

fn is_wildcard_domain(domain: &str) -> bool {
    domain.contains('*')
}

/// Extract domain name from a PEM-encoded X.509 certificate.
///
/// Tries Subject Alternative Names (DNS) first, then falls back to Common Name.
///
/// # Errors
///
/// Returns an error if:
/// - The PEM data cannot be parsed
/// - The certificate cannot be parsed
/// - No domain is found (neither SAN nor CN)
pub fn extract_domain_from_cert(pem: &str) -> Result<String> {
    let (_, pem_obj) = parse_x509_pem(pem.as_bytes()).context("failed to parse PEM data")?;
    let cert = pem_obj
        .parse_x509()
        .context("failed to parse server certificate")?;

    // Try Subject Alternative Names first (modern standard)
    if let Ok(Some(san_ext)) = cert.subject_alternative_name() {
        let mut saw_wildcard = false;
        for name in &san_ext.value.general_names {
            if let GeneralName::DNSName(dns) = name {
                if is_wildcard_domain(dns) {
                    saw_wildcard = true;
                    continue;
                }
                return Ok(dns.to_string());
            }
        }

        if saw_wildcard {
            bail!(
                "certificate contains wildcard DNS names; use --domain to specify a concrete hostname"
            );
        }
    }

    // Fall back to Common Name
    let cn = cert
        .subject()
        .iter_common_name()
        .next()
        .context("no domain found in certificate (no SAN or CN)")?
        .attr_value()
        .as_str()
        .context("common name is not valid UTF-8")?
        .to_string();

    if is_wildcard_domain(&cn) {
        bail!("certificate common name is wildcard; use --domain to specify a concrete hostname");
    }

    Ok(cn)
}

#[cfg(test)]
mod tests {
    use rcgen::{CertificateParams, DnType, KeyPair, SanType};

    use super::*;

    fn test_cert_pem(cn: &str, sans: &[&str]) -> String {
        let mut params = CertificateParams::default();
        params.distinguished_name.push(DnType::CommonName, cn);
        params.subject_alt_names = sans
            .iter()
            .map(|name| SanType::DnsName((*name).try_into().unwrap()))
            .collect();

        let key_pair = KeyPair::generate().unwrap();
        params.self_signed(&key_pair).unwrap().pem()
    }

    #[test]
    fn extract_domain_from_valid_san() {
        let cert_pem = test_cert_pem("unused.example.com", &["vpn.example.com"]);
        let domain = extract_domain_from_cert(&cert_pem).unwrap();
        assert_eq!(domain, "vpn.example.com");
    }

    #[test]
    fn extract_domain_from_wildcard_san_errors() {
        let cert_pem = test_cert_pem("unused.example.com", &["*.example.com"]);
        let err = extract_domain_from_cert(&cert_pem).unwrap_err();
        assert!(err.to_string().contains("wildcard"));
    }

    #[test]
    fn extract_domain_from_invalid_cert() {
        let result = extract_domain_from_cert("not a valid cert");
        assert!(result.is_err());
    }
}
