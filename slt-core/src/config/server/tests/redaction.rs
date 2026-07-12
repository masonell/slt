use super::test_config;
use crate::types::{SharedSecret, TlsMaterial};

#[test]
fn debug_redacts_secret_material() {
    const INLINE_PRIVATE_KEY: &str =
        "-----BEGIN PRIVATE KEY----- server-secret -----END PRIVATE KEY-----";

    let mut config = test_config();
    config.server_secret = SharedSecret([0x61; 32]);
    config.tls.tls_key = TlsMaterial::Pem(INLINE_PRIVATE_KEY.to_string());

    let server_secret_bytes = format!("{:?}", config.server_secret.as_bytes());
    let server_secret_hex = hex::encode(config.server_secret.as_bytes());
    let rendered = format!("{config:?}");

    assert!(rendered.contains("SharedSecret(<redacted>)"));
    assert!(rendered.contains("Pem(<redacted>)"));
    assert!(!rendered.contains(&server_secret_bytes));
    assert!(!rendered.contains(&server_secret_hex));
    assert!(!rendered.contains(INLINE_PRIVATE_KEY));
}
