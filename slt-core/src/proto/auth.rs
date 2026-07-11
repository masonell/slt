//! AUTH message construction.
//!
//! The signed bytes an AUTH payload covers, and the payload builder that signs them.
//! The signer (client) and verifier (server) must construct identical context bytes, so
//! [`auth_signature_context`] is the single source of truth shared by both.

use std::net::Ipv4Addr;

use ed25519_dalek::{Signer, SigningKey};

use super::{AUTH_CHALLENGE_LEN, AuthPayload};
use crate::config::ClientConfig;
use crate::types::ClientId;

/// TLS exporter label used to derive the per-connection auth challenge.
///
/// Both peers call `export_keying_material` with this label so they derive identical
/// challenge bytes; centralizing it prevents the two sides from drifting apart.
pub const AUTH_CHALLENGE_LABEL: &str = "slt-auth-challenge";

/// Length of the `"slt-auth-v2"` context prefix.
const CONTEXT_PREFIX_LEN: usize = 11;

/// Build the canonical bytes an AUTH Ed25519 signature covers.
///
/// The context is `"slt-auth-v2" || client_id || assigned_ipv4 || tun_mtu || challenge`.
/// Signing and verification both build these exact bytes, then sign/verify over them.
#[must_use]
pub fn auth_signature_context(
    client_id: &ClientId,
    assigned_ipv4: Ipv4Addr,
    tun_mtu: u16,
    challenge: &[u8; AUTH_CHALLENGE_LEN],
) -> Vec<u8> {
    let mut context = Vec::with_capacity(CONTEXT_PREFIX_LEN + 16 + 4 + 2 + challenge.len());
    context.extend_from_slice(b"slt-auth-v2");
    context.extend_from_slice(client_id.as_bytes());
    context.extend_from_slice(&assigned_ipv4.octets());
    context.extend_from_slice(&tun_mtu.to_be_bytes());
    context.extend_from_slice(challenge);
    context
}

/// Build a signed [`AuthPayload`] from a client config and the TLS-derived challenge.
///
/// Constructs the canonical context via [`auth_signature_context`] and signs it with the
/// client's Ed25519 private key.
///
/// # Errors
///
/// This function itself is infallible; it returns [`AuthPayload`] directly. The signature
/// is produced by `ed25519-dalek`, which cannot fail for a valid private key.
#[must_use]
pub fn build_auth_payload(
    config: &ClientConfig,
    challenge: [u8; AUTH_CHALLENGE_LEN],
) -> AuthPayload {
    let context = auth_signature_context(
        &config.identity.client_id,
        config.identity.assigned_ipv4,
        config.tun.tun_mtu,
        &challenge,
    );
    let signing_key = SigningKey::from_bytes(config.identity.privkey_ed25519.as_bytes());
    let signature = signing_key.sign(&context).to_bytes();
    AuthPayload {
        client_id: config.identity.client_id,
        assigned_ipv4: config.identity.assigned_ipv4,
        tun_mtu: config.tun.tun_mtu,
        challenge,
        signature,
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use ed25519_dalek::{Signature, Verifier};

    use super::*;
    use crate::types::{
        ClientIdentity, ClientNetworkConfig, ClientTimingConfig, ClientTlsConfig, PrivKeyEd25519,
        SharedSecret, TlsMaterial, TunConfig,
    };

    fn config_with_identity(
        client_id: ClientId,
        ipv4: Ipv4Addr,
        privkey: PrivKeyEd25519,
    ) -> ClientConfig {
        ClientConfig {
            network: ClientNetworkConfig {
                hostname: "example.com".to_string(),
                port: 443,
                ip: None,
            },
            tls: ClientTlsConfig {
                tls_ca: TlsMaterial::Pem(String::new()),
                quic_ca: None,
            },
            identity: ClientIdentity {
                client_id,
                shared_secret: SharedSecret([0u8; 32]),
                assigned_ipv4: ipv4,
                privkey_ed25519: privkey,
            },
            tun: TunConfig {
                tun_name: "tun0".to_string(),
                tun_mtu: 1280,
                tun_ipv4: ipv4,
                tun_prefix: 24,
            },
            transport: Default::default(),
            enable_upgrade: false,
            require_udp: false,
            timing: ClientTimingConfig::default(),
        }
    }

    fn verify_signature(
        payload: &AuthPayload,
        challenge: [u8; AUTH_CHALLENGE_LEN],
        verifying_key: &ed25519_dalek::VerifyingKey,
    ) -> Result<(), ed25519_dalek::SignatureError> {
        let context = auth_signature_context(
            &payload.client_id,
            payload.assigned_ipv4,
            payload.tun_mtu,
            &challenge,
        );
        let signature = Signature::from_bytes(&payload.signature);
        verifying_key.verify(&context, &signature)
    }

    #[test]
    fn auth_payload_roundtrip_and_signature_verifies() {
        let config = config_with_identity(
            ClientId([0x11; 16]),
            Ipv4Addr::new(10, 10, 0, 2),
            PrivKeyEd25519([0x33; 32]),
        );

        let challenge = [0x44; AUTH_CHALLENGE_LEN];
        let payload = build_auth_payload(&config, challenge);

        let mut buf = Vec::new();
        payload.encode(&mut buf);
        let decoded = AuthPayload::decode(&buf).unwrap();
        assert_eq!(decoded, payload);

        let signing_key = SigningKey::from_bytes(config.identity.privkey_ed25519.as_bytes());
        verify_signature(&payload, challenge, &signing_key.verifying_key()).unwrap();
    }

    #[test]
    fn signature_fails_with_wrong_verifying_key() {
        let config = config_with_identity(
            ClientId([0x11; 16]),
            Ipv4Addr::new(10, 10, 0, 2),
            PrivKeyEd25519([0x33; 32]),
        );
        let challenge = [0x44; AUTH_CHALLENGE_LEN];
        let payload = build_auth_payload(&config, challenge);

        let wrong = SigningKey::from_bytes(&[0x99; 32]).verifying_key();
        assert!(verify_signature(&payload, challenge, &wrong).is_err());
    }

    #[test]
    fn signature_fails_with_tampered_signature() {
        let config = config_with_identity(
            ClientId([0x11; 16]),
            Ipv4Addr::new(10, 10, 0, 2),
            PrivKeyEd25519([0x33; 32]),
        );
        let challenge = [0x44; AUTH_CHALLENGE_LEN];
        let mut payload = build_auth_payload(&config, challenge);
        payload.signature[0] ^= 0xFF;

        let signing_key = SigningKey::from_bytes(config.identity.privkey_ed25519.as_bytes());
        assert!(verify_signature(&payload, challenge, &signing_key.verifying_key()).is_err());
    }

    #[test]
    fn signature_fails_with_tampered_client_id() {
        let config = config_with_identity(
            ClientId([0x11; 16]),
            Ipv4Addr::new(10, 10, 0, 2),
            PrivKeyEd25519([0x33; 32]),
        );
        let challenge = [0x44; AUTH_CHALLENGE_LEN];
        let mut payload = build_auth_payload(&config, challenge);
        payload.client_id.0[0] ^= 0xFF;

        let signing_key = SigningKey::from_bytes(config.identity.privkey_ed25519.as_bytes());
        assert!(verify_signature(&payload, challenge, &signing_key.verifying_key()).is_err());
    }

    #[test]
    fn signature_fails_with_tampered_ipv4() {
        let config = config_with_identity(
            ClientId([0x11; 16]),
            Ipv4Addr::new(10, 10, 0, 2),
            PrivKeyEd25519([0x33; 32]),
        );
        let challenge = [0x44; AUTH_CHALLENGE_LEN];
        let mut payload = build_auth_payload(&config, challenge);
        payload.assigned_ipv4 = Ipv4Addr::new(10, 10, 0, 3);

        let signing_key = SigningKey::from_bytes(config.identity.privkey_ed25519.as_bytes());
        assert!(verify_signature(&payload, challenge, &signing_key.verifying_key()).is_err());
    }

    #[test]
    fn signature_fails_with_tampered_tun_mtu() {
        let config = config_with_identity(
            ClientId([0x11; 16]),
            Ipv4Addr::new(10, 10, 0, 2),
            PrivKeyEd25519([0x33; 32]),
        );
        let challenge = [0x44; AUTH_CHALLENGE_LEN];
        let mut payload = build_auth_payload(&config, challenge);
        payload.tun_mtu -= 1;

        let signing_key = SigningKey::from_bytes(config.identity.privkey_ed25519.as_bytes());
        assert!(verify_signature(&payload, challenge, &signing_key.verifying_key()).is_err());
    }

    #[test]
    fn signature_fails_with_wrong_challenge() {
        let config = config_with_identity(
            ClientId([0x11; 16]),
            Ipv4Addr::new(10, 10, 0, 2),
            PrivKeyEd25519([0x33; 32]),
        );
        let challenge = [0x44; AUTH_CHALLENGE_LEN];
        let payload = build_auth_payload(&config, challenge);

        let signing_key = SigningKey::from_bytes(config.identity.privkey_ed25519.as_bytes());
        assert!(
            verify_signature(
                &payload,
                [0x55; AUTH_CHALLENGE_LEN],
                &signing_key.verifying_key()
            )
            .is_err()
        );
    }
}
