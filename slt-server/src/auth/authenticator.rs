use std::collections::HashMap;

use ed25519_dalek::{Signature, VerifyingKey};
use slt_core::config::ServerConfig;
use slt_core::proto::{AUTH_CHALLENGE_LEN, AuthFailCode, AuthPayload};
use slt_core::types::{ClientId, ServerClient};
use tracing::trace;

use crate::AssignedIp;

/// Simple allowlist-based authenticator.
///
/// Maintains a mapping of client IDs to their server configuration entries,
/// providing methods for client lookup and validation during the authentication
/// phase. Clients must be present in the allowlist and enabled to authenticate.
#[derive(Debug, Clone)]
pub struct Authenticator {
    clients_config: HashMap<ClientId, ServerClient>,
}

impl Authenticator {
    /// Build an authenticator from the server config allowlist.
    #[must_use]
    pub fn from_config(config: &ServerConfig) -> Self {
        let clients = config
            .clients
            .iter()
            .cloned()
            .map(|client| (client.client_id, client))
            .collect();
        Self {
            clients_config: clients,
        }
    }

    /// Returns the configured client entry, if present.
    #[must_use]
    pub fn get(&self, client_id: &ClientId) -> Option<&ServerClient> {
        self.clients_config.get(client_id)
    }

    /// Returns true if the client exists and is enabled.
    #[must_use]
    pub fn is_enabled(&self, client_id: &ClientId) -> bool {
        self.clients_config
            .get(client_id)
            .is_some_and(|c| c.enabled)
    }

    /// Creates an authenticator with the given clients (test-only).
    #[cfg(test)]
    #[must_use]
    pub fn new(clients: impl IntoIterator<Item = ServerClient>) -> Self {
        Self {
            clients_config: clients
                .into_iter()
                .map(|client| (client.client_id, client))
                .collect(),
        }
    }
}

/// Verifies an authentication payload against the authenticator and challenge.
///
/// Performs comprehensive validation including:
/// - Client existence in the allowlist
/// - Client enabled status
/// - Assigned IP address match
/// - Challenge value correctness
/// - Ed25519 signature verification over the context string
///
/// # Arguments
///
/// * `authenticator` - The authenticator containing client configurations
/// * `payload` - The authentication payload from the client
/// * `challenge` - The challenge bytes derived from TLS keying material
///
/// # Returns
///
/// Returns the assigned IP address on success, or an authentication failure
/// code indicating the specific reason for rejection.
///
/// # Signature Context
///
/// Verified over the bytes produced by [`slt_core::proto::auth_signature_context`].
pub(super) fn verify_auth_payload(
    authenticator: &Authenticator,
    payload: &AuthPayload,
    challenge: &[u8; AUTH_CHALLENGE_LEN],
) -> Result<AssignedIp, AuthFailCode> {
    let client = authenticator
        .get(&payload.client_id)
        .ok_or(AuthFailCode::UnknownClient)?;
    trace!(client_id = %payload.client_id, "looking up client in authenticator");

    if !client.enabled {
        trace!(client_id = %payload.client_id, "client is disabled");
        return Err(AuthFailCode::Disabled);
    }
    if client.assigned_ipv4 != payload.assigned_ipv4 {
        trace!(client_id = %payload.client_id, expected = %client.assigned_ipv4, provided = %payload.assigned_ipv4, "IP address mismatch");
        return Err(AuthFailCode::IpMismatch);
    }
    if &payload.challenge != challenge {
        trace!(client_id = %payload.client_id, "challenge mismatch");
        return Err(AuthFailCode::ChallengeInvalid);
    }

    let context = slt_core::proto::auth_signature_context(
        &payload.client_id,
        payload.assigned_ipv4,
        challenge,
    );

    let key = VerifyingKey::from_bytes(client.pubkey_ed25519.as_bytes()).map_err(|_| {
        trace!(client_id = %payload.client_id, "failed to parse verifying key");
        AuthFailCode::BadSignature
    })?;
    let signature = Signature::from_bytes(&payload.signature);
    key.verify_strict(&context, &signature).map_err(|_| {
        trace!(client_id = %payload.client_id, "signature verification failed");
        AuthFailCode::BadSignature
    })?;

    trace!(client_id = %payload.client_id, "signature verified successfully");
    Ok(AssignedIp(client.assigned_ipv4))
}
