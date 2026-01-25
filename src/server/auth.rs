//! Client authentication helpers.

use std::collections::HashMap;

use crate::config::{ServerClient, ServerConfig};

use super::ClientId;

/// Simple allowlist-based authenticator.
#[derive(Debug, Clone)]
pub struct Authenticator {
    clients: HashMap<ClientId, ServerClient>,
}

impl Authenticator {
    /// Build an authenticator from the server config allowlist.
    #[must_use]
    pub fn from_config(config: &ServerConfig) -> Self {
        let clients = config
            .clients
            .iter()
            .cloned()
            .map(|client| (ClientId(client.client_id), client))
            .collect();
        Self { clients }
    }

    /// Returns the configured client entry, if present.
    #[must_use]
    pub fn get(&self, client_id: &ClientId) -> Option<&ServerClient> {
        self.clients.get(client_id)
    }

    /// Returns true if the client exists and is enabled.
    #[must_use]
    pub fn is_enabled(&self, client_id: &ClientId) -> bool {
        self.clients
            .get(client_id)
            .map(|c| c.enabled)
            .unwrap_or(false)
    }
}
