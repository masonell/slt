//! Session tracking and lifecycle helpers.

use std::collections::HashMap;
use std::time::Instant;

use super::{AssignedIp, ClientId};

/// A single authenticated client session.
#[derive(Debug, Clone)]
pub struct Session {
    /// Client identifier.
    pub client_id: ClientId,
    /// Assigned VPN IPv4 address.
    pub assigned_ipv4: AssignedIp,
    /// Session creation timestamp.
    pub created_at: Instant,
    /// Last activity timestamp.
    pub last_activity: Instant,
}

/// Tracks active sessions.
#[derive(Debug, Default)]
pub struct SessionManager {
    sessions: HashMap<ClientId, Session>,
}

impl SessionManager {
    /// Create a new empty session manager.
    #[must_use]
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
        }
    }

    /// Insert or replace a session.
    pub fn insert(&mut self, session: Session) {
        self.sessions.insert(session.client_id, session);
    }

    /// Fetch a session by client id.
    #[must_use]
    pub fn get(&self, client_id: &ClientId) -> Option<&Session> {
        self.sessions.get(client_id)
    }

    /// Fetch a mutable session by client id.
    pub fn get_mut(&mut self, client_id: &ClientId) -> Option<&mut Session> {
        self.sessions.get_mut(client_id)
    }

    /// Remove a session by client id.
    pub fn remove(&mut self, client_id: &ClientId) -> Option<Session> {
        self.sessions.remove(client_id)
    }

    /// Update last activity timestamp.
    pub fn touch(&mut self, client_id: &ClientId, now: Instant) {
        if let Some(session) = self.sessions.get_mut(client_id) {
            session.last_activity = now;
        }
    }
}
