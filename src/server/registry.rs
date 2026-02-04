//! Session registry and CID routing.

use std::collections::HashMap;
use std::net::Ipv4Addr;

use parking_lot::RwLock;
use tracing::{debug, info, trace, warn};

use super::sessions::SessionTx;
use super::{AssignedIp, ClientId};
use crate::types::CidPrefix;

/// Error returned when inserting a CID prefix into the registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CidInsertError {
    /// The CID prefix is already registered to another session.
    PrefixCollision(CidPrefix),
}

#[derive(Debug, Clone)]
struct CidRoute {
    session_id: u64,
    tx: SessionTx,
}

#[derive(Debug, Clone)]
pub struct SessionHandle {
    /// Stable session identifier.
    pub session_id: u64,
    /// Client identifier.
    pub client_id: ClientId,
    /// Assigned VPN IPv4 address.
    pub assigned_ipv4: AssignedIp,
    /// Sender for delivering events to the session.
    pub tx: SessionTx,
}

#[derive(Debug)]
struct RegistryInner {
    next_session_id: u64,
    sessions: HashMap<ClientId, SessionHandle>,
    ip_routes: HashMap<Ipv4Addr, SessionHandle>,
    cid_routes: HashMap<CidPrefix, CidRoute>,
}

/// Global session registry.
#[derive(Debug)]
pub struct SessionRegistry {
    inner: RwLock<RegistryInner>,
}

impl SessionRegistry {
    /// Create an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(RegistryInner {
                next_session_id: 1,
                sessions: HashMap::new(),
                ip_routes: HashMap::new(),
                cid_routes: HashMap::new(),
            }),
        }
    }

    /// Register a session, returning the new handle and any previous one.
    ///
    /// If a session already exists for the same `client_id`, it is replaced and
    /// returned so the caller can shut it down. Any CID routes owned by the
    /// replaced session are removed immediately.
    pub fn register_session(
        &self,
        client_id: ClientId,
        assigned_ipv4: AssignedIp,
        tx: SessionTx,
    ) -> (SessionHandle, Option<SessionHandle>) {
        let mut inner = self.inner.write();
        let session_id = inner.next_session_id;
        inner.next_session_id = inner.next_session_id.saturating_add(1);

        let handle = SessionHandle {
            session_id,
            client_id,
            assigned_ipv4,
            tx,
        };

        let old = inner.sessions.insert(client_id, handle.clone());

        if let Some(old_handle) = &old {
            info!(
                session_id = session_id,
                old_session_id = old_handle.session_id,
                client_id = %client_id,
                assigned_ip = %assigned_ipv4.addr(),
                old_assigned_ip = %old_handle.assigned_ipv4.addr(),
                "replacing existing session"
            );
            if old_handle.assigned_ipv4.addr() != assigned_ipv4.addr() {
                trace!(
                    old_session_id = old_handle.session_id,
                    ip = %old_handle.assigned_ipv4.addr(),
                    "removing old IP route"
                );
                inner.ip_routes.remove(&old_handle.assigned_ipv4.addr());
            }
            let before = inner.cid_routes.len();
            inner
                .cid_routes
                .retain(|_, route| route.session_id != old_handle.session_id);
            let removed_count = before - inner.cid_routes.len();
            debug!(
                old_session_id = old_handle.session_id,
                removed_cid_routes = removed_count,
                "removed CID routes for replaced session"
            );
        } else {
            debug!(
                session_id = session_id,
                client_id = %client_id,
                assigned_ip = %assigned_ipv4.addr(),
                "registering new session"
            );
        }

        trace!(
            session_id = session_id,
            ip = %assigned_ipv4.addr(),
            "inserting IP route"
        );
        inner.ip_routes.insert(assigned_ipv4.addr(), handle.clone());
        drop(inner);
        (handle, old)
    }

    /// Remove a session entry if it still matches `session_id`.
    pub fn remove_session(&self, session_id: u64, client_id: ClientId, assigned_ipv4: AssignedIp) {
        debug!(
            session_id = session_id,
            client_id = %client_id,
            assigned_ip = %assigned_ipv4.addr(),
            "removing session"
        );
        let mut inner = self.inner.write();
        if inner
            .sessions
            .get(&client_id)
            .is_some_and(|handle| handle.session_id == session_id)
        {
            trace!(session_id = session_id, client_id = %client_id, "removing session entry");
            inner.sessions.remove(&client_id);
        }

        if inner
            .ip_routes
            .get(&assigned_ipv4.addr())
            .is_some_and(|handle| handle.session_id == session_id)
        {
            trace!(
                session_id = session_id,
                ip = %assigned_ipv4.addr(),
                "removing IP route"
            );
            inner.ip_routes.remove(&assigned_ipv4.addr());
        }

        let before = inner.cid_routes.len();
        inner
            .cid_routes
            .retain(|_, route| route.session_id != session_id);
        let removed_count = before - inner.cid_routes.len();
        drop(inner);
        trace!(
            session_id = session_id,
            removed_cid_routes = removed_count,
            "removed CID routes for session"
        );
    }

    /// Insert a CID prefix for routing.
    ///
    /// Returns an error if the prefix is owned by a different session.
    ///
    /// # Errors
    ///
    /// Returns `CidInsertError::PrefixCollision` if another session already
    /// registered the same prefix.
    pub fn insert_cid(
        &self,
        session_id: u64,
        prefix: CidPrefix,
        tx: SessionTx,
    ) -> Result<(), CidInsertError> {
        let mut inner = self.inner.write();
        if let Some(route) = inner.cid_routes.get(&prefix)
            && route.session_id != session_id
        {
            warn!(
                session_id = session_id,
                conflicting_session_id = route.session_id,
                prefix = ?prefix,
                "CID prefix collision detected"
            );
            return Err(CidInsertError::PrefixCollision(prefix));
        }
        trace!(
            session_id = session_id,
            prefix = ?prefix,
            "inserting CID route"
        );
        inner.cid_routes.insert(prefix, CidRoute { session_id, tx });
        drop(inner);
        Ok(())
    }

    /// Remove all CID routes owned by `session_id`.
    pub fn remove_cids_for_session(&self, session_id: u64) {
        let mut inner = self.inner.write();
        let before = inner.cid_routes.len();
        inner
            .cid_routes
            .retain(|_, route| route.session_id != session_id);
        let removed_count = before - inner.cid_routes.len();
        drop(inner);
        trace!(
            session_id = session_id,
            removed_cid_routes = removed_count,
            "removed all CID routes for session"
        );
    }

    /// Remove all CID routes for `session_id` except `keep_prefix`.
    pub fn remove_cids_for_session_except(&self, session_id: u64, keep_prefix: CidPrefix) {
        let mut inner = self.inner.write();
        let before = inner.cid_routes.len();
        inner
            .cid_routes
            .retain(|prefix, route| route.session_id != session_id || *prefix == keep_prefix);
        let removed_count = before - inner.cid_routes.len();
        drop(inner);
        trace!(
            session_id = session_id,
            keep_prefix = ?keep_prefix,
            removed_cid_routes = removed_count,
            "removed CID routes for session (except keep_prefix)"
        );
    }

    /// Lookup a session by CID prefix.
    #[must_use]
    pub fn lookup_cid(&self, prefix: CidPrefix) -> Option<SessionTx> {
        self.inner
            .read()
            .cid_routes
            .get(&prefix)
            .map(|route| route.tx.clone())
    }

    /// Lookup a session by assigned IPv4 address.
    #[must_use]
    pub fn lookup_ip(&self, ip: Ipv4Addr) -> Option<SessionTx> {
        self.inner
            .read()
            .ip_routes
            .get(&ip)
            .map(|handle| handle.tx.clone())
    }

    /// Return true if the prefix is currently registered.
    #[must_use]
    pub fn has_cid(&self, prefix: CidPrefix) -> bool {
        self.inner.read().cid_routes.contains_key(&prefix)
    }
}

impl Default for SessionRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use tokio::sync::mpsc;

    use crate::types::QUIC_DCID_PREFIX_LEN;

    fn make_tx() -> SessionTx {
        let (tx, _rx) = mpsc::channel(1);
        tx
    }

    #[test]
    fn registry_replaces_session_and_cleans_routes() {
        let registry = SessionRegistry::new();
        let client_id = ClientId([0x11; 16]);
        let ip_old = AssignedIp(Ipv4Addr::new(10, 0, 0, 1));
        let ip_new = AssignedIp(Ipv4Addr::new(10, 0, 0, 2));

        let (handle, old) = registry.register_session(client_id, ip_old, make_tx());
        assert!(old.is_none());

        let prefix = CidPrefix::from([0xAA; QUIC_DCID_PREFIX_LEN]);
        registry
            .insert_cid(handle.session_id, prefix, make_tx())
            .unwrap();
        assert!(registry.has_cid(prefix));
        assert!(registry.lookup_ip(ip_old.addr()).is_some());

        let (_handle_new, old) = registry.register_session(client_id, ip_new, make_tx());
        assert!(old.is_some());
        assert!(registry.lookup_ip(ip_old.addr()).is_none());
        assert!(registry.lookup_ip(ip_new.addr()).is_some());
        assert!(!registry.has_cid(prefix));
    }

    #[test]
    fn registry_rejects_cid_collisions() {
        let registry = SessionRegistry::new();
        let prefix = CidPrefix::from([0xBB; QUIC_DCID_PREFIX_LEN]);

        registry.insert_cid(1, prefix, make_tx()).unwrap();
        assert!(matches!(
            registry.insert_cid(2, prefix, make_tx()),
            Err(CidInsertError::PrefixCollision(p)) if p == prefix
        ));
    }

    #[test]
    fn registry_keeps_selected_cids() {
        let registry = SessionRegistry::new();
        let keep = CidPrefix::from([0xCC; QUIC_DCID_PREFIX_LEN]);
        let drop = CidPrefix::from([0xDD; QUIC_DCID_PREFIX_LEN]);

        registry.insert_cid(42, keep, make_tx()).unwrap();
        registry.insert_cid(42, drop, make_tx()).unwrap();
        registry.remove_cids_for_session_except(42, keep);

        assert!(registry.has_cid(keep));
        assert!(!registry.has_cid(drop));
    }
}
