//! UDP-QSP CID map and packet helpers.

use std::collections::HashMap;

use slt_core::crypto::udp_qsp::{OpenedPacket, QspCryptoError, UdpQspKeys};
use slt_core::proto::RegisterCidPayload;
use slt_core::types::{Cid, CidPrefix};
use tracing::{debug, error, trace, warn};

/// CID map entry for a single UDP-QSP session.
#[derive(Debug)]
pub struct CidEntry {
    /// Opaque handle linking this CID to a connection/session.
    pub conn_handle: u64,
    /// Pre-computed prefix for the DCID (used for classification).
    dcid_prefix: CidPrefix,
    /// Destination connection ID for client->server packets.
    pub dcid: Cid,
    /// Destination connection ID for server->client packets.
    pub scid: Cid,
    /// Packet protection keys.
    pub keys: UdpQspKeys,
    /// Next packet number to use for outbound traffic.
    pub next_pn: u64,
    /// Current key phase.
    pub key_phase: bool,
}

impl CidEntry {
    /// Construct a CID entry from a `REGISTER_CID` payload.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Key extraction from the payload fails (see `UdpQspKeys::from_register`)
    /// - The `client_to_server_cid` is too short for prefix extraction
    pub fn from_register(
        conn_handle: u64,
        payload: &RegisterCidPayload,
        pn_start: u64,
        key_phase: bool,
    ) -> Result<Self, QspCryptoError> {
        debug!(
            conn_handle,
            dcid = ?payload.client_to_server_cid,
            scid = ?payload.server_to_client_cid,
            pn_start,
            key_phase,
            cipher = ?payload.cipher,
            "installing UDP-QSP keys"
        );
        let keys = UdpQspKeys::from_register(payload)?;
        let dcid_prefix = payload.client_to_server_cid.prefix().map_err(|e| {
            error!(
                conn_handle,
                error = %e,
                "failed to extract DCID prefix"
            );
            QspCryptoError::InvalidCid
        })?;
        trace!(
            conn_handle,
            dcid_prefix = ?dcid_prefix,
            "UDP-QSP keys installed successfully"
        );
        Ok(Self {
            conn_handle,
            dcid_prefix,
            dcid: payload.client_to_server_cid,
            scid: payload.server_to_client_cid,
            keys,
            next_pn: pn_start,
            key_phase,
        })
    }

    /// Protect an outbound payload, advancing the packet number.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The packet number would overflow
    /// - Packet protection fails (see `UdpQspKeys::protect`)
    pub fn protect(&mut self, payload: &[u8]) -> Result<Vec<u8>, QspCryptoError> {
        let pn = self.next_pn;
        trace!(
            conn_handle = self.conn_handle,
            scid = ?self.scid,
            pn,
            payload_len = payload.len(),
            key_phase = self.key_phase,
            "protecting outbound UDP-QSP packet"
        );
        self.next_pn = pn.checked_add(1).ok_or_else(|| {
            error!(
                conn_handle = self.conn_handle,
                scid = ?self.scid,
                pn,
                "packet number overflow, cannot protect packet"
            );
            QspCryptoError::InvalidPacketNumber
        })?;
        self.keys
            .protect(self.scid.as_slice(), pn, self.key_phase, payload)
            .inspect_err(|&e| {
                error!(
                    conn_handle = self.conn_handle,
                    scid = ?self.scid,
                    pn,
                    error = ?e,
                    "UDP-QSP protect failed"
                );
            })
    }

    /// Open an inbound UDP-QSP packet.
    ///
    /// `expected_pn` should be the next packet number you expect to receive
    /// (typically `largest_pn + 1`) to allow packet number reconstruction.
    ///
    /// # Errors
    ///
    /// Propagates errors from `UdpQspKeys::open`.
    pub fn open(&self, packet: &[u8], expected_pn: u64) -> Result<OpenedPacket, QspCryptoError> {
        trace!(
            conn_handle = self.conn_handle,
            dcid = ?self.dcid,
            expected_pn,
            packet_len = packet.len(),
            "opening inbound UDP-QSP packet"
        );
        self.keys
            .open(self.dcid.len(), packet, expected_pn)
            .inspect_err(|&e| {
                // Log specific error types with appropriate levels
                match &e {
                    QspCryptoError::InvalidPacketNumber => {
                        warn!(
                            conn_handle = self.conn_handle,
                            dcid = ?self.dcid,
                            expected_pn,
                            error = ?e,
                            "UDP-QSP open failed: packet number window error"
                        );
                    }
                    QspCryptoError::CryptoFail => {
                        warn!(
                            conn_handle = self.conn_handle,
                            dcid = ?self.dcid,
                            expected_pn,
                            error = ?e,
                            "UDP-QSP open failed: crypto operation failed (likely authentication)"
                        );
                    }
                    _ => {
                        error!(
                            conn_handle = self.conn_handle,
                            dcid = ?self.dcid,
                            expected_pn,
                            error = ?e,
                            "UDP-QSP open failed"
                        );
                    }
                }
            })
    }

    /// Return the prefix used to classify the CID.
    #[must_use]
    pub const fn prefix(&self) -> CidPrefix {
        self.dcid_prefix
    }
}

/// Errors returned when inserting into the CID map.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CidMapError {
    /// The CID prefix is already registered to a different connection.
    PrefixCollision(CidPrefix),
    /// The CID prefix is already registered to the same connection and CID.
    AlreadyRegistered(CidPrefix),
}

/// CID map keyed by UDP-QSP destination connection ID prefixes.
///
/// Thread-local map tracking CID entries for UDP-QSP sessions. Each entry
/// contains the connection IDs, keys, and packet number state for a single
/// UDP-QSP flow. Supports insert, lookup, and removal operations with
/// collision detection.
#[derive(Debug, Default)]
pub struct CidMap {
    entries: HashMap<CidPrefix, CidEntry>,
}

impl CidMap {
    /// Create an empty CID map.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Insert a CID entry, returning the previous entry if present.
    ///
    /// # Errors
    ///
    /// Returns `CidMapError::PrefixCollision` if another connection already
    /// uses the same prefix.
    pub fn insert(&mut self, entry: CidEntry) -> Result<Option<CidEntry>, CidMapError> {
        let prefix = entry.prefix();
        if let Some(existing) = self.entries.get(&prefix) {
            if existing.conn_handle == entry.conn_handle && existing.dcid == entry.dcid {
                return Err(CidMapError::AlreadyRegistered(prefix));
            }
            return Err(CidMapError::PrefixCollision(prefix));
        }
        Ok(self.entries.insert(prefix, entry))
    }

    /// Remove a CID entry by its connection ID prefix.
    pub fn remove(&mut self, dcid_prefix: CidPrefix) -> Option<CidEntry> {
        self.entries.remove(&dcid_prefix)
    }

    /// Fetch a CID entry by its connection ID prefix.
    #[must_use]
    pub fn get(&self, dcid_prefix: CidPrefix) -> Option<&CidEntry> {
        self.entries.get(&dcid_prefix)
    }

    /// Fetch a mutable CID entry by its connection ID prefix.
    pub fn get_mut(&mut self, dcid_prefix: CidPrefix) -> Option<&mut CidEntry> {
        self.entries.get_mut(&dcid_prefix)
    }

    /// Return the number of stored CID entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Return true if no entries exist.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use slt_core::proto::{CipherSuite, RegisterCidPayload, UDP_QSP_TRAFFIC_SECRET_LEN};
    use slt_core::types::{Cid, MAX_DCID_LEN};

    use super::*;

    fn make_test_payload() -> RegisterCidPayload {
        let c2s_cid = Cid::from([0xAA; MAX_DCID_LEN]);
        let s2c_cid = Cid::new(&[]).unwrap(); // Empty SCID
        RegisterCidPayload {
            client_to_server_cid: c2s_cid,
            server_to_client_cid: s2c_cid,
            cipher: CipherSuite::Aes128Gcm,
            secret_tx: [0x01; UDP_QSP_TRAFFIC_SECRET_LEN],
            secret_rx: [0x02; UDP_QSP_TRAFFIC_SECRET_LEN],
            pn_start: 0,
            pn_start_rx: 0,
            key_phase: false,
        }
    }

    #[test]
    fn cid_map_insert_lookup_remove() {
        let payload = make_test_payload();
        let entry = CidEntry::from_register(7, &payload, 0, false).unwrap();
        let mut map = CidMap::new();
        assert!(map.is_empty());
        map.insert(entry).unwrap();
        assert_eq!(map.len(), 1);
        assert!(
            map.get(payload.client_to_server_cid.prefix().unwrap())
                .is_some()
        );
        map.remove(payload.client_to_server_cid.prefix().unwrap());
        assert!(map.is_empty());
    }

    #[test]
    fn cid_map_rejects_prefix_collision() {
        let payload = make_test_payload();

        // Create a different payload with the same prefix
        let c2s_cid = Cid::from([0xAA; MAX_DCID_LEN]); // Same prefix
        let s2c_cid = Cid::new(&[]).unwrap();
        let payload_collision = RegisterCidPayload {
            client_to_server_cid: c2s_cid,
            server_to_client_cid: s2c_cid,
            ..payload.clone()
        };

        let entry = CidEntry::from_register(7, &payload, 0, false).unwrap();
        let entry_collision = CidEntry::from_register(8, &payload_collision, 0, false).unwrap();

        let mut map = CidMap::new();
        map.insert(entry).unwrap();
        assert!(matches!(
            map.insert(entry_collision),
            Err(CidMapError::PrefixCollision(prefix)) if prefix == payload.client_to_server_cid.prefix().unwrap()
        ));
    }

    #[test]
    fn cid_map_reports_duplicate_registration() {
        let payload = make_test_payload();

        let entry = CidEntry::from_register(7, &payload, 0, false).unwrap();
        let entry_dup = CidEntry::from_register(7, &payload, 0, false).unwrap();

        let mut map = CidMap::new();
        map.insert(entry).unwrap();
        assert!(matches!(
            map.insert(entry_dup),
            Err(CidMapError::AlreadyRegistered(prefix)) if prefix == payload.client_to_server_cid.prefix().unwrap()
        ));
    }

    #[test]
    fn cid_entry_accepts_large_pn_start() {
        let payload = make_test_payload();
        let pn_start = u64::from(u32::MAX) + 1;
        let entry = CidEntry::from_register(7, &payload, pn_start, false).unwrap();
        assert_eq!(entry.next_pn, pn_start);
    }

    #[test]
    fn cid_entry_rejects_pn_wrap() {
        let payload = make_test_payload();
        let mut entry = CidEntry::from_register(7, &payload, u64::MAX, false).unwrap();
        assert_eq!(
            entry.protect(&[0xAA; 4]),
            Err(QspCryptoError::InvalidPacketNumber)
        );
    }
}
