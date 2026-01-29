//! UDP-QSP CID map and packet helpers.

use std::collections::HashMap;

use crate::crypto::udp_qsp::{OpenedPacket, QspCryptoError, UdpQspKeys};
use crate::proto::RegisterCidPayload;

/// CID map entry for a single UDP-QSP session.
#[derive(Debug, Clone)]
pub struct CidEntry {
    /// Opaque handle linking this CID to a connection/session.
    pub conn_handle: u64,
    /// Destination connection ID used on the wire.
    pub dcid: Vec<u8>,
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
    /// Returns an error if key extraction from the payload fails (see
    /// `UdpQspKeys::from_register`).
    pub fn from_register(
        conn_handle: u64,
        payload: &RegisterCidPayload<'_>,
        pn_start: u64,
        key_phase: bool,
    ) -> Result<Self, QspCryptoError> {
        Ok(Self {
            conn_handle,
            dcid: payload.dcid.to_vec(),
            keys: UdpQspKeys::from_register(payload)?,
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
        self.next_pn = pn
            .checked_add(1)
            .ok_or(QspCryptoError::InvalidPacketNumber)?;
        self.keys.protect(&self.dcid, pn, self.key_phase, payload)
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
        self.keys.open(self.dcid.len(), packet, expected_pn)
    }
}

/// CID map keyed by UDP-QSP destination connection IDs.
#[derive(Debug, Default)]
pub struct CidMap {
    entries: HashMap<Vec<u8>, CidEntry>,
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
    pub fn insert(&mut self, entry: CidEntry) -> Option<CidEntry> {
        self.entries.insert(entry.dcid.clone(), entry)
    }

    /// Remove a CID entry by its connection ID.
    pub fn remove(&mut self, dcid: &[u8]) -> Option<CidEntry> {
        self.entries.remove(dcid)
    }

    /// Fetch a CID entry by its connection ID.
    #[must_use]
    pub fn get(&self, dcid: &[u8]) -> Option<&CidEntry> {
        self.entries.get(dcid)
    }

    /// Fetch a mutable CID entry by its connection ID.
    pub fn get_mut(&mut self, dcid: &[u8]) -> Option<&mut CidEntry> {
        self.entries.get_mut(dcid)
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
    use super::*;
    use crate::proto::{AEAD_IV_LEN, AEAD_KEY_LEN, CipherSuite, HP_KEY_LEN, RegisterCidPayload};

    #[test]
    fn cid_map_insert_lookup_remove() {
        let dcid = [0xAA; 8];
        let payload = RegisterCidPayload {
            dcid: &dcid,
            cipher: CipherSuite::Aes128Gcm,
            hp_tx: [0x01; HP_KEY_LEN],
            hp_rx: [0x02; HP_KEY_LEN],
            aead_tx: [0x03; AEAD_KEY_LEN],
            aead_rx: [0x04; AEAD_KEY_LEN],
            iv_tx: [0x05; AEAD_IV_LEN],
            iv_rx: [0x06; AEAD_IV_LEN],
            pn_start: 0,
            key_phase: false,
        };

        let entry = CidEntry::from_register(7, &payload, 0, false).unwrap();
        let mut map = CidMap::new();
        assert!(map.is_empty());
        map.insert(entry);
        assert_eq!(map.len(), 1);
        assert!(map.get(&dcid).is_some());
        map.remove(&dcid);
        assert!(map.is_empty());
    }

    #[test]
    fn cid_entry_accepts_large_pn_start() {
        let dcid = [0xAA; 8];
        let payload = RegisterCidPayload {
            dcid: &dcid,
            cipher: CipherSuite::Aes128Gcm,
            hp_tx: [0x01; HP_KEY_LEN],
            hp_rx: [0x02; HP_KEY_LEN],
            aead_tx: [0x03; AEAD_KEY_LEN],
            aead_rx: [0x04; AEAD_KEY_LEN],
            iv_tx: [0x05; AEAD_IV_LEN],
            iv_rx: [0x06; AEAD_IV_LEN],
            pn_start: 0,
            key_phase: false,
        };

        let pn_start = u64::from(u32::MAX) + 1;
        let entry = CidEntry::from_register(7, &payload, pn_start, false).unwrap();
        assert_eq!(entry.next_pn, pn_start);
    }

    #[test]
    fn cid_entry_rejects_pn_wrap() {
        let dcid = [0xAA; 8];
        let payload = RegisterCidPayload {
            dcid: &dcid,
            cipher: CipherSuite::Aes128Gcm,
            hp_tx: [0x01; HP_KEY_LEN],
            hp_rx: [0x02; HP_KEY_LEN],
            aead_tx: [0x03; AEAD_KEY_LEN],
            aead_rx: [0x04; AEAD_KEY_LEN],
            iv_tx: [0x05; AEAD_IV_LEN],
            iv_rx: [0x06; AEAD_IV_LEN],
            pn_start: 0,
            key_phase: false,
        };

        let mut entry = CidEntry::from_register(7, &payload, u64::MAX, false).unwrap();
        assert_eq!(
            entry.protect(&[0xAA; 4]),
            Err(QspCryptoError::InvalidPacketNumber)
        );
    }
}
