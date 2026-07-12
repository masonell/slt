//! Directional traffic-secret state and key rotation.

use super::super::QspCryptoError;
use super::backend::{CipherConfig, HeaderProtectionKey, PacketKey};
use super::derivation::{derive_header_protection_key, derive_next_secret, derive_packet_material};
use crate::proto::UDP_QSP_TRAFFIC_SECRET_LEN;

pub(super) struct DirectionKeys {
    secret: [u8; UDP_QSP_TRAFFIC_SECRET_LEN],
    pub(super) hp: HeaderProtectionKey,
    pub(super) aead: PacketKey,
}

impl DirectionKeys {
    pub(super) fn from_secret(secret: &[u8], config: CipherConfig) -> Result<Self, QspCryptoError> {
        let secret: [u8; UDP_QSP_TRAFFIC_SECRET_LEN] =
            secret.try_into().map_err(|_| QspCryptoError::CryptoFail)?;
        let hp_key = derive_header_protection_key(&secret, config.hp_key_len())?;
        let packet = derive_packet_material(&secret, config.aead_key_len(), config.iv_len())?;

        Ok(Self {
            secret,
            hp: HeaderProtectionKey::new(config.header_protection_kind(), &hp_key)?,
            aead: PacketKey::new(&packet.key, &packet.iv, config.aead_kind())?,
        })
    }

    #[cfg(any(test, feature = "testing"))]
    pub(super) fn from_packet_material(
        config: CipherConfig,
        hp: &[u8],
        aead: &[u8],
        iv: &[u8],
    ) -> Result<Self, QspCryptoError> {
        Ok(Self {
            secret: [0u8; UDP_QSP_TRAFFIC_SECRET_LEN],
            hp: HeaderProtectionKey::new(config.header_protection_kind(), hp)?,
            aead: PacketKey::new(aead, iv, config.aead_kind())?,
        })
    }

    pub(super) fn next_generation(&self, config: CipherConfig) -> Result<Self, QspCryptoError> {
        let secret = derive_next_secret(&self.secret)?;
        let hp = self.hp.try_clone()?;
        let packet = derive_packet_material(&secret, config.aead_key_len(), config.iv_len())?;

        Ok(Self {
            secret,
            hp,
            aead: PacketKey::new(&packet.key, &packet.iv, config.aead_kind())?,
        })
    }

    pub(super) fn try_clone(&self) -> Result<Self, QspCryptoError> {
        Ok(Self {
            secret: self.secret,
            hp: self.hp.try_clone()?,
            aead: self.aead.try_clone()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::UdpQspKeys;
    use crate::proto::{CipherSuite, UDP_QSP_TRAFFIC_SECRET_LEN};

    fn make_symmetric_keys() -> UdpQspKeys {
        UdpQspKeys::new(
            CipherSuite::Aes128Gcm,
            [0xAA; UDP_QSP_TRAFFIC_SECRET_LEN],
            [0xAA; UDP_QSP_TRAFFIC_SECRET_LEN],
        )
        .unwrap()
    }

    fn make_directional_keys() -> UdpQspKeys {
        UdpQspKeys::new(
            CipherSuite::Aes128Gcm,
            [0x11; UDP_QSP_TRAFFIC_SECRET_LEN],
            [0x22; UDP_QSP_TRAFFIC_SECRET_LEN],
        )
        .unwrap()
    }

    fn make_symmetric_chacha_keys() -> UdpQspKeys {
        UdpQspKeys::new(
            CipherSuite::ChaCha20Poly1305,
            [0xAA; UDP_QSP_TRAFFIC_SECRET_LEN],
            [0xAA; UDP_QSP_TRAFFIC_SECRET_LEN],
        )
        .unwrap()
    }

    fn make_directional_chacha_keys() -> UdpQspKeys {
        UdpQspKeys::new(
            CipherSuite::ChaCha20Poly1305,
            [0x11; UDP_QSP_TRAFFIC_SECRET_LEN],
            [0x22; UDP_QSP_TRAFFIC_SECRET_LEN],
        )
        .unwrap()
    }

    #[test]
    fn new_keys_with_aes128gcm_succeeds() {
        let keys = UdpQspKeys::new(
            CipherSuite::Aes128Gcm,
            [0u8; UDP_QSP_TRAFFIC_SECRET_LEN],
            [0u8; UDP_QSP_TRAFFIC_SECRET_LEN],
        );
        assert!(keys.is_ok());
    }

    #[test]
    fn new_keys_with_chacha20_poly1305_succeeds() {
        let keys = UdpQspKeys::new(
            CipherSuite::ChaCha20Poly1305,
            [0u8; UDP_QSP_TRAFFIC_SECRET_LEN],
            [0u8; UDP_QSP_TRAFFIC_SECRET_LEN],
        );
        assert!(keys.is_ok());
    }

    #[test]
    fn chacha20_poly1305_protect_and_open_roundtrip() {
        let dcid = [0xAB; 8];
        let plaintext = b"hello with chacha20-poly1305";
        let pn = 7;

        let keys = make_symmetric_chacha_keys();
        let protected = keys.protect(&dcid, pn, true, plaintext).unwrap();

        let opened = keys.open(dcid.len(), &protected, pn).unwrap();
        assert_eq!(opened.pn, pn);
        assert!(opened.key_phase);
        assert_eq!(opened.payload, plaintext);
    }

    #[test]
    fn with_next_tx_keys_produces_valid_keys() {
        let keys = make_directional_keys();
        let next = keys.with_next_tx_keys();
        assert!(next.is_ok());
    }

    #[test]
    fn with_next_rx_keys_produces_valid_keys() {
        let keys = make_directional_keys();
        let next = keys.with_next_rx_keys();
        assert!(next.is_ok());
    }

    #[test]
    fn tx_key_rotation_changes_encrypt_keys() {
        let dcid = [0xAB; 8];
        let plaintext = b"test payload";
        let pn = 42;

        let keys = make_directional_keys();
        let next_keys = keys.with_next_tx_keys().unwrap();
        let packet_original = keys.protect(&dcid, pn, false, plaintext).unwrap();
        let packet_rotated = next_keys.protect(&dcid, pn, false, plaintext).unwrap();

        assert_ne!(
            packet_original, packet_rotated,
            "rotated TX keys should produce different ciphertext"
        );
    }

    #[test]
    fn key_update_preserves_hp_key_and_changes_aead_key_and_iv() {
        let keys = make_directional_keys();
        let next = keys.with_next_tx_keys().unwrap();

        assert_eq!(keys.tx.hp.key_bytes(), next.tx.hp.key_bytes());
        assert_ne!(keys.tx.aead.key_bytes(), next.tx.aead.key_bytes());
        assert_ne!(keys.tx.aead.iv(), next.tx.aead.iv());
    }

    #[test]
    fn rx_key_rotation_changes_decrypt_keys() {
        let dcid = [0xAB; 8];
        let plaintext = b"test payload";
        let pn = 42;

        let keys = make_symmetric_keys();
        let next_keys = keys.with_next_rx_keys().unwrap();
        let packet = keys.protect(&dcid, pn, false, plaintext).unwrap();

        assert!(keys.open(dcid.len(), &packet, pn).is_ok());
        assert!(
            next_keys.open(dcid.len(), &packet, pn).is_err(),
            "rotated RX keys should not decrypt packets from original keys"
        );
    }

    #[test]
    fn tx_rotation_preserves_rx_keys() {
        let dcid = [0xAB; 8];
        let plaintext = b"test payload";
        let pn = 42;
        let server_tx = [0x33; UDP_QSP_TRAFFIC_SECRET_LEN];
        let server_rx = [0x44; UDP_QSP_TRAFFIC_SECRET_LEN];

        let server_keys = UdpQspKeys::new(CipherSuite::Aes128Gcm, server_tx, server_rx).unwrap();
        let server_next = server_keys.with_next_tx_keys().unwrap();
        let peer_keys = UdpQspKeys::new(CipherSuite::Aes128Gcm, server_rx, server_tx).unwrap();
        let packet = peer_keys.protect(&dcid, pn, false, plaintext).unwrap();

        let opened_orig = server_keys.open(dcid.len(), &packet, pn);
        let opened_next = server_next.open(dcid.len(), &packet, pn);

        assert!(opened_orig.is_ok(), "original server RX should decrypt");
        assert!(
            opened_next.is_ok(),
            "rotated server RX should still decrypt (RX unchanged)"
        );
        assert_eq!(opened_orig.unwrap().payload, plaintext);
        assert_eq!(opened_next.unwrap().payload, plaintext);
    }

    #[test]
    fn rx_rotation_preserves_tx_keys() {
        let dcid = [0xAB; 8];
        let plaintext = b"test payload";
        let pn = 42;

        let keys = make_directional_keys();
        let next_rx = keys.with_next_rx_keys().unwrap();
        let packet_orig = keys.protect(&dcid, pn, false, plaintext).unwrap();
        let packet_next = next_rx.protect(&dcid, pn, false, plaintext).unwrap();

        assert_eq!(
            packet_orig, packet_next,
            "same TX keys should produce identical ciphertext"
        );
    }

    #[test]
    fn chacha20_poly1305_tx_key_rotation_changes_encrypt_keys() {
        let dcid = [0xAB; 8];
        let plaintext = b"test payload";
        let pn = 42;

        let keys = make_directional_chacha_keys();
        let next_keys = keys.with_next_tx_keys().unwrap();
        let packet_original = keys.protect(&dcid, pn, false, plaintext).unwrap();
        let packet_rotated = next_keys.protect(&dcid, pn, true, plaintext).unwrap();

        assert_ne!(
            packet_original, packet_rotated,
            "rotated ChaCha TX keys should produce different ciphertext"
        );
    }

    #[test]
    fn chacha20_poly1305_rx_key_rotation_derives_working_next_keys() {
        let dcid = [0xAB; 8];
        let plaintext = b"test payload";
        let pn = 42;

        let keys = make_symmetric_chacha_keys();
        let tx_next = keys.with_next_tx_keys().unwrap();
        let rx_next = keys.with_next_rx_keys().unwrap();
        let packet = tx_next.protect(&dcid, pn, true, plaintext).unwrap();

        let opened = rx_next.open(dcid.len(), &packet, pn).unwrap();
        assert_eq!(opened.payload, plaintext);
        assert!(opened.key_phase);
    }

    #[test]
    fn chacha20_poly1305_old_and_new_phase_packets_use_matching_keys() {
        let dcid = [0xAB; 8];
        let plaintext = b"test payload";
        let pn = 42;

        let keys = make_symmetric_chacha_keys();
        let tx_next = keys.with_next_tx_keys().unwrap();
        let rx_next = keys.with_next_rx_keys().unwrap();

        let old_phase = keys.protect(&dcid, pn, false, plaintext).unwrap();
        let new_phase = tx_next.protect(&dcid, pn, true, plaintext).unwrap();

        let opened_old = keys.open(dcid.len(), &old_phase, pn).unwrap();
        let opened_new = rx_next.open(dcid.len(), &new_phase, pn).unwrap();
        assert_eq!(opened_old.payload, plaintext);
        assert!(!opened_old.key_phase);
        assert_eq!(opened_new.payload, plaintext);
        assert!(opened_new.key_phase);

        assert!(keys.open(dcid.len(), &new_phase, pn).is_err());
        assert!(rx_next.open(dcid.len(), &old_phase, pn).is_err());
    }

    #[test]
    fn opposite_directional_secrets_rekey_and_roundtrip() {
        let dcid = [0xAB; 8];
        let plaintext = b"server to client after rekey";
        let server_to_client = [0xA5; UDP_QSP_TRAFFIC_SECRET_LEN];
        let client_to_server = [0x5A; UDP_QSP_TRAFFIC_SECRET_LEN];

        let server =
            UdpQspKeys::new(CipherSuite::Aes128Gcm, server_to_client, client_to_server).unwrap();
        let client =
            UdpQspKeys::new(CipherSuite::Aes128Gcm, client_to_server, server_to_client).unwrap();

        let server_next = server.with_next_tx_keys().unwrap();
        let client_next = client.with_next_rx_keys().unwrap();
        let packet = server_next.protect(&dcid, 42, true, plaintext).unwrap();
        let opened = client_next.open(dcid.len(), &packet, 42).unwrap();

        assert_eq!(opened.payload, plaintext);
        assert!(opened.key_phase);
    }

    #[test]
    fn multiple_tx_rotations_produce_different_keys() {
        let dcid = [0xAB; 8];
        let plaintext = b"test payload";
        let pn = 42;

        let keys = make_directional_keys();
        let keys1 = keys.with_next_tx_keys().unwrap();
        let keys2 = keys1.with_next_tx_keys().unwrap();
        let keys3 = keys2.with_next_tx_keys().unwrap();

        let p0 = keys.protect(&dcid, pn, false, plaintext).unwrap();
        let p1 = keys1.protect(&dcid, pn, true, plaintext).unwrap();
        let p2 = keys2.protect(&dcid, pn, false, plaintext).unwrap();
        let p3 = keys3.protect(&dcid, pn, true, plaintext).unwrap();

        assert_ne!(p0, p1);
        assert_ne!(p1, p2);
        assert_ne!(p2, p3);
        assert_ne!(p0, p2);
        assert_ne!(p1, p3);
    }

    #[test]
    fn multiple_rx_rotations_produce_different_keys() {
        let dcid = [0xAB; 8];
        let plaintext = b"test payload";
        let pn = 42;

        let keys = make_symmetric_keys();
        let rx1 = keys.with_next_rx_keys().unwrap();
        let rx2 = rx1.with_next_rx_keys().unwrap();
        let rx3 = rx2.with_next_rx_keys().unwrap();
        let tx1 = keys.with_next_tx_keys().unwrap();
        let tx2 = tx1.with_next_tx_keys().unwrap();
        let tx3 = tx2.with_next_tx_keys().unwrap();

        let p1 = tx1.protect(&dcid, pn, true, plaintext).unwrap();
        let p2 = tx2.protect(&dcid, pn, false, plaintext).unwrap();
        let p3 = tx3.protect(&dcid, pn, true, plaintext).unwrap();

        assert!(rx1.open(dcid.len(), &p1, pn).is_ok(), "rx1 should open p1");
        assert!(rx2.open(dcid.len(), &p2, pn).is_ok(), "rx2 should open p2");
        assert!(rx3.open(dcid.len(), &p3, pn).is_ok(), "rx3 should open p3");
        assert!(
            rx1.open(dcid.len(), &p2, pn).is_err(),
            "rx1 should not open p2"
        );
        assert!(
            rx2.open(dcid.len(), &p3, pn).is_err(),
            "rx2 should not open p3"
        );
        assert!(
            rx3.open(dcid.len(), &p1, pn).is_err(),
            "rx3 should not open p1"
        );
    }
}
