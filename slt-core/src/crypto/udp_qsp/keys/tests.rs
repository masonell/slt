use super::*;
use crate::proto::{
    AEAD_IV_LEN, CHACHA20_POLY1305_KEY_LEN, CipherSuite, HP_KEY_LEN, UDP_QSP_TRAFFIC_SECRET_LEN,
};

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

#[test]
fn from_packet_material_rejects_wrong_chacha_key_lengths() {
    let keys = UdpQspKeys::from_packet_material(
        CipherSuite::ChaCha20Poly1305,
        &[0u8; HP_KEY_LEN],
        &[0u8; CHACHA20_POLY1305_KEY_LEN],
        &[0u8; CHACHA20_POLY1305_KEY_LEN],
        &[0u8; CHACHA20_POLY1305_KEY_LEN],
        &[0u8; AEAD_IV_LEN],
        &[0u8; AEAD_IV_LEN],
    );

    assert!(matches!(keys, Err(QspCryptoError::CryptoFail)));
}

#[test]
fn protect_and_open_roundtrip() {
    let dcid = [0xAB; 8];
    let plaintext = b"hello, world!";
    let pn = 1;

    let keys = make_symmetric_keys();
    let protected = keys.protect(&dcid, pn, false, plaintext).unwrap();

    let opened = keys.open(dcid.len(), &protected, pn).unwrap();
    assert_eq!(opened.pn, pn);
    assert!(!opened.key_phase);
    assert_eq!(opened.payload, plaintext);
}

#[test]
fn protect_and_open_empty_payload_returns_padding_only() {
    let dcid = [0xAB; 8];
    let pn = 1;
    let keys = make_symmetric_keys();
    let protected = keys.protect(&dcid, pn, false, b"").unwrap();
    let opened = keys.open(dcid.len(), &protected, pn).unwrap();

    assert!(opened.payload.iter().all(|b| *b == 0));
}

#[test]
fn protect_and_open_with_different_dcids() {
    let dcid1 = [0x01; 8];
    let dcid2 = [0x02; 8];
    let plaintext = b"hello";
    let pn = 1;

    let keys = make_symmetric_keys();
    let protected1 = keys.protect(&dcid1, pn, false, plaintext).unwrap();
    let protected2 = keys.protect(&dcid2, pn, false, plaintext).unwrap();

    assert_ne!(protected1, protected2);
    assert_eq!(
        keys.open(dcid1.len(), &protected1, pn).unwrap().payload,
        plaintext
    );
    assert_eq!(
        keys.open(dcid2.len(), &protected2, pn).unwrap().payload,
        plaintext
    );
}

#[test]
fn debug_redacts_key_material() {
    let keys = make_directional_keys();
    let debug_str = format!("{keys:?}");

    assert!(debug_str.contains("UdpQspKeys"));
    assert!(debug_str.contains("cipher"));
    assert!(debug_str.contains("<redacted>"));
    assert!(!debug_str.contains("0x11"));
}
