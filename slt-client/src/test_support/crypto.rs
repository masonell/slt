//! Crypto key helpers for UDP-QSP testing.

use slt_core::crypto::udp_qsp::UdpQspKeys;
use slt_core::proto::{AEAD_IV_LEN, AEAD_KEY_LEN, CipherSuite, HP_KEY_LEN};

/// Fixed client keys for UDP-QSP testing.
///
/// Uses deterministic values for reproducible tests:
/// - HP TX: `[0x11; 16]`
/// - HP RX: `[0x22; 16]`
/// - AEAD TX: `[0x33; 16]`
/// - AEAD RX: `[0x44; 16]`
/// - IV TX: `[0x55; 12]`
/// - IV RX: `[0x66; 12]`
#[must_use]
pub fn make_test_keys() -> UdpQspKeys {
    UdpQspKeys::from_packet_material(
        CipherSuite::Aes128Gcm,
        [0x11; HP_KEY_LEN],
        [0x22; HP_KEY_LEN],
        [0x33; AEAD_KEY_LEN],
        [0x44; AEAD_KEY_LEN],
        [0x55; AEAD_IV_LEN],
        [0x66; AEAD_IV_LEN],
    )
    .expect("test keys should always be valid")
}

/// Fixed server keys (directions swapped relative to client).
///
/// When pairing with `make_test_keys()`, this provides the complementary
/// keys needed for a server endpoint.
#[must_use]
pub fn make_server_keys() -> UdpQspKeys {
    // Swapped directions relative to client keys
    UdpQspKeys::from_packet_material(
        CipherSuite::Aes128Gcm,
        [0x22; HP_KEY_LEN],
        [0x11; HP_KEY_LEN],
        [0x44; AEAD_KEY_LEN],
        [0x33; AEAD_KEY_LEN],
        [0x66; AEAD_IV_LEN],
        [0x55; AEAD_IV_LEN],
    )
    .expect("test keys should always be valid")
}
