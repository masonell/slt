use super::*;

#[tokio::test]
async fn session_rekeys_at_interval_and_accepts_new_phase() {
    struct CaptureIo {
        sent: Vec<Vec<u8>>,
    }

    impl SessionIo for CaptureIo {
        async fn send(&mut self, bytes: &[u8]) -> io::Result<()> {
            self.sent.push(bytes.to_vec());
            Ok(())
        }

        async fn recv(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::WouldBlock, "no recv"))
        }
    }

    let keys = UdpQspKeys::from_packet_material(
        CipherSuite::Aes128Gcm,
        [0x11; HP_KEY_LEN],
        [0x11; HP_KEY_LEN],
        [0x33; AEAD_KEY_LEN],
        [0x33; AEAD_KEY_LEN],
        [0x55; AEAD_IV_LEN],
        [0x55; AEAD_IV_LEN],
    )
    .unwrap();
    let dcid = Cid::from([0xAB; 20]);
    let scid = Cid::from([0xCD; 20]);
    let limits = MessageLimits::new(2048, 2048);

    let mut sender = QuicQspSession::new(
        CaptureIo { sent: Vec::new() },
        scid,
        dcid,
        keys.try_clone().unwrap(),
        0,
        0,
        false,
    );
    let mut receiver = QuicQspSession::new(
        CaptureIo { sent: Vec::new() },
        scid,
        dcid,
        keys,
        0,
        0,
        false,
    );
    set_rekey_policy(&mut sender, 8, 16);
    set_rekey_policy(&mut receiver, 8, 16);

    for nonce in 0..=8u64 {
        let frame = encode_ping_frame(nonce);
        sender.send(&frame).await.unwrap();
    }

    for nonce in 0usize..=7usize {
        let opened = receiver.open_packet(&sender.io.sent[nonce]).unwrap();
        assert!(!opened.key_phase);
        let Message::Ping { payload } = decode_one(opened.payload, limits) else {
            panic!("expected ping");
        };
        assert_eq!(PingPayload::decode(payload).unwrap().nonce, nonce as u64);
    }

    let opened = receiver.open_packet(&sender.io.sent[8]).unwrap();
    assert!(opened.key_phase);
    let Message::Ping { payload } = decode_one(opened.payload, limits) else {
        panic!("expected ping");
    };
    assert_eq!(PingPayload::decode(payload).unwrap().nonce, 8);
}

#[tokio::test]
async fn session_accepts_reordered_old_phase_packet_within_grace() {
    struct CaptureIo {
        sent: Vec<Vec<u8>>,
    }

    impl SessionIo for CaptureIo {
        async fn send(&mut self, bytes: &[u8]) -> io::Result<()> {
            self.sent.push(bytes.to_vec());
            Ok(())
        }

        async fn recv(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::WouldBlock, "no recv"))
        }
    }

    let keys = UdpQspKeys::from_packet_material(
        CipherSuite::Aes128Gcm,
        [0x11; HP_KEY_LEN],
        [0x11; HP_KEY_LEN],
        [0x33; AEAD_KEY_LEN],
        [0x33; AEAD_KEY_LEN],
        [0x55; AEAD_IV_LEN],
        [0x55; AEAD_IV_LEN],
    )
    .unwrap();
    let dcid = Cid::from([0xAB; 20]);
    let scid = Cid::from([0xCD; 20]);
    let limits = MessageLimits::new(2048, 2048);

    let mut sender = QuicQspSession::new(
        CaptureIo { sent: Vec::new() },
        scid,
        dcid,
        keys.try_clone().unwrap(),
        0,
        0,
        false,
    );
    let mut receiver = QuicQspSession::new(
        CaptureIo { sent: Vec::new() },
        scid,
        dcid,
        keys,
        0,
        0,
        false,
    );
    set_rekey_policy(&mut sender, 8, 16);
    set_rekey_policy(&mut receiver, 8, 16);

    for nonce in 0..=8u64 {
        let frame = encode_ping_frame(nonce);
        sender.send(&frame).await.unwrap();
    }

    for nonce in 0usize..=6usize {
        let opened = receiver.open_packet(&sender.io.sent[nonce]).unwrap();
        assert!(!opened.key_phase);
    }

    let opened = receiver.open_packet(&sender.io.sent[8]).unwrap();
    assert!(opened.key_phase);
    let Message::Ping { payload } = decode_one(opened.payload, limits) else {
        panic!("expected ping");
    };
    assert_eq!(PingPayload::decode(payload).unwrap().nonce, 8);

    let opened = receiver.open_packet(&sender.io.sent[7]).unwrap();
    assert!(!opened.key_phase);
    let Message::Ping { payload } = decode_one(opened.payload, limits) else {
        panic!("expected ping");
    };
    assert_eq!(PingPayload::decode(payload).unwrap().nonce, 7);
}

#[test]
fn late_crypto_failures_remain_packet_local() {
    struct TestIo;

    impl SessionIo for TestIo {
        async fn send(&mut self, _bytes: &[u8]) -> io::Result<()> {
            Ok(())
        }

        async fn recv(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::WouldBlock, "no recv"))
        }
    }

    let keys_a = UdpQspKeys::from_packet_material(
        CipherSuite::Aes128Gcm,
        [0x11; HP_KEY_LEN],
        [0x11; HP_KEY_LEN],
        [0x33; AEAD_KEY_LEN],
        [0x33; AEAD_KEY_LEN],
        [0x55; AEAD_IV_LEN],
        [0x55; AEAD_IV_LEN],
    )
    .unwrap();
    let keys_b = UdpQspKeys::from_packet_material(
        CipherSuite::Aes128Gcm,
        [0x21; HP_KEY_LEN],
        [0x21; HP_KEY_LEN],
        [0x43; AEAD_KEY_LEN],
        [0x43; AEAD_KEY_LEN],
        [0x65; AEAD_IV_LEN],
        [0x65; AEAD_IV_LEN],
    )
    .unwrap();

    let mut receiver = QuicQspSession::new(
        TestIo,
        Cid::from([0xCD; 20]),
        Cid::from([0xAB; 20]),
        keys_a,
        0,
        100,
        false,
    );
    set_rekey_policy(&mut receiver, 8, 1);
    receiver.rx_next_rekey_pn = Some(90);

    let packet = keys_b
        .protect(receiver.scid().as_slice(), 100, false, b"late-fail")
        .unwrap();

    for _ in 0..128 {
        assert!(matches!(
            receiver.open_packet(&packet),
            Err(QspSessionError::Crypto(QspCryptoError::CryptoFail))
        ));
    }
}

// =========================================================================
// Edge case tests for pn_distance
// =========================================================================

#[test]
fn pn_distance_handles_wraparound() {
    // Test pn_distance correctness for various value combinations
    assert_eq!(pn_distance(0, 0), 0);
    assert_eq!(pn_distance(100, 50), 50);
    assert_eq!(pn_distance(50, 100), 50);
    assert_eq!(pn_distance(u64::MAX, 0), u64::MAX);
    assert_eq!(pn_distance(0, u64::MAX), u64::MAX);
    assert_eq!(pn_distance(u64::MAX - 1, u64::MAX), 1);
    assert_eq!(pn_distance(u64::MAX, u64::MAX - 1), 1);
    assert_eq!(pn_distance(u64::MAX / 2, u64::MAX / 2 + 100), 100);
}

// =========================================================================
// Edge case tests for ReplayWindow
// =========================================================================

#[test]
fn next_rekey_after_handles_zero_interval() {
    // With interval = 0, should return None (no rekeying)
    assert_eq!(next_rekey_after(0, 0), None);
    assert_eq!(next_rekey_after(100, 0), None);
    assert_eq!(next_rekey_after(u64::MAX, 0), None);
}

#[test]
fn next_rekey_after_handles_overflow() {
    // With interval = 10, starting from MAX - 5, the next rekey would overflow
    // MAX - 5 = ...610, which is divisible by 10, so step = 10
    // MAX - 5 + 10 = MAX + 5 which overflows
    assert_eq!(next_rekey_after(u64::MAX - 5, 10), None);

    // With interval = 1 at MAX, should overflow (step = 1, MAX + 1 overflows)
    assert_eq!(next_rekey_after(u64::MAX, 1), None);

    // At MAX - 9, interval 10: rem = 6, step = 4, result = MAX - 9 + 4 = MAX - 5
    assert_eq!(next_rekey_after(u64::MAX - 9, 10), Some(u64::MAX - 5));

    // At MAX - 10, interval 10: rem = 5, step = 5, result = MAX - 10 + 5 = MAX - 5
    assert_eq!(next_rekey_after(u64::MAX - 10, 10), Some(u64::MAX - 5));

    // At MAX - 5, interval 10: rem = 0, step = 10, overflow
    assert_eq!(next_rekey_after(u64::MAX - 5, 10), None);

    // Edge case: exactly at MAX with interval that would overflow
    assert_eq!(next_rekey_after(u64::MAX, 10), None);
}

#[test]
fn next_rekey_after_at_interval_boundaries() {
    // At pn = 0, interval = 100, next rekey at 100
    assert_eq!(next_rekey_after(0, 100), Some(100));

    // At pn = 50, interval = 100, next rekey at 100
    assert_eq!(next_rekey_after(50, 100), Some(100));

    // At pn = 100 (exactly at boundary), next rekey at 200
    assert_eq!(next_rekey_after(100, 100), Some(200));

    // At pn = 99, interval = 100, next rekey at 100
    assert_eq!(next_rekey_after(99, 100), Some(100));
}

// =========================================================================
// Key rotation cycle tests
// =========================================================================

#[tokio::test]
async fn full_key_rotation_cycle_tx_direction() {
    struct CaptureIo {
        sent: Vec<Vec<u8>>,
    }

    impl SessionIo for CaptureIo {
        async fn send(&mut self, bytes: &[u8]) -> io::Result<()> {
            self.sent.push(bytes.to_vec());
            Ok(())
        }

        async fn recv(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::WouldBlock, "no recv"))
        }
    }

    let keys = UdpQspKeys::from_packet_material(
        CipherSuite::Aes128Gcm,
        [0x11; HP_KEY_LEN],
        [0x11; HP_KEY_LEN],
        [0x33; AEAD_KEY_LEN],
        [0x33; AEAD_KEY_LEN],
        [0x55; AEAD_IV_LEN],
        [0x55; AEAD_IV_LEN],
    )
    .unwrap();
    let dcid = Cid::from([0xAB; 20]);
    let scid = Cid::from([0xCD; 20]);

    let mut sender = QuicQspSession::new(
        CaptureIo { sent: Vec::new() },
        scid,
        dcid,
        keys.try_clone().unwrap(),
        0,
        0,
        false,
    );
    // Use interval=8 to trigger rotation at packet 8
    set_rekey_policy(&mut sender, 8, 16);

    // Phase 0: packets 0-7 (no rotation yet)
    for _ in 0..8 {
        sender.send(b"test").await.unwrap();
    }
    assert!(
        !sender.tx_key_phase(),
        "after packets 0-7, phase should still be 0"
    );

    // Packet 8 triggers rotation to phase 1
    sender.send(b"test").await.unwrap();
    assert!(
        sender.tx_key_phase(),
        "after packet 8, phase should flip to 1"
    );

    // Phase 1: packets 9-15
    for _ in 0..7 {
        sender.send(b"test").await.unwrap();
    }
    assert!(
        sender.tx_key_phase(),
        "during phase 1 (packets 9-15), phase should remain 1"
    );

    // Verify we have 16 packets total
    assert_eq!(sender.io.sent.len(), 16);
}

#[tokio::test]
async fn full_key_rotation_cycle_rx_direction() {
    struct CaptureIo {
        sent: Vec<Vec<u8>>,
    }

    impl SessionIo for CaptureIo {
        async fn send(&mut self, bytes: &[u8]) -> io::Result<()> {
            self.sent.push(bytes.to_vec());
            Ok(())
        }

        async fn recv(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::WouldBlock, "no recv"))
        }
    }

    let keys = UdpQspKeys::from_packet_material(
        CipherSuite::Aes128Gcm,
        [0x11; HP_KEY_LEN],
        [0x11; HP_KEY_LEN],
        [0x33; AEAD_KEY_LEN],
        [0x33; AEAD_KEY_LEN],
        [0x55; AEAD_IV_LEN],
        [0x55; AEAD_IV_LEN],
    )
    .unwrap();
    let dcid = Cid::from([0xAB; 20]);
    let scid = Cid::from([0xCD; 20]);

    let mut sender = QuicQspSession::new(
        CaptureIo { sent: Vec::new() },
        scid,
        dcid,
        keys.try_clone().unwrap(),
        0,
        0,
        false,
    );
    let mut receiver = QuicQspSession::new(
        CaptureIo { sent: Vec::new() },
        scid,
        dcid,
        keys,
        0,
        0,
        false,
    );
    set_rekey_policy(&mut sender, 8, 16);
    set_rekey_policy(&mut receiver, 8, 16);

    // Phase 0: packets 0-7
    for _nonce in 0..8u64 {
        sender.send(b"test").await.unwrap();
    }
    for nonce in 0..8usize {
        let opened = receiver.open_packet(&sender.io.sent[nonce]).unwrap();
        assert!(!opened.key_phase, "packet {nonce} should be phase 0");
    }
    assert!(
        !receiver.rx_key_phase(),
        "receiver phase should still be 0 after packets 0-7"
    );

    // Packet 8 triggers rotation to phase 1
    sender.send(b"test").await.unwrap();
    let opened = receiver.open_packet(&sender.io.sent[8]).unwrap();
    assert!(opened.key_phase, "packet 8 should be phase 1");
    assert!(
        receiver.rx_key_phase(),
        "receiver phase should be 1 after packet 8"
    );

    // Phase 1: packets 9-15 (still in phase 1)
    for _nonce in 9..16u64 {
        sender.send(b"test").await.unwrap();
    }
    for nonce in 9..16usize {
        let opened = receiver.open_packet(&sender.io.sent[nonce]).unwrap();
        assert!(opened.key_phase, "packet {nonce} should be phase 1");
    }
    assert!(
        receiver.rx_key_phase(),
        "receiver phase should still be 1 after packets 9-15"
    );
}

#[tokio::test]
async fn key_phase_transition_at_exact_threshold_boundary() {
    struct CaptureIo {
        sent: Vec<Vec<u8>>,
    }

    impl SessionIo for CaptureIo {
        async fn send(&mut self, bytes: &[u8]) -> io::Result<()> {
            self.sent.push(bytes.to_vec());
            Ok(())
        }

        async fn recv(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::WouldBlock, "no recv"))
        }
    }

    let keys = UdpQspKeys::from_packet_material(
        CipherSuite::Aes128Gcm,
        [0x11; HP_KEY_LEN],
        [0x11; HP_KEY_LEN],
        [0x33; AEAD_KEY_LEN],
        [0x33; AEAD_KEY_LEN],
        [0x55; AEAD_IV_LEN],
        [0x55; AEAD_IV_LEN],
    )
    .unwrap();
    let dcid = Cid::from([0xAB; 20]);
    let scid = Cid::from([0xCD; 20]);

    let mut sender = QuicQspSession::new(
        CaptureIo { sent: Vec::new() },
        scid,
        dcid,
        keys.try_clone().unwrap(),
        0,
        0,
        false,
    );
    let mut receiver = QuicQspSession::new(
        CaptureIo { sent: Vec::new() },
        scid,
        dcid,
        keys,
        0,
        0,
        false,
    );
    set_rekey_policy(&mut sender, 8, 16);
    set_rekey_policy(&mut receiver, 8, 16);

    // Send packets 0-6 (phase 0)
    for nonce in 0..7u64 {
        sender.send(b"test").await.unwrap();
        let opened = receiver
            .open_packet(&sender.io.sent[nonce as usize])
            .unwrap();
        assert!(!opened.key_phase, "packet {nonce} should be phase 0");
    }

    // Packet 7 (still phase 0 - boundary is at 8)
    sender.send(b"test").await.unwrap();
    let opened = receiver.open_packet(&sender.io.sent[7]).unwrap();
    assert!(!opened.key_phase, "packet 7 should still be phase 0");

    // Packet 8 (exact boundary - triggers phase 1)
    sender.send(b"test").await.unwrap();
    let opened = receiver.open_packet(&sender.io.sent[8]).unwrap();
    assert!(opened.key_phase, "packet 8 should be phase 1");
}

// =========================================================================
// Failure handling tests
// =========================================================================

#[test]
fn decrypt_failures_do_not_poison_later_valid_packets() {
    struct TestIo;

    impl SessionIo for TestIo {
        async fn send(&mut self, _bytes: &[u8]) -> io::Result<()> {
            Ok(())
        }

        async fn recv(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::WouldBlock, "no recv"))
        }
    }

    let keys = UdpQspKeys::from_packet_material(
        CipherSuite::Aes128Gcm,
        [0x11; HP_KEY_LEN],
        [0x11; HP_KEY_LEN],
        [0x33; AEAD_KEY_LEN],
        [0x33; AEAD_KEY_LEN],
        [0x55; AEAD_IV_LEN],
        [0x55; AEAD_IV_LEN],
    )
    .unwrap();
    let keys_bad = UdpQspKeys::from_packet_material(
        CipherSuite::Aes128Gcm,
        [0x21; HP_KEY_LEN],
        [0x21; HP_KEY_LEN],
        [0x43; AEAD_KEY_LEN],
        [0x43; AEAD_KEY_LEN],
        [0x65; AEAD_IV_LEN],
        [0x65; AEAD_IV_LEN],
    )
    .unwrap();

    let mut receiver = QuicQspSession::new(
        TestIo,
        Cid::from([0xCD; 20]),
        Cid::from([0xAB; 20]),
        keys.try_clone().unwrap(),
        0,
        100,
        false,
    );
    set_rekey_policy(&mut receiver, 8, 1);

    let bad_packet = keys_bad
        .protect(receiver.scid().as_slice(), 100, false, b"fail")
        .unwrap();
    for _ in 0..256 {
        assert!(matches!(
            receiver.open_packet(&bad_packet),
            Err(QspSessionError::Crypto(QspCryptoError::CryptoFail))
        ));
    }

    let good_packet = keys
        .protect(receiver.scid().as_slice(), 100, false, b"good")
        .unwrap();
    let opened = receiver.open_packet(&good_packet).unwrap();
    assert_eq!(opened.payload, b"good");
}

// =========================================================================
// Session flush / peer-update proxying contract
// =========================================================================
