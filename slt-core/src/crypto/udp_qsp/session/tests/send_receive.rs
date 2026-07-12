use super::*;

#[tokio::test]
async fn replace_io_preserves_packet_numbers_replay_window_and_rekey_state() {
    let keys = symmetric_keys();
    let scid = Cid::from([0xCD; 20]);
    let dcid = Cid::from([0xAB; 20]);
    let scid_len = scid.len();
    let replayed_packet = keys.protect(dcid.as_slice(), 0, false, b"inbound").unwrap();
    let (io, _old_sent) = QueueIo::new(vec![replayed_packet.clone()]);
    let mut session = QuicQspSession::new(io, scid, dcid, keys.try_clone().unwrap(), 1, 0, false);
    set_rekey_policy(&mut session, 2, KEY_UPDATE_LATE_MARGIN);

    let mut packet_buf = vec![0u8; 2048];
    let opened = session.recv(&mut packet_buf).await.unwrap();
    assert_eq!(opened.pn, 0);
    assert_eq!(opened.payload, b"inbound");
    assert_eq!(session.expected_pn(), 1);
    assert_eq!(session.next_pn(), 1);
    assert!(!session.tx_key_phase());

    let (replacement_io, replacement_sent) = QueueIo::new(vec![replayed_packet]);
    let _old_io = session.replace_io(replacement_io);
    assert_eq!(session.expected_pn(), 1);
    assert_eq!(session.next_pn(), 1);
    assert!(!session.tx_key_phase());

    assert!(matches!(
        session.recv(&mut packet_buf).await,
        Err(QspSessionError::Replay)
    ));

    session.send(b"first-after-replace").await.unwrap();
    assert_eq!(session.next_pn(), 2);
    assert!(!session.tx_key_phase());

    let first_sent = {
        let sent = replacement_sent.lock().expect("replacement sent lock");
        assert_eq!(sent.len(), 1);
        sent[0].clone()
    };
    let mut opened_payload = Vec::new();
    let opened = keys
        .open_into(scid_len, &first_sent, 1, &mut opened_payload)
        .unwrap();
    assert_eq!(opened.pn, 1);
    assert_eq!(opened.payload, b"first-after-replace");

    session.send(b"second-after-replace").await.unwrap();
    assert_eq!(session.next_pn(), 3);
    assert!(session.tx_key_phase());
}

#[tokio::test]
async fn session_recv_replay_detection() {
    struct TestIo {
        packet: Vec<u8>,
        sent: Vec<Vec<u8>>,
    }

    impl SessionIo for TestIo {
        async fn send(&mut self, bytes: &[u8]) -> io::Result<()> {
            self.sent.push(bytes.to_vec());
            Ok(())
        }

        async fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let len = self.packet.len();
            buf[..len].copy_from_slice(&self.packet);
            Ok(len)
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
    let packet = keys.protect(dcid.as_slice(), 7, false, b"hello").unwrap();

    let io = TestIo {
        packet: packet.clone(),
        sent: Vec::new(),
    };
    let mut session = QuicQspSession::new(io, Cid::from([0xCD; 20]), dcid, keys, 0, 7, false);
    let mut buf = vec![0u8; 1500];

    let opened = session.recv(&mut buf).await.unwrap();
    assert_eq!(opened.pn, 7);
    assert_eq!(opened.payload, b"hello");

    assert!(matches!(
        session.recv(&mut buf).await,
        Err(QspSessionError::Replay)
    ));
}

#[tokio::test]
async fn session_recv_rejects_first_packet_below_initial_expected() {
    struct TestIo {
        packet: Vec<u8>,
    }

    impl SessionIo for TestIo {
        async fn send(&mut self, _bytes: &[u8]) -> io::Result<()> {
            Ok(())
        }

        async fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let len = self.packet.len();
            buf[..len].copy_from_slice(&self.packet);
            Ok(len)
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
    let scid = Cid::from([0xCD; 20]);
    let packet = keys.protect(scid.as_slice(), 999, false, b"hello").unwrap();

    let io = TestIo { packet };
    let mut session = QuicQspSession::new(io, scid, Cid::from([0xAB; 20]), keys, 0, 1000, false);
    let mut buf = vec![0u8; 1500];

    assert!(matches!(
        session.recv(&mut buf).await,
        Err(QspSessionError::TooOld)
    ));
    assert_eq!(session.expected_pn(), 1000);
}

#[tokio::test]
async fn session_send_rejects_packet_number_overflow() {
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

    let mut session = QuicQspSession::new(
        TestIo,
        Cid::from([0xCD; 20]),
        Cid::from([0xAB; 20]),
        keys,
        u64::MAX,
        0,
        false,
    );

    assert!(matches!(
        session.send(b"hello").await,
        Err(QspSessionError::PacketNumberOverflow)
    ));
}

#[tokio::test]
async fn session_recv_accepts_packet_number_above_u32_max() {
    struct TestIo {
        packet: Vec<u8>,
    }

    impl SessionIo for TestIo {
        async fn send(&mut self, _bytes: &[u8]) -> io::Result<()> {
            Ok(())
        }

        async fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let len = self.packet.len();
            buf[..len].copy_from_slice(&self.packet);
            Ok(len)
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

    let pn = u64::from(u32::MAX) + 7;
    let dcid = Cid::from([0xAB; 20]);
    let packet = keys.protect(dcid.as_slice(), pn, false, b"hello").unwrap();

    let io = TestIo { packet };
    let mut session = QuicQspSession::new(io, Cid::from([0xCD; 20]), dcid, keys, 0, pn, false);
    let mut buf = vec![0u8; 1500];

    let opened = session.recv(&mut buf).await.unwrap();
    assert_eq!(opened.pn, pn);
    assert_eq!(opened.payload, b"hello");
}

#[tokio::test]
async fn session_roundtrip_with_large_packet_number() {
    let (c2s_tx, c2s_rx) = mpsc::channel::<Vec<u8>>(8);
    let (s2c_tx, s2c_rx) = mpsc::channel::<Vec<u8>>(8);

    let hp_c2s = [0x11; HP_KEY_LEN];
    let hp_s2c = [0x22; HP_KEY_LEN];
    let aead_c2s = [0x33; AEAD_KEY_LEN];
    let aead_s2c = [0x44; AEAD_KEY_LEN];
    let iv_c2s = [0x55; AEAD_IV_LEN];
    let iv_s2c = [0x66; AEAD_IV_LEN];

    let keys_client = UdpQspKeys::from_packet_material(
        CipherSuite::Aes128Gcm,
        hp_c2s,
        hp_s2c,
        aead_c2s,
        aead_s2c,
        iv_c2s,
        iv_s2c,
    )
    .unwrap();
    let keys_server = UdpQspKeys::from_packet_material(
        CipherSuite::Aes128Gcm,
        hp_s2c,
        hp_c2s,
        aead_s2c,
        aead_c2s,
        iv_s2c,
        iv_c2s,
    )
    .unwrap();

    let client_scid = Cid::from([0xA1; 20]);
    let server_scid = Cid::from([0xB2; 20]);
    let pn = u64::from(u32::MAX) + 17;

    let mut client = QuicQspSession::new(
        ChanIo {
            tx: c2s_tx,
            rx: s2c_rx,
        },
        client_scid,
        server_scid,
        keys_client,
        pn,
        pn,
        false,
    );
    let mut server = QuicQspSession::new(
        ChanIo {
            tx: s2c_tx,
            rx: c2s_rx,
        },
        server_scid,
        client_scid,
        keys_server,
        pn,
        pn,
        false,
    );

    let limits = MessageLimits::new(2048, 2048);
    let mut packet_buf = vec![0u8; 2048];

    let nonce = 0xCAFE_BABE_DEAD_BEEFu64;
    let frame = encode_ping_frame(nonce);
    client.send(&frame).await.unwrap();
    let opened = server.recv(&mut packet_buf).await.unwrap();
    assert_eq!(opened.pn, pn);
    let Message::Ping { payload } = decode_one(opened.payload, limits) else {
        panic!("expected ping");
    };
    assert_eq!(PingPayload::decode(payload).unwrap().nonce, nonce);

    let frame = encode_pong_frame(nonce);
    server.send(&frame).await.unwrap();
    let opened = client.recv(&mut packet_buf).await.unwrap();
    assert_eq!(opened.pn, pn);
    let Message::Pong { payload } = decode_one(opened.payload, limits) else {
        panic!("expected pong");
    };
    assert_eq!(PongPayload::decode(payload).unwrap().nonce, nonce);
}

#[tokio::test]
async fn session_roundtrips_framed_messages_over_in_memory_io() {
    let (c2s_tx, c2s_rx) = mpsc::channel::<Vec<u8>>(8);
    let (s2c_tx, s2c_rx) = mpsc::channel::<Vec<u8>>(8);

    let hp_c2s = [0x11; HP_KEY_LEN];
    let hp_s2c = [0x22; HP_KEY_LEN];
    let aead_c2s = [0x33; AEAD_KEY_LEN];
    let aead_s2c = [0x44; AEAD_KEY_LEN];
    let iv_c2s = [0x55; AEAD_IV_LEN];
    let iv_s2c = [0x66; AEAD_IV_LEN];

    let keys_client = UdpQspKeys::from_packet_material(
        CipherSuite::Aes128Gcm,
        hp_c2s,
        hp_s2c,
        aead_c2s,
        aead_s2c,
        iv_c2s,
        iv_s2c,
    )
    .unwrap();
    let keys_server = UdpQspKeys::from_packet_material(
        CipherSuite::Aes128Gcm,
        hp_s2c,
        hp_c2s,
        aead_s2c,
        aead_c2s,
        iv_s2c,
        iv_c2s,
    )
    .unwrap();

    let client_scid = Cid::from([0xA1; 20]);
    let server_scid = Cid::from([0xB2; 20]);

    let mut client = QuicQspSession::new(
        ChanIo {
            tx: c2s_tx,
            rx: s2c_rx,
        },
        client_scid,
        server_scid,
        keys_client,
        0,
        0,
        false,
    );
    let mut server = QuicQspSession::new(
        ChanIo {
            tx: s2c_tx,
            rx: c2s_rx,
        },
        server_scid,
        client_scid,
        keys_server,
        0,
        0,
        false,
    );

    let limits = MessageLimits::new(2048, 2048);
    let mut packet_buf = vec![0u8; 2048];

    let nonce = 0x1122_3344_5566_7788_u64;
    let frame = encode_ping_frame(nonce);
    client.send(&frame).await.unwrap();
    let opened = server.recv(&mut packet_buf).await.unwrap();
    assert_eq!(opened.pn, 0);
    let Message::Ping { payload } = decode_one(opened.payload, limits) else {
        panic!("expected ping");
    };
    assert_eq!(PingPayload::decode(payload).unwrap().nonce, nonce);

    let frame = encode_pong_frame(nonce);
    server.send(&frame).await.unwrap();
    let opened = client.recv(&mut packet_buf).await.unwrap();
    assert_eq!(opened.pn, 0);
    let Message::Pong { payload } = decode_one(opened.payload, limits) else {
        panic!("expected pong");
    };
    assert_eq!(PongPayload::decode(payload).unwrap().nonce, nonce);
}
