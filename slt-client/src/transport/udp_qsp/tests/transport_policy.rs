use std::sync::Arc;

use slt_core::crypto::udp_qsp::{QspCryptoError, QspSessionError, QuicQspSession};
use slt_core::proto::{
    HEADER_LEN, Message, MessageLimits, MessageType, PingPayload, PongPayload, encode_message,
};
use slt_core::types::Cid;
use tokio::sync::mpsc;

use super::super::*;
use crate::metrics::MetricsSnapshot;
use crate::test_support::{ChanIo, encode_ping, encode_pong, make_server_keys, make_test_keys};

// Keep in sync with slt-core::crypto::udp_qsp::session::KEY_UPDATE_INTERVAL.
const KEY_UPDATE_INTERVAL: u64 = 1 << 21;

fn make_session(io: ChanIo) -> QuicQspSession<ChanIo> {
    make_session_with_pn(io, 0, 0)
}

fn make_session_with_pn(io: ChanIo, send_pn: u64, recv_expected_pn: u64) -> QuicQspSession<ChanIo> {
    let scid = Cid::from([0xA1; 20]);
    let dcid = Cid::from([0xB2; 20]);
    QuicQspSession::new(
        io,
        scid,
        dcid,
        make_test_keys(),
        send_pn,
        recv_expected_pn,
        false,
    )
}

fn make_transport(session: QuicQspSession<ChanIo>) -> UdpQspTransport<ChanIo> {
    let metrics = Arc::new(Metrics::default());
    UdpQspTransport::new(session, metrics)
}

fn snapshot(transport: &UdpQspTransport<ChanIo>) -> MetricsSnapshot {
    transport.metrics.snapshot()
}

async fn read_authenticated_payload(
    payload: &[u8],
    limits: MessageLimits,
) -> Result<slt_core::proto::OwnedMessageBuf, UdpQspError> {
    let (c2s_tx, c2s_rx) = mpsc::channel::<Vec<u8>>(8);
    let (s2c_tx, s2c_rx) = mpsc::channel::<Vec<u8>>(8);
    let scid = Cid::from([0xA1; 20]);
    let dcid = Cid::from([0xB2; 20]);

    let client_io = ChanIo {
        tx: c2s_tx,
        rx: s2c_rx,
    };
    let client_session = QuicQspSession::new(client_io, scid, dcid, make_test_keys(), 0, 0, false);
    let mut client = make_transport(client_session);

    let server_io = ChanIo {
        tx: s2c_tx,
        rx: c2s_rx,
    };
    let mut server = QuicQspSession::new(server_io, dcid, scid, make_server_keys(), 0, 0, false);
    server.send(payload).await.unwrap();

    client.read_next_message(limits).await
}

#[tokio::test]
async fn write_message_encodes_and_sends_framed_message() {
    let (c2s_tx, c2s_rx) = mpsc::channel::<Vec<u8>>(8);
    let (s2c_tx, s2c_rx) = mpsc::channel::<Vec<u8>>(8);

    let scid = Cid::from([0xA1; 20]);
    let dcid = Cid::from([0xB2; 20]);

    let client_io = ChanIo {
        tx: c2s_tx,
        rx: s2c_rx,
    };
    let client_session = QuicQspSession::new(client_io, scid, dcid, make_test_keys(), 0, 0, false);
    let mut transport = make_transport(client_session);

    let server_io = ChanIo {
        tx: s2c_tx,
        rx: c2s_rx,
    };
    let mut server_session =
        QuicQspSession::new(server_io, dcid, scid, make_server_keys(), 0, 0, false);

    let frame = encode_ping(0x1234_5678);
    transport
        .write_message(Message::Ping {
            payload: &frame[HEADER_LEN..],
        })
        .await
        .unwrap();

    let mut packet_buf = [0u8; 2048];
    let opened = server_session.recv(&mut packet_buf).await.unwrap();
    assert_eq!(opened.payload, frame.as_slice());
}

#[tokio::test]
async fn read_next_message_decodes_framed_message() {
    let (c2s_tx, c2s_rx) = mpsc::channel::<Vec<u8>>(8);
    let (s2c_tx, s2c_rx) = mpsc::channel::<Vec<u8>>(8);

    let server_io = ChanIo {
        tx: s2c_tx,
        rx: c2s_rx,
    };
    let client_io = ChanIo {
        tx: c2s_tx,
        rx: s2c_rx,
    };

    let scid = Cid::from([0xA1; 20]);
    let dcid = Cid::from([0xB2; 20]);

    let mut server_session =
        QuicQspSession::new(server_io, dcid, scid, make_server_keys(), 0, 0, false);
    let client_session = QuicQspSession::new(client_io, scid, dcid, make_test_keys(), 0, 0, false);

    let mut client_transport = make_transport(client_session);

    let nonce = 0xABCD_EF12_3456_7890u64;
    let frame = encode_ping(nonce);
    server_session.send(&frame).await.unwrap();

    let limits = MessageLimits::new(2048, 2048);
    let msg = client_transport.read_next_message(limits).await.unwrap();

    // Use message() to get the decoded message
    match msg.message() {
        Message::Ping { payload } => {
            assert_eq!(PingPayload::decode(payload).unwrap().nonce, nonce);
        }
        _ => panic!("expected ping"),
    }
}

#[tokio::test]
async fn authenticated_plaintext_violations_are_not_recoverable() {
    let unknown_type = [0xff, 0, 0, 0, 0];
    let unknown = read_authenticated_payload(&unknown_type, MessageLimits::new(2048, 2048))
        .await
        .unwrap_err();
    assert!(matches!(
        &unknown,
        UdpQspError::Message(MessageError::Frame(FrameError::UnknownType(0xff)))
    ));
    assert!(!unknown.is_recoverable());

    let mut oversized_data = Vec::new();
    encode_message(Message::Data { packet: &[0; 9] }, &mut oversized_data).unwrap();
    let oversized = read_authenticated_payload(&oversized_data, MessageLimits::new(2048, 8))
        .await
        .unwrap_err();
    assert!(matches!(
        &oversized,
        UdpQspError::Message(MessageError::DataTooLarge { len: 9, max: 8 })
    ));
    assert!(!oversized.is_recoverable());

    let mut incomplete = vec![u8::from(MessageType::Ping)];
    incomplete.extend_from_slice(&8u32.to_be_bytes());
    incomplete.extend_from_slice(&[0; 7]);
    let incomplete = read_authenticated_payload(&incomplete, MessageLimits::new(2048, 2048))
        .await
        .unwrap_err();
    assert!(matches!(&incomplete, UdpQspError::IncompleteMessage));
    assert!(!incomplete.is_recoverable());
}

#[tokio::test]
async fn unauthenticated_packet_noise_does_not_poison_the_receive_path() {
    let (c2s_tx, c2s_rx) = mpsc::channel::<Vec<u8>>(8);
    let (s2c_tx, s2c_rx) = mpsc::channel::<Vec<u8>>(8);
    let packet_injector = s2c_tx.clone();
    let scid = Cid::from([0xA1; 20]);
    let dcid = Cid::from([0xB2; 20]);

    let client_io = ChanIo {
        tx: c2s_tx,
        rx: s2c_rx,
    };
    let client_session = QuicQspSession::new(client_io, scid, dcid, make_test_keys(), 0, 0, false);
    let mut client = make_transport(client_session);

    let server_io = ChanIo {
        tx: s2c_tx,
        rx: c2s_rx,
    };
    let mut server = QuicQspSession::new(server_io, dcid, scid, make_server_keys(), 0, 0, false);

    packet_injector.send(vec![0; 64]).await.unwrap();
    let err = client
        .read_next_message(MessageLimits::new(2048, 2048))
        .await
        .unwrap_err();
    assert!(matches!(&err, UdpQspError::Qsp(QspSessionError::Crypto(_))));
    assert!(err.is_recoverable());

    let valid = encode_ping(0xCAFE_BABE);
    server.send(&valid).await.unwrap();
    let message = client
        .read_next_message(MessageLimits::new(2048, 2048))
        .await
        .unwrap();
    let Message::Ping { payload } = message.message() else {
        panic!("expected ping after unauthenticated packet noise");
    };
    assert_eq!(PingPayload::decode(payload).unwrap().nonce, 0xCAFE_BABE);
}

#[tokio::test]
async fn full_roundtrip_write_recv_read_returns_original_message() {
    let (c2s_tx, c2s_rx) = mpsc::channel::<Vec<u8>>(8);
    let (s2c_tx, s2c_rx) = mpsc::channel::<Vec<u8>>(8);

    let scid = Cid::from([0xA1; 20]);
    let dcid = Cid::from([0xB2; 20]);

    // Client transport
    let client_io = ChanIo {
        tx: c2s_tx,
        rx: s2c_rx,
    };
    let client_session = QuicQspSession::new(client_io, scid, dcid, make_test_keys(), 0, 0, false);
    let mut client = make_transport(client_session);

    // Server transport
    let server_io = ChanIo {
        tx: s2c_tx,
        rx: c2s_rx,
    };
    let server_session =
        QuicQspSession::new(server_io, dcid, scid, make_server_keys(), 0, 0, false);
    let mut server = make_transport(server_session);

    let limits = MessageLimits::new(2048, 2048);
    let nonce = 0xDEAD_BEEF_CAFE_BABEu64;

    // Client sends ping
    let request_frame = encode_ping(nonce);
    client
        .write_message(Message::Ping {
            payload: &request_frame[HEADER_LEN..],
        })
        .await
        .unwrap();

    // Server receives and decodes
    let msg = server.read_next_message(limits).await.unwrap();
    match msg.message() {
        Message::Ping { payload } => {
            assert_eq!(PingPayload::decode(payload).unwrap().nonce, nonce);
        }
        _ => panic!("expected ping"),
    }

    // Server sends pong
    let response_frame = encode_pong(nonce);
    server
        .write_message(Message::Pong {
            payload: &response_frame[HEADER_LEN..],
        })
        .await
        .unwrap();

    // Client receives pong
    let msg = client.read_next_message(limits).await.unwrap();
    match msg.message() {
        Message::Pong { payload } => {
            assert_eq!(PongPayload::decode(payload).unwrap().nonce, nonce);
        }
        _ => panic!("expected pong"),
    }
}

#[test]
fn qsp_io_preserves_shape_and_is_recoverable() {
    // Transient recv I/O is recoverable (see `is_recoverable` doc) — one
    // failed datagram does not kill the path.
    let io_err = io::Error::new(io::ErrorKind::TimedOut, "timeout");
    let err: UdpQspError = QspSessionError::Io(io_err).into();
    assert!(matches!(err, UdpQspError::Qsp(QspSessionError::Io(_))));
    assert!(err.is_recoverable());
}

#[test]
fn persistent_socket_io_errors_propagate_not_dropped() {
    // Real socket failures are NOT droppable: PermissionDenied (firewall/
    // policy), NetworkUnreachable/HostUnreachable (no route), BrokenPipe,
    // or NotConnected must propagate to TCP fallback / close / reconnect
    // rather than be silently dropped (which would let the session spin on
    // a permanent I/O error and the refresh probe retry until its timeout).
    // Only transient kinds (WouldBlock/TimedOut/ConnectionRefused/
    // ConnectionReset) are recoverable.
    for kind in [
        io::ErrorKind::PermissionDenied,
        io::ErrorKind::NetworkUnreachable,
        io::ErrorKind::HostUnreachable,
        io::ErrorKind::BrokenPipe,
        io::ErrorKind::NotConnected,
    ] {
        let direct: UdpQspError = io::Error::from(kind).into();
        assert!(
            !direct.is_recoverable(),
            "{kind:?}: direct UdpQspError::Io should propagate, not drop"
        );
        let wrapped: UdpQspError = QspSessionError::Io(io::Error::from(kind)).into();
        assert!(
            !wrapped.is_recoverable(),
            "{kind:?}: Qsp(Io(_)) should propagate, not drop"
        );
    }
}

#[test]
fn send_io_errors_are_never_recoverable() {
    // Send-side socket I/O (from `session.send` / send_to / GSO flush) is
    // NEVER recoverable, even for kinds that are transient on the recv path:
    // a send failure must fall back to TCP (or close if TCP is dead), not be
    // silently dropped — dropping it would lose the outbound packet and leave
    // the active transport on UDP while the send path is failing.
    for kind in [
        io::ErrorKind::WouldBlock,
        io::ErrorKind::TimedOut,
        io::ErrorKind::ConnectionRefused,
        io::ErrorKind::ConnectionReset,
        io::ErrorKind::PermissionDenied,
        io::ErrorKind::NetworkUnreachable,
        io::ErrorKind::BrokenPipe,
    ] {
        let err = UdpQspError::SendIo {
            source: io::Error::from(kind),
        };
        assert!(
            !err.is_recoverable(),
            "{kind:?}: SendIo must propagate to TCP fallback, not drop"
        );
    }
}

#[test]
fn packet_number_overflow_preserves_shape_and_is_fatal() {
    // Packet-number overflow is FATAL: the TX pn space is exhausted, so the
    // session cannot send again on this UDP path. The runtime routes it
    // through `handle_udp_error` to TCP fallback (or close if TCP is also
    // dead) — NOT a drop. Dropping overflow would lose packets on a session
    // that can no longer send, so fatal keeps the TCP-fallback routing. The
    // session reconnects for a fresh pn space only once it re-establishes,
    // not as an immediate consequence of the overflow.
    let err: UdpQspError = QspSessionError::PacketNumberOverflow.into();
    assert!(matches!(
        err,
        UdpQspError::Qsp(QspSessionError::PacketNumberOverflow)
    ));
    assert!(!err.is_recoverable());
    let rendered = format!("{err:#}");
    assert!(rendered.contains("overflow"), "{rendered:?}");
}

#[test]
fn crypto_failure_preserves_qsp_shape_and_is_recoverable() {
    let err: UdpQspError = QspSessionError::Crypto(QspCryptoError::CryptoFail).into();
    assert!(matches!(
        err,
        UdpQspError::Qsp(QspSessionError::Crypto(QspCryptoError::CryptoFail))
    ));
    // Authentication failure is packet-local and cannot retire the path.
    assert!(err.is_recoverable());
}

#[test]
fn replay_preserves_qsp_shape_and_is_recoverable() {
    let err: UdpQspError = QspSessionError::Replay.into();
    assert!(matches!(err, UdpQspError::Qsp(QspSessionError::Replay)));
    assert!(err.is_recoverable());
}

#[test]
fn too_old_preserves_qsp_shape_and_is_recoverable() {
    let err: UdpQspError = QspSessionError::TooOld.into();
    assert!(matches!(err, UdpQspError::Qsp(QspSessionError::TooOld)));
    assert!(err.is_recoverable());
}

#[tokio::test]
async fn rx_key_phase_transition_increments_metric() {
    let (c2s_tx, c2s_rx) = mpsc::channel::<Vec<u8>>(8);
    let (s2c_tx, s2c_rx) = mpsc::channel::<Vec<u8>>(8);

    let scid = Cid::from([0xA1; 20]);
    let dcid = Cid::from([0xB2; 20]);

    let client_io = ChanIo {
        tx: c2s_tx,
        rx: s2c_rx,
    };
    let client_session = QuicQspSession::new(
        client_io,
        scid,
        dcid,
        make_test_keys(),
        0,
        KEY_UPDATE_INTERVAL - 1,
        false,
    );
    let mut client = make_transport(client_session);

    let server_io = ChanIo {
        tx: s2c_tx,
        rx: c2s_rx,
    };
    let mut server_session = QuicQspSession::new(
        server_io,
        dcid,
        scid,
        make_server_keys(),
        KEY_UPDATE_INTERVAL - 1,
        0,
        false,
    );

    let limits = MessageLimits::new(2048, 2048);

    assert_eq!(snapshot(&client).udp_qsp_rx_key_phase_transitions, 0);

    let first_ping = encode_ping(1);
    server_session.send(&first_ping).await.unwrap();
    client.read_next_message(limits).await.unwrap();
    assert_eq!(snapshot(&client).udp_qsp_rx_key_phase_transitions, 0);

    // Second packet crosses the sender rekey threshold and flips key phase.
    let second_ping = encode_ping(2);
    server_session.send(&second_ping).await.unwrap();
    client.read_next_message(limits).await.unwrap();

    assert_eq!(snapshot(&client).udp_qsp_rx_key_phase_transitions, 1);
}

#[tokio::test]
async fn tx_key_phase_transition_increments_metric() {
    let (tx, _rx) = mpsc::channel::<Vec<u8>>(8);
    let io = ChanIo {
        tx,
        rx: mpsc::channel(1).1,
    };
    let session = make_session_with_pn(io, KEY_UPDATE_INTERVAL - 1, 0);
    let mut transport = make_transport(session);

    assert_eq!(snapshot(&transport).udp_qsp_tx_key_phase_transitions, 0);

    let first_frame = encode_ping(1);
    transport
        .write_message(Message::Ping {
            payload: &first_frame[HEADER_LEN..],
        })
        .await
        .unwrap();
    assert_eq!(snapshot(&transport).udp_qsp_tx_key_phase_transitions, 0);

    // Second packet crosses the sender rekey threshold and flips key phase.
    let second_frame = encode_ping(2);
    transport
        .write_message(Message::Ping {
            payload: &second_frame[HEADER_LEN..],
        })
        .await
        .unwrap();

    assert_eq!(snapshot(&transport).udp_qsp_tx_key_phase_transitions, 1);
}

#[tokio::test]
async fn trailing_padding_bytes_ignored_after_message_decode() {
    let (c2s_tx, c2s_rx) = mpsc::channel::<Vec<u8>>(8);
    let (s2c_tx, s2c_rx) = mpsc::channel::<Vec<u8>>(8);

    let scid = Cid::from([0xA1; 20]);
    let dcid = Cid::from([0xB2; 20]);

    let client_io = ChanIo {
        tx: c2s_tx,
        rx: s2c_rx,
    };
    let client_session = QuicQspSession::new(client_io, scid, dcid, make_test_keys(), 0, 0, false);
    let mut client = make_transport(client_session);

    let server_io = ChanIo {
        tx: s2c_tx,
        rx: c2s_rx,
    };
    let mut server_session =
        QuicQspSession::new(server_io, dcid, scid, make_server_keys(), 0, 0, false);

    // Send a ping frame with explicit trailing bytes.
    let nonce = 0u64;
    let mut ping_with_padding = encode_ping(nonce);
    ping_with_padding.extend_from_slice(&[0x00, 0x00, 0xFF, 0xEE]);
    server_session.send(&ping_with_padding).await.unwrap();

    let limits = MessageLimits::new(2048, 2048);
    let msg = client.read_next_message(limits).await.unwrap();

    // The decoded message payload excludes trailing bytes.
    match msg.message() {
        Message::Ping { payload } => {
            assert_eq!(payload.len(), std::mem::size_of::<u64>());
            assert_eq!(PingPayload::decode(payload).unwrap().nonce, nonce);
        }
        _ => panic!("expected ping"),
    }
}

#[tokio::test]
async fn note_recv_error_replay_increments_metric_and_is_recoverable() {
    let (tx, _rx) = mpsc::channel::<Vec<u8>>(8);
    let io = ChanIo {
        tx,
        rx: mpsc::channel(1).1,
    };
    let session = make_session(io);
    let transport = make_transport(session);

    assert_eq!(snapshot(&transport).udp_qsp_decrypt_fail_replay, 0);

    let qsp_err = QspSessionError::Replay;
    transport.note_recv_error(&qsp_err);
    assert_eq!(snapshot(&transport).udp_qsp_decrypt_fail_replay, 1);

    // The typed UdpQspError classifies the recoverable decision.
    let err: UdpQspError = qsp_err.into();
    assert!(err.is_recoverable());
}

#[tokio::test]
async fn note_recv_error_too_old_increments_metric_and_is_recoverable() {
    let (tx, _rx) = mpsc::channel::<Vec<u8>>(8);
    let io = ChanIo {
        tx,
        rx: mpsc::channel(1).1,
    };
    let session = make_session(io);
    let transport = make_transport(session);

    assert_eq!(snapshot(&transport).udp_qsp_decrypt_fail_too_old, 0);

    let qsp_err = QspSessionError::TooOld;
    transport.note_recv_error(&qsp_err);
    assert_eq!(snapshot(&transport).udp_qsp_decrypt_fail_too_old, 1);

    let err: UdpQspError = qsp_err.into();
    assert!(err.is_recoverable());
}

#[tokio::test]
async fn note_recv_error_crypto_increments_metric_and_is_recoverable() {
    let (tx, _rx) = mpsc::channel::<Vec<u8>>(8);
    let io = ChanIo {
        tx,
        rx: mpsc::channel(1).1,
    };
    let session = make_session(io);
    let transport = make_transport(session);

    assert_eq!(snapshot(&transport).udp_qsp_decrypt_fail_crypto, 0);

    let qsp_err = QspSessionError::Crypto(QspCryptoError::CryptoFail);
    transport.note_recv_error(&qsp_err);
    assert_eq!(snapshot(&transport).udp_qsp_decrypt_fail_crypto, 1);

    let err: UdpQspError = qsp_err.into();
    assert!(err.is_recoverable());
}

#[tokio::test]
async fn note_recv_error_io_does_not_bump_decrypt_metrics() {
    let (tx, _rx) = mpsc::channel::<Vec<u8>>(8);
    let io = ChanIo {
        tx,
        rx: mpsc::channel(1).1,
    };
    let session = make_session(io);
    let transport = make_transport(session);

    let before = snapshot(&transport);
    let qsp_err = QspSessionError::Io(io::Error::new(io::ErrorKind::TimedOut, "timeout"));
    transport.note_recv_error(&qsp_err);
    let after = snapshot(&transport);
    // Socket I/O bumps no decrypt-fail counter; it is preserved as a typed
    // UdpQspError::Qsp(QspSessionError::Io(_)) for the caller.
    assert_eq!(before, after);

    let err: UdpQspError = qsp_err.into();
    assert!(err.is_recoverable());
}

#[tokio::test]
async fn note_recv_error_packet_number_overflow_increments_metric_and_is_fatal() {
    let (tx, _rx) = mpsc::channel::<Vec<u8>>(8);
    let io = ChanIo {
        tx,
        rx: mpsc::channel(1).1,
    };
    let session = make_session(io);
    let transport = make_transport(session);

    assert_eq!(snapshot(&transport).udp_qsp_decrypt_fail_other, 0);

    let qsp_err = QspSessionError::PacketNumberOverflow;
    transport.note_recv_error(&qsp_err);
    assert_eq!(snapshot(&transport).udp_qsp_decrypt_fail_other, 1);

    // Overflow is FATAL (the TX pn space is exhausted): propagate ->
    // reconnect. See `is_recoverable` doc for the behaviour-fix rationale.
    let err: UdpQspError = qsp_err.into();
    assert!(!err.is_recoverable());
}

/// The typed `UdpQspError::is_recoverable` policy, pinned per shape: each
/// shape's recoverable-vs-fatal classification is asserted explicitly
/// (drop, or TCP-fallback/close) through the typed path.
#[test]
fn recoverable_policy_pins_each_shape() {
    // === Fatal (propagate out of the UDP-QSP transport -> TCP fallback /
    // session close at the session layer) ===
    // PacketNumberOverflow: keeps the runtime routing. Dropping overflow
    // would silently lose packets on a session that can no longer send, so
    // classifying it fatal here keeps the TCP-fallback routing. See
    // `is_recoverable` doc.
    assert!(!UdpQspError::from(QspSessionError::PacketNumberOverflow).is_recoverable());

    assert!(!UdpQspError::from(FrameError::UnknownType(0xFF)).is_recoverable());
    assert!(!UdpQspError::from(MessageError::DataTooLarge { len: 10, max: 5 }).is_recoverable());
    assert!(!UdpQspError::IncompleteMessage.is_recoverable());

    // === Recoverable packet noise: drop & continue ===
    assert!(UdpQspError::from(QspSessionError::Replay).is_recoverable());
    assert!(UdpQspError::from(QspSessionError::TooOld).is_recoverable());
    assert!(
        UdpQspError::from(QspSessionError::Crypto(QspCryptoError::CryptoFail)).is_recoverable()
    );

    // === Recoverable: transient datagram I/O ===
    // Dropping a single transient recv failure is correct for UDP; the
    // idle-timeout backstops persistent failure. Pinned for both the
    // wrapped and standalone io::Error shapes, using a transient kind
    // (`TimedOut`); a non-transient kind (PermissionDenied/
    // NetworkUnreachable/BrokenPipe/...) propagates — see
    // `persistent_socket_io_errors_propagate_not_dropped`.
    let transient = io::ErrorKind::TimedOut;
    assert!(UdpQspError::from(QspSessionError::Io(io::Error::from(transient))).is_recoverable());
    assert!(UdpQspError::from(io::Error::from(transient)).is_recoverable());
}

/// A transient recv socket I/O failure (`WouldBlock`, `TimedOut`,
/// `ConnectionRefused`, ...) must be DROPPED (not propagated, not routed to
/// TCP fallback) by the typed policy. This is the guardrail for the
/// classification documented on `UdpQspError::Io` and `is_recoverable`: a
/// single failed datagram recv is not evidence the UDP path is dead.
#[test]
fn transient_recv_io_is_dropped_not_propagated() {
    for kind in [
        io::ErrorKind::WouldBlock,
        io::ErrorKind::TimedOut,
        io::ErrorKind::ConnectionRefused,
        io::ErrorKind::ConnectionReset,
    ] {
        let err = UdpQspError::from(io::Error::new(kind, "transient recv"));
        assert!(
            err.is_recoverable(),
            "transient recv {kind:?} must be recoverable (dropped), got fatal"
        );
    }
}
