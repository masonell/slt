use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use slt_core::crypto::udp_qsp::{QspSessionError, QuicQspSession, SessionIo};
use tokio::net::UdpSocket;
use tracing::{info, trace, warn};

use crate::metrics::Metrics;

/// Client-side UDP-QSP socket I/O backed by a `tokio::net::UdpSocket`.
pub struct ClientUdpIo {
    socket: Arc<UdpSocket>,
    peer: SocketAddr,
}

impl ClientUdpIo {
    /// Create a new UDP-QSP I/O wrapper for traffic to/from `peer`.
    #[must_use]
    pub const fn new(socket: Arc<UdpSocket>, peer: SocketAddr) -> Self {
        Self { socket, peer }
    }
}

impl SessionIo for ClientUdpIo {
    async fn send<'a>(&'a mut self, bytes: &'a [u8]) -> io::Result<()> {
        let _ = self.socket.send_to(bytes, self.peer).await?;
        Ok(())
    }

    async fn recv<'a>(&'a mut self, buf: &'a mut [u8]) -> io::Result<usize> {
        loop {
            let (len, from) = self.socket.recv_from(buf).await?;
            if from == self.peer {
                return Ok(len);
            }
        }
    }
}

/// UDP-QSP transport wrapper for VPN protocol messages.
pub struct UdpQspTransport<I> {
    session: QuicQspSession<I>,
    write_buf: Vec<u8>,
    packet_buf: Vec<u8>,
    metrics: Arc<Metrics>,
}

/// Production UDP-QSP transport with real socket I/O.
pub type ClientTransport = UdpQspTransport<ClientUdpIo>;

impl<I: SessionIo> UdpQspTransport<I> {
    /// Create a new UDP-QSP transport around an established session.
    #[must_use]
    pub fn new(session: QuicQspSession<I>, metrics: Arc<Metrics>) -> Self {
        Self {
            session,
            write_buf: Vec::new(),
            packet_buf: vec![0u8; 2048],
            metrics,
        }
    }

    /// Encode and send a VPN protocol message over UDP-QSP.
    pub async fn write_message(&mut self, message: slt_core::proto::Message<'_>) -> io::Result<()> {
        self.write_buf.clear();
        slt_core::proto::encode_message(message, &mut self.write_buf)
            .map_err(crate::wire::map_frame_error)?;

        let tx_phase_before = self.session.tx_key_phase();
        match self.session.send(&self.write_buf).await {
            Ok(()) => {
                if self.session.tx_key_phase() != tx_phase_before {
                    self.metrics.inc_udp_qsp_tx_key_phase_transition();
                    info!(
                        key_phase = self.session.tx_key_phase(),
                        "UDP-QSP TX key phase transitioned"
                    );
                }
                Ok(())
            }
            Err(QspSessionError::DeadChannel) => {
                self.metrics.inc_udp_qsp_dead_channel();
                warn!("UDP-QSP channel marked dead");
                Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "udp-qsp channel dead",
                ))
            }
            Err(err) => Err(map_qsp_error(err)),
        }
    }

    /// Receive and decode a single VPN protocol message from UDP-QSP.
    pub async fn read_next_message(
        &mut self,
        limits: slt_core::proto::MessageLimits,
    ) -> io::Result<slt_core::proto::OwnedMessageBuf> {
        let rx_phase_before = self.session.rx_key_phase();
        let opened = match self.session.recv(&mut self.packet_buf).await {
            Ok(opened) => opened,
            Err(err) => {
                self.handle_recv_error(err)?;
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "recv error handled",
                ));
            }
        };

        // Copy payload before checking session state (opened holds a reference to session)
        let payload = opened.payload.to_vec();

        // Check for key phase transition by comparing session state before/after recv
        let rx_phase_after = self.session.rx_key_phase();
        if rx_phase_after != rx_phase_before {
            self.metrics.inc_udp_qsp_rx_key_phase_transition();
            info!(
                key_phase = rx_phase_after,
                "UDP-QSP RX key phase transitioned"
            );
        }

        let Some((message, consumed)) = slt_core::proto::decode_message(&payload, limits)
            .map_err(crate::wire::map_message_error)?
        else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "udp-qsp message incomplete",
            ));
        };
        // Per protocol.md Section 4.4: receivers MUST ignore any trailing bytes
        // after decoding the first framed message (may be padding for HP sample).

        let frame = payload[..consumed].to_vec();
        Ok(slt_core::proto::OwnedMessageBuf::new(message.ty(), frame))
    }

    fn handle_recv_error(&self, err: QspSessionError) -> io::Result<()> {
        match err {
            QspSessionError::Replay => {
                self.metrics.inc_udp_qsp_decrypt_fail_replay();
                trace!(reason = "replay", "UDP-QSP packet dropped: decrypt failure");
                Err(io::Error::new(io::ErrorKind::InvalidData, "replay"))
            }
            QspSessionError::TooOld => {
                self.metrics.inc_udp_qsp_decrypt_fail_too_old();
                trace!(
                    reason = "too_old",
                    "UDP-QSP packet dropped: decrypt failure"
                );
                Err(io::Error::new(io::ErrorKind::InvalidData, "too old"))
            }
            QspSessionError::DeadChannel => {
                self.metrics.inc_udp_qsp_dead_channel();
                warn!("UDP-QSP channel marked dead");
                Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "udp-qsp channel dead",
                ))
            }
            QspSessionError::Crypto(crypto_err) => {
                self.metrics.inc_udp_qsp_decrypt_fail_crypto();
                trace!(
                    reason = "crypto",
                    error = ?crypto_err,
                    "UDP-QSP packet dropped: decrypt failure"
                );
                Err(io::Error::new(io::ErrorKind::InvalidData, "crypto error"))
            }
            QspSessionError::Io(io_err) => Err(io_err),
            QspSessionError::PacketNumberOverflow => {
                self.metrics.inc_udp_qsp_decrypt_fail_other();
                trace!(
                    reason = "packet_number_overflow",
                    "UDP-QSP packet dropped: decrypt failure"
                );
                Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "packet number overflow",
                ))
            }
        }
    }
}

fn map_qsp_error(err: QspSessionError) -> io::Error {
    match err {
        QspSessionError::Io(err) => err,
        QspSessionError::DeadChannel => {
            io::Error::new(io::ErrorKind::ConnectionAborted, "udp-qsp channel dead")
        }
        QspSessionError::PacketNumberOverflow => io::Error::new(
            io::ErrorKind::QuotaExceeded,
            "udp-qsp packet number overflow",
        ),
        other => io::Error::new(
            io::ErrorKind::InvalidData,
            format!("udp-qsp error: {other:?}"),
        ),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use slt_core::crypto::udp_qsp::{QspCryptoError, QspSessionError, QuicQspSession, SessionIo};
    use slt_core::proto::{
        AEAD_IV_LEN, AEAD_KEY_LEN, CipherSuite, HEADER_LEN, HP_KEY_LEN, Message, MessageLimits,
        PingPayload, PongPayload, encode_message,
    };
    use slt_core::types::Cid;
    use tokio::sync::mpsc;

    use super::*;
    use crate::metrics::MetricsSnapshot;

    /// In-memory channel I/O for testing (mirrors core's `ChanIo` pattern).
    struct ChanIo {
        tx: mpsc::Sender<Vec<u8>>,
        rx: mpsc::Receiver<Vec<u8>>,
    }

    // Keep in sync with slt-core::crypto::udp_qsp::session::KEY_UPDATE_INTERVAL.
    const KEY_UPDATE_INTERVAL: u64 = 1 << 21;

    impl SessionIo for ChanIo {
        async fn send(&mut self, bytes: &[u8]) -> io::Result<()> {
            self.tx
                .send(bytes.to_vec())
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "channel closed"))
        }

        async fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let packet =
                self.rx.recv().await.ok_or_else(|| {
                    io::Error::new(io::ErrorKind::UnexpectedEof, "channel closed")
                })?;
            if packet.len() > buf.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "packet too large",
                ));
            }
            buf[..packet.len()].copy_from_slice(&packet);
            Ok(packet.len())
        }
    }

    fn make_test_keys() -> slt_core::crypto::udp_qsp::UdpQspKeys {
        slt_core::crypto::udp_qsp::UdpQspKeys::new(
            CipherSuite::Aes128Gcm,
            [0x11; HP_KEY_LEN],
            [0x22; HP_KEY_LEN],
            [0x33; AEAD_KEY_LEN],
            [0x44; AEAD_KEY_LEN],
            [0x55; AEAD_IV_LEN],
            [0x66; AEAD_IV_LEN],
        )
        .unwrap()
    }

    fn make_server_keys() -> slt_core::crypto::udp_qsp::UdpQspKeys {
        // Swapped directions relative to client keys
        slt_core::crypto::udp_qsp::UdpQspKeys::new(
            CipherSuite::Aes128Gcm,
            [0x22; HP_KEY_LEN],
            [0x11; HP_KEY_LEN],
            [0x44; AEAD_KEY_LEN],
            [0x33; AEAD_KEY_LEN],
            [0x66; AEAD_IV_LEN],
            [0x55; AEAD_IV_LEN],
        )
        .unwrap()
    }

    fn make_session(io: ChanIo) -> QuicQspSession<ChanIo> {
        make_session_with_pn(io, 0, 0)
    }

    fn make_session_with_pn(
        io: ChanIo,
        send_pn: u64,
        recv_expected_pn: u64,
    ) -> QuicQspSession<ChanIo> {
        let scid = Cid::from([0xA1; 8]);
        let dcid = Cid::from([0xB2; 8]);
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

    fn encode_ping(nonce: u64) -> Vec<u8> {
        let payload = PingPayload { nonce };
        let mut buf = Vec::new();
        payload.encode(&mut buf);
        let mut frame = Vec::new();
        encode_message(Message::Ping { payload: &buf }, &mut frame).unwrap();
        frame
    }

    fn encode_pong(nonce: u64) -> Vec<u8> {
        let wire = nonce.to_be_bytes();
        let mut frame = Vec::new();
        encode_message(Message::Pong { payload: &wire }, &mut frame).unwrap();
        frame
    }

    fn snapshot(transport: &UdpQspTransport<ChanIo>) -> MetricsSnapshot {
        transport.metrics.snapshot()
    }

    #[tokio::test]
    async fn write_message_encodes_and_sends_framed_message() {
        let (c2s_tx, c2s_rx) = mpsc::channel::<Vec<u8>>(8);
        let (s2c_tx, s2c_rx) = mpsc::channel::<Vec<u8>>(8);

        let scid = Cid::from([0xA1; 8]);
        let dcid = Cid::from([0xB2; 8]);

        let client_io = ChanIo {
            tx: c2s_tx,
            rx: s2c_rx,
        };
        let client_session =
            QuicQspSession::new(client_io, scid, dcid, make_test_keys(), 0, 0, false);
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

        let scid = Cid::from([0xA1; 8]);
        let dcid = Cid::from([0xB2; 8]);

        let mut server_session =
            QuicQspSession::new(server_io, dcid, scid, make_server_keys(), 0, 0, false);
        let client_session =
            QuicQspSession::new(client_io, scid, dcid, make_test_keys(), 0, 0, false);

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
    async fn full_roundtrip_write_recv_read_returns_original_message() {
        let (c2s_tx, c2s_rx) = mpsc::channel::<Vec<u8>>(8);
        let (s2c_tx, s2c_rx) = mpsc::channel::<Vec<u8>>(8);

        let scid = Cid::from([0xA1; 8]);
        let dcid = Cid::from([0xB2; 8]);

        // Client transport
        let client_io = ChanIo {
            tx: c2s_tx,
            rx: s2c_rx,
        };
        let client_session =
            QuicQspSession::new(client_io, scid, dcid, make_test_keys(), 0, 0, false);
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
    fn error_mapping_dead_channel_returns_connection_aborted() {
        let err = map_qsp_error(QspSessionError::DeadChannel);
        assert_eq!(err.kind(), io::ErrorKind::ConnectionAborted);
        assert!(err.to_string().contains("dead"));
    }

    #[test]
    fn error_mapping_io_passthrough() {
        let io_err = io::Error::new(io::ErrorKind::TimedOut, "timeout");
        let err = map_qsp_error(QspSessionError::Io(io_err));
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
    }

    #[test]
    fn error_mapping_packet_number_overflow_returns_quota_exceeded() {
        let err = map_qsp_error(QspSessionError::PacketNumberOverflow);
        assert_eq!(err.kind(), io::ErrorKind::QuotaExceeded);
        assert!(err.to_string().contains("overflow"));
    }

    #[test]
    fn error_mapping_crypto_returns_invalid_data() {
        let err = map_qsp_error(QspSessionError::Crypto(QspCryptoError::CryptoFail));
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn error_mapping_replay_session_error_returns_invalid_data() {
        let err = map_qsp_error(QspSessionError::Replay);
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn error_mapping_too_old_returns_invalid_data() {
        let err = map_qsp_error(QspSessionError::TooOld);
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn rx_key_phase_transition_increments_metric() {
        let (c2s_tx, c2s_rx) = mpsc::channel::<Vec<u8>>(8);
        let (s2c_tx, s2c_rx) = mpsc::channel::<Vec<u8>>(8);

        let scid = Cid::from([0xA1; 8]);
        let dcid = Cid::from([0xB2; 8]);

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

        let scid = Cid::from([0xA1; 8]);
        let dcid = Cid::from([0xB2; 8]);

        let client_io = ChanIo {
            tx: c2s_tx,
            rx: s2c_rx,
        };
        let client_session =
            QuicQspSession::new(client_io, scid, dcid, make_test_keys(), 0, 0, false);
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
    async fn handle_recv_error_replay_increments_metric() {
        let (tx, _rx) = mpsc::channel::<Vec<u8>>(8);
        let io = ChanIo {
            tx,
            rx: mpsc::channel(1).1,
        };
        let session = make_session(io);
        let transport = make_transport(session);

        assert_eq!(snapshot(&transport).udp_qsp_decrypt_fail_replay, 0);

        let result = transport.handle_recv_error(QspSessionError::Replay);
        assert!(result.is_err());
        assert_eq!(snapshot(&transport).udp_qsp_decrypt_fail_replay, 1);
        let err = result.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn handle_recv_error_too_old_increments_metric() {
        let (tx, _rx) = mpsc::channel::<Vec<u8>>(8);
        let io = ChanIo {
            tx,
            rx: mpsc::channel(1).1,
        };
        let session = make_session(io);
        let transport = make_transport(session);

        assert_eq!(snapshot(&transport).udp_qsp_decrypt_fail_too_old, 0);

        let result = transport.handle_recv_error(QspSessionError::TooOld);
        assert!(result.is_err());
        assert_eq!(snapshot(&transport).udp_qsp_decrypt_fail_too_old, 1);
        let err = result.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn handle_recv_error_dead_channel_increments_metric() {
        let (tx, _rx) = mpsc::channel::<Vec<u8>>(8);
        let io = ChanIo {
            tx,
            rx: mpsc::channel(1).1,
        };
        let session = make_session(io);
        let transport = make_transport(session);

        assert_eq!(snapshot(&transport).udp_qsp_dead_channel, 0);

        let result = transport.handle_recv_error(QspSessionError::DeadChannel);
        assert!(result.is_err());
        assert_eq!(snapshot(&transport).udp_qsp_dead_channel, 1);
        let err = result.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::ConnectionAborted);
    }

    #[tokio::test]
    async fn handle_recv_error_crypto_increments_metric() {
        let (tx, _rx) = mpsc::channel::<Vec<u8>>(8);
        let io = ChanIo {
            tx,
            rx: mpsc::channel(1).1,
        };
        let session = make_session(io);
        let transport = make_transport(session);

        assert_eq!(snapshot(&transport).udp_qsp_decrypt_fail_crypto, 0);

        let result =
            transport.handle_recv_error(QspSessionError::Crypto(QspCryptoError::CryptoFail));
        assert!(result.is_err());
        assert_eq!(snapshot(&transport).udp_qsp_decrypt_fail_crypto, 1);
        let err = result.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn handle_recv_error_io_passthrough() {
        let (tx, _rx) = mpsc::channel::<Vec<u8>>(8);
        let io = ChanIo {
            tx,
            rx: mpsc::channel(1).1,
        };
        let session = make_session(io);
        let transport = make_transport(session);

        let io_err = io::Error::new(io::ErrorKind::TimedOut, "timeout");
        let result = transport.handle_recv_error(QspSessionError::Io(io_err));
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
    }

    #[tokio::test]
    async fn handle_recv_error_packet_number_overflow_increments_metric() {
        let (tx, _rx) = mpsc::channel::<Vec<u8>>(8);
        let io = ChanIo {
            tx,
            rx: mpsc::channel(1).1,
        };
        let session = make_session(io);
        let transport = make_transport(session);

        assert_eq!(snapshot(&transport).udp_qsp_decrypt_fail_other, 0);

        let result = transport.handle_recv_error(QspSessionError::PacketNumberOverflow);
        assert!(result.is_err());
        assert_eq!(snapshot(&transport).udp_qsp_decrypt_fail_other, 1);
        let err = result.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }
}
