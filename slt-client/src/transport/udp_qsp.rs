use std::io;
use std::net::SocketAddr;
#[cfg(unix)]
use std::os::fd::AsFd;
use std::sync::Arc;

#[cfg(not(unix))]
pub use ClientUdpIo as ClientUdpQspIo;
use slt_core::crypto::udp_qsp::{QspSessionError, QuicQspSession, SessionIo};
#[cfg(unix)]
pub use slt_core::transport::UdpQspIo as ClientUdpQspIo;
use tokio::net::UdpSocket;
use tracing::{info, trace, warn};

use crate::metrics::Metrics;

/// Client-side UDP-QSP socket I/O backed by a `tokio::net::UdpSocket`.
#[cfg(any(test, not(unix)))]
pub struct ClientUdpIo {
    socket: Arc<UdpSocket>,
    peer: SocketAddr,
}

#[cfg(any(test, not(unix)))]
impl ClientUdpIo {
    /// Create a new UDP-QSP I/O wrapper for traffic to/from `peer`.
    #[must_use]
    pub const fn new(socket: Arc<UdpSocket>, peer: SocketAddr) -> Self {
        Self { socket, peer }
    }

    #[cfg(not(unix))]
    /// Return the accepted receive peer and outbound transmit destination.
    #[must_use]
    pub const fn peer(&self) -> SocketAddr {
        self.peer
    }
}

#[cfg(unix)]
pub fn client_udp_qsp_io(socket: &Arc<UdpSocket>, peer: SocketAddr) -> io::Result<ClientUdpQspIo> {
    let fd = socket.as_fd().try_clone_to_owned()?;
    let socket = std::net::UdpSocket::from(fd);
    socket.set_nonblocking(true)?;
    ClientUdpQspIo::new(socket, peer)
}

#[cfg(not(unix))]
pub fn client_udp_qsp_io(socket: &Arc<UdpSocket>, peer: SocketAddr) -> io::Result<ClientUdpQspIo> {
    Ok(ClientUdpQspIo::new(socket.clone(), peer))
}

#[cfg(any(test, not(unix)))]
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
pub type ClientTransport = UdpQspTransport<ClientUdpQspIo>;

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

    /// Flush protected packets buffered by the underlying I/O layer.
    ///
    /// # Errors
    ///
    /// Returns any I/O error reported by the socket backend.
    pub async fn flush(&mut self) -> io::Result<()> {
        self.session.flush().await
    }

    /// Returns whether the underlying I/O layer has packets waiting for flush.
    #[must_use]
    pub fn has_pending_flush(&self) -> bool {
        self.session.has_pending_flush()
    }

    /// Replace the underlying UDP-QSP I/O backend after a best-effort flush.
    ///
    /// Flush failures during network handoff are logged and ignored: any packet
    /// already assigned a packet number may be lost, but the session's packet
    /// number, replay, and key-phase state remain monotonic.
    pub async fn replace_io(&mut self, new_io: I) -> I {
        if self.session.has_pending_flush()
            && let Err(err) = self.session.flush().await
        {
            warn!(error = %err, "failed to flush udp-qsp packets before io replacement");
        }
        self.session.replace_io(new_io)
    }

    /// Encode and send a VPN protocol message over UDP-QSP.
    ///
    /// Frames the message using the SLT wire protocol, encrypts it with UDP-QSP
    /// packet protection, and sends it to the peer. Tracks TX key phase transitions
    /// in metrics.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Message encoding fails
    /// - UDP-QSP session is dead (connection aborted)
    /// - Socket send fails
    /// - Packet number overflows
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
    ///
    /// Receives a UDP-QSP protected packet, decrypts and validates it, then
    /// decodes the framed message payload. Tracks RX key phase transitions in
    /// metrics and ignores trailing bytes after the first message per protocol spec.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Packet decryption fails (replay, too old, crypto error, etc.)
    /// - UDP-QSP session is dead (connection aborted)
    /// - Message decoding fails
    /// - Message is incomplete
    pub async fn read_next_message(
        &mut self,
        limits: slt_core::proto::MessageLimits,
    ) -> io::Result<slt_core::proto::OwnedMessageBuf> {
        let rx_phase_before = self.session.rx_key_phase();
        let decode_result = {
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

            match slt_core::proto::decode_message(opened.payload, limits) {
                Ok(Some((message, consumed))) => {
                    // Per protocol.md Section 4.4: receivers MUST ignore any trailing bytes
                    // after decoding the first framed message (may be padding for HP sample).
                    Ok((message.ty(), opened.payload[..consumed].to_vec()))
                }
                Ok(None) => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "udp-qsp message incomplete",
                )),
                Err(err) => Err(crate::wire::map_message_error(err)),
            }
        };
        // Check for key phase transition by comparing session state before/after recv
        let rx_phase_after = self.session.rx_key_phase();
        if rx_phase_after != rx_phase_before {
            self.metrics.inc_udp_qsp_rx_key_phase_transition();
            info!(
                key_phase = rx_phase_after,
                "UDP-QSP RX key phase transitioned"
            );
        }
        let (message_ty, frame) = decode_result?;
        Ok(slt_core::proto::OwnedMessageBuf::new(message_ty, frame))
    }

    /// Handle a UDP-QSP receive error and update metrics.
    ///
    /// Classifies the error type, updates the corresponding metrics counter,
    /// and returns an appropriate `io::Error` for the failure.
    ///
    /// # Errors
    ///
    /// Always returns an error with kind:
    /// - `InvalidData` for replay, too old, crypto, and packet number overflow errors
    /// - `ConnectionAborted` for dead channel errors
    /// - Preserves original error kind for I/O errors
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

impl UdpQspTransport<ClientUdpQspIo> {
    /// Return the current UDP peer address for client-side socket recreation.
    #[must_use]
    pub const fn peer(&self) -> SocketAddr {
        self.session.io().peer()
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

    use slt_core::crypto::udp_qsp::{QspCryptoError, QspSessionError, QuicQspSession};
    use slt_core::proto::{HEADER_LEN, Message, MessageLimits, PingPayload, PongPayload};
    use slt_core::types::Cid;
    use tokio::sync::mpsc;

    use super::*;
    use crate::metrics::MetricsSnapshot;
    use crate::test_support::{ChanIo, encode_ping, encode_pong, make_server_keys, make_test_keys};

    // Keep in sync with slt-core::crypto::udp_qsp::session::KEY_UPDATE_INTERVAL.
    const KEY_UPDATE_INTERVAL: u64 = 1 << 21;

    fn make_session(io: ChanIo) -> QuicQspSession<ChanIo> {
        make_session_with_pn(io, 0, 0)
    }

    fn make_session_with_pn(
        io: ChanIo,
        send_pn: u64,
        recv_expected_pn: u64,
    ) -> QuicQspSession<ChanIo> {
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

        let scid = Cid::from([0xA1; 20]);
        let dcid = Cid::from([0xB2; 20]);

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

        let scid = Cid::from([0xA1; 20]);
        let dcid = Cid::from([0xB2; 20]);

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

/// Tests for `ClientUdpIo` peer filtering behavior using real UDP sockets.
#[cfg(test)]
mod peer_filtering_tests {
    use std::time::Duration;

    use tokio::time::timeout;

    use super::*;
    use crate::test_support::{encode_ping, udp_pair};

    #[tokio::test]
    async fn client_udp_io_accepts_packets_from_peer() {
        let (socket_a, socket_b) = udp_pair().await;

        // Create ClientUdpIo with socket_a, expecting packets from socket_b
        let peer_addr = socket_b.local_addr().unwrap();
        let mut io = ClientUdpIo::new(socket_a.clone(), peer_addr);

        // Send a packet from the peer (socket_b)
        let ping_frame = encode_ping(0x1234);
        socket_b.send(&ping_frame).await.unwrap();

        // Receive should succeed
        let mut buf = [0u8; 2048];
        let len = io.recv(&mut buf).await.unwrap();
        assert_eq!(&buf[..len], ping_frame.as_slice());
    }

    #[tokio::test]
    async fn client_udp_io_ignores_packets_from_non_peer() {
        let (socket_a, socket_b) = udp_pair().await;

        // Create a third socket that is NOT the peer
        let socket_c = Arc::new(
            tokio::net::UdpSocket::bind("127.0.0.1:0")
                .await
                .expect("failed to bind socket C"),
        );

        // Create ClientUdpIo with socket_a, expecting packets from socket_b
        let peer_addr = socket_b.local_addr().unwrap();
        let mut io = ClientUdpIo::new(socket_a.clone(), peer_addr);

        // Send a packet from non-peer (socket_c) to socket_a
        let junk_packet = b"junk from non-peer";
        socket_c
            .send_to(junk_packet, socket_a.local_addr().unwrap())
            .await
            .unwrap();

        // Give the packet time to arrive
        tokio::time::sleep(Duration::from_millis(10)).await;

        // Now send the real packet from the peer
        let ping_frame = encode_ping(0x5678);
        socket_b.send(&ping_frame).await.unwrap();

        // Receive should return the peer's packet, skipping the non-peer's
        let mut buf = [0u8; 2048];
        let len = io.recv(&mut buf).await.unwrap();
        assert_eq!(&buf[..len], ping_frame.as_slice());
        // Verify we got the ping, not the junk
        assert_ne!(&buf[..len.min(junk_packet.len())], junk_packet);
    }

    #[tokio::test]
    async fn client_udp_io_send_delivers_to_peer() {
        let (socket_a, socket_b) = udp_pair().await;

        // Create ClientUdpIo with socket_a, sending to socket_b
        let peer_addr = socket_b.local_addr().unwrap();
        let mut io = ClientUdpIo::new(socket_a.clone(), peer_addr);

        // Send a packet
        let ping_frame = encode_ping(0xABCD);
        io.send(&ping_frame).await.unwrap();

        // Socket_b should receive it
        let mut buf = [0u8; 2048];
        let (len, from) = socket_b.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..len], ping_frame.as_slice());
        assert_eq!(from, socket_a.local_addr().unwrap());
    }

    #[tokio::test]
    async fn client_udp_io_multiple_packets_in_order() {
        let (socket_a, socket_b) = udp_pair().await;

        let peer_addr = socket_b.local_addr().unwrap();
        let mut io = ClientUdpIo::new(socket_a.clone(), peer_addr);

        // Send multiple packets from peer
        for nonce in 0u64..5 {
            let ping_frame = encode_ping(nonce);
            socket_b.send(&ping_frame).await.unwrap();
        }

        // Receive them in order
        let mut buf = [0u8; 2048];
        for expected_nonce in 0u64..5 {
            let len = io.recv(&mut buf).await.unwrap();
            let expected = encode_ping(expected_nonce);
            assert_eq!(&buf[..len], expected.as_slice());
        }
    }

    #[tokio::test]
    async fn client_udp_io_recv_timeout_when_no_peer_packet() {
        let (socket_a, socket_b) = udp_pair().await;

        // Create a third socket that is NOT the peer
        let socket_c = Arc::new(
            tokio::net::UdpSocket::bind("127.0.0.1:0")
                .await
                .expect("failed to bind socket C"),
        );

        let peer_addr = socket_b.local_addr().unwrap();
        let mut io = ClientUdpIo::new(socket_a.clone(), peer_addr);

        // Send junk from non-peer
        let junk_packet = b"junk from non-peer";
        socket_c
            .send_to(junk_packet, socket_a.local_addr().unwrap())
            .await
            .unwrap();

        // Recv should block waiting for a packet from the actual peer
        // Use a short timeout to verify it doesn't return the non-peer packet
        let mut buf = [0u8; 2048];
        let result = timeout(Duration::from_millis(50), io.recv(&mut buf)).await;
        assert!(
            result.is_err(),
            "recv should timeout since no peer packet arrived"
        );
    }
}

/// Real socket integration tests for UDP-QSP transport.
#[cfg(test)]
mod real_socket_tests {
    use slt_core::crypto::udp_qsp::QuicQspSession;
    use slt_core::proto::{
        CloseCode, HEADER_LEN, Message, MessageLimits, PingPayload, PongPayload,
    };
    use slt_core::types::Cid;

    use super::*;
    use crate::test_support::{
        encode_close, encode_data, encode_ping, encode_pong, make_server_keys, make_test_keys,
        udp_pair,
    };

    /// Create a paired client/server UDP-QSP transport for integration testing.
    async fn udp_qsp_transport_pair() -> (UdpQspTransport<ClientUdpIo>, UdpQspTransport<ClientUdpIo>)
    {
        let (client_socket, server_socket) = udp_pair().await;
        let client_addr = client_socket.local_addr().unwrap();
        let server_addr = server_socket.local_addr().unwrap();

        let scid = Cid::from([0xA1; 20]);
        let dcid = Cid::from([0xB2; 20]);

        let client_io = ClientUdpIo::new(client_socket, server_addr);
        let client_session =
            QuicQspSession::new(client_io, scid, dcid, make_test_keys(), 0, 0, false);
        let client_metrics = Arc::new(Metrics::default());
        let client = UdpQspTransport::new(client_session, client_metrics);

        let server_io = ClientUdpIo::new(server_socket, client_addr);
        let server_session =
            QuicQspSession::new(server_io, dcid, scid, make_server_keys(), 0, 0, false);
        let server_metrics = Arc::new(Metrics::default());
        let server = UdpQspTransport::new(server_session, server_metrics);

        (client, server)
    }

    #[tokio::test]
    async fn full_roundtrip_over_real_udp_sockets() {
        let (mut client, mut server) = udp_qsp_transport_pair().await;

        let limits = MessageLimits::new(2048, 2048);
        let nonce = 0x1234_5678_9ABC_DEF0u64;

        // Client sends ping
        let ping_frame = encode_ping(nonce);
        client
            .write_message(Message::Ping {
                payload: &ping_frame[HEADER_LEN..],
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
    }

    #[tokio::test]
    async fn bidirectional_message_exchange_over_real_udp() {
        let (mut client, mut server) = udp_qsp_transport_pair().await;

        let limits = MessageLimits::new(2048, 2048);
        let nonce = 0xDEAD_BEEF_CAFE_BABEu64;

        // Client sends ping
        let ping_frame = encode_ping(nonce);
        client
            .write_message(Message::Ping {
                payload: &ping_frame[HEADER_LEN..],
            })
            .await
            .unwrap();

        // Server receives ping
        let msg = server.read_next_message(limits).await.unwrap();
        match msg.message() {
            Message::Ping { payload } => {
                assert_eq!(PingPayload::decode(payload).unwrap().nonce, nonce);
            }
            _ => panic!("expected ping"),
        }

        // Server sends pong
        let pong_frame = encode_pong(nonce);
        server
            .write_message(Message::Pong {
                payload: &pong_frame[HEADER_LEN..],
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

    #[tokio::test]
    async fn multiple_packets_in_sequence_over_real_udp() {
        let (mut client, mut server) = udp_qsp_transport_pair().await;

        let limits = MessageLimits::new(2048, 2048);

        // Send multiple pings in sequence
        for nonce in 0u64..5 {
            let ping_frame = encode_ping(nonce);
            client
                .write_message(Message::Ping {
                    payload: &ping_frame[HEADER_LEN..],
                })
                .await
                .unwrap();

            let msg = server.read_next_message(limits).await.unwrap();
            match msg.message() {
                Message::Ping { payload } => {
                    assert_eq!(PingPayload::decode(payload).unwrap().nonce, nonce);
                }
                _ => panic!("expected ping for nonce {nonce}"),
            }
        }
    }

    #[tokio::test]
    async fn data_message_roundtrip_over_real_udp() {
        let (mut client, mut server) = udp_qsp_transport_pair().await;

        let limits = MessageLimits::new(2048, 2048);
        let packet_data = b"hello world vpn packet";

        let data_frame = encode_data(packet_data);
        client
            .write_message(Message::Data {
                packet: &data_frame[HEADER_LEN..],
            })
            .await
            .unwrap();

        let msg = server.read_next_message(limits).await.unwrap();
        match msg.message() {
            Message::Data { packet } => {
                assert_eq!(packet, &data_frame[HEADER_LEN..]);
            }
            _ => panic!("expected data"),
        }
    }

    #[tokio::test]
    async fn close_message_roundtrip_over_real_udp() {
        let (mut client, mut server) = udp_qsp_transport_pair().await;

        let limits = MessageLimits::new(2048, 2048);
        let close_code = CloseCode::Normal;

        let close_frame = encode_close(close_code);
        client
            .write_message(Message::Close {
                payload: &close_frame[HEADER_LEN..],
            })
            .await
            .unwrap();

        let msg = server.read_next_message(limits).await.unwrap();
        match msg.message() {
            Message::Close { payload } => {
                use slt_core::proto::ClosePayload;
                assert_eq!(ClosePayload::decode(payload).unwrap().code, close_code);
            }
            _ => panic!("expected close"),
        }
    }

    #[tokio::test]
    async fn server_to_client_message_over_real_udp() {
        let (mut client, mut server) = udp_qsp_transport_pair().await;

        let limits = MessageLimits::new(2048, 2048);
        let nonce = 0xF00D_FACEu64;

        // Server sends ping to client
        let ping_frame = encode_ping(nonce);
        server
            .write_message(Message::Ping {
                payload: &ping_frame[HEADER_LEN..],
            })
            .await
            .unwrap();

        // Client receives it
        let msg = client.read_next_message(limits).await.unwrap();
        match msg.message() {
            Message::Ping { payload } => {
                assert_eq!(PingPayload::decode(payload).unwrap().nonce, nonce);
            }
            _ => panic!("expected ping"),
        }
    }

    /// On Unix the client transport wraps the GSO `UdpQspIo` backend, so a data
    /// write buffers into the send slab and is only transmitted once `flush` runs.
    #[cfg(unix)]
    #[tokio::test]
    async fn write_message_buffers_until_flush_over_gso_backend() {
        use std::time::Duration;

        use tokio::time::timeout;

        let (client_socket, server_socket) = udp_pair().await;
        let client_addr = client_socket.local_addr().unwrap();
        let server_addr = server_socket.local_addr().unwrap();

        let scid = Cid::from([0xA1; 20]);
        let dcid = Cid::from([0xB2; 20]);

        let client_io = client_udp_qsp_io(&client_socket, server_addr).unwrap();
        let client_session =
            QuicQspSession::new(client_io, scid, dcid, make_test_keys(), 0, 0, false);
        let mut client = UdpQspTransport::new(client_session, Arc::new(Metrics::default()));

        let server_io = client_udp_qsp_io(&server_socket, client_addr).unwrap();
        let server_session =
            QuicQspSession::new(server_io, dcid, scid, make_server_keys(), 0, 0, false);
        let mut server = UdpQspTransport::new(server_session, Arc::new(Metrics::default()));

        let limits = MessageLimits::new(2048, 2048);
        let ping_frame = encode_ping(0xBEEF);

        // Writing buffers into the GSO send slab; nothing is transmitted yet.
        client
            .write_message(Message::Ping {
                payload: &ping_frame[HEADER_LEN..],
            })
            .await
            .unwrap();
        assert!(
            client.has_pending_flush(),
            "write_message must leave a pending flush"
        );
        assert!(
            timeout(Duration::from_millis(80), server.read_next_message(limits))
                .await
                .is_err(),
            "buffered packet must not be delivered until flush"
        );

        // Flushing transmits the slab and clears the pending flag.
        client.flush().await.unwrap();
        assert!(!client.has_pending_flush());

        let msg = server.read_next_message(limits).await.unwrap();
        match msg.message() {
            Message::Ping { payload } => {
                assert_eq!(PingPayload::decode(payload).unwrap().nonce, 0xBEEF);
            }
            _ => panic!("expected ping"),
        }
    }
}
