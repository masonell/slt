use crate::metrics::Metrics;
use slt_core::crypto::udp_qsp::{QspSessionError, QuicQspSession, SessionIo};
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tracing::{info, trace, warn};

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
pub struct UdpQspTransport {
    session: QuicQspSession<ClientUdpIo>,
    write_buf: Vec<u8>,
    packet_buf: Vec<u8>,
    metrics: Arc<Metrics>,
}

impl UdpQspTransport {
    /// Create a new UDP-QSP transport around an established session.
    #[must_use]
    pub fn new(session: QuicQspSession<ClientUdpIo>, metrics: Arc<Metrics>) -> Self {
        Self {
            session,
            write_buf: Vec::new(),
            packet_buf: vec![0u8; 2048],
            metrics,
        }
    }

    /// Return the destination connection ID used for outbound packets.
    #[must_use]
    pub const fn dcid(&self) -> &slt_core::types::Cid {
        self.session.dcid()
    }

    /// Return the source connection ID used for inbound packets.
    #[must_use]
    pub const fn scid(&self) -> &slt_core::types::Cid {
        self.session.scid()
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
    ) -> io::Result<crate::wire::OwnedMessageBuf> {
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

        let Some((message, _consumed)) = slt_core::proto::decode_message(&payload, limits)
            .map_err(crate::wire::map_message_error)?
        else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "udp-qsp message incomplete",
            ));
        };
        // Per protocol.md Section 4.4: receivers MUST ignore any trailing bytes
        // after decoding the first framed message (may be padding for HP sample).

        Ok(crate::wire::OwnedMessageBuf::new(message.ty(), payload))
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
