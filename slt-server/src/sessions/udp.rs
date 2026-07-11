//! UDP message handling for client sessions.

use slt_core::crypto::udp_qsp::QspSessionError;
use slt_core::proto::{Message, PongPayload, decode_padded_message};
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::{info, trace};

use super::error::SessionError;
use super::types::SessionControl;
use super::{ClientSessionBase, UdpFailureRecovery, UdpSessionIo};
use crate::quic::UdpClaim;
use crate::tun::TunDeviceIo;

/// Outcome of decrypting an inbound UDP-QSP packet in [`ClientSessionBase`]'s
/// `open_udp_packet`.
enum UdpOpenOutcome {
    /// Decrypted; plaintext written to the reused output buffer.
    Opened {
        /// Reconstructed client-to-server packet number.
        packet_number: u64,
    },
    /// Dropped (replay / too-old / crypto / other). Already counted and logged.
    Dropped,
}

impl<T: TunDeviceIo, S: AsyncRead + AsyncWrite + Unpin + Send + 'static, I: UdpSessionIo>
    ClientSessionBase<T, S, I>
{
    /// Processes a UDP packet claimed for this session.
    ///
    /// Handles the full UDP message pipeline:
    /// 1. Decrypts and validates the packet with UDP-QSP
    /// 2. Decodes the inner VPN message
    /// 3. Dispatches the message to the appropriate handler
    ///
    /// # Parameters
    ///
    /// * `claim` - The claimed UDP packet containing peer address and payload
    ///
    /// # Returns
    ///
    /// * `Ok(SessionControl::Continue)` if the packet was processed or dropped
    /// * `Ok(SessionControl::Close)` if the message requested session termination
    /// * `Err(SessionError)` if a non-recoverable error occurs
    pub(super) async fn handle_udp_claim(
        &mut self,
        claim: UdpClaim,
    ) -> Result<SessionControl, SessionError> {
        let peer = claim.peer;

        trace!(
            session_id = self.session_id,
            client_id = %self.client_id,
            peer = %peer,
            dcid_prefix = ?claim.dcid_prefix,
            "UDP claim received"
        );

        let mut opened = std::mem::take(&mut self.udp_opened_payload_buf);
        let control = match self.open_udp_packet(&claim.payload, &mut opened) {
            UdpOpenOutcome::Opened { packet_number } => {
                self.note_authenticated_udp_activity();
                self.adopt_udp_peer_if_newer(peer, packet_number);
                match self.decode_udp_message(&opened) {
                    Ok(Some(message)) => {
                        self.note_activity();
                        self.dispatch_udp_message(message).await
                    }
                    Ok(None) => Ok(SessionControl::Continue),
                    Err(err) => Err(err),
                }
            }
            UdpOpenOutcome::Dropped => Ok(SessionControl::Continue),
        };
        self.udp_opened_payload_buf = opened;

        control
    }

    /// Decrypts and validates a UDP-QSP packet.
    ///
    /// Opens the packet using the session's UDP-QSP crypto state, handling
    /// various packet errors (replay, too old, crypto failures).
    /// Tracks key phase transitions for metrics.
    ///
    /// # Parameters
    ///
    /// * `payload` - The encrypted UDP-QSP packet bytes
    /// * `out` - Reused output buffer for decrypted payload bytes
    ///
    /// # Returns
    ///
    /// * [`UdpOpenOutcome::Opened`] - The decrypted plaintext payload was written to `out`
    /// * [`UdpOpenOutcome::Dropped`] - The packet should be dropped (logged + counted)
    ///
    /// On replay/old/crypto errors, logs and returns [`UdpOpenOutcome::Dropped`].
    /// Tracks RX key phase transitions for metrics.
    fn open_udp_packet(&mut self, payload: &[u8], out: &mut Vec<u8>) -> UdpOpenOutcome {
        out.clear();
        let Some(session) = self.udp_session.as_mut() else {
            return UdpOpenOutcome::Dropped;
        };
        let rx_phase_before = session.rx_key_phase();

        let packet_number = match session.open_packet(payload) {
            Ok(opened) => {
                let packet_number = opened.pn;
                out.extend_from_slice(opened.payload);
                packet_number
            }
            Err(QspSessionError::Replay) => {
                self.metrics.inc_udp_qsp_decrypt_fail_replay();
                trace!(
                    session_id = self.session_id,
                    client_id = %self.client_id,
                    reason = "replay",
                    "UDP packet dropped: decrypt failure"
                );
                return UdpOpenOutcome::Dropped;
            }
            Err(QspSessionError::TooOld) => {
                self.metrics.inc_udp_qsp_decrypt_fail_too_old();
                trace!(
                    session_id = self.session_id,
                    client_id = %self.client_id,
                    reason = "too_old",
                    "UDP packet dropped: decrypt failure"
                );
                return UdpOpenOutcome::Dropped;
            }
            Err(QspSessionError::Crypto(err)) => {
                self.metrics.inc_udp_qsp_decrypt_fail_crypto();
                trace!(
                    session_id = self.session_id,
                    client_id = %self.client_id,
                    reason = "crypto",
                    error = ?err,
                    "UDP packet dropped: decrypt failure"
                );
                return UdpOpenOutcome::Dropped;
            }
            Err(err) => {
                self.metrics.inc_udp_qsp_decrypt_fail_other();
                trace!(
                    session_id = self.session_id,
                    client_id = %self.client_id,
                    reason = "other",
                    error = ?err,
                    "UDP packet dropped: decrypt failure"
                );
                return UdpOpenOutcome::Dropped;
            }
        };

        // Check for key phase transition after the match to avoid borrow conflicts.
        if let Some(session) = self.udp_session.as_ref()
            && session.rx_key_phase() != rx_phase_before
        {
            self.metrics.inc_udp_qsp_rx_key_phase_transition();
            info!(
                session_id = self.session_id,
                client_id = %self.client_id,
                key_phase = session.rx_key_phase(),
                "UDP-QSP RX key phase transitioned"
            );
        }

        UdpOpenOutcome::Opened { packet_number }
    }

    /// Decodes a VPN message from the decrypted UDP payload.
    ///
    /// Parses the first message and ignores trailing bytes.
    ///
    /// UDP-QSP payloads may carry trailing bytes after the first frame
    /// (for example, padding added to satisfy header-protection sampling rules).
    /// Per protocol, receivers decode the first frame and ignore the rest.
    ///
    /// # Parameters
    ///
    /// * `payload` - The decrypted plaintext payload from UDP-QSP
    ///
    /// # Returns
    ///
    /// * `Ok(Some(message))` - A valid message was decoded
    /// * `Ok(None)` - The payload was empty or incomplete
    /// * `Err(SessionError)` - The message was malformed
    fn decode_udp_message<'a>(
        &self,
        payload: &'a [u8],
    ) -> Result<Option<Message<'a>>, SessionError> {
        let decoded = decode_padded_message(payload, self.limits)?;
        let Some((message, _frame_bytes)) = decoded else {
            return Ok(None);
        };
        Ok(Some(message))
    }

    /// Dispatches a decoded UDP message to its appropriate handler.
    ///
    /// Routes the message based on type:
    /// - Ping: Responds with Pong
    /// - Pong: Logs and continues
    /// - Data: Forwards to TUN device if valid
    /// - `UpgradeProbe`: Sends UDP probe ack and may trigger a TCP switch request
    /// - Close: Initiates session shutdown
    /// - `RegisterCid`: Fails as a protocol violation
    /// - Other control messages: Silently ignored
    ///
    /// # Parameters
    ///
    /// * `message` - The decoded message to dispatch
    ///
    /// # Returns
    ///
    /// * `Ok(SessionControl::Continue)` for most messages
    /// * `Ok(SessionControl::Close)` if the message requested termination
    /// * `Err(SessionError)` if message handling fails
    async fn dispatch_udp_message(
        &mut self,
        message: Message<'_>,
    ) -> Result<SessionControl, SessionError> {
        match message {
            Message::Ping { payload } => {
                let payload = Self::pong_payload_for_ping(payload)?;
                self.send_udp_message_and_flush(
                    Message::Pong { payload: &payload },
                    UdpFailureRecovery::SignalTcpFallback,
                )
                .await?;
                Ok(SessionControl::Continue)
            }
            Message::Pong { payload } => {
                let pong_in = PongPayload::decode(payload)?;
                trace!(
                    session_id = self.session_id,
                    client_id = %self.client_id,
                    nonce = pong_in.nonce,
                    "received udp pong"
                );
                Ok(SessionControl::Continue)
            }
            Message::Data { packet } => {
                if self.should_forward_packet_to_tun(packet) {
                    let outcome = self.tun.accept_packet(packet).await?;
                    self.handle_tun_packet_send_outcome(outcome)?;
                }
                Ok(SessionControl::Continue)
            }
            Message::UpgradeProbe { payload } => self.handle_upgrade_probe(payload).await,
            Message::Close { .. } => Ok(self.peer_close_control(false)),
            Message::RegisterCid { .. } => Err(SessionError::ProtocolViolation),
            Message::Auth { .. }
            | Message::AuthOk { .. }
            | Message::AuthFail { .. }
            | Message::RegisterOk { .. }
            | Message::RegisterFail { .. }
            | Message::UpgradeProbeAck { .. }
            | Message::UdpReady { .. }
            | Message::SwitchToUdp { .. }
            | Message::SwitchAck { .. }
            | Message::SwitchOk { .. }
            | Message::FallbackToTcp { .. }
            | Message::FallbackOk { .. } => Ok(SessionControl::Continue),
        }
    }
}
