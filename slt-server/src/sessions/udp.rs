//! UDP message handling for client sessions.

use std::io;

use slt_core::crypto::udp_qsp::QspSessionError;
use slt_core::proto::{Message, PongPayload, decode_message};
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::{info, trace, warn};

use super::types::SessionControl;
use super::{
    ActiveTransport, ClientSessionBase, UdpSocketIo, map_message_error, map_payload_error,
};
use crate::quic::UdpClaim;
use crate::tun::TunDeviceIo;

impl<T: TunDeviceIo, S: AsyncRead + AsyncWrite + Unpin + Send + 'static, U: UdpSocketIo>
    ClientSessionBase<T, S, U>
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
    /// * `Err(io::Error)` if a non-recoverable error occurs
    pub(super) async fn handle_udp_claim(&mut self, claim: UdpClaim) -> io::Result<SessionControl> {
        let peer = claim.peer;

        trace!(
            session_id = self.session_id,
            client_id = %self.client_id,
            peer = %peer,
            dcid_prefix = ?claim.dcid_prefix,
            "UDP claim received"
        );

        let mut opened = std::mem::take(&mut self.udp_opened_payload_buf);
        let control = if self.open_udp_packet(&claim.payload, &mut opened).is_none() {
            Ok(SessionControl::Continue)
        } else {
            self.update_udp_peer(peer);
            match self.decode_udp_message(&opened) {
                Ok(Some(message)) => self.dispatch_udp_message(message).await,
                Ok(None) => Ok(SessionControl::Continue),
                Err(err) => Err(err),
            }
        };
        self.udp_opened_payload_buf = opened;

        control
    }

    /// Decrypts and validates a UDP-QSP packet.
    ///
    /// Opens the packet using the session's UDP-QSP crypto state, handling
    /// various error conditions (replay, too old, dead channel, crypto failures).
    /// Tracks key phase transitions for metrics.
    ///
    /// # Parameters
    ///
    /// * `payload` - The encrypted UDP-QSP packet bytes
    /// * `out` - Reused output buffer for decrypted payload bytes
    ///
    /// # Returns
    ///
    /// * `Some(())` - The decrypted plaintext payload was written to `out`
    /// * `None` - If the packet should be dropped (with appropriate metrics logged)
    ///
    /// # Behavior
    ///
    /// - On `DeadChannel` error: removes all registered CIDs, clears the UDP session,
    ///   and falls back to TCP transport
    /// - On replay/old/crypto errors: logs and returns None
    /// - Tracks RX key phase transitions for metrics
    fn open_udp_packet(&mut self, payload: &[u8], out: &mut Vec<u8>) -> Option<()> {
        out.clear();
        let session = self.udp_session.as_mut()?;
        let rx_phase_before = session.rx_key_phase();

        match session.open_packet(payload) {
            Ok(opened) => {
                out.extend_from_slice(opened.payload);
            }
            Err(QspSessionError::Replay) => {
                self.metrics.inc_udp_qsp_decrypt_fail_replay();
                trace!(
                    session_id = self.session_id,
                    client_id = %self.client_id,
                    reason = "replay",
                    "UDP packet dropped: decrypt failure"
                );
                return None;
            }
            Err(QspSessionError::TooOld) => {
                self.metrics.inc_udp_qsp_decrypt_fail_too_old();
                trace!(
                    session_id = self.session_id,
                    client_id = %self.client_id,
                    reason = "too_old",
                    "UDP packet dropped: decrypt failure"
                );
                return None;
            }
            Err(QspSessionError::DeadChannel) => {
                self.metrics.inc_udp_qsp_dead_channel();
                warn!(
                    session_id = self.session_id,
                    client_id = %self.client_id,
                    "UDP-QSP channel marked dead; falling back to tcp"
                );
                self.registry.remove_cids_for_session(self.session_id);
                self.udp_session = None;
                self.reset_udp_upgrade_state();
                self.set_active_transport(ActiveTransport::Tcp);
                return None;
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
                return None;
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
                return None;
            }
        }

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

        Some(())
    }

    /// Decodes a VPN message from the decrypted UDP payload.
    ///
    /// Parses the message and validates that no trailing data remains
    /// (which would indicate malformed or padded input).
    ///
    /// # Parameters
    ///
    /// * `payload` - The decrypted plaintext payload from UDP-QSP
    ///
    /// # Returns
    ///
    /// * `Ok(Some(message))` - A valid message was decoded
    /// * `Ok(None)` - The payload was empty or incomplete
    /// * `Err(io::Error)` - The message was malformed or had trailing data
    fn decode_udp_message<'a>(&self, payload: &'a [u8]) -> io::Result<Option<Message<'a>>> {
        let decoded = decode_message(payload, self.limits).map_err(map_message_error)?;
        let Some((message, consumed)) = decoded else {
            return Ok(None);
        };
        if consumed != payload.len() {
            return Ok(None);
        }
        Ok(Some(message))
    }

    /// Dispatches a decoded UDP message to its appropriate handler.
    ///
    /// Routes the message based on type:
    /// - Ping: Responds with Pong
    /// - Pong: Logs and continues
    /// - Data: Forwards to TUN device if valid
    /// - `UpgradeProbe`: Sends UDP probe ack and may trigger TCP switch commit
    /// - Close: Initiates session shutdown
    /// - `RegisterCid`: Handles CID registration
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
    /// * `Err(io::Error)` if message handling fails
    async fn dispatch_udp_message(&mut self, message: Message<'_>) -> io::Result<SessionControl> {
        match message {
            Message::Ping { payload } => {
                let payload = Self::pong_payload_for_ping(payload)?;
                self.send_udp_message(Message::Pong { payload: &payload })
                    .await?;
                Ok(SessionControl::Continue)
            }
            Message::Pong { payload } => {
                let pong_in = PongPayload::decode(payload).map_err(map_payload_error)?;
                trace!(
                    session_id = self.session_id,
                    client_id = %self.client_id,
                    nonce = pong_in.nonce,
                    "received udp pong"
                );
                Ok(SessionControl::Continue)
            }
            Message::Data { packet } => {
                if self.active_transport != ActiveTransport::UdpQsp {
                    trace!(
                        session_id = self.session_id,
                        client_id = %self.client_id,
                        "UDP data dropped: not active transport"
                    );
                    return Ok(SessionControl::Continue);
                }
                if self.should_forward_packet_to_tun(packet) {
                    self.tun.send(packet).await?;
                }
                Ok(SessionControl::Continue)
            }
            Message::UpgradeProbe { payload } => self.handle_upgrade_probe(payload).await,
            Message::Close { .. } => Ok(self.peer_close_control(false)),
            Message::RegisterCid { payload } => self.handle_register_cid(payload).await,
            Message::Auth { .. }
            | Message::AuthOk { .. }
            | Message::AuthFail { .. }
            | Message::RegisterOk { .. }
            | Message::RegisterFail { .. }
            | Message::UpgradeProbeAck { .. }
            | Message::UdpReady { .. }
            | Message::SwitchToUdp { .. }
            | Message::SwitchAck { .. } => Ok(SessionControl::Continue),
        }
    }
}
