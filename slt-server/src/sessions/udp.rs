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
    pub(super) async fn handle_udp_claim(&mut self, claim: UdpClaim) -> io::Result<SessionControl> {
        let peer = claim.peer;

        trace!(
            session_id = self.session_id,
            client_id = %self.client_id,
            peer = %peer,
            dcid_prefix = ?claim.dcid_prefix,
            "UDP claim received"
        );

        let Some(opened) = self.open_udp_packet(&claim.payload) else {
            return Ok(SessionControl::Continue);
        };

        self.update_udp_peer(peer);

        let Some(message) = self.decode_udp_message(&opened)? else {
            return Ok(SessionControl::Continue);
        };

        self.maybe_activate_udp(&message);

        self.dispatch_udp_message(message).await
    }

    /// Decrypt and validate a UDP-QSP packet.
    ///
    /// Returns `Some(payload)` on success, or `None` if the packet should be dropped.
    /// Handles dead channel fallback internally.
    fn open_udp_packet(&mut self, payload: &[u8]) -> Option<Vec<u8>> {
        let session = self.udp_session.as_mut()?;
        let rx_phase_before = session.rx_key_phase();

        let payload_vec = match session.open_packet(payload) {
            Ok(opened) => opened.payload.to_vec(),
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

        Some(payload_vec)
    }

    /// Decode a message from the decrypted UDP payload.
    ///
    /// Returns `Some(message)` on success, or `None` if the message
    /// is malformed or has trailing data.
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

    /// Activate UDP transport if the message warrants it.
    fn maybe_activate_udp(&mut self, message: &Message<'_>) {
        let should_activate = matches!(
            message,
            Message::Ping { .. }
                | Message::Pong { .. }
                | Message::Data { .. }
                | Message::Close { .. }
                | Message::RegisterCid { .. }
        );
        if should_activate {
            self.set_active_transport(ActiveTransport::UdpQsp);
        }
    }

    /// Dispatch a decrypted UDP message to the appropriate handler.
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
                if self.should_forward_packet_to_tun(packet) {
                    self.tun.send(packet).await?;
                }
                Ok(SessionControl::Continue)
            }
            Message::Close { .. } => Ok(self.peer_close_control(false)),
            Message::RegisterCid { payload } => self.handle_register_cid(payload).await,
            Message::Auth { .. }
            | Message::AuthOk { .. }
            | Message::AuthFail { .. }
            | Message::RegisterOk { .. }
            | Message::RegisterFail { .. } => Ok(SessionControl::Continue),
        }
    }
}
