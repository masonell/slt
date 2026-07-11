//! TCP message handling for client sessions.

use std::time::Instant;

use slt_core::proto::{
    ClosePayload, FallbackOkPayload, FallbackToTcpPayload, Message, PongPayload,
};
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::{info, trace};

use super::error::SessionError;
use super::types::SessionControl;
use super::{ActiveTransport, ClientSessionBase, UdpSessionIo};
use crate::tun::TunDeviceIo;

impl<T: TunDeviceIo, S: AsyncRead + AsyncWrite + Unpin + Send + 'static, I: UdpSessionIo>
    ClientSessionBase<T, S, I>
{
    /// Reads and processes all pending messages from the TCP transport.
    ///
    /// Drains the TCP message buffer, dispatching each complete message to
    /// `handle_tcp_message` for processing. Returns early if any message
    /// results in a session close request.
    ///
    /// # Returns
    ///
    /// * `Ok(SessionControl::Continue)` if all messages were processed successfully
    /// * `Ok(SessionControl::Close)` if any message requested session termination
    /// * `Err(SessionError)` if reading from the TCP buffer fails
    pub(super) async fn handle_tcp_read(&mut self) -> Result<SessionControl, SessionError> {
        loop {
            let Some(msg_buf) = self.tcp.try_pop_message(self.limits)? else {
                return Ok(SessionControl::Continue);
            };

            let received_at = Instant::now();
            let control = self.handle_tcp_message(msg_buf.message()).await?;
            self.note_activity(received_at);
            if control == SessionControl::Close {
                return Ok(SessionControl::Close);
            }
        }
    }

    /// Processes a single message received from the TCP transport.
    ///
    /// Dispatches the message based on its type, handling data forwarding to TUN,
    /// ping/pong responses, and control messages. Rejects unexpected messages
    /// for established sessions.
    ///
    /// # Parameters
    ///
    /// * `message` - The decoded message from the TCP stream
    ///
    /// # Returns
    ///
    /// * `Ok(SessionControl::Continue)` for most messages
    /// * `Ok(SessionControl::Close)` if the peer sent a close message
    /// * `Err(SessionError)` if message handling fails (e.g., unexpected message type)
    async fn handle_tcp_message(
        &mut self,
        message: Message<'_>,
    ) -> Result<SessionControl, SessionError> {
        match message {
            Message::Auth { .. }
            | Message::AuthOk { .. }
            | Message::AuthFail { .. }
            | Message::RegisterOk { .. }
            | Message::RegisterFail { .. }
            | Message::UpgradeProbe { .. }
            | Message::UpgradeProbeAck { .. }
            | Message::SwitchToUdp { .. }
            | Message::SwitchOk { .. } => Err(SessionError::ProtocolViolation),
            Message::UdpReady { payload } => self.handle_udp_ready(payload).await,
            Message::SwitchAck { payload } => self.handle_switch_ack(payload).await,
            Message::Data { packet } => {
                if self.should_forward_packet_to_tun(packet) {
                    let outcome = self.tun.accept_packet(packet).await?;
                    self.handle_tun_packet_send_outcome(outcome)?;
                }
                Ok(SessionControl::Continue)
            }
            Message::Ping { payload } => {
                let payload = Self::pong_payload_for_ping(payload)?;
                self.send_tcp_message(Message::Pong { payload: &payload })
                    .await?;
                Ok(SessionControl::Continue)
            }
            Message::Pong { payload } => {
                let pong = PongPayload::decode(payload)?;
                trace!(
                    session_id = self.session_id,
                    client_id = %self.client_id,
                    nonce = pong.nonce,
                    "received tcp pong"
                );
                Ok(SessionControl::Continue)
            }
            Message::Close { payload } => {
                let close = ClosePayload::decode(payload)?;
                info!(
                    session_id = self.session_id,
                    client_id = %self.client_id,
                    code = ?close.code,
                    "received tcp close"
                );
                Ok(self.peer_close_control(true))
            }
            Message::RegisterCid { payload } => {
                if self.active_transport == ActiveTransport::UdpQsp {
                    Err(SessionError::ProtocolViolation)
                } else {
                    self.handle_register_cid(payload).await
                }
            }
            Message::FallbackToTcp { payload } => self.handle_fallback_to_tcp(payload).await,
            Message::FallbackOk { payload } => self.handle_fallback_ok(payload),
        }
    }

    async fn handle_fallback_to_tcp(
        &mut self,
        payload: &[u8],
    ) -> Result<SessionControl, SessionError> {
        let request = FallbackToTcpPayload::decode(payload)?;
        let is_duplicate = self.last_peer_fallback_id == Some(request.fallback_id);
        if !is_duplicate {
            self.set_active_transport(ActiveTransport::Tcp);
            self.reset_udp_upgrade_state();
            self.last_peer_fallback_id = Some(request.fallback_id);
        }

        let ok = FallbackOkPayload {
            fallback_id: request.fallback_id,
        };
        let mut buf = Vec::with_capacity(8);
        ok.encode(&mut buf);
        self.send_tcp_message(Message::FallbackOk { payload: &buf })
            .await?;
        if is_duplicate {
            trace!(
                session_id = self.session_id,
                client_id = %self.client_id,
                fallback_id = request.fallback_id,
                "acknowledged duplicate tcp fallback"
            );
        } else {
            info!(
                session_id = self.session_id,
                client_id = %self.client_id,
                fallback_id = request.fallback_id,
                "accepted tcp fallback"
            );
        }
        Ok(SessionControl::Continue)
    }

    fn handle_fallback_ok(&mut self, payload: &[u8]) -> Result<SessionControl, SessionError> {
        let ok = FallbackOkPayload::decode(payload)?;
        if self.pending_tcp_fallback == Some(ok.fallback_id) {
            self.pending_tcp_fallback = None;
            info!(
                session_id = self.session_id,
                client_id = %self.client_id,
                fallback_id = ok.fallback_id,
                "tcp fallback acknowledged"
            );
        } else {
            trace!(
                session_id = self.session_id,
                client_id = %self.client_id,
                fallback_id = ok.fallback_id,
                "ignoring stale tcp fallback acknowledgement"
            );
        }
        Ok(SessionControl::Continue)
    }
}
