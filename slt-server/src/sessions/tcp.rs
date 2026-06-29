//! TCP message handling for client sessions.

use slt_core::proto::Message;
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::trace;

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
            // MessageError flows via #[from], preserving the proto detail (was
            // map_message_error).
            let Some(msg_buf) = self.tcp.try_pop_message(self.limits)? else {
                return Ok(SessionControl::Continue);
            };

            if self.handle_tcp_message(msg_buf.message()).await? == SessionControl::Close {
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
            | Message::SwitchToUdp { .. } => Err(SessionError::ProtocolViolation),
            Message::UdpReady { payload } => self.handle_udp_ready(payload).await,
            Message::SwitchAck { payload } => self.handle_switch_ack(payload),
            Message::Data { packet } => {
                if self.active_transport != ActiveTransport::Tcp {
                    trace!(
                        session_id = self.session_id,
                        client_id = %self.client_id,
                        "TCP data dropped: not active transport"
                    );
                    return Ok(SessionControl::Continue);
                }
                if self.should_forward_packet_to_tun(packet) {
                    self.tun.send(packet).await?;
                }
                Ok(SessionControl::Continue)
            }
            Message::Ping { payload } => {
                let payload = Self::pong_payload_for_ping(payload)?;
                self.send_tcp_message(Message::Pong { payload: &payload })
                    .await?;
                Ok(SessionControl::Continue)
            }
            Message::Pong { .. } => Ok(SessionControl::Continue),
            Message::Close { .. } => Ok(self.peer_close_control(true)),
            Message::RegisterCid { payload } => self.handle_register_cid(payload).await,
        }
    }
}
