//! TCP message handling for client sessions.

use std::io;

use slt_core::proto::Message;
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::trace;

use super::types::SessionControl;
use super::{ActiveTransport, ClientSessionBase, UdpSocketIo, map_message_error};
use crate::tun::TunDeviceIo;

impl<T: TunDeviceIo, S: AsyncRead + AsyncWrite + Unpin + Send + 'static, U: UdpSocketIo>
    ClientSessionBase<T, S, U>
{
    pub(super) async fn handle_tcp_read(&mut self) -> io::Result<SessionControl> {
        loop {
            let Some(msg_buf) = self
                .tcp
                .try_pop_message(self.limits)
                .map_err(map_message_error)?
            else {
                return Ok(SessionControl::Continue);
            };

            if self.handle_tcp_message(msg_buf.message()).await? == SessionControl::Close {
                return Ok(SessionControl::Close);
            }
        }
    }

    async fn handle_tcp_message(&mut self, message: Message<'_>) -> io::Result<SessionControl> {
        match message {
            Message::Auth { .. }
            | Message::AuthOk { .. }
            | Message::AuthFail { .. }
            | Message::RegisterOk { .. }
            | Message::RegisterFail { .. } => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unexpected control message on established session",
            )),
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
