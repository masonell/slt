//! TCP message handling for `ClientSession`.

use std::io;

use slt_core::proto::{ClosePayload, Message, PingPayload, PongPayload};
use tracing::{debug, info, trace};

use super::{ClientSession, SessionControl, SessionExit};
use crate::runtime::session::state::ActiveTransport;
use crate::wire;

impl ClientSession<'_> {
    /// Process buffered TCP data and dispatch messages.
    pub(super) async fn handle_tcp_read(&mut self) -> io::Result<SessionControl> {
        loop {
            let Some(msg_buf) = self
                .tcp
                .try_pop_message(self.limits)
                .map_err(wire::map_message_error)?
            else {
                return Ok(SessionControl::Continue);
            };

            if let SessionControl::Close(exit) = self.handle_tcp_message(msg_buf.message()).await? {
                return Ok(SessionControl::Close(exit));
            }
        }
    }

    /// Handle a single TCP message.
    async fn handle_tcp_message(&mut self, message: Message<'_>) -> io::Result<SessionControl> {
        match message {
            Message::RegisterOk { payload } => self.handle_register_ok(payload),
            Message::RegisterFail { payload } => self.handle_register_fail(payload),
            Message::Data { packet } => {
                if self.active_transport != ActiveTransport::Tcp {
                    debug!("tcp data received while udp-qsp is active; switching to tcp");
                    self.metrics.inc_transport_udp_to_tcp();
                    self.active_transport = ActiveTransport::Tcp;
                }
                if self
                    .tun_channels
                    .to_tun_tx
                    .send(packet.to_vec())
                    .await
                    .is_err()
                {
                    self.metrics.inc_disconnect_close();
                    return Ok(SessionControl::Close(SessionExit::TunClosed));
                }
                Ok(SessionControl::Continue)
            }
            Message::Ping { payload } => {
                let ping_in = PingPayload::decode(payload).map_err(wire::map_payload_error)?;
                if self.active_transport != ActiveTransport::Tcp {
                    debug!("tcp ping received while udp-qsp is active; switching to tcp");
                    self.metrics.inc_transport_udp_to_tcp();
                    self.active_transport = ActiveTransport::Tcp;
                }
                let pong_out = PongPayload {
                    nonce: ping_in.nonce,
                };
                let mut pong_buf = Vec::with_capacity(8);
                pong_out.encode(&mut pong_buf);
                self.tcp
                    .write_message(Message::Pong { payload: &pong_buf })
                    .await?;
                Ok(SessionControl::Continue)
            }
            Message::Pong { payload } => {
                let pong_in = PongPayload::decode(payload).map_err(wire::map_payload_error)?;
                trace!(nonce = pong_in.nonce, "received pong");
                Ok(SessionControl::Continue)
            }
            Message::Close { payload } => {
                let close = ClosePayload::decode(payload).map_err(wire::map_payload_error)?;
                info!(code = ?close.code, "received close");
                self.metrics.inc_disconnect_close();
                Ok(SessionControl::Close(SessionExit::RemoteClose(close.code)))
            }
            Message::RegisterCid { .. }
            | Message::Auth { .. }
            | Message::AuthOk { .. }
            | Message::AuthFail { .. } => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unexpected control message on established session",
            )),
        }
    }
}
