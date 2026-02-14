//! UDP-QSP message handling for `ClientSession`.

use std::io;

use slt_core::proto::{ClosePayload, Message, PingPayload, PongPayload};
use tracing::{info, trace, warn};

use super::{ClientSession, SessionControl, SessionExit};
use crate::runtime::session::state::ActiveTransport;
use crate::wire;

impl ClientSession<'_> {
    /// Handle a UDP-QSP message.
    pub(super) async fn handle_udp_message(
        &mut self,
        message: Message<'_>,
    ) -> io::Result<SessionControl> {
        match message {
            Message::RegisterOk { .. } => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unexpected register_ok on udp-qsp transport",
            )),
            Message::RegisterFail { .. } => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unexpected register_fail on udp-qsp transport",
            )),
            Message::Ping { payload } => {
                let ping_in = PingPayload::decode(payload).map_err(wire::map_payload_error)?;
                let pong_payload = ping_in.nonce.to_be_bytes();
                self.write_udp_message(Message::Pong {
                    payload: &pong_payload,
                })
                .await?;
                trace!(nonce = ping_in.nonce, "responded to udp ping");
                Ok(SessionControl::Continue)
            }
            Message::Pong { payload } => {
                let pong_in = PongPayload::decode(payload).map_err(wire::map_payload_error)?;
                trace!(nonce = pong_in.nonce, "received udp pong");
                Ok(SessionControl::Continue)
            }
            Message::Data { packet } => {
                if self.active_transport != ActiveTransport::UdpQsp {
                    self.metrics.inc_transport_tcp_to_udp();
                    self.active_transport = ActiveTransport::UdpQsp;
                    info!("udp-qsp data received; switching to udp");
                }
                if self
                    .tun_channels
                    .to_tun_tx
                    .send(packet.to_vec())
                    .await
                    .is_err()
                {
                    return Ok(SessionControl::Close(SessionExit::TunClosed));
                }
                Ok(SessionControl::Continue)
            }
            Message::Close { payload } => {
                let close = ClosePayload::decode(payload).map_err(wire::map_payload_error)?;
                info!(code = ?close.code, "received udp close");
                Ok(SessionControl::Close(SessionExit::RemoteClose(close.code)))
            }
            Message::RegisterCid { .. }
            | Message::Auth { .. }
            | Message::AuthOk { .. }
            | Message::AuthFail { .. } => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unexpected control message on udp-qsp transport",
            )),
        }
    }

    /// Handle UDP-QSP transport errors.
    pub(super) fn handle_udp_error(&mut self, err: &io::Error) {
        // Transient errors (replay, too_old, crypto) can be retried
        // InvalidData is typically packet-level issues that should be dropped, not fatal
        if err.kind() == io::ErrorKind::InvalidData {
            trace!(error = %err, "dropping udp-qsp packets");
            return;
        }

        let was_udp_active = self.active_transport == ActiveTransport::UdpQsp;
        warn!(
            kind = ?err.kind(),
            error = %err,
            "udp-qsp io error; falling back to tcp and scheduling retry"
        );
        if was_udp_active {
            self.metrics.inc_transport_udp_to_tcp();
        }
        self.active_transport = ActiveTransport::Tcp;
        self.note_tcp_activity();

        // Transition to NeedDiscovery state to re-discover quic_ids
        self.schedule_discovery_retry();
    }
}
