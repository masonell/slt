//! TCP message handling for `ClientSession`.

use std::io;
use std::time::Instant;

use slt_core::proto::{
    ClosePayload, FallbackOkPayload, FallbackToTcpPayload, Message, MessageContext, MessageSender,
    MessageTransport, MessageType, OwnedMessageBuf, PingPayload, PongPayload, ProtocolPhase,
    validate_message,
};
use tracing::{debug, info, trace};

use super::error::SessionError;
use super::{ClientSession, ClientTcpIo, SessionControl, SessionExit};
use crate::runtime::observer::{Transport, TransportChangeReason};
use crate::runtime::services::ClientRuntimeServices;
use crate::runtime::session::state::ActiveTransport;

impl<S: ClientRuntimeServices, T: ClientTcpIo> ClientSession<'_, S, T> {
    /// Drop UDP packets that have not reached the socket at a TCP fallback.
    ///
    /// Fallback is a hard egress cutover: queued UDP sends are not flushed or
    /// replayed on TCP. This discard leaves receive state untouched; the caller
    /// separately decides whether the old path remains receive-capable.
    fn discard_pending_udp_send_for_fallback(&mut self, initiator: &'static str) {
        let Some(udp) = self.udp_receive_transport_mut() else {
            return;
        };
        let discarded_packets = udp.discard_pending_send();
        if discarded_packets != 0 {
            debug!(
                discarded_packets,
                initiator, "discarded pending udp packets at tcp fallback"
            );
        }
    }

    /// Send an idempotent TCP fallback request before any DATA retried on TCP.
    pub(super) async fn request_tcp_fallback(
        &mut self,
        reason: TransportChangeReason,
    ) -> Result<(), SessionError> {
        if !self.tcp_alive {
            return Err(SessionError::Connection {
                source: io::Error::new(io::ErrorKind::NotConnected, "tcp fallback unavailable"),
            });
        }

        if self.pending_tcp_fallback.is_none() {
            let fallback_id = fastrand::u64(..);
            let payload = FallbackToTcpPayload { fallback_id };
            let mut buf = Vec::with_capacity(8);
            payload.encode(&mut buf);
            self.write_tcp_message(Message::FallbackToTcp { payload: &buf })
                .await?;
            self.pending_tcp_fallback = Some(fallback_id);
            debug!(fallback_id, "requested tcp fallback");
        }

        self.discard_pending_udp_send_for_fallback("client");
        if self.active_transport == ActiveTransport::UdpQsp {
            self.metrics.inc_transport_udp_to_tcp();
            self.active_transport = ActiveTransport::Tcp;
            self.note_transport_change(Transport::UdpQsp, Transport::Tcp, reason);
        }
        Ok(())
    }

    async fn handle_fallback_to_tcp(
        &mut self,
        payload: &[u8],
    ) -> Result<SessionControl, SessionError> {
        let request = FallbackToTcpPayload::decode(payload)?;
        let is_duplicate = self.last_peer_fallback_id == Some(request.fallback_id);
        if !is_duplicate {
            self.discard_pending_udp_send_for_fallback("server");
            if self.active_transport == ActiveTransport::UdpQsp {
                self.metrics.inc_transport_udp_to_tcp_server();
                self.active_transport = ActiveTransport::Tcp;
                self.note_transport_change(
                    Transport::UdpQsp,
                    Transport::Tcp,
                    TransportChangeReason::ServerInitiated,
                );
            }
            // The client owns CID discovery, so peer fallback resets the handshake
            // and starts make-before-break rediscovery while the old UDP transport
            // remains available for authenticated receive traffic.
            self.schedule_discovery_retry();
            self.last_peer_fallback_id = Some(request.fallback_id);
        }
        let ok = FallbackOkPayload {
            fallback_id: request.fallback_id,
        };
        let mut buf = Vec::with_capacity(8);
        ok.encode(&mut buf);
        self.write_tcp_message(Message::FallbackOk { payload: &buf })
            .await?;
        if is_duplicate {
            trace!(
                fallback_id = request.fallback_id,
                "acknowledged duplicate server tcp fallback"
            );
        } else {
            info!(
                fallback_id = request.fallback_id,
                "accepted server tcp fallback"
            );
        }
        Ok(SessionControl::Continue)
    }

    fn handle_fallback_ok(&mut self, payload: &[u8]) -> Result<SessionControl, SessionError> {
        let ok = FallbackOkPayload::decode(payload)?;
        if self.pending_tcp_fallback == Some(ok.fallback_id) {
            self.pending_tcp_fallback = None;
            info!(fallback_id = ok.fallback_id, "tcp fallback acknowledged");
        } else {
            trace!(
                fallback_id = ok.fallback_id,
                "ignoring stale tcp fallback acknowledgement"
            );
        }
        Ok(SessionControl::Continue)
    }

    /// Processes buffered TCP data and dispatches messages.
    ///
    /// Repeatedly pops messages from the TCP transport buffer and handles
    /// each one until the buffer is exhausted. Returns `Continue` if all
    /// messages were processed successfully, or `Close(exit)` if a message
    /// handler requests session termination.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Message parsing fails (invalid wire format)
    /// - Payload decoding fails (invalid payload data)
    pub(super) async fn handle_tcp_read(&mut self) -> Result<SessionControl, SessionError> {
        loop {
            let Some(msg_buf) = self.tcp.try_pop_message(self.limits)? else {
                return Ok(SessionControl::Continue);
            };

            let received_at = Instant::now();
            let control = self.handle_tcp_message(msg_buf).await?;
            self.note_activity(received_at);
            if let SessionControl::Close(exit) = control {
                return Ok(SessionControl::Close(exit));
            }
        }
    }

    /// Handles a single TCP message.
    ///
    /// Dispatches the message to the appropriate handler based on its type.
    /// Registration responses, data messages, ping/pong, and close frames
    /// are each handled specifically. Unexpected messages result in an error.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Payload decoding fails
    /// - An unexpected control message is received (e.g., AUTH on established session)
    /// - TUN channel send fails
    async fn handle_tcp_message(
        &mut self,
        msg_buf: OwnedMessageBuf,
    ) -> Result<SessionControl, SessionError> {
        validate_message(
            msg_buf.message(),
            MessageContext::new(
                MessageSender::Server,
                ProtocolPhase::Established,
                MessageTransport::Tcp,
            ),
        )?;

        if msg_buf.message().ty() == MessageType::Data {
            return Ok(self.send_to_tun_or_shutdown(msg_buf).await);
        }

        match msg_buf.message() {
            Message::RegisterOk { payload } => self.handle_register_ok(payload),
            Message::RegisterFail { payload } => self.handle_register_fail(payload),
            Message::Data { .. } => unreachable!("data handled by fast-path above"),
            Message::Ping { payload } => {
                let ping_in = PingPayload::decode(payload)?;
                let pong_out = PongPayload {
                    nonce: ping_in.nonce,
                };
                let mut pong_buf = Vec::with_capacity(8);
                pong_out.encode(&mut pong_buf);
                self.write_tcp_message(Message::Pong { payload: &pong_buf })
                    .await?;
                Ok(SessionControl::Continue)
            }
            Message::Pong { payload } => {
                let pong_in = PongPayload::decode(payload)?;
                trace!(nonce = pong_in.nonce, "received pong");
                Ok(SessionControl::Continue)
            }
            Message::Close { payload } => {
                let close = ClosePayload::decode(payload)?;
                info!(code = ?close.code, "received close");
                self.metrics.inc_disconnect_close();
                Ok(SessionControl::Close(SessionExit::RemoteClose(close.code)))
            }
            Message::SwitchToUdp { payload } => self.handle_switch_to_udp(payload).await,
            Message::SwitchOk { payload } => self.handle_switch_ok(payload),
            Message::FallbackToTcp { payload } => self.handle_fallback_to_tcp(payload).await,
            Message::FallbackOk { payload } => self.handle_fallback_ok(payload),
            Message::RegisterCid { .. }
            | Message::Auth { .. }
            | Message::AuthOk { .. }
            | Message::AuthFail { .. }
            | Message::UpgradeProbe { .. }
            | Message::UpgradeProbeAck { .. }
            | Message::UdpReady { .. }
            | Message::SwitchAck { .. } => {
                unreachable!("shared validation rejected inadmissible tcp session message")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io;

    use slt_core::proto::PayloadError;

    use super::*;
    use crate::runtime::session::SessionExit;

    /// A ping payload decode failure is preserved as a typed `SessionError`
    /// carrying the `PayloadError` — the proto error survives to the caller.
    #[test]
    fn ping_payload_decode_error_preserved_as_session_error() {
        let result = PingPayload::decode(&[]);
        assert!(result.is_err());

        let err = SessionError::from(result.unwrap_err());
        assert!(matches!(err, SessionError::Payload(_)));
        assert_eq!(err.exit(), SessionExit::ProtocolError);
    }

    /// A pong payload decode failure is preserved as a typed `SessionError`.
    #[test]
    fn pong_payload_decode_error_preserved_as_session_error() {
        let result = PongPayload::decode(&[0x01, 0x02, 0x03]); // 3 bytes instead of 8
        assert!(result.is_err());

        let err = SessionError::from(result.unwrap_err());
        assert!(matches!(
            err,
            SessionError::Payload(PayloadError::LengthMismatch { .. })
        ));
        assert_eq!(err.exit(), SessionExit::ProtocolError);
    }

    /// A close payload decode failure (invalid close code) is preserved.
    #[test]
    fn close_payload_decode_error_preserved_as_session_error() {
        let result = ClosePayload::decode(&[0xFF]); // Invalid code
        assert!(result.is_err());

        let err = SessionError::from(result.unwrap_err());
        assert!(matches!(err, SessionError::Payload(_)));
        assert_eq!(err.exit(), SessionExit::ProtocolError);
    }

    /// Test valid ping payload roundtrip.
    #[test]
    fn ping_payload_roundtrip() {
        let ping = PingPayload { nonce: 0x12345678 };
        let mut buf = Vec::new();
        ping.encode(&mut buf);

        let decoded = PingPayload::decode(&buf).unwrap();
        assert_eq!(decoded.nonce, ping.nonce);
    }

    /// Test valid pong payload roundtrip.
    #[test]
    fn pong_payload_roundtrip() {
        let pong = PongPayload { nonce: 0xDEADBEEF };
        let mut buf = Vec::new();
        pong.encode(&mut buf);

        let decoded = PongPayload::decode(&buf).unwrap();
        assert_eq!(decoded.nonce, pong.nonce);
    }

    /// Test valid close payload roundtrip.
    #[test]
    fn close_payload_roundtrip() {
        use slt_core::proto::CloseCode;

        let close = ClosePayload {
            code: CloseCode::Normal,
        };
        let mut buf = Vec::new();
        close.encode(&mut buf);

        let decoded = ClosePayload::decode(&buf).unwrap();
        assert_eq!(decoded.code, CloseCode::Normal);
    }

    /// An unexpected control message is reported as a typed protocol violation
    /// (client-detected), not an `io::Error` kind. It must project to the
    /// fatal `ProtocolError` exit.
    #[test]
    fn unexpected_control_message_is_typed_protocol_violation() {
        let err = SessionError::ProtocolViolation {
            detail: "unexpected control message on established session".into(),
        };
        assert_eq!(err.exit(), SessionExit::ProtocolError);
        let rendered = format!("{err:#}");
        assert!(rendered.contains("session protocol violation"));
        assert!(rendered.contains("unexpected control message"));
    }

    /// A TCP-path `SessionError::Io` wrapping an `io::Error` preserves the
    /// underlying error via the variant (the TCP path's `SessionError::Io`
    /// keeps the source intact for the terminal cause chain).
    #[test]
    fn io_error_source_is_preserved_through_session_error() {
        let err = SessionError::from(io::Error::from(io::ErrorKind::ConnectionAborted));
        match err {
            SessionError::Io(io_err) => {
                assert_eq!(io_err.kind(), io::ErrorKind::ConnectionAborted);
            }
            other => panic!("expected SessionError::Io, got {other:?}"),
        }

        // A typed (non-I/O) variant is distinct from the I/O variant.
        let proto = SessionError::ProtocolViolation { detail: "x".into() };
        assert!(!matches!(proto, SessionError::Io(_)));
    }
}
