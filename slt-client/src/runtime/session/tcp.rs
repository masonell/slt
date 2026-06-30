//! TCP message handling for `ClientSession`.

use slt_core::proto::{
    ClosePayload, Message, MessageType, OwnedMessageBuf, PingPayload, PongPayload,
};
use tracing::{debug, info, trace};

use super::error::SessionError;
use super::{ClientSession, SessionControl, SessionExit};
use crate::metrics::Metrics;
use crate::runtime::observer::{Transport, TransportChangeReason};
use crate::runtime::services::ClientRuntimeServices;
use crate::runtime::session::state::ActiveTransport;

fn switch_to_tcp_on_server_traffic(
    active_transport: &mut ActiveTransport,
    metrics: &Metrics,
    signal: &'static str,
) -> bool {
    if *active_transport != ActiveTransport::UdpQsp {
        return false;
    }

    debug!(
        signal,
        "received tcp traffic while udp-qsp is active; switching to tcp"
    );
    metrics.inc_transport_udp_to_tcp_server();
    *active_transport = ActiveTransport::Tcp;
    true
}

impl<S: ClientRuntimeServices> ClientSession<'_, S> {
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

            if let SessionControl::Close(exit) = self.handle_tcp_message(msg_buf).await? {
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
        if msg_buf.message().ty() == MessageType::Data {
            if switch_to_tcp_on_server_traffic(
                &mut self.active_transport,
                self.metrics.as_ref(),
                "data",
            ) {
                self.note_transport_change(
                    Transport::UdpQsp,
                    Transport::Tcp,
                    TransportChangeReason::ServerInitiated,
                );
                self.note_tcp_activity();
                self.schedule_discovery_retry();
            }
            if self.tun_channels.to_tun_tx.send(msg_buf).await.is_err() {
                self.metrics.inc_disconnect_close();
                return Ok(SessionControl::Close(SessionExit::TunClosed));
            }
            return Ok(SessionControl::Continue);
        }

        match msg_buf.message() {
            Message::RegisterOk { payload } => self.handle_register_ok(payload),
            Message::RegisterFail { payload } => self.handle_register_fail(payload),
            Message::Data { .. } => unreachable!("data handled by fast-path above"),
            Message::Ping { payload } => {
                let ping_in = PingPayload::decode(payload)?;
                if switch_to_tcp_on_server_traffic(
                    &mut self.active_transport,
                    self.metrics.as_ref(),
                    "ping",
                ) {
                    self.note_transport_change(
                        Transport::UdpQsp,
                        Transport::Tcp,
                        TransportChangeReason::ServerInitiated,
                    );
                    self.note_tcp_activity();
                    self.schedule_discovery_retry();
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
                let pong_in = PongPayload::decode(payload)?;
                if self.maybe_commit_udp_upgrade_on_barrier_pong(pong_in.nonce) {
                    return Ok(SessionControl::Continue);
                }
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
            Message::RegisterCid { .. }
            | Message::Auth { .. }
            | Message::AuthOk { .. }
            | Message::AuthFail { .. }
            | Message::UpgradeProbe { .. }
            | Message::UpgradeProbeAck { .. }
            | Message::UdpReady { .. }
            | Message::SwitchAck { .. } => Err(SessionError::ProtocolViolation {
                detail: "unexpected control message on established session".into(),
            }),
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

    mod server_initiated_fallback {
        use super::*;

        #[test]
        fn tcp_server_traffic_switches_udp_to_tcp_once() {
            let metrics = Metrics::default();
            let mut active_transport = ActiveTransport::UdpQsp;

            assert!(switch_to_tcp_on_server_traffic(
                &mut active_transport,
                &metrics,
                "data"
            ));
            assert!(!switch_to_tcp_on_server_traffic(
                &mut active_transport,
                &metrics,
                "data"
            ));

            assert_eq!(active_transport, ActiveTransport::Tcp);
            let snapshot = metrics.snapshot();
            assert_eq!(snapshot.transport_udp_to_tcp_server, 1);
            assert_eq!(snapshot.transport_udp_to_tcp, 0);
        }

        #[test]
        fn tcp_server_traffic_does_not_increment_when_already_on_tcp() {
            let metrics = Metrics::default();
            let mut active_transport = ActiveTransport::Tcp;

            assert!(!switch_to_tcp_on_server_traffic(
                &mut active_transport,
                &metrics,
                "ping"
            ));

            assert_eq!(active_transport, ActiveTransport::Tcp);
            let snapshot = metrics.snapshot();
            assert_eq!(snapshot.transport_udp_to_tcp_server, 0);
        }
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
