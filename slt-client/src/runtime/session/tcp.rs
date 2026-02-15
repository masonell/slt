//! TCP message handling for `ClientSession`.

use std::io;

use slt_core::proto::{ClosePayload, Message, PingPayload, PongPayload};
use tracing::{debug, info, trace};

use super::{ClientSession, SessionControl, SessionExit};
use crate::runtime::session::state::ActiveTransport;
use crate::wire;

impl ClientSession<'_> {
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
    async fn handle_tcp_message(&mut self, message: Message<'_>) -> io::Result<SessionControl> {
        match message {
            Message::RegisterOk { payload } => self.handle_register_ok(payload),
            Message::RegisterFail { payload } => self.handle_register_fail(payload),
            Message::Data { packet } => {
                if self.active_transport != ActiveTransport::Tcp {
                    debug!("tcp data received while udp-qsp is active; switching to tcp");
                    self.metrics.inc_transport_udp_to_tcp_server();
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
                    self.metrics.inc_transport_udp_to_tcp_server();
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

#[cfg(test)]
mod tests {
    use std::io;

    use super::*;

    /// Test that ping payload decoding error is mapped correctly.
    #[test]
    fn ping_payload_decode_error_maps_to_invalid_data() {
        // Empty payload should fail decode
        let result = PingPayload::decode(&[]);
        assert!(result.is_err());

        // Verify the error maps to InvalidData
        let err = wire::map_payload_error(result.unwrap_err());
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    /// Test that pong payload decoding error is mapped correctly.
    #[test]
    fn pong_payload_decode_error_maps_to_invalid_data() {
        // Wrong length payload should fail decode
        let result = PongPayload::decode(&[0x01, 0x02, 0x03]); // 3 bytes instead of 8
        assert!(result.is_err());

        let err = wire::map_payload_error(result.unwrap_err());
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    /// Test that close payload decoding error is mapped correctly.
    #[test]
    fn close_payload_decode_error_maps_to_invalid_data() {
        // Invalid close code should fail decode
        let result = ClosePayload::decode(&[0xFF]); // Invalid code
        assert!(result.is_err());

        let err = wire::map_payload_error(result.unwrap_err());
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
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

    /// Test unexpected control message error properties.
    #[test]
    fn unexpected_control_message_error_kind() {
        let err = io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected control message on established session",
        );
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    mod classify_error {
        use std::io;

        use super::super::super::ClientSession;

        /// Test that InvalidData maps to ProtocolError.
        #[test]
        fn invalid_data_maps_to_protocol_error() {
            let err = io::Error::new(io::ErrorKind::InvalidData, "test");
            let exit = ClientSession::classify_error(&err);
            assert_eq!(exit, super::SessionExit::ProtocolError);
        }

        /// Test that InvalidInput maps to ProtocolError.
        #[test]
        fn invalid_input_maps_to_protocol_error() {
            let err = io::Error::new(io::ErrorKind::InvalidInput, "test");
            let exit = ClientSession::classify_error(&err);
            assert_eq!(exit, super::SessionExit::ProtocolError);
        }

        /// Test that PermissionDenied maps to PermissionDenied.
        #[test]
        fn permission_denied_maps_to_permission_denied() {
            let err = io::Error::new(io::ErrorKind::PermissionDenied, "test");
            let exit = ClientSession::classify_error(&err);
            assert_eq!(exit, super::SessionExit::PermissionDenied);
        }

        /// Test that ConnectionReset maps to ConnectionError.
        #[test]
        fn connection_reset_maps_to_connection_error() {
            let err = io::Error::new(io::ErrorKind::ConnectionReset, "test");
            let exit = ClientSession::classify_error(&err);
            assert_eq!(exit, super::SessionExit::ConnectionError);
        }

        /// Test that BrokenPipe maps to ConnectionError.
        #[test]
        fn broken_pipe_maps_to_connection_error() {
            let err = io::Error::new(io::ErrorKind::BrokenPipe, "test");
            let exit = ClientSession::classify_error(&err);
            assert_eq!(exit, super::SessionExit::ConnectionError);
        }

        /// Test that TimedOut maps to ConnectionError.
        #[test]
        fn timed_out_maps_to_connection_error() {
            let err = io::Error::new(io::ErrorKind::TimedOut, "test");
            let exit = ClientSession::classify_error(&err);
            assert_eq!(exit, super::SessionExit::ConnectionError);
        }

        /// Test that UnexpectedEof maps to ConnectionError.
        #[test]
        fn unexpected_eof_maps_to_connection_error() {
            let err = io::Error::new(io::ErrorKind::UnexpectedEof, "test");
            let exit = ClientSession::classify_error(&err);
            assert_eq!(exit, super::SessionExit::ConnectionError);
        }

        /// Test that Interrupted maps to ConnectionError.
        #[test]
        fn interrupted_maps_to_connection_error() {
            let err = io::Error::new(io::ErrorKind::Interrupted, "test");
            let exit = ClientSession::classify_error(&err);
            assert_eq!(exit, super::SessionExit::ConnectionError);
        }

        /// Test that other error kinds map to ConnectionError.
        #[test]
        fn other_errors_map_to_connection_error() {
            let other_kinds = [
                io::ErrorKind::NotFound,
                io::ErrorKind::AddrInUse,
                io::ErrorKind::AddrNotAvailable,
                io::ErrorKind::AlreadyExists,
                io::ErrorKind::WouldBlock,
                io::ErrorKind::WriteZero,
                io::ErrorKind::Other,
            ];

            for kind in other_kinds {
                let err = io::Error::new(kind, "test");
                let exit = ClientSession::classify_error(&err);
                assert_eq!(
                    exit,
                    super::SessionExit::ConnectionError,
                    "{kind:?} should map to ConnectionError"
                );
            }
        }
    }
}
