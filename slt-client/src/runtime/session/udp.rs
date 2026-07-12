//! UDP-QSP message handling for `ClientSession`.

use std::io;
use std::sync::Arc;
use std::time::Instant;

use slt_core::proto::{
    ClosePayload, Message, MessageContext, MessageSender, MessageTransport, MessageType,
    OwnedMessageBuf, PingPayload, PongPayload, ProtocolPhase, validate_message,
};
use tokio::time;
use tracing::{info, trace, warn};

use super::error::SessionError;
use super::{ClientSession, ClientTcpIo, SessionControl, SessionExit};
use crate::runtime::observer::{ClientEventKind, TransportChangeReason};
use crate::runtime::services::ClientRuntimeServices;
use crate::runtime::session::state::{ActiveTransport, UdpState};
use crate::transport::quic_discovery;
use crate::transport::udp_qsp::client_udp_qsp_io;

impl<S: ClientRuntimeServices, T: ClientTcpIo> ClientSession<'_, S, T> {
    /// Handles a host-reported network change.
    ///
    /// If UDP-QSP is the preferred data path, first tries to validate the existing
    /// UDP socket by sending an authenticated ping and waiting for the matching
    /// pong. A successful round trip proves the server accepted the client's
    /// current source address and updated its peer. UDP path failures recreate
    /// the socket or fall back to TCP; authenticated protocol failures propagate
    /// and terminate the session.
    pub(super) async fn handle_network_changed(&mut self) -> Result<SessionControl, SessionError> {
        info!("underlying network changed");

        if self.active_transport != ActiveTransport::UdpQsp || self.udp_state.as_active().is_none()
        {
            info!("no active udp-qsp path to refresh; reconnecting");
            self.emit_network_changed_reconnect();
            return Ok(SessionControl::Close(SessionExit::NetworkChanged));
        }

        self.services
            .observer()
            .emit(ClientEventKind::UdpPathRefreshStarted);
        match self.refresh_udp_path_with_replacement_fallback().await {
            Ok(SessionControl::Continue) => Ok(self.note_udp_path_refresh_succeeded()),
            Ok(SessionControl::Close(exit)) => Ok(SessionControl::Close(exit)),
            Err(err) => {
                let detail = err.to_string();
                warn!(error = %err, "udp-qsp path refresh failed");
                self.services
                    .observer()
                    .emit(ClientEventKind::UdpPathRefreshFailed { detail });
                if !err.is_udp_path_transport_error() {
                    return Err(err);
                }
                if !self.tcp_alive {
                    self.emit_network_changed_reconnect();
                    return Ok(SessionControl::Close(SessionExit::NetworkChanged));
                }

                self.request_tcp_fallback(TransportChangeReason::UdpError)
                    .await?;
                self.schedule_discovery_now();
                Ok(SessionControl::Continue)
            }
        }
    }

    async fn refresh_udp_path_with_replacement_fallback(
        &mut self,
    ) -> Result<SessionControl, SessionError> {
        match self.refresh_udp_path().await {
            Ok(control) => return Ok(control),
            Err(err) if err.is_udp_path_transport_error() => {
                warn!(error = %err, "udp-qsp path refresh failed on existing socket");
            }
            Err(err) => return Err(err),
        }

        info!("recreating udp-qsp socket after path refresh failure");
        self.recreate_udp_io().await?;
        self.refresh_udp_path().await
    }

    async fn recreate_udp_io(&mut self) -> Result<(), SessionError> {
        let peer = self
            .udp_state
            .as_active()
            .ok_or_else(|| SessionError::ProtocolViolation {
                detail: "udp-qsp transport missing".into(),
            })?
            .peer();
        let socket = Arc::new(quic_discovery::bind_protected_udp_socket(
            peer,
            self.services.socket_protector(),
        )?);
        let new_io = client_udp_qsp_io(&socket, peer)?;
        let udp =
            self.udp_state
                .as_active_mut()
                .ok_or_else(|| SessionError::ProtocolViolation {
                    detail: "udp-qsp transport missing".into(),
                })?;
        let _old_io = udp.replace_io(new_io).await;
        Ok(())
    }

    fn note_udp_path_refresh_succeeded(&self) -> SessionControl {
        self.services
            .observer()
            .emit(ClientEventKind::UdpPathRefreshSucceeded);
        info!("udp-qsp path refresh succeeded");
        SessionControl::Continue
    }

    fn emit_network_changed_reconnect(&self) {
        self.services
            .observer()
            .emit(ClientEventKind::NetworkChanged {
                detail: "underlying network changed".to_string(),
            });
    }

    /// Handles a UDP-QSP message.
    ///
    /// Dispatches the message to the appropriate handler based on its type.
    /// Data, ping/pong, and close frames are handled. Registration responses
    /// are unexpected on UDP and result in an error.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Payload decoding fails
    /// - An unexpected message is received (e.g., `REGISTER_OK` on UDP transport)
    /// - TUN channel send fails
    pub(super) async fn handle_udp_message(
        &mut self,
        msg_buf: OwnedMessageBuf,
    ) -> Result<SessionControl, SessionError> {
        validate_message(
            msg_buf.message(),
            MessageContext::new(
                MessageSender::Server,
                ProtocolPhase::Established,
                MessageTransport::UdpQsp,
            ),
        )?;

        let message_type = msg_buf.message().ty();
        if message_type == MessageType::Data {
            return Ok(self.send_to_tun_or_shutdown(msg_buf).await);
        }

        match msg_buf.message() {
            Message::Ping { payload } => {
                let ping_in = PingPayload::decode(payload)?;
                let pong_payload = ping_in.nonce.to_be_bytes();
                self.write_udp_message_and_flush(Message::Pong {
                    payload: &pong_payload,
                })
                .await?;
                trace!(nonce = ping_in.nonce, "responded to udp ping");
                Ok(SessionControl::Continue)
            }
            Message::Pong { payload } => {
                let pong_in = PongPayload::decode(payload)?;
                trace!(nonce = pong_in.nonce, "received udp pong");
                Ok(SessionControl::Continue)
            }
            Message::Data { .. } => unreachable!("data handled by fast-path above"),
            Message::Close { payload } => {
                let close = ClosePayload::decode(payload)?;
                info!(code = ?close.code, "received udp close");
                self.metrics.inc_disconnect_close();
                Ok(SessionControl::Close(SessionExit::RemoteClose(close.code)))
            }
            Message::UpgradeProbeAck { payload } => self.handle_upgrade_probe_ack(payload).await,
            Message::Auth { .. }
            | Message::AuthOk { .. }
            | Message::AuthFail { .. }
            | Message::RegisterCid { .. }
            | Message::RegisterOk { .. }
            | Message::RegisterFail { .. }
            | Message::UpgradeProbe { .. }
            | Message::UdpReady { .. }
            | Message::SwitchToUdp { .. }
            | Message::SwitchAck { .. }
            | Message::SwitchOk { .. }
            | Message::FallbackToTcp { .. }
            | Message::FallbackOk { .. } => {
                unreachable!("shared validation rejected inadmissible udp-qsp session message")
            }
        }
    }

    async fn refresh_udp_path(&mut self) -> Result<SessionControl, SessionError> {
        let nonce = fastrand::u64(..);
        let ping = PingPayload { nonce };
        let mut ping_buf = Vec::with_capacity(8);
        ping.encode(&mut ping_buf);
        self.write_udp_message_and_flush(Message::Ping { payload: &ping_buf })
            .await?;

        let deadline = Instant::now() + self.config.timing.register_timeout;
        loop {
            let cancel = self.cancel.clone();
            let udp =
                self.udp_state
                    .as_active_mut()
                    .ok_or_else(|| SessionError::ProtocolViolation {
                        detail: "udp-qsp transport missing".into(),
                    })?;
            let msg_buf = tokio::select! {
                biased;

                () = cancel.cancelled() => return Ok(SessionControl::Close(SessionExit::Shutdown)),
                result = time::timeout_at(deadline.into(), udp.read_next_message(self.limits)) => match result {
                    Ok(Ok(msg_buf)) => msg_buf,
                    // Typed UDP-QSP transport error: drop recoverable
                    // packet-level failures (replay, too-old, single crypto
                    // failure); propagate path failures and authenticated
                    // protocol violations.
                    Ok(Err(err)) => {
                        let err = SessionError::from(err);
                        if err.is_udp_qsp_recoverable() {
                            trace!(error = %err, "dropping udp-qsp packet during path refresh");
                            continue;
                        }
                        return Err(err);
                    }
                    Err(_) => {
                        return Err(SessionError::Io(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "udp-qsp path refresh timed out",
                        )));
                    }
                }
            };
            let received_at = Instant::now();

            match is_matching_pong(&msg_buf, nonce) {
                Ok(true) => {
                    self.note_authenticated_udp_activity(received_at);
                    return Ok(SessionControl::Continue);
                }
                Ok(false) => {}
                Err(err) if err.is_udp_qsp_recoverable() => {
                    trace!(error = %err, "dropping udp-qsp pong during path refresh");
                    continue;
                }
                Err(err) => return Err(err),
            }

            let control = match self.handle_udp_message(msg_buf).await {
                Ok(control) => control,
                Err(err) if err.is_udp_qsp_recoverable() => {
                    trace!(error = %err, "dropping udp-qsp message during path refresh");
                    continue;
                }
                Err(err) => return Err(err),
            };
            self.note_authenticated_udp_activity(received_at);
            if !matches!(control, SessionControl::Continue) {
                return Ok(control);
            }
        }
    }

    /// Handle a UDP-QSP transport failure from the session event loop.
    pub(super) async fn handle_udp_event_error(
        &mut self,
        err: &SessionError,
    ) -> Result<SessionControl, SessionError> {
        if !self.handle_udp_error(err).await? {
            self.metrics.inc_disconnect_error();
            return Ok(SessionControl::Close(SessionExit::ConnectionError));
        }
        Ok(SessionControl::Continue)
    }

    /// Handle a UDP-QSP transport failure from a session operation.
    ///
    /// Takes the typed [`SessionError`] (which wraps a `UdpQspError` on this
    /// path) and applies the recoverable-vs-fatal policy. Recoverable failures
    /// drop and continue. A fatal failure on a retained receive path retires
    /// only that path so discovery or an in-flight replacement registration is
    /// preserved. Other fatal failures fall back to TCP or close the session.
    /// Returns `true` if the session can continue, or `false` if both preferred
    /// transports are dead and the session should close.
    pub(super) async fn handle_udp_error(
        &mut self,
        err: &SessionError,
    ) -> Result<bool, SessionError> {
        // Recoverable UDP-QSP transport failure (replay, too-old, single crypto
        // failure, transient socket I/O): drop & continue.
        if err.is_udp_qsp_recoverable() {
            trace!(error = %err, "dropping udp-qsp packets");
            return Ok(true);
        }

        if matches!(
            &self.udp_state,
            UdpState::NeedDiscovery { .. } | UdpState::Pending { .. }
        ) && self.retained_udp_transport.is_some()
        {
            self.retained_udp_transport = None;
            self.last_authenticated_udp_activity = None;
            warn!(
                error = %err,
                "retained udp receive path failed; preserving replacement attempt"
            );
            return Ok(true);
        }

        if !self.tcp_alive {
            warn!(
                error = %err,
                "udp-qsp io error and tcp dead; closing session"
            );
            return Ok(false);
        }

        warn!(
            error = %err,
            "udp-qsp io error; falling back to tcp and scheduling retry"
        );
        self.request_tcp_fallback(TransportChangeReason::UdpError)
            .await?;

        self.schedule_discovery_retry_after_udp_failure();
        Ok(true)
    }
}

fn is_matching_pong(msg_buf: &OwnedMessageBuf, nonce: u64) -> Result<bool, SessionError> {
    let Message::Pong { payload } = msg_buf.message() else {
        return Ok(false);
    };
    let pong = PongPayload::decode(payload)?;
    Ok(pong.nonce == nonce)
}

#[cfg(test)]
mod tests {
    use slt_core::crypto::udp_qsp::QspSessionError;
    use slt_core::proto::{OwnedMessageBuf, encode_message};

    use super::*;
    use crate::transport::udp_qsp::UdpQspError;

    fn pong_message(nonce: u64) -> OwnedMessageBuf {
        let payload = nonce.to_be_bytes();
        let mut frame = Vec::new();
        encode_message(Message::Pong { payload: &payload }, &mut frame).unwrap();
        OwnedMessageBuf::new(MessageType::Pong, frame)
    }

    fn ping_message(nonce: u64) -> OwnedMessageBuf {
        let payload = nonce.to_be_bytes();
        let mut frame = Vec::new();
        encode_message(Message::Ping { payload: &payload }, &mut frame).unwrap();
        OwnedMessageBuf::new(MessageType::Ping, frame)
    }

    #[test]
    fn matching_pong_is_accepted_for_refresh_nonce() {
        let msg = pong_message(0x1234);
        assert!(is_matching_pong(&msg, 0x1234).unwrap());
    }

    #[test]
    fn nonmatching_pong_is_not_accepted_for_refresh_nonce() {
        let msg = pong_message(0x1234);
        assert!(!is_matching_pong(&msg, 0x5678).unwrap());
    }

    #[test]
    fn non_pong_message_is_not_accepted_for_refresh_nonce() {
        let msg = ping_message(0x1234);
        assert!(!is_matching_pong(&msg, 0x1234).unwrap());
    }

    #[test]
    fn malformed_pong_fails_refresh_probe() {
        let mut frame = Vec::new();
        encode_message(Message::Pong { payload: &[] }, &mut frame).unwrap();
        let msg = OwnedMessageBuf::new(MessageType::Pong, frame);
        let err = is_matching_pong(&msg, 0x1234).unwrap_err();
        // A malformed pong surfaces as a preserved `PayloadError` (typed), not
        // a recoverable UDP-QSP transport failure. The proto decode source
        // survives and propagates out of the refresh probe.
        assert!(matches!(err, SessionError::Payload(_)));
        assert!(!err.is_udp_qsp_recoverable());
    }

    /// Recoverable UDP-QSP transport failures are droppable during the refresh
    /// probe.
    #[test]
    fn refresh_drops_recoverable_udp_qsp_errors() {
        for qsp in [
            QspSessionError::Replay,
            QspSessionError::TooOld,
            QspSessionError::Io(io::Error::from(io::ErrorKind::TimedOut)),
        ] {
            let label = format!("{qsp:?}");
            let err = SessionError::from(UdpQspError::from(qsp));
            assert!(err.is_udp_qsp_recoverable(), "{label} must be recoverable");
        }
    }

    /// Non-recoverable UDP-QSP transport failures (dead-channel, packet-number
    /// overflow) and non-UDP session errors are never droppable as transient
    /// packet errors: they propagate out of the refresh probe.
    #[test]
    fn refresh_does_not_drop_fatal_or_typed_session_errors() {
        // Packet-number overflow is fatal (propagates): the TX pn space is
        // exhausted; the refresh probe cannot succeed on this session.
        let overflow = SessionError::from(UdpQspError::from(QspSessionError::PacketNumberOverflow));
        assert!(!overflow.is_udp_qsp_recoverable());

        // Plain socket io::Error wrapped as SessionError::Io (not via UdpQsp):
        // the typed UDP-QSP recoverable classification does not apply — it
        // propagates. (The UDP transport returns UdpQspError::Io for its
        // socket I/O, which IS recoverable; a bare SessionError::Io comes from
        // other session-path I/O and is not a UDP-QSP transport condition.)
        for kind in [
            io::ErrorKind::TimedOut,
            io::ErrorKind::ConnectionReset,
            io::ErrorKind::ConnectionAborted,
            io::ErrorKind::BrokenPipe,
        ] {
            let err = SessionError::from(io::Error::new(kind, "transport failure"));
            assert!(!err.is_udp_qsp_recoverable());
        }

        // Typed (non-I/O) session errors propagate.
        let proto = SessionError::Payload(slt_core::proto::PayloadError::InvalidCipher(0x99));
        assert!(!proto.is_udp_qsp_recoverable());
        let violation = SessionError::ProtocolViolation { detail: "x".into() };
        assert!(!violation.is_udp_qsp_recoverable());
    }

    /// Shared UDP-QSP admissibility failures become typed protocol violations
    /// with the rejected message type preserved in terminal diagnostics.
    #[test]
    fn udp_unexpected_message_is_typed_protocol_violation() {
        use crate::runtime::session::SessionExit;

        let validation = validate_message(
            Message::RegisterOk { payload: &[] },
            MessageContext::new(
                MessageSender::Server,
                ProtocolPhase::Established,
                MessageTransport::UdpQsp,
            ),
        )
        .unwrap_err();
        let err = SessionError::from(validation);
        assert_eq!(err.exit(), SessionExit::ProtocolError);
        let rendered = format!("{err:#}");
        assert!(
            rendered.contains("session protocol violation"),
            "missing stage framing: {rendered:?}"
        );
        assert!(rendered.contains("RegisterOk"), "{rendered:?}");
        assert!(rendered.contains("UdpQsp"), "{rendered:?}");
    }

    /// The "udp-qsp transport missing" sites report
    /// `SessionError::ProtocolViolation` (a client-state inconsistency:
    /// `as_active_mut()` that should be `Some`) rather than the generic
    /// `Io(BrokenPipe)`. Both reconnect; `ProtocolViolation` is more faithful
    /// to the actual cause (a client-state bug, not a socket condition). Pin
    /// that shape.
    #[test]
    fn udp_transport_missing_is_protocol_violation() {
        use crate::runtime::session::SessionExit;

        let err = SessionError::ProtocolViolation {
            detail: "udp-qsp transport missing".into(),
        };
        assert_eq!(err.exit(), SessionExit::ProtocolError);
        let rendered = format!("{err:#}");
        assert!(rendered.contains("transport missing"), "{rendered:?}");
    }
}
