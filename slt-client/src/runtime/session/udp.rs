//! UDP-QSP message handling for `ClientSession`.

use std::io;
use std::sync::Arc;
use std::time::Instant;

use slt_core::proto::{
    ClosePayload, Message, MessageType, OwnedMessageBuf, PingPayload, PongPayload,
};
use tokio::time;
use tracing::{info, trace, warn};

use super::error::SessionError;
use super::{ClientSession, SessionControl, SessionExit};
use crate::runtime::observer::{ClientEventKind, Transport, TransportChangeReason};
use crate::runtime::services::ClientRuntimeServices;
use crate::runtime::session::state::ActiveTransport;
use crate::transport::quic_discovery;
use crate::transport::udp_qsp::client_udp_qsp_io;

impl<S: ClientRuntimeServices> ClientSession<'_, S> {
    /// Handles a host-reported network change.
    ///
    /// If UDP-QSP is the active data path, first tries to validate the existing
    /// UDP socket by sending an authenticated ping and waiting for the matching
    /// pong. A successful round trip proves the server accepted the client's
    /// current source address and updated its peer. On refresh failure, a live
    /// TCP channel is used to rediscover QUIC IDs and register a fresh UDP path;
    /// if TCP is unavailable the session exits so the runtime reconnects TCP.
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
                if !self.tcp_alive {
                    self.emit_network_changed_reconnect();
                    return Ok(SessionControl::Close(SessionExit::NetworkChanged));
                }

                self.active_transport = ActiveTransport::Tcp;
                self.metrics.inc_transport_udp_to_tcp();
                self.note_transport_change(
                    Transport::UdpQsp,
                    Transport::Tcp,
                    TransportChangeReason::UdpError,
                );
                self.note_tcp_activity();
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
            Err(err) => {
                warn!(error = %err, "udp-qsp path refresh failed on existing socket");
            }
        }

        info!("recreating udp-qsp socket after path refresh failure");
        self.recreate_udp_io().await?;
        self.refresh_udp_path().await
    }

    async fn recreate_udp_io(&mut self) -> Result<(), SessionError> {
        let peer = self
            .udp_state
            .as_active()
            .ok_or_else(|| {
                SessionError::Io(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "udp-qsp transport missing",
                ))
            })?
            .peer();
        let socket = Arc::new(quic_discovery::bind_protected_udp_socket(
            peer,
            self.services.socket_protector(),
        )?);
        let new_io = client_udp_qsp_io(&socket, peer)?;
        let udp = self.udp_state.as_active_mut().ok_or_else(|| {
            SessionError::Io(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "udp-qsp transport missing",
            ))
        })?;
        let _old_io = udp.replace_io(new_io).await;
        Ok(())
    }

    fn note_udp_path_refresh_succeeded(&mut self) -> SessionControl {
        self.note_udp_activity();
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
        if msg_buf.message().ty() == MessageType::Data {
            if self.active_transport != ActiveTransport::UdpQsp {
                trace!("dropping udp data while tcp is active");
                return Ok(SessionControl::Continue);
            }
            if self.tun_channels.to_tun_tx.send(msg_buf).await.is_err() {
                self.metrics.inc_disconnect_close();
                return Ok(SessionControl::Close(SessionExit::TunClosed));
            }
            return Ok(SessionControl::Continue);
        }

        match msg_buf.message() {
            Message::RegisterOk { .. } => Err(SessionError::ProtocolViolation {
                detail: "unexpected register_ok on udp-qsp transport",
            }),
            Message::RegisterFail { .. } => Err(SessionError::ProtocolViolation {
                detail: "unexpected register_fail on udp-qsp transport",
            }),
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
            Message::RegisterCid { .. }
            | Message::Auth { .. }
            | Message::AuthOk { .. }
            | Message::AuthFail { .. }
            | Message::UpgradeProbe { .. }
            | Message::UdpReady { .. }
            | Message::SwitchToUdp { .. }
            | Message::SwitchAck { .. } => Err(SessionError::ProtocolViolation {
                detail: "unexpected control message on udp-qsp transport",
            }),
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
            let udp = self.udp_state.as_active_mut().ok_or_else(|| {
                SessionError::Io(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "udp-qsp transport missing",
                ))
            })?;
            let msg_buf = tokio::select! {
                biased;

                () = cancel.cancelled() => return Ok(SessionControl::Close(SessionExit::Shutdown)),
                result = time::timeout_at(deadline.into(), udp.read_next_message(self.limits)) => match result {
                    Ok(Ok(msg_buf)) => msg_buf,
                    // Raw UDP-QSP transport io::Error (phase 3): drop transient
                    // packet-level errors, wrap and propagate the rest.
                    Ok(Err(err)) if should_drop_refresh_udp_io_error(&err) => {
                        trace!(error = %err, "dropping udp-qsp packet during path refresh");
                        continue;
                    }
                    Ok(Err(err)) => return Err(SessionError::from(err)),
                    Err(_) => {
                        return Err(SessionError::Io(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "udp-qsp path refresh timed out",
                        )));
                    }
                }
            };

            match is_matching_pong(&msg_buf, nonce) {
                Ok(true) => return Ok(SessionControl::Continue),
                Ok(false) => {}
                Err(err) if should_drop_refresh_session_error(&err) => {
                    trace!(error = %err, "dropping udp-qsp pong during path refresh");
                    continue;
                }
                Err(err) => return Err(err),
            }

            let control = match self.handle_udp_message(msg_buf).await {
                Ok(control) => control,
                Err(err) if should_drop_refresh_session_error(&err) => {
                    trace!(error = %err, "dropping udp-qsp message during path refresh");
                    continue;
                }
                Err(err) => return Err(err),
            };
            if !matches!(control, SessionControl::Continue) {
                return Ok(control);
            }
        }
    }

    /// Handle UDP-QSP transport errors.
    ///
    /// Returns `true` if the session can continue (TCP fallback available),
    /// or `false` if both transports are dead and the session should close.
    pub(super) fn handle_udp_error(&mut self, err: &io::Error) -> bool {
        // Transient errors (replay, too_old, crypto) can be retried
        // InvalidData is typically packet-level issues that should be dropped, not fatal
        if err.kind() == io::ErrorKind::InvalidData {
            trace!(error = %err, "dropping udp-qsp packets");
            return true;
        }

        if !self.tcp_alive {
            warn!(
                kind = ?err.kind(),
                error = %err,
                "udp-qsp io error and tcp dead; closing session"
            );
            return false;
        }

        let was_udp_active = self.active_transport == ActiveTransport::UdpQsp;
        warn!(
            kind = ?err.kind(),
            error = %err,
            "udp-qsp io error; falling back to tcp and scheduling retry"
        );
        self.active_transport = ActiveTransport::Tcp;
        if was_udp_active {
            self.metrics.inc_transport_udp_to_tcp();
            self.note_transport_change(
                Transport::UdpQsp,
                Transport::Tcp,
                TransportChangeReason::UdpError,
            );
        }
        self.note_tcp_activity();

        // Transition to NeedDiscovery state to re-discover quic_ids
        self.schedule_discovery_retry();
        true
    }
}

fn is_matching_pong(msg_buf: &OwnedMessageBuf, nonce: u64) -> Result<bool, SessionError> {
    let Message::Pong { payload } = msg_buf.message() else {
        return Ok(false);
    };
    let pong = PongPayload::decode(payload)?;
    Ok(pong.nonce == nonce)
}

/// Whether a raw UDP-QSP transport `io::Error` (phase 3) should be dropped
/// during the path-refresh probe rather than propagated. Packet-level issues
/// (`InvalidData`: replay, too-old, crypto) are transient.
fn should_drop_refresh_udp_io_error(err: &io::Error) -> bool {
    err.kind() == io::ErrorKind::InvalidData
}

/// Whether a typed `SessionError` surfaced during the path-refresh probe
/// should be dropped rather than propagated. Mirrors
/// [`should_drop_refresh_udp_io_error`] for the wrapped-I/O case; typed
/// non-I/O session errors (proto decode failures, protocol violations) are
/// never dropped here — they propagate.
fn should_drop_refresh_session_error(err: &SessionError) -> bool {
    matches!(err.io_kind(), Some(io::ErrorKind::InvalidData))
}

#[cfg(test)]
mod tests {
    use std::io;

    use slt_core::proto::{OwnedMessageBuf, encode_message};

    use super::*;

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
        // an `io::ErrorKind::InvalidData`. The proto decode source survives.
        assert!(matches!(err, SessionError::Payload(_)));
        // It is not droppable as a transient UDP packet error (it has no
        // io::ErrorKind), so the refresh probe propagates it.
        assert!(!should_drop_refresh_session_error(&err));
    }

    #[test]
    fn refresh_drops_invalid_udp_errors() {
        let err = io::Error::new(io::ErrorKind::InvalidData, "replay");
        assert!(should_drop_refresh_udp_io_error(&err));
        // The same InvalidData wrapped in a SessionError is also droppable.
        let session_err = SessionError::from(err);
        assert!(should_drop_refresh_session_error(&session_err));
    }

    #[test]
    fn refresh_does_not_drop_io_errors() {
        for kind in [
            io::ErrorKind::TimedOut,
            io::ErrorKind::ConnectionReset,
            io::ErrorKind::ConnectionAborted,
            io::ErrorKind::BrokenPipe,
        ] {
            let err = io::Error::new(kind, "transport failure");
            assert!(!should_drop_refresh_udp_io_error(&err));
            // Wrapped in a SessionError, still not droppable.
            let session_err = SessionError::from(io::Error::new(kind, "transport failure"));
            assert!(!should_drop_refresh_session_error(&session_err));
        }
    }

    /// Typed (non-I/O) session errors are never droppable as transient UDP
    /// packet errors: they have no `io::ErrorKind`, so a proto decode failure
    /// or protocol violation propagates out of the refresh probe.
    #[test]
    fn refresh_does_not_drop_typed_session_errors() {
        let proto = SessionError::Payload(slt_core::proto::PayloadError::InvalidCipher(0x99));
        assert!(!should_drop_refresh_session_error(&proto));
        let violation = SessionError::ProtocolViolation { detail: "x" };
        assert!(!should_drop_refresh_session_error(&violation));
    }

    /// The unexpected-message branches in `handle_udp_message` emit
    /// `SessionError::ProtocolViolation` with specific `detail` strings (these
    /// are the variants the producer builds, not synthetic io::Errors). Each
    /// must project to the fatal `ProtocolError` exit and render its detail, so
    /// the terminal `{:#}` report is stage-specific rather than a bare
    /// `io::ErrorKind`.
    #[test]
    fn udp_unexpected_message_variants_are_typed_protocol_violations() {
        use crate::runtime::session::SessionExit;

        for detail in [
            "unexpected register_ok on udp-qsp transport",
            "unexpected register_fail on udp-qsp transport",
            "unexpected control message on udp-qsp transport",
        ] {
            let err = SessionError::ProtocolViolation { detail };
            assert_eq!(err.exit(), SessionExit::ProtocolError);
            let rendered = format!("{err:#}");
            assert!(
                rendered.contains("session protocol violation"),
                "missing stage framing: {rendered:?}"
            );
            assert!(
                rendered.contains(detail),
                "missing producer detail: {rendered:?}"
            );
        }
    }

    mod transport_switching {
        use super::super::ActiveTransport;

        /// Verify UDP active-transport identity comparisons.
        #[test]
        fn udp_qsp_active_transport_value_is_distinct() {
            assert_eq!(ActiveTransport::UdpQsp, ActiveTransport::UdpQsp);
            assert_ne!(ActiveTransport::UdpQsp, ActiveTransport::Tcp);
        }

        /// Verify transport comparison logic.
        #[test]
        fn tcp_and_udp_qsp_are_distinct() {
            assert_ne!(ActiveTransport::Tcp, ActiveTransport::UdpQsp);
            assert_eq!(ActiveTransport::Tcp, ActiveTransport::Tcp);
            assert_eq!(ActiveTransport::UdpQsp, ActiveTransport::UdpQsp);
        }

        /// Verify explicit transport values remain stable.
        #[test]
        fn explicit_transport_values_are_stable() {
            assert_eq!(ActiveTransport::Tcp, ActiveTransport::Tcp);
            assert_eq!(ActiveTransport::UdpQsp, ActiveTransport::UdpQsp);
        }
    }
}
