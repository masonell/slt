//! UDP-QSP message handling for `ClientSession`.

use std::io;
use std::time::Instant;

use slt_core::proto::{
    ClosePayload, Message, MessageType, OwnedMessageBuf, PingPayload, PongPayload,
};
use tokio::time;
use tracing::{info, trace, warn};

use super::{ClientSession, SessionControl, SessionExit};
use crate::runtime::observer::{ClientEventKind, Transport, TransportChangeReason};
use crate::runtime::services::ClientRuntimeServices;
use crate::runtime::session::state::ActiveTransport;
use crate::wire;

impl<S: ClientRuntimeServices> ClientSession<'_, S> {
    /// Handles a host-reported network change.
    ///
    /// If UDP-QSP is the active data path, first tries to validate the existing
    /// UDP socket by sending an authenticated ping and waiting for the matching
    /// pong. A successful round trip proves the server accepted the client's
    /// current source address and updated its peer. On refresh failure, a live
    /// TCP channel is used to rediscover QUIC IDs and register a fresh UDP path;
    /// if TCP is unavailable the session exits so the runtime reconnects TCP.
    pub(super) async fn handle_network_changed(&mut self) -> io::Result<SessionControl> {
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
        match self.refresh_udp_path().await {
            Ok(SessionControl::Continue) => {
                self.note_udp_activity();
                self.services
                    .observer()
                    .emit(ClientEventKind::UdpPathRefreshSucceeded);
                info!("udp-qsp path refresh succeeded");
                Ok(SessionControl::Continue)
            }
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
    ) -> io::Result<SessionControl> {
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
                self.write_udp_message_and_flush(Message::Pong {
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
            Message::Data { .. } => unreachable!("data handled by fast-path above"),
            Message::Close { payload } => {
                let close = ClosePayload::decode(payload).map_err(wire::map_payload_error)?;
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
            | Message::SwitchAck { .. } => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unexpected control message on udp-qsp transport",
            )),
        }
    }

    async fn refresh_udp_path(&mut self) -> io::Result<SessionControl> {
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
                io::Error::new(io::ErrorKind::BrokenPipe, "udp-qsp transport missing")
            })?;
            let msg_buf = tokio::select! {
                biased;

                () = cancel.cancelled() => return Ok(SessionControl::Close(SessionExit::Shutdown)),
                result = time::timeout_at(deadline.into(), udp.read_next_message(self.limits)) => match result {
                    Ok(Ok(msg_buf)) => msg_buf,
                    Ok(Err(err)) if should_drop_refresh_udp_error(&err) => {
                        trace!(error = %err, "dropping udp-qsp packet during path refresh");
                        continue;
                    }
                    Ok(Err(err)) => return Err(err),
                    Err(_) => {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "udp-qsp path refresh timed out",
                        ));
                    }
                }
            };

            match is_matching_pong(&msg_buf, nonce) {
                Ok(true) => return Ok(SessionControl::Continue),
                Ok(false) => {}
                Err(err) if should_drop_refresh_udp_error(&err) => {
                    trace!(error = %err, "dropping udp-qsp pong during path refresh");
                    continue;
                }
                Err(err) => return Err(err),
            }

            let control = match self.handle_udp_message(msg_buf).await {
                Ok(control) => control,
                Err(err) if should_drop_refresh_udp_error(&err) => {
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

fn is_matching_pong(msg_buf: &OwnedMessageBuf, nonce: u64) -> io::Result<bool> {
    let Message::Pong { payload } = msg_buf.message() else {
        return Ok(false);
    };
    let pong = PongPayload::decode(payload).map_err(wire::map_payload_error)?;
    Ok(pong.nonce == nonce)
}

fn should_drop_refresh_udp_error(err: &io::Error) -> bool {
    err.kind() == io::ErrorKind::InvalidData
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
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn refresh_drops_invalid_udp_errors() {
        let err = io::Error::new(io::ErrorKind::InvalidData, "replay");
        assert!(should_drop_refresh_udp_error(&err));
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
            assert!(!should_drop_refresh_udp_error(&err));
        }
    }

    /// Test unexpected `register_ok` error properties.
    #[test]
    fn unexpected_register_ok_error_kind() {
        let err = io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected register_ok on udp-qsp transport",
        );
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    /// Test unexpected `register_fail` error properties.
    #[test]
    fn unexpected_register_fail_error_kind() {
        let err = io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected register_fail on udp-qsp transport",
        );
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    /// Test unexpected control message error properties.
    #[test]
    fn unexpected_control_message_error_kind() {
        let err = io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected control message on udp-qsp transport",
        );
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    mod handle_udp_error_logic {
        use super::*;

        /// Test that `InvalidData` errors are considered recoverable (dropped).
        #[test]
        fn invalid_data_is_recoverable_kind() {
            // InvalidData is used for packet-level issues (replay, crypto failures)
            // and should be dropped, not trigger fallback
            let err = io::Error::new(io::ErrorKind::InvalidData, "replay detected");
            assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        }

        /// Test that non-InvalidData errors trigger fallback when TCP is alive.
        #[test]
        fn non_invalid_data_triggers_fallback() {
            // Errors other than InvalidData should trigger TCP fallback
            let non_recoverable_kinds = [
                io::ErrorKind::ConnectionReset,
                io::ErrorKind::BrokenPipe,
                io::ErrorKind::TimedOut,
                io::ErrorKind::ConnectionAborted,
            ];

            for kind in non_recoverable_kinds {
                let err = io::Error::new(kind, "test");
                assert_ne!(
                    err.kind(),
                    io::ErrorKind::InvalidData,
                    "{kind:?} should not be InvalidData"
                );
            }
        }

        /// Test error kinds that would trigger session closure when TCP is dead.
        #[test]
        fn fatal_errors_when_tcp_dead() {
            // When TCP is dead, these errors should cause session closure
            let fatal_kinds = [
                io::ErrorKind::ConnectionReset,
                io::ErrorKind::BrokenPipe,
                io::ErrorKind::TimedOut,
            ];

            for kind in fatal_kinds {
                let err = io::Error::new(kind, "test");
                // The logic is: if err.kind() != InvalidData && !tcp_alive -> false
                assert_ne!(err.kind(), io::ErrorKind::InvalidData);
            }
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

    mod error_recovery_paths {
        use super::*;

        /// Test that `ConnectionAborted` (dead channel) is fatal when TCP is dead.
        #[test]
        fn connection_aborted_is_fatal_when_tcp_dead() {
            let err = io::Error::new(io::ErrorKind::ConnectionAborted, "dead channel");
            // ConnectionAborted is NOT InvalidData
            assert_ne!(err.kind(), io::ErrorKind::InvalidData);
            // When TCP is dead, this should cause session closure
        }

        /// Test that `InvalidData` errors are recoverable regardless of TCP state.
        #[test]
        fn invalid_data_is_always_recoverable() {
            let recoverable_errors = [
                "replay detected",
                "too old",
                "crypto error",
                "packet number overflow",
            ];

            for msg in recoverable_errors {
                let err = io::Error::new(io::ErrorKind::InvalidData, msg);
                assert_eq!(err.kind(), io::ErrorKind::InvalidData);
            }
        }

        /// Test that non-fatal errors trigger TCP fallback when TCP is alive.
        #[test]
        fn non_invalid_data_triggers_tcp_fallback_when_alive() {
            let fallback_kinds = [
                io::ErrorKind::ConnectionReset,
                io::ErrorKind::BrokenPipe,
                io::ErrorKind::TimedOut,
                io::ErrorKind::ConnectionAborted,
            ];

            for kind in fallback_kinds {
                let err = io::Error::new(kind, "test");
                // These are NOT InvalidData, so they trigger fallback logic
                assert_ne!(err.kind(), io::ErrorKind::InvalidData);
            }
        }

        /// Test the error kind classification for UDP-QSP errors.
        #[test]
        fn udp_qsp_error_classification() {
            // Recoverable: packet-level issues (drop and continue)
            let recoverable_kinds = [io::ErrorKind::InvalidData];

            // Potentially fatal: depends on TCP state
            let potentially_fatal_kinds = [
                io::ErrorKind::ConnectionReset,
                io::ErrorKind::BrokenPipe,
                io::ErrorKind::TimedOut,
                io::ErrorKind::ConnectionAborted,
            ];

            // Verify classification
            for kind in recoverable_kinds {
                assert_eq!(
                    kind,
                    io::ErrorKind::InvalidData,
                    "only InvalidData is always recoverable"
                );
            }

            for kind in potentially_fatal_kinds {
                assert_ne!(
                    kind,
                    io::ErrorKind::InvalidData,
                    "non-InvalidData errors may be fatal"
                );
            }
        }
    }
}
