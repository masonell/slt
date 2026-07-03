//! UDP upgrade logic: discovery, registration, and retries.

use std::io;
use std::time::Instant;

use slt_core::proto::{
    Message, PingPayload, RegisterFailPayload, RegisterOkPayload, SwitchAckPayload,
    SwitchToUdpPayload, UdpReadyPayload, UpgradeProbeAckPayload, UpgradeProbePayload,
};
use tokio::task::JoinHandle;
use tokio::time;
use tracing::{debug, info, trace, warn};

use super::error::SessionError;
use super::{ClientSession, SessionControl, SessionExit, UdpState};
use crate::runtime::observer::{ClientEventKind, Transport, TransportChangeReason};
use crate::runtime::services::ClientRuntimeServices;
use crate::runtime::session::state::{ActiveTransport, PendingUdpQspRegistration, UdpUpgradeState};
use crate::runtime::{ReconnectBackoff, register};
use crate::transport::quic_discovery as quic;
use crate::transport::udp_qsp::UdpQspTransport;

const MAX_UPGRADE_PROBES: u32 = 8;

const fn upgrade_id_from_active_upgrade_state(state: &UdpUpgradeState) -> Option<u64> {
    match state {
        UdpUpgradeState::Upgrading { upgrade_id, .. }
        | UdpUpgradeState::AwaitingSwitchCommit { upgrade_id, .. } => Some(*upgrade_id),
        UdpUpgradeState::Disabled
        | UdpUpgradeState::Idle
        | UdpUpgradeState::TcpOnlyBlockedUdp { .. } => None,
    }
}

const fn barrier_upgrade_id_for_nonce(state: &UdpUpgradeState, nonce: u64) -> Option<u64> {
    match state {
        UdpUpgradeState::AwaitingSwitchCommit {
            upgrade_id,
            barrier_nonce,
            ..
        } if *barrier_nonce == nonce => Some(*upgrade_id),
        _ => None,
    }
}

impl<S: ClientRuntimeServices> ClientSession<'_, S> {
    /// Spawns a QUIC discovery task.
    ///
    /// Returns a `JoinHandle` for the background task that will resolve to
    /// `Some(ids)` on success or `None` on failure/cancellation. The task
    /// is cancelled if the session's cancellation token is triggered.
    pub(super) fn spawn_quic_discovery(&self) -> JoinHandle<Option<quic::QuicIds>> {
        let config = self.config.clone();
        let cancel = self.cancel.clone();
        let peer = self.peer;
        let socket_protector = self.services.socket_protector().clone();
        let host_resolver = self.services.host_resolver().clone();
        let discovery_timeout = self.config.timing.quic_discovery_timeout;

        tokio::spawn(async move {
            debug!(
                timeout_ms = discovery_timeout.as_millis(),
                peer = ?peer,
                "starting quic dcid discovery"
            );
            let result = tokio::select! {
                () = cancel.cancelled() => return None,
                result = time::timeout(
                    discovery_timeout,
                    quic::discover_quic_ids(&config, &cancel, peer, &socket_protector, &host_resolver),
                ) => result,
            };

            match result {
                Ok(Ok(ids)) => {
                    info!(
                        dcid_len = ids.dcid.len(),
                        scid_len = ids.scid.len(),
                        "quic dcid discovery succeeded"
                    );
                    Some(ids)
                }
                Ok(Err(err)) => {
                    warn!(error = %err, "quic dcid discovery failed");
                    None
                }
                Err(_) => {
                    warn!(
                        timeout_ms = discovery_timeout.as_millis(),
                        "quic dcid discovery timed out"
                    );
                    None
                }
            }
        })
    }

    /// Starts a UDP-QSP registration attempt and tracks it in session state.
    ///
    /// If the session is in `Pending` state without an in-flight registration,
    /// prepares and sends `REGISTER_CID` over TCP, then stores the prepared
    /// state with a deadline. If preparation or sending fails, retries unless
    /// `require_udp` is enabled, in which case the session closes.
    pub(super) async fn attempt_udp_registration(&mut self) -> SessionControl {
        let quic_ids = match &mut self.udp_state {
            UdpState::Pending {
                quic_ids,
                registration,
                ..
            } => {
                if registration.is_some() {
                    return SessionControl::Continue;
                }
                quic_ids.clone()
            }
            _ => return SessionControl::Continue,
        };

        match register::start_udp_qsp_registration(
            &mut self.tcp,
            &quic_ids,
            self.config.transport.udp_qsp.cipher,
        )
        .await
        {
            Ok(prepared) => {
                let deadline = Instant::now() + self.config.timing.register_timeout;
                if let UdpState::Pending { registration, .. } = &mut self.udp_state {
                    *registration =
                        Some(Box::new(PendingUdpQspRegistration { prepared, deadline }));
                }
                self.services
                    .observer()
                    .emit(ClientEventKind::UdpRegisterStarted);
            }
            Err(err) => {
                warn!(error = %err, "register_cid failed");
                if self.config.require_udp {
                    warn!("register_cid failed with require_udp=true");
                    return SessionControl::Close(SessionExit::UdpUpgradeRequired);
                }
                self.services
                    .observer()
                    .emit(ClientEventKind::UdpRegisterFailed {
                        detail: err.to_string(),
                    });
                self.schedule_registration_retry();
            }
        }
        SessionControl::Continue
    }

    /// Schedules a QUIC discovery retry with backoff.
    ///
    /// Transitions to `NeedDiscovery` state (if not already) and sets the
    /// reconnect deadline using exponential backoff with jitter.
    pub(super) fn schedule_discovery_retry(&mut self) {
        self.udp_upgrade = if self.config.enable_upgrade || self.config.require_udp {
            UdpUpgradeState::Idle
        } else {
            UdpUpgradeState::Disabled
        };
        let UdpState::NeedDiscovery {
            backoff,
            reconnect_at,
        } = &mut self.udp_state
        else {
            let mut backoff = ReconnectBackoff::new(
                self.config.timing.reconnect_min,
                self.config.timing.reconnect_max,
            );
            let delay = backoff.next_delay();
            self.udp_state = UdpState::NeedDiscovery {
                backoff,
                reconnect_at: Instant::now() + delay,
            };
            debug!(delay_ms = delay.as_millis(), "scheduled quic discovery");
            return;
        };

        let delay = backoff.next_delay();
        *reconnect_at = Instant::now() + delay;
        debug!(delay_ms = delay.as_millis(), "scheduled quic discovery");
    }

    /// Schedules immediate QUIC discovery without applying retry backoff.
    ///
    /// Used after an Android network handoff when the existing UDP-QSP path
    /// cannot be refreshed but the TCP control channel is still alive.
    pub(super) fn schedule_discovery_now(&mut self) {
        if !(self.config.enable_upgrade || self.config.require_udp) {
            self.udp_state = UdpState::Disabled;
            self.udp_upgrade = UdpUpgradeState::Disabled;
            return;
        }

        self.udp_upgrade = UdpUpgradeState::Idle;
        self.udp_state = UdpState::NeedDiscovery {
            backoff: ReconnectBackoff::new(
                self.config.timing.reconnect_min,
                self.config.timing.reconnect_max,
            ),
            reconnect_at: Instant::now(),
        };
        debug!("scheduled immediate quic discovery");
    }

    /// Schedules a UDP registration retry with backoff.
    ///
    /// Clears any in-flight registration, advances the backoff, and sets
    /// the reconnect deadline. Only valid if already in `Pending` state.
    pub(super) fn schedule_registration_retry(&mut self) {
        let UdpState::Pending {
            backoff,
            reconnect_at,
            registration,
            ..
        } = &mut self.udp_state
        else {
            return;
        };

        let delay = backoff.next_delay();
        *reconnect_at = Instant::now() + delay;
        *registration = None;
        debug!(delay_ms = delay.as_millis(), "scheduled udp registration");
    }

    fn start_udp_upgrade_attempt(&mut self, now: Instant) {
        if matches!(self.udp_upgrade, UdpUpgradeState::Disabled) {
            return;
        }
        if !matches!(self.udp_state, UdpState::Active(_)) {
            self.udp_upgrade = UdpUpgradeState::Idle;
            return;
        }
        if self.active_transport != crate::runtime::session::state::ActiveTransport::Tcp {
            return;
        }

        let upgrade_id = fastrand::u64(..);
        self.udp_upgrade = UdpUpgradeState::Upgrading {
            upgrade_id,
            deadline: now + self.config.timing.register_timeout,
            attempts: 0,
            next_probe_at: now,
            last_probe_nonce: 0,
            probe_acked: false,
            ready_sent: false,
            probe_backoff: ReconnectBackoff::new(
                self.config.timing.reconnect_min,
                self.config.timing.reconnect_max,
            ),
        };
        self.services
            .observer()
            .emit(ClientEventKind::UdpUpgradeStarted { upgrade_id });
        info!(upgrade_id, "starting udp upgrade attempt");
    }

    /// Handles `REGISTER_OK` received on TCP transport.
    ///
    /// Validates the payload DCID matches the pending registration, installs
    /// the pre-built UDP-QSP session, and transitions to `Active` state.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Not in `Pending` state with an in-flight registration
    /// - Payload decoding fails
    /// - DCID in response doesn't match expected DCID
    /// - Pre-built session is missing (double-take bug)
    pub(super) fn handle_register_ok(
        &mut self,
        payload: &[u8],
    ) -> Result<SessionControl, SessionError> {
        let (quic_ids, session) = {
            let UdpState::Pending {
                quic_ids,
                registration,
                ..
            } = &mut self.udp_state
            else {
                debug!("unexpected register_ok without pending registration");
                return Ok(SessionControl::Continue);
            };
            let Some(in_flight) = registration.as_mut() else {
                debug!("unexpected register_ok without in-flight registration");
                return Ok(SessionControl::Continue);
            };

            let ok = RegisterOkPayload::decode(payload)?;
            if ok.client_to_server_cid != quic_ids.dcid {
                // Carry the offending value (the mismatched DCIDs) into the
                // terminal report rather than discarding it. `Cow::Owned`
                // formats the two CIDs into the detail string.
                return Err(SessionError::ProtocolViolation {
                    detail: format!(
                        "register_ok client_to_server_cid mismatch: expected={:?}, got={:?}",
                        quic_ids.dcid, ok.client_to_server_cid,
                    )
                    .into(),
                });
            }

            let session = in_flight.prepared.session.take().ok_or_else(|| {
                SessionError::ProtocolViolation {
                    detail: "udp-qsp session missing".into(),
                }
            })?;
            (quic_ids, session)
        };

        info!(
            dcid_len = quic_ids.dcid.len(),
            scid_len = quic_ids.scid.len(),
            peer = %quic_ids.peer,
            "register_cid accepted"
        );
        self.udp_state = UdpState::Active(Box::new(UdpQspTransport::new(
            session,
            self.metrics.clone(),
        )));
        self.last_udp_rx = Instant::now();
        self.services
            .observer()
            .emit(ClientEventKind::UdpRegistered);
        self.start_udp_upgrade_attempt(Instant::now());
        Ok(SessionControl::Continue)
    }

    /// Handles `REGISTER_FAIL` received on TCP transport.
    ///
    /// Decodes the failure code, logs it, updates metrics, and schedules
    /// a retry. If received without an in-flight registration, logs and
    /// continues.
    ///
    /// # Errors
    ///
    /// Returns an error if payload decoding fails.
    pub(super) fn handle_register_fail(
        &mut self,
        payload: &[u8],
    ) -> Result<SessionControl, SessionError> {
        let has_in_flight_registration = matches!(
            &self.udp_state,
            UdpState::Pending {
                registration: Some(_),
                ..
            }
        );
        if !has_in_flight_registration {
            debug!("unexpected register_fail without in-flight registration");
            return Ok(SessionControl::Continue);
        }

        let fail = RegisterFailPayload::decode(payload)?;
        warn!(code = ?fail.code, "register_cid rejected");
        self.metrics.inc_udp_register_failure();
        if self.config.require_udp {
            warn!(code = ?fail.code, "register_cid rejected with require_udp=true");
            return Ok(SessionControl::Close(SessionExit::UdpUpgradeRequired));
        }
        self.services
            .observer()
            .emit(ClientEventKind::UdpRegisterFailed {
                detail: format!("register_cid rejected: {:?}", fail.code),
            });
        self.schedule_registration_retry();
        Ok(SessionControl::Continue)
    }

    /// Handles registration timeout for in-flight `REGISTER_CID`.
    ///
    /// If registration is in flight, retries unless `require_udp` is enabled,
    /// in which case the session closes.
    pub(super) fn handle_registration_timeout(&mut self) -> SessionControl {
        if !matches!(
            &self.udp_state,
            UdpState::Pending {
                registration: Some(_),
                ..
            }
        ) {
            return SessionControl::Continue;
        }

        warn!("register_cid timed out");
        if self.config.require_udp {
            warn!("register_cid timed out with require_udp=true");
            return SessionControl::Close(SessionExit::UdpUpgradeRequired);
        }
        self.services
            .observer()
            .emit(ClientEventKind::UdpRegisterFailed {
                detail: "register_cid timed out".to_string(),
            });
        self.schedule_registration_retry();
        SessionControl::Continue
    }

    /// Handles completion of QUIC discovery.
    ///
    /// Installs discovered IDs on success. On failure, retries discovery unless
    /// `require_udp` is enabled, in which case the session closes.
    pub(super) fn handle_discovery_result(
        &mut self,
        maybe_ids: Option<quic::QuicIds>,
    ) -> SessionControl {
        if let Some(ids) = maybe_ids {
            self.udp_state = UdpState::Pending {
                quic_ids: ids,
                backoff: ReconnectBackoff::new(
                    self.config.timing.reconnect_min,
                    self.config.timing.reconnect_max,
                ),
                reconnect_at: Instant::now(),
                registration: None,
            };
            return SessionControl::Continue;
        }

        self.metrics.inc_udp_discovery_failure();
        self.services
            .observer()
            .emit(ClientEventKind::UdpDiscoveryFailed {
                detail: "quic dcid discovery failed".to_string(),
            });
        if self.config.require_udp {
            warn!("quic dcid discovery failed with require_udp=true");
            return SessionControl::Close(SessionExit::UdpUpgradeRequired);
        }
        self.schedule_discovery_retry();
        SessionControl::Continue
    }

    pub(super) async fn handle_udp_upgrade_tick(&mut self) -> Result<SessionControl, SessionError> {
        let now = Instant::now();
        match &self.udp_upgrade {
            UdpUpgradeState::Disabled | UdpUpgradeState::Idle => Ok(SessionControl::Continue),
            UdpUpgradeState::TcpOnlyBlockedUdp { retry_at } => {
                if now < *retry_at {
                    return Ok(SessionControl::Continue);
                }
                self.start_udp_upgrade_attempt(now);
                Ok(SessionControl::Continue)
            }
            UdpUpgradeState::Upgrading {
                deadline,
                attempts,
                next_probe_at,
                probe_acked,
                ready_sent,
                ..
            } => {
                if now >= *deadline {
                    let reason = if *probe_acked && *ready_sent {
                        "switch_to_udp_timeout"
                    } else {
                        "probe_timeout"
                    };
                    return Ok(self.handle_udp_upgrade_timeout(reason));
                }

                if *probe_acked || now < *next_probe_at {
                    return Ok(SessionControl::Continue);
                }

                if *attempts >= MAX_UPGRADE_PROBES {
                    return Ok(self.handle_udp_upgrade_timeout("max_probes"));
                }

                self.send_upgrade_probe(now).await?;
                Ok(SessionControl::Continue)
            }
            UdpUpgradeState::AwaitingSwitchCommit { deadline, .. } => {
                if now >= *deadline {
                    return Ok(self.handle_udp_upgrade_timeout("switch_commit_timeout"));
                }
                Ok(SessionControl::Continue)
            }
        }
    }

    async fn send_upgrade_probe(&mut self, now: Instant) -> Result<(), SessionError> {
        let (upgrade_id, nonce, attempts) = {
            let UdpUpgradeState::Upgrading {
                upgrade_id,
                attempts,
                next_probe_at,
                last_probe_nonce,
                probe_backoff,
                probe_acked,
                ..
            } = &mut self.udp_upgrade
            else {
                return Ok(());
            };
            if *probe_acked || *attempts >= MAX_UPGRADE_PROBES {
                return Ok(());
            }

            let nonce = fastrand::u64(..);
            *attempts = attempts.saturating_add(1);
            *last_probe_nonce = nonce;
            *next_probe_at = now + probe_backoff.next_delay();
            (*upgrade_id, nonce, *attempts)
        };

        let probe = UpgradeProbePayload { upgrade_id, nonce };
        let mut buf = Vec::with_capacity(16);
        probe.encode(&mut buf);
        match self
            .write_udp_message_and_flush(Message::UpgradeProbe { payload: &buf })
            .await
        {
            Ok(()) => {
                debug!(upgrade_id, attempts, "sent udp upgrade probe");
                Ok(())
            }
            Err(err) => {
                if err.is_udp_path_transport_error() {
                    if !self.handle_udp_error(&err) {
                        return Err(SessionError::Connection {
                            source: io::Error::new(
                                io::ErrorKind::NotConnected,
                                "both transports dead",
                            ),
                        });
                    }
                } else {
                    // Typed non-transport session error from the UDP path; propagate.
                    return Err(err);
                }
                warn!(error = %err, "failed to send udp upgrade probe; retry via rediscovery");
                Ok(())
            }
        }
    }

    fn handle_udp_upgrade_timeout(&mut self, reason: &'static str) -> SessionControl {
        let upgrade_id = upgrade_id_from_active_upgrade_state(&self.udp_upgrade);

        if self.config.require_udp {
            warn!(
                reason,
                upgrade_id = ?upgrade_id,
                "udp upgrade timed out with require_udp=true"
            );
            return SessionControl::Close(SessionExit::UdpUpgradeRequired);
        }

        let delay = self.udp_upgrade_backoff.next_delay();
        self.udp_upgrade = UdpUpgradeState::TcpOnlyBlockedUdp {
            retry_at: Instant::now() + delay,
        };
        warn!(
            reason,
            upgrade_id = ?upgrade_id,
            retry_in_ms = delay.as_millis(),
            "udp upgrade timed out; staying on tcp until cooldown expires"
        );
        SessionControl::Continue
    }

    pub(super) async fn handle_upgrade_probe_ack(
        &mut self,
        payload: &[u8],
    ) -> Result<SessionControl, SessionError> {
        let ack = UpgradeProbeAckPayload::decode(payload)?;
        let should_send_ready = if let UdpUpgradeState::Upgrading {
            upgrade_id,
            probe_acked,
            ready_sent,
            last_probe_nonce,
            ..
        } = &mut self.udp_upgrade
        {
            if ack.upgrade_id != *upgrade_id {
                debug!(
                    expected_upgrade_id = *upgrade_id,
                    received_upgrade_id = ack.upgrade_id,
                    "ignoring upgrade_probe_ack with mismatched upgrade_id"
                );
                return Ok(SessionControl::Continue);
            }

            if ack.nonce != *last_probe_nonce {
                trace!(
                    expected_nonce = *last_probe_nonce,
                    received_nonce = ack.nonce,
                    "received stale udp upgrade probe ack nonce"
                );
            }
            *probe_acked = true;
            !*ready_sent
        } else {
            trace!(
                upgrade_id = ack.upgrade_id,
                "ignoring udp upgrade probe ack without active upgrade"
            );
            return Ok(SessionControl::Continue);
        };

        if !should_send_ready {
            return Ok(SessionControl::Continue);
        }

        let ready = UdpReadyPayload {
            upgrade_id: ack.upgrade_id,
        };
        let mut buf = Vec::with_capacity(8);
        ready.encode(&mut buf);
        self.tcp
            .write_message(Message::UdpReady { payload: &buf })
            .await?;

        if let UdpUpgradeState::Upgrading { ready_sent, .. } = &mut self.udp_upgrade {
            *ready_sent = true;
        }
        self.services
            .observer()
            .emit(ClientEventKind::UdpPathValidated {
                upgrade_id: ack.upgrade_id,
            });
        info!(
            upgrade_id = ack.upgrade_id,
            "udp path validated; sent udp_ready"
        );
        Ok(SessionControl::Continue)
    }

    pub(super) async fn handle_switch_to_udp(
        &mut self,
        payload: &[u8],
    ) -> Result<SessionControl, SessionError> {
        let switch = SwitchToUdpPayload::decode(payload)?;

        let deadline = if let UdpUpgradeState::Upgrading {
            upgrade_id,
            probe_acked,
            ready_sent,
            deadline,
            ..
        } = &self.udp_upgrade
        {
            if switch.upgrade_id != *upgrade_id {
                debug!(
                    expected_upgrade_id = *upgrade_id,
                    received_upgrade_id = switch.upgrade_id,
                    "ignoring switch_to_udp with mismatched upgrade_id"
                );
                return Ok(SessionControl::Continue);
            }
            if !*probe_acked || !*ready_sent {
                debug!(
                    upgrade_id = switch.upgrade_id,
                    probe_acked = *probe_acked,
                    ready_sent = *ready_sent,
                    "ignoring switch_to_udp before upgrade readiness"
                );
                return Ok(SessionControl::Continue);
            }
            *deadline
        } else {
            trace!(
                upgrade_id = switch.upgrade_id,
                "ignoring switch_to_udp without active upgrade"
            );
            return Ok(SessionControl::Continue);
        };

        let ack = SwitchAckPayload {
            upgrade_id: switch.upgrade_id,
        };
        let mut switch_ack_buf = Vec::with_capacity(8);
        ack.encode(&mut switch_ack_buf);
        self.tcp
            .write_message(Message::SwitchAck {
                payload: &switch_ack_buf,
            })
            .await?;

        let barrier_nonce = fastrand::u64(..);
        let barrier_ping = PingPayload {
            nonce: barrier_nonce,
        };
        let mut barrier_ping_buf = Vec::with_capacity(8);
        barrier_ping.encode(&mut barrier_ping_buf);
        self.tcp
            .write_message(Message::Ping {
                payload: &barrier_ping_buf,
            })
            .await?;

        self.udp_upgrade = UdpUpgradeState::AwaitingSwitchCommit {
            upgrade_id: switch.upgrade_id,
            barrier_nonce,
            deadline,
        };
        info!(
            upgrade_id = switch.upgrade_id,
            barrier_nonce, "sent switch_ack; awaiting tcp barrier pong before udp commit"
        );
        Ok(SessionControl::Continue)
    }

    pub(super) fn maybe_commit_udp_upgrade_on_barrier_pong(&mut self, nonce: u64) -> bool {
        let Some(upgrade_id) = barrier_upgrade_id_for_nonce(&self.udp_upgrade, nonce) else {
            return false;
        };

        if self.active_transport != ActiveTransport::UdpQsp {
            self.metrics.inc_transport_tcp_to_udp();
            self.active_transport = ActiveTransport::UdpQsp;
            self.note_transport_change(
                Transport::Tcp,
                Transport::UdpQsp,
                TransportChangeReason::UpgradeCommitted,
            );
        }
        self.last_udp_rx = Instant::now();
        self.udp_upgrade = UdpUpgradeState::Idle;
        self.udp_upgrade_backoff.reset();
        self.services
            .observer()
            .emit(ClientEventKind::UdpSwitchCommitted { upgrade_id });
        info!(upgrade_id, "udp upgrade committed");
        true
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    mod upgrade_state_helpers {
        use std::time::Instant;

        use super::*;

        #[test]
        fn active_upgrade_id_includes_waiting_commit_state() {
            let waiting = UdpUpgradeState::AwaitingSwitchCommit {
                upgrade_id: 0xAA,
                barrier_nonce: 0xBB,
                deadline: Instant::now(),
            };
            assert_eq!(upgrade_id_from_active_upgrade_state(&waiting), Some(0xAA));
        }

        #[test]
        fn barrier_nonce_must_match_to_commit() {
            let waiting = UdpUpgradeState::AwaitingSwitchCommit {
                upgrade_id: 11,
                barrier_nonce: 22,
                deadline: Instant::now(),
            };
            assert_eq!(barrier_upgrade_id_for_nonce(&waiting, 22), Some(11));
            assert_eq!(barrier_upgrade_id_for_nonce(&waiting, 23), None);
        }
    }

    mod register_fail_payload_decode {
        use slt_core::proto::{RegisterFailCode, RegisterFailPayload};

        use super::*;

        #[test]
        fn valid_payload_with_unknown_code_decodes() {
            // RegisterFailPayload has no encode method, so we build the buffer manually
            // Format: 1 byte for the code
            let buf = [u8::from(RegisterFailCode::Unknown)];
            let decoded = RegisterFailPayload::decode(&buf).unwrap();
            assert_eq!(decoded.code, RegisterFailCode::Unknown);
        }

        #[test]
        fn valid_payload_with_not_authenticated_decodes() {
            let buf = [u8::from(RegisterFailCode::NotAuthenticated)];
            let decoded = RegisterFailPayload::decode(&buf).unwrap();
            assert_eq!(decoded.code, RegisterFailCode::NotAuthenticated);
        }

        #[test]
        fn valid_payload_with_invalid_cipher_decodes() {
            let buf = [u8::from(RegisterFailCode::InvalidCipher)];
            let decoded = RegisterFailPayload::decode(&buf).unwrap();
            assert_eq!(decoded.code, RegisterFailCode::InvalidCipher);
        }

        #[test]
        fn valid_payload_with_invalid_cid_decodes() {
            let buf = [u8::from(RegisterFailCode::InvalidCid)];
            let decoded = RegisterFailPayload::decode(&buf).unwrap();
            assert_eq!(decoded.code, RegisterFailCode::InvalidCid);
        }

        #[test]
        fn valid_payload_with_invalid_keys_decodes() {
            let buf = [u8::from(RegisterFailCode::InvalidKeys)];
            let decoded = RegisterFailPayload::decode(&buf).unwrap();
            assert_eq!(decoded.code, RegisterFailCode::InvalidKeys);
        }

        #[test]
        fn empty_payload_fails() {
            let result = RegisterFailPayload::decode(&[]);
            assert!(result.is_err());
        }

        #[test]
        fn invalid_code_fails() {
            // 0xFF is not a valid RegisterFailCode
            let result = RegisterFailPayload::decode(&[0xFF]);
            assert!(result.is_err());
        }

        #[test]
        fn decode_error_preserved_as_session_error() {
            let result = RegisterFailPayload::decode(&[]);
            assert!(result.is_err());

            // The payload decode error is preserved as a typed `SessionError`,
            // carrying the proto detail.
            let err = SessionError::from(result.unwrap_err());
            assert!(matches!(err, SessionError::Payload(_)));
            assert_eq!(err.exit(), super::super::SessionExit::ProtocolError);
        }

        #[test]
        fn too_long_payload_fails() {
            // Payload must be exactly 1 byte
            let result = RegisterFailPayload::decode(&[0x00, 0x01]);
            assert!(result.is_err());
        }
    }

    mod register_ok_payload_decode {
        use slt_core::proto::RegisterOkPayload;
        use slt_core::types::{Cid, MAX_DCID_LEN};

        use super::*;

        #[test]
        fn valid_payload_decodes() {
            let c2s_cid = Cid::from([0xAA; MAX_DCID_LEN]);
            let payload = RegisterOkPayload {
                client_to_server_cid: c2s_cid,
            };
            let mut buf = Vec::new();
            payload.encode(&mut buf).unwrap();

            let decoded = RegisterOkPayload::decode(&buf).unwrap();
            assert_eq!(decoded.client_to_server_cid, c2s_cid);
        }

        #[test]
        fn empty_payload_fails() {
            let result = RegisterOkPayload::decode(&[]);
            assert!(result.is_err());
        }

        #[test]
        fn truncated_payload_fails() {
            // Only 4 bytes, need 20 for cid
            let result = RegisterOkPayload::decode(&[0x01, 0x02, 0x03, 0x04]);
            assert!(result.is_err());
        }

        #[test]
        fn decode_error_preserved_as_session_error() {
            let result = RegisterOkPayload::decode(&[]);
            assert!(result.is_err());

            let err = SessionError::from(result.unwrap_err());
            assert!(matches!(err, SessionError::Payload(_)));
            assert_eq!(err.exit(), super::super::SessionExit::ProtocolError);
        }
    }

    /// The DCID-mismatch and missing-session branches in `handle_register_ok`
    /// emit `SessionError::ProtocolViolation` with specific `detail` strings
    /// (the variants the producer builds, not synthetic io::Errors). Each must
    /// project to the fatal `ProtocolError` exit and render its detail.
    ///
    /// The DCID-mismatch site formats the offending value into a `Cow::Owned`
    /// detail (verified separately by `register_ok_dcid_mismatch_carries_value`);
    /// the strings iterated here are the common prefixes both producer shapes
    /// render, so the substring assertion holds for the literal and the owned
    /// shape alike.
    #[test]
    fn register_ok_failure_variants_are_typed_protocol_violations() {
        use crate::runtime::session::SessionExit;

        for detail in [
            "register_ok client_to_server_cid mismatch",
            "udp-qsp session missing",
        ] {
            let err = SessionError::ProtocolViolation {
                detail: detail.into(),
            };
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

    /// The DCID-mismatch producer carries the offending value: the two CIDs are
    /// formatted into the `Cow::Owned` detail (not discarded). Pin that both the
    /// expected and received CID bytes survive in the terminal `{:#}` render.
    #[test]
    fn register_ok_dcid_mismatch_carries_offending_value() {
        use slt_core::types::{Cid, MAX_DCID_LEN};

        let expected = Cid::from([0x11; MAX_DCID_LEN]);
        let got = Cid::from([0x22; MAX_DCID_LEN]);
        let err = SessionError::ProtocolViolation {
            detail: format!(
                "register_ok client_to_server_cid mismatch: expected={expected:?}, got={got:?}",
            )
            .into(),
        };
        let rendered = format!("{err:#}");
        // Both offending CID values survive the render (the whole point of
        // widening `detail` to `Cow<'static, str>`). `Cid`'s `Debug` emits the
        // raw byte values, so we assert on the decimal byte values.
        assert!(
            rendered.contains("17, 17, 17, 17"),
            "expected CID bytes missing from render: {rendered:?}"
        );
        assert!(
            rendered.contains("34, 34, 34, 34"),
            "received CID bytes missing from render: {rendered:?}"
        );
    }

    mod backoff_timing {
        use super::*;
        use crate::runtime::ReconnectBackoff;

        #[test]
        fn discovery_backoff_doubles_on_failure() {
            let base = Duration::from_millis(100);
            let max = Duration::from_secs(30);
            let mut backoff = ReconnectBackoff::new(base, max);

            fastrand::seed(42);

            let d1 = backoff.next_delay();
            assert!(d1 >= Duration::from_millis(50) && d1 <= Duration::from_millis(100));

            let d2 = backoff.next_delay();
            assert!(d2 >= Duration::from_millis(100) && d2 <= Duration::from_millis(200));

            let d3 = backoff.next_delay();
            assert!(d3 >= Duration::from_millis(200) && d3 <= Duration::from_millis(400));
        }

        #[test]
        fn registration_backoff_doubles_on_failure() {
            let base = Duration::from_millis(100);
            let max = Duration::from_secs(30);
            let mut backoff = ReconnectBackoff::new(base, max);

            fastrand::seed(123);

            // Simulate multiple registration failures
            let delays: Vec<_> = (0..5).map(|_| backoff.next_delay()).collect();

            // Each delay should be in a valid range for the current backoff level
            assert!(
                delays[0] >= Duration::from_millis(50) && delays[0] <= Duration::from_millis(100)
            );
            assert!(
                delays[1] >= Duration::from_millis(100) && delays[1] <= Duration::from_millis(200)
            );
            assert!(
                delays[2] >= Duration::from_millis(200) && delays[2] <= Duration::from_millis(400)
            );
        }

        #[test]
        fn backoff_capped_at_max() {
            let base = Duration::from_millis(100);
            let max = Duration::from_millis(500);
            let mut backoff = ReconnectBackoff::new(base, max);

            fastrand::seed(42);

            // Exhaust the backoff until it hits the cap
            for _ in 0..10 {
                let _ = backoff.next_delay();
            }

            // Current should be at max
            assert_eq!(backoff.current, max);
        }

        #[test]
        fn backoff_reset_returns_to_base() {
            let base = Duration::from_millis(100);
            let max = Duration::from_secs(30);
            let mut backoff = ReconnectBackoff::new(base, max);

            // Advance backoff
            let _ = backoff.next_delay();
            let _ = backoff.next_delay();
            assert!(backoff.current > base);

            // Reset
            backoff.reset();
            assert_eq!(backoff.current, base);
        }
    }

    mod timeout_deadline {
        use std::time::Instant;

        use super::*;

        #[test]
        fn deadline_in_future() {
            let now = Instant::now();
            let timeout = Duration::from_secs(5);
            let deadline = now + timeout;

            // Deadline should be in the future
            assert!(deadline > now);
            assert!(deadline.duration_since(now) <= timeout);
        }

        #[test]
        fn deadline_elapsed_check() {
            let now = Instant::now();
            let past_deadline = now.checked_sub(Duration::from_secs(1)).unwrap();
            let future_deadline = now + Duration::from_secs(1);

            // Past deadline should be before now
            assert!(past_deadline < now);
            // Future deadline should be after now
            assert!(future_deadline > now);
        }
    }

    mod unexpected_message_handling {
        use slt_core::proto::{RegisterFailCode, RegisterFailPayload};

        #[test]
        fn register_fail_payload_with_unknown_decodes() {
            let buf = [u8::from(RegisterFailCode::Unknown)];
            let decoded = RegisterFailPayload::decode(&buf).unwrap();
            assert_eq!(decoded.code, RegisterFailCode::Unknown);
        }

        #[test]
        fn register_fail_payload_with_not_authenticated_decodes() {
            let buf = [u8::from(RegisterFailCode::NotAuthenticated)];
            let decoded = RegisterFailPayload::decode(&buf).unwrap();
            assert_eq!(decoded.code, RegisterFailCode::NotAuthenticated);
        }
    }
}
