//! UDP upgrade logic: discovery, registration, and retries.

use std::io;
use std::time::Instant;

use slt_core::proto::{
    Message, RegisterFailCode, RegisterFailPayload, RegisterOkPayload, SwitchAckPayload,
    SwitchOkPayload, SwitchToUdpPayload, UdpReadyPayload, UpgradeProbeAckPayload,
    UpgradeProbePayload,
};
use slt_core::types::ClientUdpQspCipher;
use tokio::task::JoinHandle;
use tokio::time;
use tracing::{debug, info, trace, warn};

use super::error::SessionError;
use super::{ClientSession, ClientTcpIo, SessionControl, SessionExit, UdpState};
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
        | UdpUpgradeState::AwaitingSwitchOk { upgrade_id, .. } => Some(*upgrade_id),
        UdpUpgradeState::Disabled
        | UdpUpgradeState::Idle
        | UdpUpgradeState::TcpOnlyBlockedUdp { .. } => None,
    }
}

impl<S: ClientRuntimeServices, T: ClientTcpIo> ClientSession<'_, S, T> {
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
    /// state with a deadline.
    ///
    /// # Errors
    ///
    /// Returns an error if the bounded TCP write fails. A TCP write failure
    /// ends the session so the runtime can reconnect the control channel.
    pub(super) async fn attempt_udp_registration(
        &mut self,
    ) -> Result<SessionControl, SessionError> {
        let quic_ids = match &mut self.udp_state {
            UdpState::Pending {
                quic_ids,
                registration,
                ..
            } => {
                if registration.is_some() {
                    return Ok(SessionControl::Continue);
                }
                quic_ids.clone()
            }
            _ => return Ok(SessionControl::Continue),
        };

        let cipher = register::select_udp_qsp_cipher(self.udp_cipher_policy);
        let prepared = match register::prepare_udp_qsp_registration(&quic_ids, cipher) {
            Ok(prepared) => prepared,
            Err(err) => return Ok(self.handle_registration_setup_failure(&err)),
        };
        self.write_tcp_message(Message::RegisterCid {
            payload: &prepared.payload_buf,
        })
        .await?;

        let deadline = Instant::now() + self.config.timing.register_timeout;
        if let UdpState::Pending { registration, .. } = &mut self.udp_state {
            *registration = Some(Box::new(PendingUdpQspRegistration { prepared, deadline }));
        }
        self.services
            .observer()
            .emit(ClientEventKind::UdpRegisterStarted);
        Ok(SessionControl::Continue)
    }

    fn handle_registration_setup_failure(&mut self, err: &SessionError) -> SessionControl {
        warn!(error = %err, "failed to prepare register_cid");
        if self.config.require_udp {
            warn!("register_cid preparation failed with require_udp=true");
            return SessionControl::Close(SessionExit::UdpUpgradeRequired);
        }
        self.services
            .observer()
            .emit(ClientEventKind::UdpRegisterFailed {
                detail: err.to_string(),
            });
        self.schedule_registration_retry();
        SessionControl::Continue
    }

    /// Schedules a QUIC discovery retry with backoff.
    ///
    /// Transitions to `NeedDiscovery` state (if not already), preserves a live
    /// UDP transport for receive traffic, and sets the reconnect deadline using
    /// exponential backoff with jitter.
    pub(super) fn schedule_discovery_retry(&mut self) {
        self.schedule_discovery_retry_with_receive_path(true);
    }

    /// Retires the failed UDP transport and schedules discovery with backoff.
    pub(super) fn schedule_discovery_retry_after_udp_failure(&mut self) {
        self.schedule_discovery_retry_with_receive_path(false);
    }

    fn schedule_discovery_retry_with_receive_path(&mut self, preserve_receive_path: bool) {
        if !(self.config.enable_upgrade || self.config.require_udp) {
            self.retained_udp_transport = None;
            self.udp_state = UdpState::Disabled;
            self.udp_upgrade = UdpUpgradeState::Disabled;
            self.last_authenticated_udp_activity = None;
            return;
        }

        self.udp_upgrade = UdpUpgradeState::Idle;
        if preserve_receive_path && self.retained_udp_transport.is_none() {
            let state = std::mem::replace(&mut self.udp_state, UdpState::Disabled);
            match state {
                UdpState::Active(transport) => self.retained_udp_transport = Some(transport),
                state => self.udp_state = state,
            }
        } else if !preserve_receive_path {
            self.retained_udp_transport = None;
            self.last_authenticated_udp_activity = None;
        }

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
            self.retained_udp_transport = None;
            self.udp_state = UdpState::Disabled;
            self.udp_upgrade = UdpUpgradeState::Disabled;
            self.last_authenticated_udp_activity = None;
            return;
        }

        self.retained_udp_transport = None;
        self.last_authenticated_udp_activity = None;
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
        let probe_nonce = fastrand::u64(..);
        self.udp_upgrade = UdpUpgradeState::Upgrading {
            upgrade_id,
            deadline: now + self.config.timing.register_timeout,
            attempts: 0,
            next_probe_at: now,
            probe_nonce,
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
        let (quic_ids, session, cipher) = {
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
            let cipher = in_flight.prepared.cipher;
            (quic_ids, session, cipher)
        };

        info!(
            cipher = ?cipher,
            dcid_len = quic_ids.dcid.len(),
            scid_len = quic_ids.scid.len(),
            peer = %quic_ids.peer,
            "register_cid accepted"
        );
        self.udp_state = UdpState::Active(Box::new(UdpQspTransport::new(
            session,
            self.metrics.clone(),
        )));
        self.retained_udp_transport = None;
        self.last_authenticated_udp_activity = None;
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

        // One-shot auto fallback: under `auto`, an `InvalidCipher` rejection means
        // the server's allowlist excludes the suite that was picked. Retry once
        // with the other explicit suite before giving up. Gating on the effective
        // policy still being `Auto` makes this self-disabling -- after the flip it
        // holds an explicit suite, so a second `InvalidCipher` will not flip again.
        if fail.code == RegisterFailCode::InvalidCipher
            && self.config.transport.udp_qsp.cipher == ClientUdpQspCipher::Auto
            && self.udp_cipher_policy == ClientUdpQspCipher::Auto
        {
            self.udp_cipher_policy = register::auto_fallback_policy();
            warn!(
                cipher = ?self.udp_cipher_policy,
                "server rejected auto-selected cipher; retrying with the other suite"
            );
        } else if self.config.require_udp {
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
            UdpUpgradeState::AwaitingSwitchOk { deadline, .. } => {
                if now < *deadline {
                    return Ok(SessionControl::Continue);
                }
                if !self.config.require_udp {
                    self.request_tcp_fallback(TransportChangeReason::UdpError)
                        .await?;
                }
                Ok(self.handle_udp_upgrade_timeout("switch_ok_timeout"))
            }
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
        }
    }

    async fn send_upgrade_probe(&mut self, now: Instant) -> Result<(), SessionError> {
        let (upgrade_id, nonce, attempts) = {
            let UdpUpgradeState::Upgrading {
                upgrade_id,
                attempts,
                next_probe_at,
                probe_nonce,
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

            *attempts = attempts.saturating_add(1);
            *next_probe_at = now + probe_backoff.next_delay();
            (*upgrade_id, *probe_nonce, *attempts)
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
                    if !self.handle_udp_error(&err).await? {
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

    /// Single recovery path for a timed-out probe or switch phase.
    ///
    /// Under `require_udp` a timeout is fatal (`UdpUpgradeRequired`); otherwise
    /// the attempt backs off to `TcpOnlyBlockedUdp` so traffic keeps flowing on
    /// TCP, and `timer_at` re-arms at `retry_at` to start a fresh attempt after
    /// the cooldown.
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
            probe_nonce,
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

            if ack.nonce != *probe_nonce {
                trace!(
                    expected_nonce = *probe_nonce,
                    received_nonce = ack.nonce,
                    "ignoring udp upgrade probe ack with mismatched nonce"
                );
                return Ok(SessionControl::Continue);
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
        self.write_tcp_message(Message::UdpReady { payload: &buf })
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

        if let UdpUpgradeState::Upgrading {
            upgrade_id,
            probe_acked,
            ready_sent,
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
        } else {
            trace!(
                upgrade_id = switch.upgrade_id,
                "ignoring switch_to_udp without active upgrade"
            );
            return Ok(SessionControl::Continue);
        }

        let ack = SwitchAckPayload {
            upgrade_id: switch.upgrade_id,
        };
        let mut switch_ack_buf = Vec::with_capacity(8);
        ack.encode(&mut switch_ack_buf);
        self.write_tcp_message(Message::SwitchAck {
            payload: &switch_ack_buf,
        })
        .await?;
        self.udp_upgrade = UdpUpgradeState::AwaitingSwitchOk {
            upgrade_id: switch.upgrade_id,
            deadline: Instant::now() + self.config.timing.register_timeout,
        };
        info!(
            upgrade_id = switch.upgrade_id,
            "sent switch_ack; awaiting switch_ok"
        );
        Ok(SessionControl::Continue)
    }

    pub(super) fn handle_switch_ok(
        &mut self,
        payload: &[u8],
    ) -> Result<SessionControl, SessionError> {
        let ok = SwitchOkPayload::decode(payload)?;
        let UdpUpgradeState::AwaitingSwitchOk { upgrade_id, .. } = &self.udp_upgrade else {
            trace!(
                upgrade_id = ok.upgrade_id,
                "ignoring switch_ok without pending switch acknowledgement"
            );
            return Ok(SessionControl::Continue);
        };
        if ok.upgrade_id != *upgrade_id {
            debug!(
                expected_upgrade_id = *upgrade_id,
                received_upgrade_id = ok.upgrade_id,
                "ignoring switch_ok with mismatched upgrade_id"
            );
            return Ok(SessionControl::Continue);
        }

        if self.active_transport != ActiveTransport::UdpQsp {
            self.metrics.inc_transport_tcp_to_udp();
            self.active_transport = ActiveTransport::UdpQsp;
            self.note_transport_change(
                Transport::Tcp,
                Transport::UdpQsp,
                TransportChangeReason::UpgradeCommitted,
            );
        }
        self.udp_upgrade = UdpUpgradeState::Idle;
        self.udp_upgrade_backoff.reset();
        self.pending_tcp_fallback = None;
        self.services
            .observer()
            .emit(ClientEventKind::UdpSwitchCommitted {
                upgrade_id: ok.upgrade_id,
            });
        info!(upgrade_id = ok.upgrade_id, "udp upgrade committed");
        Ok(SessionControl::Continue)
    }
}

#[cfg(test)]
mod tests;
