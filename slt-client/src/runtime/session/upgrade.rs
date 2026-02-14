//! UDP upgrade logic: discovery, registration, and retries.

use std::io;
use std::time::Instant;

use slt_core::proto::{RegisterFailPayload, RegisterOkPayload};
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use super::{ClientSession, SessionControl, UdpState};
use crate::runtime::session::state::{ActiveTransport, PendingUdpQspRegistration};
use crate::runtime::{ReconnectBackoff, register};
use crate::transport::quic_discovery as quic;
use crate::transport::udp_qsp::UdpQspTransport;

impl ClientSession<'_> {
    /// Spawn QUIC discovery task. Returns a `JoinHandle`.
    pub(super) fn spawn_quic_discovery(&self) -> JoinHandle<Option<quic::QuicIds>> {
        let config = self.config.clone();
        let cancel = self.cancel.clone();
        let peer = self.peer;

        tokio::spawn(async move {
            let result = tokio::select! {
                () = cancel.cancelled() => return None,
                result = quic::discover_quic_ids(&config, &cancel, peer) => result,
            };

            match result {
                Ok(ids) => {
                    info!(
                        dcid_len = ids.dcid.len(),
                        scid_len = ids.scid.len(),
                        "quic dcid discovery succeeded"
                    );
                    Some(ids)
                }
                Err(err) => {
                    warn!(error = %err, "quic dcid discovery failed");
                    None
                }
            }
        })
    }

    /// Start a UDP-QSP registration attempt and track it in session state.
    pub(super) async fn attempt_udp_registration(&mut self) {
        let quic_ids = match &mut self.udp_state {
            UdpState::Pending {
                quic_ids,
                registration,
                ..
            } => {
                if registration.is_some() {
                    return;
                }
                quic_ids.clone()
            }
            _ => return,
        };

        match register::start_udp_qsp_registration(&mut self.tcp, &quic_ids).await {
            Ok(prepared) => {
                let deadline = Instant::now() + self.config.timing.register_timeout;
                if let UdpState::Pending { registration, .. } = &mut self.udp_state {
                    *registration =
                        Some(Box::new(PendingUdpQspRegistration { prepared, deadline }));
                }
            }
            Err(err) => {
                warn!(error = %err, "register_cid failed; scheduling retry");
                self.schedule_registration_retry();
            }
        }
    }

    /// Schedule a QUIC discovery retry with backoff.
    pub(super) fn schedule_discovery_retry(&mut self) {
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

    /// Schedule a UDP registration retry with backoff.
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

    /// Handle `REGISTER_OK` received on TCP transport.
    pub(super) fn handle_register_ok(&mut self, payload: &[u8]) -> io::Result<SessionControl> {
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

            let ok = RegisterOkPayload::decode(payload).map_err(crate::wire::map_payload_error)?;
            if ok.dcid != quic_ids.dcid {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "register_ok dcid mismatch",
                ));
            }

            let session = in_flight.prepared.session.take().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "udp-qsp session missing")
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
        self.active_transport = ActiveTransport::UdpQsp;
        self.last_udp_rx = Instant::now();
        self.metrics.inc_transport_tcp_to_udp();
        Ok(SessionControl::Continue)
    }

    /// Handle `REGISTER_FAIL` received on TCP transport.
    pub(super) fn handle_register_fail(&mut self, payload: &[u8]) -> io::Result<SessionControl> {
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

        let fail = RegisterFailPayload::decode(payload).map_err(crate::wire::map_payload_error)?;
        warn!(code = ?fail.code, "register_cid rejected; scheduling retry");
        self.schedule_registration_retry();
        Ok(SessionControl::Continue)
    }
}
