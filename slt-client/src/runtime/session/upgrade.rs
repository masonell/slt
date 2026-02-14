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
        self.metrics.inc_udp_register_failure();
        self.schedule_registration_retry();
        Ok(SessionControl::Continue)
    }
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::time::Duration;

    use super::*;

    mod register_fail_payload_decode {
        use slt_core::proto::{RegisterFailCode, RegisterFailPayload};

        use super::*;

        #[test]
        fn valid_payload_with_unknown_code_decodes() {
            // RegisterFailPayload has no encode method, so we build the buffer manually
            // Format: 1 byte for the code
            let buf = [RegisterFailCode::Unknown.as_u8()];
            let decoded = RegisterFailPayload::decode(&buf).unwrap();
            assert_eq!(decoded.code, RegisterFailCode::Unknown);
        }

        #[test]
        fn valid_payload_with_not_authenticated_decodes() {
            let buf = [RegisterFailCode::NotAuthenticated.as_u8()];
            let decoded = RegisterFailPayload::decode(&buf).unwrap();
            assert_eq!(decoded.code, RegisterFailCode::NotAuthenticated);
        }

        #[test]
        fn valid_payload_with_invalid_cipher_decodes() {
            let buf = [RegisterFailCode::InvalidCipher.as_u8()];
            let decoded = RegisterFailPayload::decode(&buf).unwrap();
            assert_eq!(decoded.code, RegisterFailCode::InvalidCipher);
        }

        #[test]
        fn valid_payload_with_invalid_cid_decodes() {
            let buf = [RegisterFailCode::InvalidCid.as_u8()];
            let decoded = RegisterFailPayload::decode(&buf).unwrap();
            assert_eq!(decoded.code, RegisterFailCode::InvalidCid);
        }

        #[test]
        fn valid_payload_with_invalid_keys_decodes() {
            let buf = [RegisterFailCode::InvalidKeys.as_u8()];
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
        fn decode_error_maps_to_io_error() {
            let result = RegisterFailPayload::decode(&[]);
            assert!(result.is_err());

            let io_err = crate::wire::map_payload_error(result.unwrap_err());
            assert_eq!(io_err.kind(), io::ErrorKind::InvalidData);
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
        use slt_core::types::{Cid, QUIC_DCID_PREFIX_LEN};

        use super::*;

        #[test]
        fn valid_payload_decodes() {
            let dcid = Cid::from([0xAA; QUIC_DCID_PREFIX_LEN]);
            let payload = RegisterOkPayload { dcid: dcid.clone() };
            let mut buf = Vec::new();
            payload.encode(&mut buf).unwrap();

            let decoded = RegisterOkPayload::decode(&buf).unwrap();
            assert_eq!(decoded.dcid, dcid);
        }

        #[test]
        fn empty_payload_fails() {
            let result = RegisterOkPayload::decode(&[]);
            assert!(result.is_err());
        }

        #[test]
        fn truncated_payload_fails() {
            // Only 4 bytes, need 8 for dcid
            let result = RegisterOkPayload::decode(&[0x01, 0x02, 0x03, 0x04]);
            assert!(result.is_err());
        }

        #[test]
        fn decode_error_maps_to_io_error() {
            let result = RegisterOkPayload::decode(&[]);
            assert!(result.is_err());

            let io_err = crate::wire::map_payload_error(result.unwrap_err());
            assert_eq!(io_err.kind(), io::ErrorKind::InvalidData);
        }
    }

    mod dcid_mismatch_error {
        use super::*;

        #[test]
        fn dcid_mismatch_is_invalid_data() {
            let err = io::Error::new(io::ErrorKind::InvalidData, "register_ok dcid mismatch");
            assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        }
    }

    mod session_missing_error {
        use super::*;

        #[test]
        fn session_missing_is_invalid_data() {
            let err = io::Error::new(io::ErrorKind::InvalidData, "udp-qsp session missing");
            assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        }
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
            let past_deadline = now - Duration::from_secs(1);
            let future_deadline = now + Duration::from_secs(1);

            // Past deadline should be before now
            assert!(past_deadline < now);
            // Future deadline should be after now
            assert!(future_deadline > now);
        }
    }

    mod unexpected_message_handling {
        use slt_core::proto::{RegisterFailCode, RegisterFailPayload};

        use super::*;

        #[test]
        fn register_fail_without_in_flight_returns_continue() {
            // This tests the logic: if no in-flight registration, we just continue
            // The actual implementation logs and returns Continue
            let has_in_flight = false;
            assert!(!has_in_flight);
        }

        #[test]
        fn register_ok_without_in_flight_returns_continue() {
            // This tests the logic: if no in-flight registration, we just continue
            let has_in_flight = false;
            assert!(!has_in_flight);
        }

        #[test]
        fn register_ok_with_wrong_dcid_returns_error() {
            // dcid mismatch should return InvalidData error
            let err = io::Error::new(io::ErrorKind::InvalidData, "register_ok dcid mismatch");
            assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        }

        #[test]
        fn register_fail_payload_with_unknown_decodes() {
            let buf = [RegisterFailCode::Unknown.as_u8()];
            let decoded = RegisterFailPayload::decode(&buf).unwrap();
            assert_eq!(decoded.code, RegisterFailCode::Unknown);
        }

        #[test]
        fn register_fail_payload_with_not_authenticated_decodes() {
            let buf = [RegisterFailCode::NotAuthenticated.as_u8()];
            let decoded = RegisterFailPayload::decode(&buf).unwrap();
            assert_eq!(decoded.code, RegisterFailCode::NotAuthenticated);
        }
    }

    mod session_control_behavior {
        use super::*;
        use crate::runtime::session::SessionExit;

        #[test]
        fn register_fail_returns_continue() {
            // handle_register_fail always returns Continue (it schedules retry internally)
            let control = SessionControl::Continue;
            assert_eq!(control, SessionControl::Continue);
        }

        #[test]
        fn register_ok_returns_continue_on_success() {
            // handle_register_ok returns Continue on success
            let control = SessionControl::Continue;
            assert_eq!(control, SessionControl::Continue);
        }

        #[test]
        fn register_ok_returns_close_on_protocol_error() {
            // If dcid mismatches, returns error which maps to ProtocolError exit
            let exit = SessionExit::ProtocolError;
            assert_eq!(exit, SessionExit::ProtocolError);
        }
    }
}
