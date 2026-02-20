//! UDP transport lifecycle state types.
use std::time::Instant;

use crate::runtime::ReconnectBackoff;
use crate::runtime::register::PreparedUdpQspRegistration;
use crate::transport::quic_discovery as quic;
use crate::transport::udp_qsp::ClientTransport;

/// UDP transport lifecycle state.
pub(super) enum UdpState {
    /// Upgrade disabled in config.
    Disabled,
    /// Need to discover `quic_ids` (or discovery in progress via `discovery_task`).
    NeedDiscovery {
        backoff: ReconnectBackoff,
        reconnect_at: Instant,
    },
    /// Have `quic_ids`, need to register UDP.
    Pending {
        quic_ids: quic::QuicIds,
        backoff: ReconnectBackoff,
        reconnect_at: Instant,
        registration: Option<Box<PendingUdpQspRegistration>>,
    },
    /// Connected and working.
    Active(Box<ClientTransport>),
}

/// In-flight `REGISTER_CID` exchange state managed by the main session loop.
///
/// Tracks a pending UDP-QSP registration attempt including the prepared
/// registration data and the timeout deadline for the server's response.
pub(super) struct PendingUdpQspRegistration {
    /// Prepared registration payload and UDP-QSP session.
    pub(super) prepared: PreparedUdpQspRegistration,
    /// Deadline for receiving `REGISTER_OK` or `REGISTER_FAIL`.
    pub(super) deadline: Instant,
}

impl UdpState {
    /// Returns `true` if waiting for reconnect timer.
    ///
    /// Returns `true` for `NeedDiscovery` or `Pending` without an in-flight
    /// registration, `false` otherwise.
    pub(super) const fn is_waiting(&self) -> bool {
        match self {
            Self::NeedDiscovery { .. } => true,
            Self::Pending { registration, .. } => registration.is_none(),
            Self::Disabled | Self::Active(_) => false,
        }
    }

    /// Returns the reconnect deadline if waiting for a retry timer.
    ///
    /// Returns `Some(deadline)` for `NeedDiscovery` or `Pending` without an
    /// in-flight registration, `None` otherwise.
    pub(super) fn reconnect_at(&self) -> Option<Instant> {
        match self {
            Self::NeedDiscovery { reconnect_at, .. } => Some(*reconnect_at),
            Self::Pending {
                reconnect_at,
                registration,
                ..
            } => registration.is_none().then_some(*reconnect_at),
            _ => None,
        }
    }

    /// Returns the registration deadline if an in-flight registration exists.
    ///
    /// Returns `Some(deadline)` only for `Pending` with an in-flight
    /// registration, `None` otherwise.
    pub(super) const fn register_deadline(&self) -> Option<Instant> {
        match self {
            Self::Pending {
                registration: Some(registration),
                ..
            } => Some(registration.deadline),
            _ => None,
        }
    }

    /// Returns a reference to the active UDP transport if in `Active` state.
    pub(super) const fn as_active(&self) -> Option<&ClientTransport> {
        match self {
            Self::Active(transport) => Some(transport),
            _ => None,
        }
    }

    /// Returns a mutable reference to the active UDP transport if in `Active` state.
    pub(super) fn as_active_mut(&mut self) -> Option<&mut ClientTransport> {
        match self {
            Self::Active(transport) => Some(transport),
            _ => None,
        }
    }
}

/// Client-side UDP upgrade handshake state.
pub(super) enum UdpUpgradeState {
    /// Upgrade disabled by configuration.
    Disabled,
    /// UDP transport is available, no upgrade attempt in flight.
    Idle,
    /// Upgrade attempt in progress.
    Upgrading {
        /// Attempt identifier shared across probe/ack/ready/switch.
        upgrade_id: u64,
        /// Hard deadline for this attempt.
        deadline: Instant,
        /// Number of probes sent in this attempt.
        attempts: u32,
        /// Next probe send deadline.
        next_probe_at: Instant,
        /// Last probe nonce sent.
        last_probe_nonce: u64,
        /// Whether a valid `UpgradeProbeAck` has been observed.
        probe_acked: bool,
        /// Whether `UdpReady` has been sent on TCP.
        ready_sent: bool,
        /// Probe retransmit backoff.
        probe_backoff: ReconnectBackoff,
    },
    /// Switch was acknowledged on TCP; wait for commit barrier pong.
    AwaitingSwitchCommit {
        /// Attempt identifier shared across probe/ack/ready/switch.
        upgrade_id: u64,
        /// Nonce used for the TCP ping/pong commit barrier.
        barrier_nonce: u64,
        /// Hard deadline for this attempt.
        deadline: Instant,
    },
    /// Upgrade is temporarily blocked after timeout/failure.
    TcpOnlyBlockedUdp {
        /// Earliest time to start another upgrade attempt.
        retry_at: Instant,
    },
}

impl UdpUpgradeState {
    /// Return the next timer deadline this state needs, if any.
    pub(super) fn timer_at(&self) -> Option<Instant> {
        match self {
            Self::Disabled | Self::Idle => None,
            Self::Upgrading {
                deadline,
                next_probe_at,
                probe_acked,
                ..
            } => {
                if *probe_acked {
                    Some(*deadline)
                } else {
                    Some((*next_probe_at).min(*deadline))
                }
            }
            Self::AwaitingSwitchCommit { deadline, .. } => Some(*deadline),
            Self::TcpOnlyBlockedUdp { retry_at } => Some(*retry_at),
        }
    }
}

/// Currently active transport for data flow.
///
/// The session uses exactly one transport at a time for sending data.
/// Transport switching can occur based on network conditions or server
/// direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ActiveTransport {
    /// TCP transport.
    Tcp,
    /// UDP-QSP transport.
    UdpQsp,
}

#[cfg(test)]
mod tests {
    use super::*;

    mod active_transport {
        use super::*;

        #[test]
        fn tcp_is_tcp() {
            assert_eq!(ActiveTransport::Tcp, ActiveTransport::Tcp);
        }

        #[test]
        fn udp_qsp_is_udp_qsp() {
            assert_eq!(ActiveTransport::UdpQsp, ActiveTransport::UdpQsp);
        }

        #[test]
        fn tcp_is_not_udp_qsp() {
            assert_ne!(ActiveTransport::Tcp, ActiveTransport::UdpQsp);
        }

        #[test]
        fn variants_are_debug_clone_copy() {
            let tcp = ActiveTransport::Tcp;
            let _tcp_copy: ActiveTransport = tcp;
            assert!(format!("{tcp:?}").contains("Tcp"));
        }
    }

    mod udp_upgrade_state {
        use std::time::{Duration, Instant};

        use super::*;

        #[test]
        fn awaiting_switch_commit_timer_uses_deadline() {
            let deadline = Instant::now() + Duration::from_secs(5);
            let state = UdpUpgradeState::AwaitingSwitchCommit {
                upgrade_id: 7,
                barrier_nonce: 9,
                deadline,
            };
            assert_eq!(state.timer_at(), Some(deadline));
        }

        #[test]
        fn upgrading_with_probe_acked_uses_deadline() {
            let deadline = Instant::now() + Duration::from_secs(5);
            let state = UdpUpgradeState::Upgrading {
                upgrade_id: 7,
                deadline,
                attempts: 2,
                next_probe_at: Instant::now() + Duration::from_secs(1),
                last_probe_nonce: 11,
                probe_acked: true,
                ready_sent: true,
                probe_backoff: ReconnectBackoff::new(
                    Duration::from_secs(1),
                    Duration::from_secs(2),
                ),
            };
            assert_eq!(state.timer_at(), Some(deadline));
        }
    }

    mod udp_state {
        use std::time::{Duration, Instant};

        use super::*;

        #[test]
        fn disabled_is_not_waiting() {
            let state = UdpState::Disabled;
            assert!(!state.is_waiting());
        }

        #[test]
        fn disabled_has_no_reconnect_at() {
            let state = UdpState::Disabled;
            assert!(state.reconnect_at().is_none());
        }

        #[test]
        fn disabled_has_no_register_deadline() {
            let state = UdpState::Disabled;
            assert!(state.register_deadline().is_none());
        }

        #[test]
        fn disabled_has_no_active_transport() {
            let state = UdpState::Disabled;
            assert!(state.as_active().is_none());
        }

        #[test]
        fn need_discovery_is_waiting() {
            let backoff = ReconnectBackoff::new(Duration::from_secs(1), Duration::from_secs(30));
            let state = UdpState::NeedDiscovery {
                backoff,
                reconnect_at: Instant::now(),
            };
            assert!(state.is_waiting());
        }

        #[test]
        fn need_discovery_has_reconnect_at() {
            let backoff = ReconnectBackoff::new(Duration::from_secs(1), Duration::from_secs(30));
            let reconnect_at = Instant::now();
            let state = UdpState::NeedDiscovery {
                backoff,
                reconnect_at,
            };
            assert_eq!(state.reconnect_at(), Some(reconnect_at));
        }

        #[test]
        fn need_discovery_has_no_register_deadline() {
            let backoff = ReconnectBackoff::new(Duration::from_secs(1), Duration::from_secs(30));
            let state = UdpState::NeedDiscovery {
                backoff,
                reconnect_at: Instant::now(),
            };
            assert!(state.register_deadline().is_none());
        }
    }

    mod pending_state {
        use std::time::{Duration, Instant};

        use super::*;
        use crate::test_support::mock_quic_ids_sync;

        fn make_pending_state_without_registration() -> UdpState {
            let backoff = ReconnectBackoff::new(Duration::from_secs(1), Duration::from_secs(30));
            let quic_ids = mock_quic_ids_sync();
            UdpState::Pending {
                quic_ids,
                backoff,
                reconnect_at: Instant::now(),
                registration: None,
            }
        }

        #[test]
        fn pending_without_registration_is_waiting() {
            let state = make_pending_state_without_registration();
            assert!(state.is_waiting());
        }

        #[test]
        fn pending_without_registration_has_reconnect_at() {
            let reconnect_at = Instant::now();
            let backoff = ReconnectBackoff::new(Duration::from_secs(1), Duration::from_secs(30));
            let quic_ids = mock_quic_ids_sync();
            let state = UdpState::Pending {
                quic_ids,
                backoff,
                reconnect_at,
                registration: None,
            };
            assert_eq!(state.reconnect_at(), Some(reconnect_at));
        }

        #[test]
        fn pending_without_registration_has_no_register_deadline() {
            let state = make_pending_state_without_registration();
            assert!(state.register_deadline().is_none());
        }

        #[test]
        fn pending_without_registration_has_no_active_transport() {
            let state = make_pending_state_without_registration();
            assert!(state.as_active().is_none());
        }

        #[test]
        fn pending_with_registration_is_not_waiting() {
            let backoff = ReconnectBackoff::new(Duration::from_secs(1), Duration::from_secs(30));
            let quic_ids = mock_quic_ids_sync();
            let rt = tokio::runtime::Runtime::new().unwrap();
            let prepared = rt.block_on(async {
                crate::runtime::register::prepare_udp_qsp_registration(&quic_ids).unwrap()
            });
            let registration = Some(Box::new(PendingUdpQspRegistration {
                prepared,
                deadline: Instant::now() + Duration::from_secs(5),
            }));
            let state = UdpState::Pending {
                quic_ids,
                backoff,
                reconnect_at: Instant::now(),
                registration,
            };
            assert!(!state.is_waiting());
        }

        #[test]
        fn pending_with_registration_has_no_reconnect_at() {
            let backoff = ReconnectBackoff::new(Duration::from_secs(1), Duration::from_secs(30));
            let quic_ids = mock_quic_ids_sync();
            let rt = tokio::runtime::Runtime::new().unwrap();
            let prepared = rt.block_on(async {
                crate::runtime::register::prepare_udp_qsp_registration(&quic_ids).unwrap()
            });
            let registration = Some(Box::new(PendingUdpQspRegistration {
                prepared,
                deadline: Instant::now() + Duration::from_secs(5),
            }));
            let state = UdpState::Pending {
                quic_ids,
                backoff,
                reconnect_at: Instant::now(),
                registration,
            };
            assert!(state.reconnect_at().is_none());
        }

        #[test]
        fn pending_with_registration_has_register_deadline() {
            let deadline = Instant::now() + Duration::from_secs(5);
            let backoff = ReconnectBackoff::new(Duration::from_secs(1), Duration::from_secs(30));
            let quic_ids = mock_quic_ids_sync();
            let rt = tokio::runtime::Runtime::new().unwrap();
            let prepared = rt.block_on(async {
                crate::runtime::register::prepare_udp_qsp_registration(&quic_ids).unwrap()
            });
            let registration = Some(Box::new(PendingUdpQspRegistration { prepared, deadline }));
            let state = UdpState::Pending {
                quic_ids,
                backoff,
                reconnect_at: Instant::now(),
                registration,
            };
            assert_eq!(state.register_deadline(), Some(deadline));
        }

        #[test]
        fn pending_with_registration_has_no_active_transport() {
            let backoff = ReconnectBackoff::new(Duration::from_secs(1), Duration::from_secs(30));
            let quic_ids = mock_quic_ids_sync();
            let rt = tokio::runtime::Runtime::new().unwrap();
            let prepared = rt.block_on(async {
                crate::runtime::register::prepare_udp_qsp_registration(&quic_ids).unwrap()
            });
            let registration = Some(Box::new(PendingUdpQspRegistration {
                prepared,
                deadline: Instant::now() + Duration::from_secs(5),
            }));
            let state = UdpState::Pending {
                quic_ids,
                backoff,
                reconnect_at: Instant::now(),
                registration,
            };
            assert!(state.as_active().is_none());
        }
    }

    mod active_state {
        use std::sync::Arc;

        use slt_core::crypto::udp_qsp::{QuicQspSession, UdpQspKeys};
        use slt_core::proto::CipherSuite;
        use slt_core::types::{Cid, MAX_DCID_LEN};
        use tokio::net::UdpSocket;

        use super::*;
        use crate::metrics::Metrics;
        use crate::transport::udp_qsp::ClientTransport;

        fn make_active_state() -> UdpState {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
                let peer: std::net::SocketAddr = "127.0.0.1:443".parse().unwrap();
                let io = crate::transport::udp_qsp::ClientUdpIo::new(socket, peer);

                let dcid = Cid::from([0xAA; MAX_DCID_LEN]);
                let scid = Cid::from([0xBB; MAX_DCID_LEN]);

                let keys = UdpQspKeys::new(
                    CipherSuite::Aes128Gcm,
                    [0u8; 16],
                    [0u8; 16],
                    [0u8; 16],
                    [0u8; 16],
                    [0u8; 12],
                    [0u8; 12],
                )
                .unwrap();

                let session = QuicQspSession::new(io, scid, dcid, keys, 0, 0, false);
                let metrics = Arc::new(Metrics::default());
                let transport = ClientTransport::new(session, metrics);
                UdpState::Active(Box::new(transport))
            })
        }

        #[test]
        fn active_is_not_waiting() {
            let state = make_active_state();
            assert!(!state.is_waiting());
        }

        #[test]
        fn active_has_no_reconnect_at() {
            let state = make_active_state();
            assert!(state.reconnect_at().is_none());
        }

        #[test]
        fn active_has_no_register_deadline() {
            let state = make_active_state();
            assert!(state.register_deadline().is_none());
        }

        #[test]
        fn active_has_active_transport() {
            let state = make_active_state();
            assert!(state.as_active().is_some());
        }

        #[test]
        fn active_mut_returns_mutable_transport() {
            let mut state = make_active_state();
            assert!(state.as_active_mut().is_some());
        }
    }

    mod state_transitions {
        use std::sync::Arc;
        use std::time::{Duration, Instant};

        use slt_core::crypto::udp_qsp::{QuicQspSession, UdpQspKeys};
        use slt_core::proto::CipherSuite;
        use slt_core::types::{Cid, MAX_DCID_LEN};
        use tokio::net::UdpSocket;

        use super::*;
        use crate::metrics::Metrics;
        use crate::test_support::mock_quic_ids_sync;
        use crate::transport::udp_qsp::ClientTransport;

        #[test]
        fn need_discovery_to_pending_transition() {
            // Simulate discovery success: NeedDiscovery -> Pending
            let backoff = ReconnectBackoff::new(Duration::from_secs(1), Duration::from_secs(30));
            let initial_state = UdpState::NeedDiscovery {
                backoff,
                reconnect_at: Instant::now(),
            };

            // Verify initial state
            assert!(initial_state.is_waiting());
            assert!(initial_state.reconnect_at().is_some());
            assert!(initial_state.register_deadline().is_none());

            // After discovery success, state becomes Pending with fresh backoff
            let quic_ids = mock_quic_ids_sync();
            let new_backoff =
                ReconnectBackoff::new(Duration::from_secs(1), Duration::from_secs(30));
            let new_state = UdpState::Pending {
                quic_ids,
                backoff: new_backoff,
                reconnect_at: Instant::now(),
                registration: None,
            };

            // Verify new state
            assert!(new_state.is_waiting());
            assert!(new_state.reconnect_at().is_some());
            assert!(new_state.register_deadline().is_none());
        }

        #[test]
        fn pending_to_active_transition() {
            // Simulate registration success: Pending -> Active
            let backoff = ReconnectBackoff::new(Duration::from_secs(1), Duration::from_secs(30));
            let quic_ids = mock_quic_ids_sync();
            let initial_state = UdpState::Pending {
                quic_ids,
                backoff,
                reconnect_at: Instant::now(),
                registration: None,
            };

            // Verify initial state
            assert!(initial_state.is_waiting());
            assert!(initial_state.reconnect_at().is_some());

            // After registration success, state becomes Active
            let rt = tokio::runtime::Runtime::new().unwrap();
            let new_state = rt.block_on(async {
                let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
                let peer: std::net::SocketAddr = "127.0.0.1:443".parse().unwrap();
                let io = crate::transport::udp_qsp::ClientUdpIo::new(socket, peer);

                let dcid = Cid::from([0xAA; MAX_DCID_LEN]);
                let scid = Cid::from([0xBB; MAX_DCID_LEN]);

                let keys = UdpQspKeys::new(
                    CipherSuite::Aes128Gcm,
                    [0u8; 16],
                    [0u8; 16],
                    [0u8; 16],
                    [0u8; 16],
                    [0u8; 12],
                    [0u8; 12],
                )
                .unwrap();

                let session = QuicQspSession::new(io, scid, dcid, keys, 0, 0, false);
                let metrics = Arc::new(Metrics::default());
                let transport = ClientTransport::new(session, metrics);
                UdpState::Active(Box::new(transport))
            });

            // Verify new state
            assert!(!new_state.is_waiting());
            assert!(new_state.reconnect_at().is_none());
            assert!(new_state.register_deadline().is_none());
            assert!(new_state.as_active().is_some());
        }

        #[test]
        fn pending_retry_clears_registration() {
            // Simulate registration failure: Pending with registration -> Pending without
            let backoff = ReconnectBackoff::new(Duration::from_secs(1), Duration::from_secs(30));
            let quic_ids = mock_quic_ids_sync();
            let rt = tokio::runtime::Runtime::new().unwrap();
            let prepared = rt.block_on(async {
                crate::runtime::register::prepare_udp_qsp_registration(&quic_ids).unwrap()
            });
            let registration = Some(Box::new(PendingUdpQspRegistration {
                prepared,
                deadline: Instant::now() + Duration::from_secs(5),
            }));

            let state_before = UdpState::Pending {
                quic_ids: mock_quic_ids_sync(),
                backoff,
                reconnect_at: Instant::now(),
                registration,
            };

            // Before retry: has registration, not waiting
            assert!(!state_before.is_waiting());
            assert!(state_before.register_deadline().is_some());

            // After retry scheduling: registration cleared, waiting again
            let state_after = UdpState::Pending {
                quic_ids: mock_quic_ids_sync(),
                backoff: ReconnectBackoff::new(Duration::from_secs(1), Duration::from_secs(30)),
                reconnect_at: Instant::now() + Duration::from_secs(2),
                registration: None,
            };

            assert!(state_after.is_waiting());
            assert!(state_after.register_deadline().is_none());
            assert!(state_after.reconnect_at().is_some());
        }

        #[test]
        fn discovery_retry_updates_reconnect_at() {
            // Discovery failure: NeedDiscovery -> NeedDiscovery with new reconnect_at
            let initial_time = Instant::now();
            let backoff = ReconnectBackoff::new(Duration::from_secs(1), Duration::from_secs(30));
            let state_before = UdpState::NeedDiscovery {
                backoff,
                reconnect_at: initial_time,
            };

            // Simulate backoff delay
            let new_time = initial_time + Duration::from_secs(2);
            let new_backoff =
                ReconnectBackoff::new(Duration::from_secs(1), Duration::from_secs(30));
            let state_after = UdpState::NeedDiscovery {
                backoff: new_backoff,
                reconnect_at: new_time,
            };

            // Both are waiting
            assert!(state_before.is_waiting());
            assert!(state_after.is_waiting());

            // reconnect_at has changed
            assert!(state_after.reconnect_at().unwrap() > state_before.reconnect_at().unwrap());
        }
    }
}
