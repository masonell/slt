//! UDP transport lifecycle state types.
use std::time::Instant;

use crate::runtime::ReconnectBackoff;
use crate::runtime::register::PreparedUdpQspRegistration;
use crate::transport::quic_discovery as quic;
use crate::transport::udp_qsp::UdpQspTransport;

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
    Active(Box<UdpQspTransport>),
}

/// In-flight `REGISTER_CID` exchange state managed by the main session loop.
pub(super) struct PendingUdpQspRegistration {
    pub(super) prepared: PreparedUdpQspRegistration,
    pub(super) deadline: Instant,
}

impl UdpState {
    /// Returns true if waiting for reconnect timer (`NeedDiscovery` or `Pending` without in-flight registration).
    pub(super) const fn is_waiting(&self) -> bool {
        match self {
            Self::NeedDiscovery { .. } => true,
            Self::Pending { registration, .. } => registration.is_none(),
            Self::Disabled | Self::Active(_) => false,
        }
    }

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

    pub(super) const fn register_deadline(&self) -> Option<Instant> {
        match self {
            Self::Pending {
                registration: Some(registration),
                ..
            } => Some(registration.deadline),
            _ => None,
        }
    }

    pub(super) const fn as_active(&self) -> Option<&UdpQspTransport> {
        match self {
            Self::Active(transport) => Some(transport),
            _ => None,
        }
    }

    pub(super) fn as_active_mut(&mut self) -> Option<&mut UdpQspTransport> {
        match self {
            Self::Active(transport) => Some(transport),
            _ => None,
        }
    }
}

/// Currently active transport for data flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ActiveTransport {
    Tcp,
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
}
