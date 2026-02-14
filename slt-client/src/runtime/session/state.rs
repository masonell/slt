//! UDP transport lifecycle state types.
use crate::runtime::ReconnectBackoff;
use crate::runtime::register::PreparedUdpQspRegistration;
use crate::transport::quic_discovery as quic;
use crate::transport::udp_qsp::UdpQspTransport;
use std::time::Instant;

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
