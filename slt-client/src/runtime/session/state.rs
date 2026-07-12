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
        /// Probe nonce shared by all retransmissions in this attempt.
        probe_nonce: u64,
        /// Whether a valid `UpgradeProbeAck` has been observed.
        probe_acked: bool,
        /// Whether `UdpReady` has been sent on TCP.
        ready_sent: bool,
        /// Probe retransmit backoff.
        probe_backoff: ReconnectBackoff,
    },
    /// Client accepted the switch request and awaits server-side commit confirmation.
    AwaitingSwitchOk {
        /// Attempt identifier echoed in `SWITCH_OK`.
        upgrade_id: u64,
        /// Deadline for receiving the confirmation on TCP.
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
            Self::AwaitingSwitchOk { deadline, .. } => Some(*deadline),
            Self::TcpOnlyBlockedUdp { retry_at } => Some(*retry_at),
        }
    }
}

/// Preferred transport for outbound data flow.
///
/// The session uses one preferred transport for outbound data. Authenticated
/// inbound data remains valid on either live transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ActiveTransport {
    /// TCP transport.
    Tcp,
    /// UDP-QSP transport.
    UdpQsp,
}

#[cfg(test)]
mod tests;
