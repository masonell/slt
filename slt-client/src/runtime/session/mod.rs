//! Client session: manages TCP/UDP transport lifecycle and data flow.
//!
//! This module is organized into submodules by responsibility:
//! - `driver`: Event polling, dispatch, scheduling, and TUN handling
//! - `state`: UDP state machine types
//! - `event`: Event and control enums
//! - `tcp`: TCP message handlers
//! - `udp`: UDP message handlers
//! - `upgrade`: Discovery, registration, and UDP upgrade FSM
//! - `lifecycle`: Ping/pong, shutdown, write helpers

mod driver;
mod error;
mod event;
mod lifecycle;
mod state;
mod tcp;
mod udp;
mod upgrade;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

pub use error::SessionError;
use event::SessionControl;
pub(super) use event::SessionExit;
use slt_core::config::ClientConfig;
use slt_core::proto::MessageLimits;
use slt_core::types::ClientUdpQspCipher;
use state::{ActiveTransport, UdpState, UdpUpgradeState};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use super::ReconnectBackoff;
use super::control::ClientCommandReceiver;
use super::observer::{ClientEventKind, Transport, TransportChangeReason};
use super::services::ClientRuntimeServices;
use crate::metrics::Metrics;
use crate::transport::quic_discovery as quic;
use crate::transport::tcp::{TcpSession, TcpTransport};
use crate::transport::udp_qsp::ClientTransport;
use crate::tun::TunChannels;

/// Session managing a single VPN connection.
///
/// Handles the complete lifecycle of a VPN session including TCP/UDP transport
/// management, message handling, transport upgrades, and idle timeout detection.
pub(super) struct ClientSession<
    'a,
    S: ClientRuntimeServices,
    T: ClientTcpIo = tokio::net::TcpStream,
> {
    config: &'a ClientConfig,
    tcp: TcpTransport<T>,
    peer: Option<SocketAddr>,
    tun_channels: &'a mut TunChannels,
    services: &'a S,
    active_transport: ActiveTransport,
    cancel: CancellationToken,
    limits: MessageLimits,
    /// Receipt time of the latest accepted message on either live transport.
    last_activity: Instant,
    /// Receipt time of the latest authenticated UDP-QSP message.
    last_authenticated_udp_activity: Option<Instant>,
    udp_state: UdpState,
    /// Superseded UDP transport kept alive for authenticated receive traffic
    /// until replacement registration completes.
    retained_udp_transport: Option<Box<ClientTransport>>,
    udp_upgrade: UdpUpgradeState,
    udp_upgrade_backoff: ReconnectBackoff,
    /// Effective UDP-QSP cipher policy for the current connection. Starts as a
    /// copy of the configured policy; under `auto`, flips once to the other
    /// explicit suite if the server rejects the auto-selected suite with
    /// `InvalidCipher`.
    udp_cipher_policy: ClientUdpQspCipher,
    discovery_task: Option<JoinHandle<Option<quic::QuicIds>>>,
    metrics: Arc<Metrics>,
    /// Whether the TCP connection is still usable. Set to false when TCP closes
    /// while UDP-QSP is active, allowing the session to continue on UDP alone.
    tcp_alive: bool,
    /// Locally initiated TCP fallback awaiting its peer acknowledgement.
    pending_tcp_fallback: Option<u64>,
    /// Peer fallback identifier retained for session-long duplicate suppression.
    last_peer_fallback_id: Option<u64>,
    control_rx: Option<&'a mut ClientCommandReceiver>,
}

pub(super) trait ClientTcpIo: AsyncRead + AsyncWrite + Unpin + Send + Sync {}

impl<T: AsyncRead + AsyncWrite + Unpin + Send + Sync> ClientTcpIo for T {}

/// Outcome of running a session to completion.
///
/// The control-flow reason ([`SessionExit`]) is always present so the runtime
/// can decide reconnect policy; the typed [`SessionError`] is present only for
/// the error exits, carrying the source-preserving failure that produced them,
/// and flows to the terminal unchanged.
pub(super) struct SessionOutcome {
    /// Reconnect-policy reason derived from the failure (or the clean-exit
    /// reason). Always present.
    pub(super) exit: SessionExit,
    /// Typed source-preserving failure. `Some` for outcomes built via
    /// `from_error` (the exit is derived from a `SessionError`, which is carried
    /// here as the source); `None` for outcomes built via `from_exit` and for
    /// exits without a typed session error (`Shutdown`, `TcpClosed`,
    /// `TunClosed`, `TunFault`, `IdleTimeout`, `RemoteClose`,
    /// `NetworkChanged`).
    pub(super) error: Option<SessionError>,
}

impl SessionOutcome {
    /// Builds an outcome from a typed session error: the exit reason is
    /// derived from the error via [`SessionError::exit`], and the error is
    /// carried as the source.
    // Not `const`-stable: moving `SessionError` (which owns a non-const-`Drop`
    // `io::Error`) into the `Option` is not allowed in a `const fn` on stable
    // Rust, even though the body is otherwise a pure derivation.
    #[allow(clippy::missing_const_for_fn)]
    fn from_error(err: SessionError) -> Self {
        let exit = err.exit();
        Self {
            exit,
            error: Some(err),
        }
    }

    /// Builds a source-less outcome from a control-flow exit reason.
    const fn from_exit(exit: SessionExit) -> Self {
        Self { exit, error: None }
    }
}

impl<'a, S: ClientRuntimeServices, T: ClientTcpIo> ClientSession<'a, S, T> {
    /// Creates a new session from an authenticated TCP connection.
    ///
    /// Initializes the session with the given TCP transport, configuration,
    /// TUN channels, cancellation token, and a borrow of the platform services
    /// (socket protector, host resolver, observer). UDP state is initialized
    /// based on the effective upgrade policy (`enable_upgrade || require_udp`).
    pub(super) fn new(
        config: &'a ClientConfig,
        tcp: TcpSession<T>,
        tun_channels: &'a mut TunChannels,
        cancel: CancellationToken,
        metrics: Arc<Metrics>,
        services: &'a S,
        control_rx: Option<&'a mut ClientCommandReceiver>,
    ) -> Self {
        let now = Instant::now();
        let limits = MessageLimits::from_mtu(config.tun.tun_mtu);
        let upgrade_enabled = config.enable_upgrade || config.require_udp;

        let udp_state = if upgrade_enabled {
            UdpState::NeedDiscovery {
                backoff: ReconnectBackoff::new(
                    config.timing.reconnect_min,
                    config.timing.reconnect_max,
                ),
                reconnect_at: now,
            }
        } else {
            UdpState::Disabled
        };
        let udp_upgrade = if upgrade_enabled {
            UdpUpgradeState::Idle
        } else {
            UdpUpgradeState::Disabled
        };

        Self {
            config,
            tcp: tcp.transport,
            peer: tcp.peer,
            tun_channels,
            active_transport: ActiveTransport::Tcp,
            cancel,
            limits,
            last_activity: now,
            last_authenticated_udp_activity: None,
            udp_state,
            retained_udp_transport: None,
            udp_upgrade,
            udp_upgrade_backoff: ReconnectBackoff::new(
                config.timing.reconnect_min,
                config.timing.reconnect_max,
            ),
            udp_cipher_policy: config.transport.udp_qsp.cipher,
            discovery_task: None,
            metrics,
            services,
            tcp_alive: true,
            pending_tcp_fallback: None,
            last_peer_fallback_id: None,
            control_rx,
        }
    }

    fn udp_receive_transport(&self) -> Option<&ClientTransport> {
        self.udp_state
            .as_active()
            .or(self.retained_udp_transport.as_deref())
    }

    fn udp_receive_transport_mut(&mut self) -> Option<&mut ClientTransport> {
        self.udp_state
            .as_active_mut()
            .or(self.retained_udp_transport.as_deref_mut())
    }

    /// Records an active-transport change: updates the tracked transport on the
    /// observer sink and emits a typed [`ClientEventKind::TransportChanged`].
    fn note_transport_change(&self, from: Transport, to: Transport, reason: TransportChangeReason) {
        let observer = self.services.observer();
        observer.set_transport(to);
        observer.emit(ClientEventKind::TransportChanged { from, to, reason });
    }
}

#[cfg(test)]
mod tests;
