//! Client session: manages TCP/UDP transport lifecycle and data flow.
//!
//! This module is organized into submodules by responsibility:
//! - `state`: UDP state machine types
//! - `event`: Event and control enums
//! - `tcp`: TCP message handlers
//! - `udp`: UDP message handlers
//! - `upgrade`: Discovery, registration, and UDP upgrade FSM
//! - `lifecycle`: Ping/pong, shutdown, write helpers

mod error;
mod event;
mod lifecycle;
mod state;
mod tcp;
mod udp;
mod upgrade;

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

pub use error::SessionError;
pub(super) use event::SessionExit;
use event::{SessionControl, SessionEvent};
use slt_core::config::ClientConfig;
use slt_core::proto::{CloseCode, Message, MessageLimits};
use slt_core::types::ClientUdpQspCipher;
use state::{ActiveTransport, UdpState, UdpUpgradeState};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::task::JoinHandle;
use tokio::time;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use super::ReconnectBackoff;
use super::control::{ClientCommand, ClientCommandReceiver};
use super::observer::{ClientEventKind, Transport, TransportChangeReason};
use super::services::ClientRuntimeServices;
use crate::metrics::Metrics;
use crate::transport::quic_discovery as quic;
use crate::transport::tcp::{TcpSession, TcpTransport};
use crate::transport::udp_qsp::{ClientTransport, UdpQspError};
use crate::tun::{TunChannels, TunTask};

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

#[derive(Clone, Copy)]
enum SessionTimer {
    Ping,
    Idle,
    UdpLiveness,
    UdpReconnect,
    Register,
    UdpUpgrade,
}

impl SessionTimer {
    const fn into_event(self) -> SessionEvent {
        match self {
            Self::Ping => SessionEvent::PingTick,
            Self::Idle => SessionEvent::IdleTimeout,
            Self::UdpLiveness => SessionEvent::UdpLivenessTimeout,
            Self::UdpReconnect => SessionEvent::UdpReconnectTick,
            Self::Register => SessionEvent::RegisterTimeout,
            Self::UdpUpgrade => SessionEvent::UdpUpgradeTick,
        }
    }
}

/// Effect of a handled event on TUN polling while a partial UDP batch is pending.
#[derive(Clone, Copy)]
enum TunScheduling {
    UdpFlush,
    BatchablePacket,
    NonBatchingTun,
    Unchanged,
}

impl TunScheduling {
    const fn defer_tun(
        self,
        was_deferred: bool,
        flush_was_pending: bool,
        flush_is_pending: bool,
    ) -> bool {
        match self {
            Self::UdpFlush | Self::BatchablePacket => false,
            Self::NonBatchingTun => flush_was_pending && flush_is_pending,
            Self::Unchanged => was_deferred && flush_is_pending,
        }
    }
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

    /// Runs the session event loop until shutdown or error.
    ///
    /// Polls for events from TCP, UDP, TUN, timers, and the cancellation token.
    /// Dispatches each event to the appropriate handler and continues until
    /// the session exits for any reason.
    pub(super) async fn run(&mut self, tun_fault: &CancellationToken) -> SessionOutcome {
        let cancel = self.cancel.clone();
        let outcome = tokio::select! {
            biased;

            () = tun_fault.cancelled() => {
                warn!("tun task failure requested session cleanup");
                SessionOutcome::from_exit(SessionExit::TunFault)
            }
            () = cancel.cancelled() => {
                info!("shutdown requested");
                self.metrics.inc_disconnect_shutdown();
                SessionOutcome::from_exit(SessionExit::Shutdown)
            }
            outcome = self.run_inner() => outcome,
        };

        match outcome.exit {
            SessionExit::Shutdown => {
                self.send_close_best_effort(CloseCode::Normal, "shutdown")
                    .await;
            }
            SessionExit::TunClosed(_) | SessionExit::TunFault => {
                self.send_close_best_effort(CloseCode::Normal, "tun_failure")
                    .await;
            }
            SessionExit::ProtocolError => {
                self.send_close_best_effort(CloseCode::ProtocolError, "protocol_error")
                    .await;
            }
            _ => {}
        }
        self.flush_pending_udp_transport_best_effort().await;
        self.shutdown_background_tasks().await;
        outcome
    }

    async fn run_inner(&mut self) -> SessionOutcome {
        match self.run_event_loop().await {
            Ok(exit) => SessionOutcome::from_exit(exit),
            Err(err) => {
                self.metrics.inc_disconnect_error();
                SessionOutcome::from_error(err)
            }
        }
    }

    async fn run_event_loop(&mut self) -> Result<SessionExit, SessionError> {
        let mut next_ping_at = self.schedule_next_ping();
        let mut defer_tun_until_flush = false;

        loop {
            if self.tcp_alive
                && self.tcp.has_buffered_input()
                && let SessionControl::Close(exit) = self.handle_tcp_read().await?
            {
                return Ok(exit);
            }

            let flush_was_pending = self.has_pending_udp_flush();
            defer_tun_until_flush &= flush_was_pending;
            let event = self
                .poll_event(next_ping_at, !defer_tun_until_flush)
                .await?;
            let tun_scheduling = self.tun_scheduling(&event);

            if let SessionControl::Close(exit) = self.handle_event(event, &mut next_ping_at).await?
            {
                return Ok(exit);
            }

            defer_tun_until_flush = tun_scheduling.defer_tun(
                defer_tun_until_flush,
                flush_was_pending,
                self.has_pending_udp_flush(),
            );
        }
    }

    /// Records an active-transport change: updates the tracked transport on the
    /// observer sink and emits a typed [`ClientEventKind::TransportChanged`].
    fn note_transport_change(&self, from: Transport, to: Transport, reason: TransportChangeReason) {
        let observer = self.services.observer();
        observer.set_transport(to);
        observer.emit(ClientEventKind::TransportChanged { from, to, reason });
    }

    /// Polls for the next session event.
    ///
    /// Uses `tokio::select!` to wait for the first of:
    /// - Shutdown signal
    /// - TCP data (if TCP is alive)
    /// - TUN packet
    /// - UDP-QSP message (if UDP is active)
    /// - Ping timer
    /// - Idle timeout
    /// - UDP-QSP liveness timeout
    /// - UDP reconnect timer (if waiting)
    /// - Registration timeout (if in-flight registration)
    /// - Discovery task completion (if discovery is running)
    async fn poll_event(
        &mut self,
        next_ping_at: Instant,
        can_receive_tun: bool,
    ) -> Result<SessionEvent, SessionError> {
        let limits = self.limits;
        let idle_deadline = self.last_activity + self.config.timing.idle_timeout;
        let udp_reconnect_at = self.udp_state.reconnect_at();
        let register_deadline = self.udp_state.register_deadline();
        let udp_enabled = self.udp_receive_transport().is_some();
        let has_discovery_task = self.discovery_task.is_some();
        let udp_upgrade_timer_at = self.udp_upgrade.timer_at();
        let udp_pending_flush = self.has_pending_udp_flush();

        let mut timer_at = idle_deadline;
        let mut timer = SessionTimer::Idle;
        update_earliest_timer(
            &mut timer_at,
            &mut timer,
            Some(next_ping_at),
            SessionTimer::Ping,
        );
        if self.active_transport == ActiveTransport::UdpQsp
            && self.tcp_alive
            && let Some(last_authenticated) = self.last_authenticated_udp_activity
        {
            update_earliest_timer(
                &mut timer_at,
                &mut timer,
                Some(last_authenticated + self.config.timing.udp_liveness_timeout),
                SessionTimer::UdpLiveness,
            );
        }
        if self.udp_state.is_waiting() && !has_discovery_task {
            update_earliest_timer(
                &mut timer_at,
                &mut timer,
                udp_reconnect_at,
                SessionTimer::UdpReconnect,
            );
        }
        update_earliest_timer(
            &mut timer_at,
            &mut timer,
            register_deadline,
            SessionTimer::Register,
        );
        update_earliest_timer(
            &mut timer_at,
            &mut timer,
            udp_upgrade_timer_at,
            SessionTimer::UdpUpgrade,
        );
        let timer_due = time::Instant::from_std(timer_at) <= time::Instant::now();

        let tun_work = async {
            // Ready uplink packets extend the current GSO batch. The lifecycle
            // gates this arm after a non-batching TUN event so a partial batch
            // cannot remain pending indefinitely.
            tokio::select! {
                biased;

                maybe = self.tun_channels.to_session_rx.recv(), if can_receive_tun => {
                    SessionEvent::TunPacket(maybe)
                }
                () = std::future::ready(()), if udp_pending_flush => {
                    SessionEvent::UdpFlushReady
                }
                else => std::future::pending().await,
            }
        };
        let packet_work = async {
            tokio::select! {
                res = self.tcp.read_more(), if self.tcp_alive => {
                    Ok::<_, SessionError>(SessionEvent::TcpRead(res?))
                }
                event = tun_work => Ok::<_, SessionError>(event),
                udp_res = async {
                    // Defensive: this arm is gated by `udp_enabled` (which checks
                    // `udp_receive_transport().is_some()`), so the mutable lookup failing
                    // here would be a client-state inconsistency that should never
                    // happen. Unlike the 6 other "transport missing" sites (which
                    // return `SessionError::ProtocolViolation`), this arm's type is
                    // `Result<_, UdpQspError>` because it returns through
                    // `SessionEvent::UdpResult`; routing it to `ProtocolViolation`
                    // would require restructuring the select arm for no behavioral
                    // gain (the branch is unreachable in practice). The error
                    // surfaces as `UdpQspError::Io(BrokenPipe)`. `BrokenPipe` is
                    // not a transient kind, so `is_recoverable()` is false and the
                    // `UdpResult(Err)` handler propagates it to TCP fallback (or
                    // close if TCP is dead) — the same routing a real `BrokenPipe`
                    // gets. Moot either way: the branch never fires.
                    let udp = self
                        .udp_state
                        .as_active_mut()
                        .or(self.retained_udp_transport.as_deref_mut())
                        .ok_or_else(|| {
                        UdpQspError::from(io::Error::new(
                            io::ErrorKind::BrokenPipe,
                            "udp-qsp transport missing",
                        ))
                    })?;
                    udp.read_next_message(limits).await
                }, if udp_enabled => Ok(SessionEvent::UdpResult(udp_res)),
            }
        };

        // Cancellation, control work, and expired deadlines retain explicit
        // priority. Packet sources are selected fairly inside `packet_work`.
        // A future deadline remains below ready packet work so the hot path
        // avoids registering and dropping a Tokio timer for every packet; the
        // due check on the next iteration bounds lateness to one event.
        tokio::select! {
            biased;

            () = self.cancel.cancelled() => Ok(SessionEvent::Shutdown),
            command = recv_control(&mut self.control_rx) => {
                Ok(command.map_or(SessionEvent::Shutdown, SessionEvent::Control))
            }
            () = std::future::ready(()), if timer_due => Ok(timer.into_event()),
            result = async {
                let task = self.discovery_task.as_mut().expect("discovery_task checked");
                task.await.unwrap_or(None)
            }, if has_discovery_task => {
                Ok(SessionEvent::DiscoveryResult(result))
            }
            event = packet_work => event,
            () = time::sleep_until(timer_at.into()), if !timer_due => Ok(timer.into_event()),
        }
    }

    fn has_pending_udp_flush(&self) -> bool {
        self.active_transport == ActiveTransport::UdpQsp
            && self
                .udp_state
                .as_active()
                .is_some_and(ClientTransport::has_pending_flush)
    }

    fn tun_scheduling(&self, event: &SessionEvent) -> TunScheduling {
        match event {
            SessionEvent::UdpFlushReady => TunScheduling::UdpFlush,
            SessionEvent::TunPacket(Some(packet))
                if self.active_transport == ActiveTransport::UdpQsp
                    && !packet.is_empty()
                    && packet.len() <= self.limits.max_data_len =>
            {
                TunScheduling::BatchablePacket
            }
            SessionEvent::TunPacket(_) => TunScheduling::NonBatchingTun,
            _ => TunScheduling::Unchanged,
        }
    }

    /// Dispatches a session event to the appropriate handler.
    ///
    /// Matches the event type and calls the corresponding handler method.
    /// Returns `Ok(SessionControl::Continue)` to continue processing events
    /// or `Ok(SessionControl::Close(exit))` to terminate the session.
    #[allow(clippy::too_many_lines)]
    async fn handle_event(
        &mut self,
        event: SessionEvent,
        next_ping_at: &mut Instant,
    ) -> Result<SessionControl, SessionError> {
        match event {
            SessionEvent::Shutdown => {
                info!("shutdown requested");
                self.metrics.inc_disconnect_shutdown();
                Ok(SessionControl::Close(SessionExit::Shutdown))
            }
            SessionEvent::Control(ClientCommand::Stop) => {
                info!("stop command received");
                self.cancel.cancel();
                self.metrics.inc_disconnect_shutdown();
                Ok(SessionControl::Close(SessionExit::Shutdown))
            }
            SessionEvent::Control(ClientCommand::NetworkChanged) => {
                self.handle_network_changed().await
            }
            SessionEvent::TcpRead(n) => {
                if n == 0 {
                    if self.active_transport == ActiveTransport::UdpQsp {
                        info!(peer = ?self.peer, "tcp connection closed; continuing on udp");
                        self.tcp_alive = false;
                        return Ok(SessionControl::Continue);
                    }
                    info!("tcp connection closed");
                    self.metrics.inc_disconnect_close();
                    return Ok(SessionControl::Close(SessionExit::TcpClosed));
                }
                self.handle_tcp_read().await
            }
            SessionEvent::TunPacket(maybe) => {
                let Some(packet) = maybe else {
                    warn!("tun channel closed unexpectedly");
                    return Ok(SessionControl::Close(SessionExit::TunClosed(
                        TunTask::Reader,
                    )));
                };
                self.handle_tun_packet(packet).await
            }
            SessionEvent::UdpResult(udp_res) => match udp_res {
                Ok(msg_buf) => {
                    let received_at = Instant::now();
                    let result = self.handle_udp_message(msg_buf).await;
                    let control = match result {
                        Ok(control) => control,
                        Err(err) => {
                            if err.is_udp_path_transport_error() {
                                return self.handle_udp_event_error(&err).await;
                            }
                            // Typed (non-I/O) session error from the UDP
                            // message handler: a proto decode failure or
                            // protocol violation. Propagate.
                            return Err(err);
                        }
                    };
                    self.note_authenticated_udp_activity(received_at);
                    Ok(control)
                }
                Err(err) => {
                    let err = SessionError::from(err);
                    if err.is_udp_path_transport_error() {
                        return self.handle_udp_event_error(&err).await;
                    }
                    Err(err)
                }
            },
            SessionEvent::PingTick => {
                self.handle_ping_tick().await?;
                *next_ping_at = self.schedule_next_ping();
                Ok(SessionControl::Continue)
            }
            SessionEvent::IdleTimeout => {
                info!("idle timeout reached");
                self.metrics.inc_disconnect_idle_timeout();
                self.send_close_best_effort(CloseCode::IdleTimeout, "idle_timeout")
                    .await;
                Ok(SessionControl::Close(SessionExit::IdleTimeout))
            }
            SessionEvent::UdpLivenessTimeout => {
                if self.active_transport != ActiveTransport::UdpQsp || !self.tcp_alive {
                    return Ok(SessionControl::Continue);
                }
                warn!(
                    timeout_ms = self.config.timing.udp_liveness_timeout.as_millis(),
                    "UDP-QSP authenticated liveness timeout; switching to tcp"
                );
                self.request_tcp_fallback(TransportChangeReason::UdpLivenessTimeout)
                    .await?;
                self.schedule_discovery_retry();
                Ok(SessionControl::Continue)
            }
            SessionEvent::UdpReconnectTick => {
                match &self.udp_state {
                    UdpState::NeedDiscovery { .. } => {
                        debug!("udp reconnect tick; spawning quic discovery task");
                        self.services
                            .observer()
                            .emit(ClientEventKind::UdpDiscoveryStarted);
                        self.discovery_task = Some(self.spawn_quic_discovery());
                    }
                    UdpState::Pending { .. } => {
                        debug!("udp reconnect tick; attempting registration");
                        return self.attempt_udp_registration().await;
                    }
                    _ => {}
                }
                Ok(SessionControl::Continue)
            }
            SessionEvent::RegisterTimeout => Ok(self.handle_registration_timeout()),
            SessionEvent::DiscoveryResult(maybe_ids) => {
                self.discovery_task = None; // Clear the completed task
                Ok(self.handle_discovery_result(maybe_ids))
            }
            SessionEvent::UdpUpgradeTick => self.handle_udp_upgrade_tick().await,
            SessionEvent::UdpFlushReady => {
                if let Err(err) = self.flush_udp_transport().await
                    && err.is_udp_path_transport_error()
                {
                    return self.handle_udp_event_error(&err).await;
                }
                Ok(SessionControl::Continue)
            }
        }
    }

    /// Forwards a TUN packet to the preferred transport.
    ///
    /// Writes the packet as a `DATA` message on the preferred outbound transport.
    /// If UDP-QSP write/enqueue fails, attempts TCP fallback if available.
    /// Later UDP flush failures are handled as transport loss; individual TUN
    /// packets already accepted by the UDP batching layer are not replayed.
    /// Drops oversized packets and updates metrics.
    async fn handle_tun_packet(&mut self, packet: Vec<u8>) -> Result<SessionControl, SessionError> {
        if packet.is_empty() {
            return Ok(SessionControl::Continue);
        }
        if packet.len() > self.limits.max_data_len {
            self.metrics.inc_tun_packets_dropped_oversized();
            tracing::trace!(
                packet_len = packet.len(),
                max_len = self.limits.max_data_len,
                "dropping tun packet: size limit exceeded"
            );
            return Ok(SessionControl::Continue);
        }

        let active = self.active_transport;
        if let Err(err) = self
            .write_active_message(Message::Data {
                packet: packet.as_slice(),
            })
            .await
        {
            if active != ActiveTransport::UdpQsp {
                return Err(err);
            }
            if err.is_udp_path_transport_error() {
                if !self.handle_udp_error(&err).await? {
                    return Err(SessionError::Connection {
                        source: io::Error::new(io::ErrorKind::NotConnected, "both transports dead"),
                    });
                }
            } else {
                // Typed non-transport session error from the UDP path; propagate.
                return Err(err);
            }
            self.write_tcp_message(Message::Data {
                packet: packet.as_slice(),
            })
            .await?;
        }
        Ok(SessionControl::Continue)
    }
}

fn update_earliest_timer(
    timer_at: &mut Instant,
    timer: &mut SessionTimer,
    candidate_at: Option<Instant>,
    candidate: SessionTimer,
) {
    if let Some(candidate_at) = candidate_at
        && candidate_at < *timer_at
    {
        *timer_at = candidate_at;
        *timer = candidate;
    }
}

async fn recv_control(
    control_rx: &mut Option<&mut ClientCommandReceiver>,
) -> Option<ClientCommand> {
    match control_rx {
        Some(rx) => {
            let command = rx.recv().await;
            if command.is_none() {
                *control_rx = None;
            }
            command
        }
        None => std::future::pending().await,
    }
}

#[cfg(test)]
mod tests;
