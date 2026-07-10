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
    last_tcp_rx: Instant,
    last_udp_rx: Instant,
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
    UdpReconnect,
    Register,
    UdpUpgrade,
}

impl SessionTimer {
    const fn into_event(self) -> SessionEvent {
        match self {
            Self::Ping => SessionEvent::PingTick,
            Self::Idle => SessionEvent::IdleTimeout,
            Self::UdpReconnect => SessionEvent::UdpReconnectTick,
            Self::Register => SessionEvent::RegisterTimeout,
            Self::UdpUpgrade => SessionEvent::UdpUpgradeTick,
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
            last_tcp_rx: now,
            last_udp_rx: now,
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
            _ => {}
        }
        self.flush_pending_udp_transport_best_effort().await;
        self.shutdown_background_tasks().await;
        outcome
    }

    async fn run_inner(&mut self) -> SessionOutcome {
        let mut next_ping_at = self.schedule_next_ping();
        loop {
            if self.tcp_alive && self.tcp.has_buffered_input() {
                match self.handle_tcp_read().await {
                    Ok(SessionControl::Continue) => {}
                    Ok(SessionControl::Close(exit)) => break SessionOutcome::from_exit(exit),
                    Err(err) => {
                        self.metrics.inc_disconnect_error();
                        break SessionOutcome::from_error(err);
                    }
                }
            }

            let event = match self.poll_event(next_ping_at).await {
                Ok(event) => event,
                Err(err) => {
                    self.metrics.inc_disconnect_error();
                    break SessionOutcome::from_error(err);
                }
            };
            match self.handle_event(event, &mut next_ping_at).await {
                Ok(SessionControl::Continue) => {}
                Ok(SessionControl::Close(exit)) => break SessionOutcome::from_exit(exit),
                Err(err) => {
                    self.metrics.inc_disconnect_error();
                    break SessionOutcome::from_error(err);
                }
            }
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
    /// - UDP reconnect timer (if waiting)
    /// - Registration timeout (if in-flight registration)
    /// - Discovery task completion (if discovery is running)
    async fn poll_event(&mut self, next_ping_at: Instant) -> Result<SessionEvent, SessionError> {
        let limits = self.limits;
        let idle_deadline = match self.active_transport {
            ActiveTransport::Tcp => self.last_tcp_rx + self.config.timing.idle_timeout,
            ActiveTransport::UdpQsp => self.last_udp_rx + self.config.timing.idle_timeout,
        };
        let udp_reconnect_at = self.udp_state.reconnect_at();
        let register_deadline = self.udp_state.register_deadline();
        let udp_enabled = self.udp_receive_transport().is_some();
        let has_discovery_task = self.discovery_task.is_some();
        let udp_upgrade_timer_at = self.udp_upgrade.timer_at();
        let udp_pending_flush = self.active_transport == ActiveTransport::UdpQsp
            && self
                .udp_state
                .as_active()
                .is_some_and(ClientTransport::has_pending_flush);

        let mut timer_at = idle_deadline;
        let mut timer = SessionTimer::Idle;
        update_earliest_timer(
            &mut timer_at,
            &mut timer,
            Some(next_ping_at),
            SessionTimer::Ping,
        );
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

        // An expired deadline precedes packet sources, while a future deadline
        // stays below them so the hot path does not register and drop a Tokio
        // timer on every packet. Rechecking on the next iteration bounds timer
        // lateness to one packet. Keep UDP-QSP partial-batch flush last; full GSO
        // slabs flush inline.
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
            res = self.tcp.read_more(), if self.tcp_alive => Ok(SessionEvent::TcpRead(res?)),
            maybe = self.tun_channels.to_session_rx.recv() => Ok(SessionEvent::TunPacket(maybe)),
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
            () = time::sleep_until(timer_at.into()), if !timer_due => Ok(timer.into_event()),
            () = std::future::ready(()), if udp_pending_flush => Ok(SessionEvent::UdpFlushReady),
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
                self.note_tcp_activity();
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
                    self.note_udp_activity();
                    Ok(control)
                }
                Err(err) => {
                    // Typed UDP-QSP transport error: the slt-core
                    // QspSessionError/QspCryptoError and proto encode errors
                    // are preserved here, not flattened. `err` is always a
                    // `UdpQspError` (the sole error type `read_next_message`
                    // returns), so `SessionError::from(err)` is always
                    // `SessionError::UdpQsp(_)`, which `is_udp_path_transport_error()`
                    // always returns true for. Recoverable packet failures are
                    // dropped; fatal path failures use authenticated TCP fallback.
                    let err = SessionError::from(err);
                    if err.is_udp_path_transport_error() {
                        return self.handle_udp_event_error(&err).await;
                    }
                    // Unreachable: `UdpResult`'s error is always a `UdpQspError`,
                    // which maps to `SessionError::UdpQsp(_)` (a UDP-path
                    // transport error). Reached only if `read_next_message`'s
                    // error type gains a non-`UdpQspError` shape without
                    // updating this arm.
                    unreachable!(
                        "UdpResult error must be a UdpQspError (UDP-path transport error): {err:?}"
                    )
                }
            },
            SessionEvent::PingTick => {
                self.handle_ping_tick().await?;
                *next_ping_at = self.schedule_next_ping();
                Ok(SessionControl::Continue)
            }
            SessionEvent::IdleTimeout => match self.active_transport {
                ActiveTransport::Tcp => {
                    info!("idle timeout reached");
                    self.metrics.inc_disconnect_idle_timeout();
                    self.send_close_best_effort(CloseCode::IdleTimeout, "idle_timeout")
                        .await;
                    Ok(SessionControl::Close(SessionExit::IdleTimeout))
                }
                ActiveTransport::UdpQsp => {
                    if !self.tcp_alive {
                        warn!("udp-qsp idle timeout and tcp dead; closing session");
                        self.metrics.inc_disconnect_idle_timeout();
                        return Ok(SessionControl::Close(SessionExit::IdleTimeout));
                    }
                    warn!("udp-qsp idle timeout; switching to tcp");
                    self.request_tcp_fallback(TransportChangeReason::IdleTimeout)
                        .await?;
                    self.schedule_discovery_retry();
                    Ok(SessionControl::Continue)
                }
            },
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
mod tests {
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use slt_core::config::ClientConfig;
    use slt_core::crypto::udp_qsp::{QspSessionError, QuicQspSession, UdpQspKeys};
    use slt_core::proto::{
        CipherSuite, FallbackOkPayload, FallbackToTcpPayload, Message, MessageType,
        OwnedMessageBuf, SwitchAckPayload, SwitchOkPayload, SwitchToUdpPayload, encode_message,
    };
    use slt_core::transport::tcp::TcpChannel;
    use slt_core::types::{Cid, MAX_DCID_LEN};
    use tokio::io::{AsyncWriteExt, DuplexStream};
    use tokio::net::UdpSocket;
    use tokio::sync::mpsc;
    use tokio::time;
    use tokio_boring::SslStream;
    use tokio_util::sync::CancellationToken;

    use super::{
        ActiveTransport, ClientSession, SessionControl, SessionError, SessionEvent, SessionExit,
        UdpState, UdpUpgradeState,
    };
    use crate::metrics::Metrics;
    use crate::runtime::ReconnectBackoff;
    use crate::runtime::observer::TransportChangeReason;
    use crate::runtime::services::DesktopServices;
    use crate::test_support::{
        ParkableWriteStream, WriteGate, mock_quic_ids, test_config,
        tls_pair_with_parkable_client_writes, tls_tcp_stream_pair,
    };
    use crate::transport::tcp::{ClientKeyUpdater, TcpSession};
    use crate::transport::udp_qsp::{ClientTransport, UdpQspError, client_udp_qsp_io};
    use crate::tun::TunChannels;

    async fn test_session<'a>(
        config: &'a ClientConfig,
        tun: &'a mut TunChannels,
        services: &'a DesktopServices,
    ) -> (
        ClientSession<'a, DesktopServices>,
        SslStream<tokio::net::TcpStream>,
    ) {
        let metrics = Arc::new(Metrics::default());
        let updater = ClientKeyUpdater::new(metrics.clone());
        let (client_stream, server_stream) = tls_tcp_stream_pair().await;
        let tcp_session = TcpSession {
            transport: TcpChannel::with_key_updater(client_stream, updater),
            peer: None,
            sni: None,
        };
        (
            ClientSession::new(
                config,
                tcp_session,
                tun,
                CancellationToken::new(),
                metrics,
                services,
                None,
            ),
            server_stream,
        )
    }

    async fn parkable_test_session<'a>(
        config: &'a ClientConfig,
        tun: &'a mut TunChannels,
        services: &'a DesktopServices,
        cancel: CancellationToken,
    ) -> (
        ClientSession<'a, DesktopServices, ParkableWriteStream>,
        SslStream<DuplexStream>,
        Arc<WriteGate>,
    ) {
        let metrics = Arc::new(Metrics::default());
        let updater = ClientKeyUpdater::new(metrics.clone());
        let (client_stream, server_stream, write_gate) =
            tls_pair_with_parkable_client_writes().await;
        let tcp_session = TcpSession {
            transport: TcpChannel::with_key_updater(client_stream, updater),
            peer: None,
            sni: None,
        };
        (
            ClientSession::new(config, tcp_session, tun, cancel, metrics, services, None),
            server_stream,
            write_gate,
        )
    }

    fn data_message(packet: &[u8]) -> OwnedMessageBuf {
        let mut frame = Vec::new();
        encode_message(Message::Data { packet }, &mut frame).unwrap();
        OwnedMessageBuf::new(MessageType::Data, frame)
    }

    async fn test_udp_transport() -> ClientTransport {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let peer = "127.0.0.1:443".parse().unwrap();
        let io = client_udp_qsp_io(&socket, peer).unwrap();
        let keys = UdpQspKeys::from_packet_material(
            CipherSuite::Aes128Gcm,
            [0; 16],
            [0; 16],
            [0; 16],
            [0; 16],
            [0; 12],
            [0; 12],
        )
        .unwrap();
        let session = QuicQspSession::new(
            io,
            Cid::from([0xBB; MAX_DCID_LEN]),
            Cid::from([0xAA; MAX_DCID_LEN]),
            keys,
            0,
            0,
            false,
        );
        ClientTransport::new(session, Arc::new(Metrics::default()))
    }

    #[tokio::test]
    async fn udp_data_is_accepted_while_tcp_is_preferred() {
        let config = test_config();
        let services = DesktopServices::new();
        let (_tun_tx, to_session_rx) = mpsc::channel(1);
        let (to_tun_tx, mut to_tun_rx) = mpsc::channel(1);
        let mut tun = TunChannels {
            to_session_rx,
            to_tun_tx,
        };
        let (mut session, _server_stream) = test_session(&config, &mut tun, &services).await;
        let packet = b"authenticated udp data";

        assert_eq!(
            session
                .handle_udp_message(data_message(packet))
                .await
                .unwrap(),
            SessionControl::Continue
        );
        assert_eq!(session.active_transport, ActiveTransport::Tcp);
        let delivered = to_tun_rx.try_recv().unwrap();
        assert!(matches!(
            delivered.message(),
            Message::Data { packet: delivered_packet } if delivered_packet == packet
        ));
    }

    #[tokio::test]
    async fn tcp_data_is_accepted_while_udp_is_preferred() {
        let config = test_config();
        let services = DesktopServices::new();
        let (_tun_tx, to_session_rx) = mpsc::channel(1);
        let (to_tun_tx, mut to_tun_rx) = mpsc::channel(1);
        let mut tun = TunChannels {
            to_session_rx,
            to_tun_tx,
        };
        let (mut session, mut server_stream) = test_session(&config, &mut tun, &services).await;
        session.active_transport = ActiveTransport::UdpQsp;
        let packet = b"late tcp data";
        let mut frame = Vec::new();
        encode_message(Message::Data { packet }, &mut frame).unwrap();
        server_stream.write_all(&frame).await.unwrap();

        assert_ne!(session.tcp.read_more().await.unwrap(), 0);
        assert_eq!(
            session.handle_tcp_read().await.unwrap(),
            SessionControl::Continue
        );
        assert_eq!(session.active_transport, ActiveTransport::UdpQsp);
        let delivered = to_tun_rx.try_recv().unwrap();
        assert!(matches!(
            delivered.message(),
            Message::Data { packet: delivered_packet } if delivered_packet == packet
        ));
    }

    #[tokio::test]
    async fn fallback_request_precedes_retried_tcp_data() {
        let config = test_config();
        let services = DesktopServices::new();
        let (_tun_tx, to_session_rx) = mpsc::channel(1);
        let (to_tun_tx, _to_tun_rx) = mpsc::channel(1);
        let mut tun = TunChannels {
            to_session_rx,
            to_tun_tx,
        };
        let (mut session, server_stream) = test_session(&config, &mut tun, &services).await;
        let mut server = TcpChannel::new(server_stream);
        session.active_transport = ActiveTransport::UdpQsp;
        session
            .request_tcp_fallback(TransportChangeReason::UdpError)
            .await
            .unwrap();
        let packet = vec![0x45; 20];
        assert_eq!(
            session.handle_tun_packet(packet.clone()).await.unwrap(),
            SessionControl::Continue
        );

        assert_ne!(server.read_more().await.unwrap(), 0);
        let request = server.try_pop_message(session.limits).unwrap().unwrap();
        let Message::FallbackToTcp { payload } = request.message() else {
            panic!("expected fallback request before tcp data");
        };
        let fallback_id = FallbackToTcpPayload::decode(payload).unwrap().fallback_id;
        assert_eq!(session.pending_tcp_fallback, Some(fallback_id));

        let data = loop {
            if let Some(message) = server.try_pop_message(session.limits).unwrap() {
                break message;
            }
            assert_ne!(server.read_more().await.unwrap(), 0);
        };
        assert!(matches!(
            data.message(),
            Message::Data { packet: delivered_packet } if delivered_packet == packet
        ));
        assert_eq!(session.active_transport, ActiveTransport::Tcp);
    }

    #[tokio::test]
    async fn server_fallback_request_switches_client_and_is_acknowledged() {
        let mut config = test_config();
        config.enable_upgrade = true;
        let services = DesktopServices::new();
        let (_tun_tx, to_session_rx) = mpsc::channel(1);
        let (to_tun_tx, _to_tun_rx) = mpsc::channel(1);
        let mut tun = TunChannels {
            to_session_rx,
            to_tun_tx,
        };
        let (mut session, mut server_stream) = test_session(&config, &mut tun, &services).await;
        session.active_transport = ActiveTransport::UdpQsp;
        session.udp_state = UdpState::Active(Box::new(test_udp_transport().await));
        session
            .write_active_message(Message::Data {
                packet: b"queued udp uplink",
            })
            .await
            .unwrap();
        assert!(session.udp_state.as_active().unwrap().has_pending_flush());
        let fallback_id = 0xFA11_BACC;
        let request = FallbackToTcpPayload { fallback_id };
        let mut payload = Vec::new();
        request.encode(&mut payload);
        let mut frame = Vec::new();
        encode_message(Message::FallbackToTcp { payload: &payload }, &mut frame).unwrap();
        server_stream.write_all(&frame).await.unwrap();

        assert_ne!(session.tcp.read_more().await.unwrap(), 0);
        assert_eq!(
            session.handle_tcp_read().await.unwrap(),
            SessionControl::Continue
        );
        assert_eq!(session.active_transport, ActiveTransport::Tcp);
        assert!(matches!(session.udp_state, UdpState::NeedDiscovery { .. }));
        assert!(session.retained_udp_transport.is_some());
        assert!(session.udp_receive_transport().is_some());
        assert!(
            !session
                .retained_udp_transport
                .as_ref()
                .unwrap()
                .has_pending_flush()
        );

        let mut server = TcpChannel::new(server_stream);
        assert_ne!(server.read_more().await.unwrap(), 0);
        let ack = server.try_pop_message(session.limits).unwrap().unwrap();
        let Message::FallbackOk { payload } = ack.message() else {
            panic!("expected fallback acknowledgement");
        };
        assert_eq!(
            FallbackOkPayload::decode(payload).unwrap().fallback_id,
            fallback_id
        );
    }

    #[tokio::test]
    async fn disabled_client_does_not_start_udp_discovery_after_fallback() {
        let mut config = test_config();
        config.enable_upgrade = false;
        config.require_udp = false;
        let services = DesktopServices::new();
        let (_tun_tx, to_session_rx) = mpsc::channel(1);
        let (to_tun_tx, _to_tun_rx) = mpsc::channel(1);
        let mut tun = TunChannels {
            to_session_rx,
            to_tun_tx,
        };
        let (mut session, mut server_stream) = test_session(&config, &mut tun, &services).await;
        let request = FallbackToTcpPayload { fallback_id: 42 };
        let mut payload = Vec::new();
        request.encode(&mut payload);
        let mut frame = Vec::new();
        encode_message(Message::FallbackToTcp { payload: &payload }, &mut frame).unwrap();
        server_stream.write_all(&frame).await.unwrap();

        assert_ne!(session.tcp.read_more().await.unwrap(), 0);
        assert_eq!(
            session.handle_tcp_read().await.unwrap(),
            SessionControl::Continue
        );
        assert!(matches!(session.udp_state, UdpState::Disabled));
        assert!(matches!(session.udp_upgrade, UdpUpgradeState::Disabled));
        assert!(session.retained_udp_transport.is_none());
    }

    #[tokio::test]
    async fn retained_udp_failure_preserves_in_flight_registration() {
        let mut config = test_config();
        config.enable_upgrade = true;
        let services = DesktopServices::new();
        let (_tun_tx, to_session_rx) = mpsc::channel(1);
        let (to_tun_tx, _to_tun_rx) = mpsc::channel(1);
        let mut tun = TunChannels {
            to_session_rx,
            to_tun_tx,
        };
        let (mut session, _server_stream) = test_session(&config, &mut tun, &services).await;
        let quic_ids = mock_quic_ids().await;
        let expected_dcid = quic_ids.dcid;
        session.udp_state = UdpState::Pending {
            quic_ids,
            backoff: ReconnectBackoff::new(
                config.timing.reconnect_min,
                config.timing.reconnect_max,
            ),
            reconnect_at: Instant::now(),
            registration: None,
        };
        assert_eq!(
            session.attempt_udp_registration().await.unwrap(),
            SessionControl::Continue
        );
        session.retained_udp_transport = Some(Box::new(test_udp_transport().await));

        let error = SessionError::from(UdpQspError::from(QspSessionError::PacketNumberOverflow));
        assert!(session.handle_udp_error(&error).await.unwrap());

        assert!(session.retained_udp_transport.is_none());
        assert!(session.pending_tcp_fallback.is_none());
        let UdpState::Pending {
            quic_ids,
            registration,
            ..
        } = &session.udp_state
        else {
            panic!("retained path failure replaced pending registration state");
        };
        assert_eq!(quic_ids.dcid, expected_dcid);
        assert!(registration.is_some());
    }

    #[tokio::test]
    async fn switch_to_udp_waits_for_switch_ok_before_committing() {
        let config = test_config();
        let services = DesktopServices::new();
        let (_tun_tx, to_session_rx) = mpsc::channel(1);
        let (to_tun_tx, _to_tun_rx) = mpsc::channel(1);
        let mut tun = TunChannels {
            to_session_rx,
            to_tun_tx,
        };
        let (mut session, server_stream) = test_session(&config, &mut tun, &services).await;
        let mut server = TcpChannel::new(server_stream);
        let upgrade_id = 0x5A17_CAFE;
        session.udp_upgrade = UdpUpgradeState::Upgrading {
            upgrade_id,
            deadline: Instant::now() + config.timing.register_timeout,
            attempts: 1,
            next_probe_at: Instant::now() + config.timing.reconnect_min,
            last_probe_nonce: 7,
            probe_acked: true,
            ready_sent: true,
            probe_backoff: ReconnectBackoff::new(
                config.timing.reconnect_min,
                config.timing.reconnect_max,
            ),
        };
        let switch = SwitchToUdpPayload { upgrade_id };
        let mut payload = Vec::new();
        switch.encode(&mut payload);

        assert_eq!(
            session.handle_switch_to_udp(&payload).await.unwrap(),
            SessionControl::Continue
        );
        assert_eq!(session.active_transport, ActiveTransport::Tcp);
        assert!(matches!(
            session.udp_upgrade,
            UdpUpgradeState::AwaitingSwitchOk {
                upgrade_id: pending_id,
                ..
            } if pending_id == upgrade_id
        ));

        assert_ne!(server.read_more().await.unwrap(), 0);
        let ack = server.try_pop_message(session.limits).unwrap().unwrap();
        let Message::SwitchAck {
            payload: ack_payload,
        } = ack.message()
        else {
            panic!("expected switch_ack");
        };
        assert_eq!(
            SwitchAckPayload::decode(ack_payload).unwrap().upgrade_id,
            upgrade_id
        );
        assert!(
            time::timeout(Duration::from_millis(25), server.read_more())
                .await
                .is_err(),
            "client emitted a post-ack barrier frame"
        );

        let confirmation = SwitchOkPayload { upgrade_id };
        payload.clear();
        confirmation.encode(&mut payload);
        server
            .write_message(Message::SwitchOk { payload: &payload })
            .await
            .unwrap();
        assert_ne!(session.tcp.read_more().await.unwrap(), 0);
        assert_eq!(
            session.handle_tcp_read().await.unwrap(),
            SessionControl::Continue
        );
        assert_eq!(session.active_transport, ActiveTransport::UdpQsp);
        assert!(matches!(session.udp_upgrade, UdpUpgradeState::Idle));
    }

    #[tokio::test]
    async fn tcp_eof_before_switch_ok_reconnects_without_preferring_udp() {
        let config = test_config();
        let services = DesktopServices::new();
        let (_tun_tx, to_session_rx) = mpsc::channel(1);
        let (to_tun_tx, _to_tun_rx) = mpsc::channel(1);
        let mut tun = TunChannels {
            to_session_rx,
            to_tun_tx,
        };
        let (mut session, _server_stream) = test_session(&config, &mut tun, &services).await;
        session.udp_upgrade = UdpUpgradeState::AwaitingSwitchOk {
            upgrade_id: 17,
            deadline: Instant::now() + config.timing.register_timeout,
        };

        let mut next_ping_at = session.schedule_next_ping();
        assert_eq!(
            session
                .handle_event(SessionEvent::TcpRead(0), &mut next_ping_at)
                .await
                .unwrap(),
            SessionControl::Close(SessionExit::TcpClosed)
        );
        assert_eq!(session.active_transport, ActiveTransport::Tcp);
    }

    #[tokio::test]
    async fn switch_ok_timeout_synchronizes_tcp_fallback() {
        let mut config = test_config();
        config.enable_upgrade = true;
        let services = DesktopServices::new();
        let (_tun_tx, to_session_rx) = mpsc::channel(1);
        let (to_tun_tx, _to_tun_rx) = mpsc::channel(1);
        let mut tun = TunChannels {
            to_session_rx,
            to_tun_tx,
        };
        let (mut session, server_stream) = test_session(&config, &mut tun, &services).await;
        let mut server = TcpChannel::new(server_stream);
        session.udp_upgrade = UdpUpgradeState::AwaitingSwitchOk {
            upgrade_id: 23,
            deadline: Instant::now() - Duration::from_millis(1),
        };

        assert_eq!(
            session.handle_udp_upgrade_tick().await.unwrap(),
            SessionControl::Continue
        );
        assert!(matches!(
            session.udp_upgrade,
            UdpUpgradeState::TcpOnlyBlockedUdp { .. }
        ));
        assert_ne!(server.read_more().await.unwrap(), 0);
        let request = server.try_pop_message(session.limits).unwrap().unwrap();
        assert!(matches!(request.message(), Message::FallbackToTcp { .. }));
    }

    #[tokio::test]
    async fn expired_idle_deadline_preempts_ready_tun_packet() {
        let config = test_config();
        let services = DesktopServices::new();
        let (tun_tx, to_session_rx) = mpsc::channel(1);
        let (to_tun_tx, _to_tun_rx) = mpsc::channel::<OwnedMessageBuf>(1);
        tun_tx.try_send(vec![0x45; 20]).unwrap();
        let mut tun = TunChannels {
            to_session_rx,
            to_tun_tx,
        };
        let (mut session, _server_stream) = test_session(&config, &mut tun, &services).await;
        session.last_tcp_rx =
            Instant::now() - config.timing.idle_timeout - Duration::from_millis(1);

        let event = session
            .poll_event(Instant::now() + Duration::from_secs(60))
            .await
            .unwrap();

        assert!(matches!(event, SessionEvent::IdleTimeout));
    }

    #[tokio::test]
    async fn expired_ping_deadline_preempts_ready_tun_packet() {
        let config = test_config();
        let services = DesktopServices::new();
        let (tun_tx, to_session_rx) = mpsc::channel(1);
        let (to_tun_tx, _to_tun_rx) = mpsc::channel::<OwnedMessageBuf>(1);
        tun_tx.try_send(vec![0x45; 20]).unwrap();
        let mut tun = TunChannels {
            to_session_rx,
            to_tun_tx,
        };
        let (mut session, _server_stream) = test_session(&config, &mut tun, &services).await;

        let event = session
            .poll_event(Instant::now() - Duration::from_millis(1))
            .await
            .unwrap();

        assert!(matches!(event, SessionEvent::PingTick));
    }

    #[tokio::test]
    async fn established_tcp_write_timeout_exits_for_reconnect() {
        let mut config = test_config();
        config.timing.tcp_write_timeout = Duration::from_millis(40);
        let services = DesktopServices::new();
        let (tun_tx, to_session_rx) = mpsc::channel(1);
        let (to_tun_tx, _to_tun_rx) = mpsc::channel::<OwnedMessageBuf>(1);
        tun_tx.try_send(vec![0x45; 20]).unwrap();
        let mut tun = TunChannels {
            to_session_rx,
            to_tun_tx,
        };
        let (mut session, _server_stream, write_gate) =
            parkable_test_session(&config, &mut tun, &services, CancellationToken::new()).await;
        write_gate.park();

        let tun_fault = CancellationToken::new();
        let outcome = time::timeout(Duration::from_secs(1), session.run(&tun_fault))
            .await
            .expect("parked DATA write must observe its deadline");

        assert_eq!(outcome.exit, SessionExit::ConnectionError);
        assert!(matches!(
            outcome.error,
            Some(SessionError::Io(ref source))
                if source.kind() == std::io::ErrorKind::TimedOut
        ));
        time::timeout(
            Duration::from_secs(1),
            write_gate.wait_until_write_blocked(),
        )
        .await
        .expect("DATA write reached the parked transport");
    }

    #[tokio::test]
    async fn internal_tun_fault_cleanup_does_not_count_shutdown() {
        let config = test_config();
        let services = DesktopServices::new();
        let (_tun_tx, to_session_rx) = mpsc::channel(1);
        let (to_tun_tx, _to_tun_rx) = mpsc::channel(1);
        let mut tun = TunChannels {
            to_session_rx,
            to_tun_tx,
        };
        let metrics = Arc::new(Metrics::default());
        let updater = ClientKeyUpdater::new(metrics.clone());
        let (client_stream, _server_stream) = tls_tcp_stream_pair().await;
        let tcp_session = TcpSession {
            transport: TcpChannel::with_key_updater(client_stream, updater),
            peer: None,
            sni: None,
        };
        let mut session = ClientSession::new(
            &config,
            tcp_session,
            &mut tun,
            CancellationToken::new(),
            metrics.clone(),
            &services,
            None,
        );
        let tun_fault = CancellationToken::new();
        tun_fault.cancel();

        let outcome = session.run(&tun_fault).await;

        assert_eq!(outcome.exit, SessionExit::TunFault);
        assert!(outcome.error.is_none());
        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.disconnect_error, 0);
        assert_eq!(snapshot.disconnect_shutdown, 0);
    }

    #[tokio::test]
    async fn shutdown_cancels_blocked_established_tcp_write() {
        let mut config = test_config();
        config.timing.tcp_write_timeout = Duration::from_secs(60);
        let services = DesktopServices::new();
        let cancel = CancellationToken::new();
        let (tun_tx, to_session_rx) = mpsc::channel(1);
        let (to_tun_tx, _to_tun_rx) = mpsc::channel::<OwnedMessageBuf>(1);
        tun_tx.try_send(vec![0x45; 20]).unwrap();
        let mut tun = TunChannels {
            to_session_rx,
            to_tun_tx,
        };
        let (mut session, _server_stream, write_gate) =
            parkable_test_session(&config, &mut tun, &services, cancel.clone()).await;
        write_gate.park();
        let tun_fault = CancellationToken::new();
        let run = session.run(&tun_fault);
        tokio::pin!(run);

        time::timeout(Duration::from_secs(1), async {
            tokio::select! {
                outcome = &mut run => panic!("session exited before cancellation: {:?}", outcome.exit),
                () = write_gate.wait_until_write_blocked() => {}
            }
        })
        .await
        .expect("DATA write reached the parked transport");

        // The parked write does not register a waker. Cancellation wakes the
        // outer session guard, which drops that write before sending CLOSE.
        write_gate.unpark();
        cancel.cancel();
        let outcome = time::timeout(Duration::from_secs(1), &mut run)
            .await
            .expect("shutdown must cancel the parked DATA write");

        assert_eq!(outcome.exit, SessionExit::Shutdown);
        assert!(outcome.error.is_none());
    }
}
