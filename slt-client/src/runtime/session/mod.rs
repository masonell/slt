//! Client session: manages TCP/UDP transport lifecycle and data flow.
//!
//! This module is organized into submodules by responsibility:
//! - `state`: UDP state machine types
//! - `event`: Event and control enums
//! - `tcp`: TCP message handlers
//! - `udp`: UDP message handlers
//! - `upgrade`: Discovery, registration, and UDP upgrade FSM
//! - `lifecycle`: Ping/pong, shutdown, write helpers

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

pub(super) use event::SessionExit;
use event::{SessionControl, SessionEvent};
use slt_core::config::ClientConfig;
use slt_core::proto::{CloseCode, Message, MessageLimits};
use state::{ActiveTransport, UdpState, UdpUpgradeState};
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
use crate::transport::udp_qsp::ClientTransport;
use crate::tun::TunChannels;

/// Session managing a single VPN connection.
///
/// Handles the complete lifecycle of a VPN session including TCP/UDP transport
/// management, message handling, transport upgrades, and idle timeout detection.
pub(super) struct ClientSession<'a, S: ClientRuntimeServices> {
    config: &'a ClientConfig,
    tcp: TcpTransport,
    peer: Option<SocketAddr>,
    tun_channels: &'a mut TunChannels,
    services: &'a S,
    active_transport: ActiveTransport,
    cancel: CancellationToken,
    limits: MessageLimits,
    last_tcp_rx: Instant,
    last_udp_rx: Instant,
    udp_state: UdpState,
    udp_upgrade: UdpUpgradeState,
    udp_upgrade_backoff: ReconnectBackoff,
    discovery_task: Option<JoinHandle<Option<quic::QuicIds>>>,
    metrics: Arc<Metrics>,
    /// Whether the TCP connection is still usable. Set to false when TCP closes
    /// while UDP-QSP is active, allowing the session to continue on UDP alone.
    tcp_alive: bool,
    control_rx: Option<&'a mut ClientCommandReceiver>,
}

/// Classifies an I/O error into the appropriate [`SessionExit`] variant.
///
/// A free function (not a method) because it does not depend on the services
/// type parameter `S`; this keeps tests from having to name a concrete
/// `ClientSession<…>` type.
///
/// Maps `io::ErrorKind` to session exit reasons:
/// - `InvalidData` / `InvalidInput` → `ProtocolError`
/// - `PermissionDenied` → `PermissionDenied`
/// - All other kinds → `ConnectionError`
pub(super) fn classify_error(err: &io::Error) -> SessionExit {
    match err.kind() {
        io::ErrorKind::InvalidData | io::ErrorKind::InvalidInput => SessionExit::ProtocolError,
        io::ErrorKind::PermissionDenied => SessionExit::PermissionDenied,
        _ => SessionExit::ConnectionError,
    }
}

impl<'a, S: ClientRuntimeServices> ClientSession<'a, S> {
    /// Creates a new session from an authenticated TCP connection.
    ///
    /// Initializes the session with the given TCP transport, configuration,
    /// TUN channels, cancellation token, and a borrow of the platform services
    /// (socket protector, host resolver, observer). UDP state is initialized
    /// based on the effective upgrade policy (`enable_upgrade || require_udp`).
    pub(super) fn new(
        config: &'a ClientConfig,
        tcp: TcpSession,
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
            udp_upgrade,
            udp_upgrade_backoff: ReconnectBackoff::new(
                config.timing.reconnect_min,
                config.timing.reconnect_max,
            ),
            discovery_task: None,
            metrics,
            services,
            tcp_alive: true,
            control_rx,
        }
    }

    /// Runs the session event loop until shutdown or error.
    ///
    /// Polls for events from TCP, UDP, TUN, timers, and the cancellation token.
    /// Dispatches each event to the appropriate handler and continues until
    /// the session exits for any reason.
    pub(super) async fn run(&mut self) -> SessionExit {
        let mut next_ping_at = self.schedule_next_ping();
        let result = loop {
            if self.tcp_alive && self.tcp.has_buffered_input() {
                match self.handle_tcp_read().await {
                    Ok(SessionControl::Continue) => {}
                    Ok(SessionControl::Close(exit)) => break exit,
                    Err(err) => {
                        self.metrics.inc_disconnect_error();
                        break classify_error(&err);
                    }
                }
            }

            let event = match self.poll_event(next_ping_at).await {
                Ok(event) => event,
                Err(err) => {
                    self.metrics.inc_disconnect_error();
                    break classify_error(&err);
                }
            };
            match self.handle_event(event, &mut next_ping_at).await {
                Ok(SessionControl::Continue) => {}
                Ok(SessionControl::Close(exit)) => break exit,
                Err(err) => {
                    self.metrics.inc_disconnect_error();
                    break classify_error(&err);
                }
            }
        };

        self.flush_pending_udp_transport_best_effort().await;
        self.shutdown_background_tasks().await;
        result
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
    async fn poll_event(&mut self, next_ping_at: Instant) -> io::Result<SessionEvent> {
        let idle_deadline = match self.active_transport {
            ActiveTransport::Tcp => self.last_tcp_rx + self.config.timing.idle_timeout,
            ActiveTransport::UdpQsp => self.last_udp_rx + self.config.timing.idle_timeout,
        };
        let udp_reconnect_at = self.udp_state.reconnect_at();
        let register_deadline = self.udp_state.register_deadline();
        let udp_enabled = self.udp_state.as_active().is_some();
        let has_discovery_task = self.discovery_task.is_some();
        let has_register_timeout = register_deadline.is_some();
        let udp_upgrade_timer_at = self.udp_upgrade.timer_at();
        let has_udp_upgrade_timer = udp_upgrade_timer_at.is_some();
        let udp_pending_flush = self.active_transport == ActiveTransport::UdpQsp
            && self
                .udp_state
                .as_active()
                .is_some_and(ClientTransport::has_pending_flush);

        // Keep UDP-QSP flush last on purpose. Data/control work gets priority;
        // full GSO slabs flush inline, and this branch drains only partial
        // batches once the session has no immediately-ready work.
        tokio::select! {
            biased;

            () = self.cancel.cancelled() => Ok(SessionEvent::Shutdown),
            command = recv_control(&mut self.control_rx) => {
                Ok(command.map_or(SessionEvent::Shutdown, SessionEvent::Control))
            }
            res = self.tcp.read_more(), if self.tcp_alive => Ok(SessionEvent::TcpRead(res?)),
            maybe = self.tun_channels.to_session_rx.recv() => Ok(SessionEvent::TunPacket(maybe)),
            udp_res = async {
                let udp = self.udp_state.as_active_mut().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::BrokenPipe, "udp-qsp transport missing")
                })?;
                udp.read_next_message(self.limits).await
            }, if udp_enabled => Ok(SessionEvent::UdpResult(udp_res)),
            () = time::sleep_until(next_ping_at.into()) => Ok(SessionEvent::PingTick),
            () = time::sleep_until(idle_deadline.into()) => Ok(SessionEvent::IdleTimeout),
            () = async {
                match udp_reconnect_at {
                    Some(at) => time::sleep_until(at.into()).await,
                    None => std::future::pending().await,
                }
            }, if self.udp_state.is_waiting() && !has_discovery_task => {
                Ok(SessionEvent::UdpReconnectTick)
            }
            () = async {
                match register_deadline {
                    Some(at) => time::sleep_until(at.into()).await,
                    None => std::future::pending().await,
                }
            }, if has_register_timeout => {
                Ok(SessionEvent::RegisterTimeout)
            }
            result = async {
                let task = self.discovery_task.as_mut().expect("discovery_task checked");
                task.await.unwrap_or(None)
            }, if has_discovery_task => {
                Ok(SessionEvent::DiscoveryResult(result))
            }
            () = async {
                match udp_upgrade_timer_at {
                    Some(at) => time::sleep_until(at.into()).await,
                    None => std::future::pending().await,
                }
            }, if has_udp_upgrade_timer => {
                Ok(SessionEvent::UdpUpgradeTick)
            }
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
    ) -> io::Result<SessionControl> {
        match event {
            SessionEvent::Shutdown => {
                info!("shutdown requested");
                self.metrics.inc_disconnect_shutdown();
                if let Err(err) = self.send_close(CloseCode::Normal).await {
                    debug!(error = %err, "failed to send close on shutdown");
                }
                Ok(SessionControl::Close(SessionExit::Shutdown))
            }
            SessionEvent::Control(ClientCommand::Stop) => {
                info!("stop command received");
                self.cancel.cancel();
                self.metrics.inc_disconnect_shutdown();
                if let Err(err) = self.send_close(CloseCode::Normal).await {
                    debug!(error = %err, "failed to send close on stop");
                }
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
                    info!("tun channel closed");
                    self.metrics.inc_disconnect_close();
                    if let Err(err) = self.send_close(CloseCode::Normal).await {
                        debug!(error = %err, "failed to send close after tun shutdown");
                    }
                    return Ok(SessionControl::Close(SessionExit::TunClosed));
                };
                self.handle_tun_packet(packet).await
            }
            SessionEvent::UdpResult(udp_res) => match udp_res {
                Ok(msg_buf) => {
                    let result = self.handle_udp_message(msg_buf).await;
                    let control = match result {
                        Ok(control) => control,
                        Err(err) => {
                            if err.kind() == io::ErrorKind::ConnectionAborted {
                                return Err(err);
                            }
                            if !self.handle_udp_error(&err) {
                                self.metrics.inc_disconnect_error();
                                return Ok(SessionControl::Close(SessionExit::ConnectionError));
                            }
                            return Ok(SessionControl::Continue);
                        }
                    };
                    self.note_udp_activity();
                    Ok(control)
                }
                Err(err) => {
                    if err.kind() == io::ErrorKind::ConnectionAborted {
                        return Err(err);
                    }
                    if !self.handle_udp_error(&err) {
                        self.metrics.inc_disconnect_error();
                        return Ok(SessionControl::Close(SessionExit::ConnectionError));
                    }
                    Ok(SessionControl::Continue)
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
                    if let Err(err) = self.send_close(CloseCode::IdleTimeout).await {
                        debug!(error = %err, "failed to send idle close");
                    }
                    Ok(SessionControl::Close(SessionExit::IdleTimeout))
                }
                ActiveTransport::UdpQsp => {
                    if !self.tcp_alive {
                        warn!("udp-qsp idle timeout and tcp dead; closing session");
                        self.metrics.inc_disconnect_idle_timeout();
                        return Ok(SessionControl::Close(SessionExit::IdleTimeout));
                    }
                    warn!("udp-qsp idle timeout; switching to tcp");
                    self.metrics.inc_transport_udp_to_tcp();
                    self.flush_pending_udp_transport_best_effort().await;
                    self.active_transport = ActiveTransport::Tcp;
                    self.note_transport_change(
                        Transport::UdpQsp,
                        Transport::Tcp,
                        TransportChangeReason::IdleTimeout,
                    );
                    self.note_tcp_activity();
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
                        return Ok(self.attempt_udp_registration().await);
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
                if let Err(err) = self.flush_udp_transport().await {
                    if err.kind() == io::ErrorKind::ConnectionAborted {
                        return Err(err);
                    }
                    if !self.handle_udp_error(&err) {
                        self.metrics.inc_disconnect_error();
                        return Ok(SessionControl::Close(SessionExit::ConnectionError));
                    }
                }
                Ok(SessionControl::Continue)
            }
        }
    }

    /// Forwards a TUN packet to the active transport.
    ///
    /// Writes the packet as a `DATA` message on the active transport.
    /// If UDP-QSP write/enqueue fails, attempts TCP fallback if available.
    /// Later UDP flush failures are handled as transport loss; individual TUN
    /// packets already accepted by the UDP batching layer are not replayed.
    /// Drops oversized packets and updates metrics.
    async fn handle_tun_packet(&mut self, packet: Vec<u8>) -> io::Result<SessionControl> {
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
            if !self.handle_udp_error(&err) {
                return Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "both transports dead",
                ));
            }
            self.tcp
                .write_message(Message::Data {
                    packet: packet.as_slice(),
                })
                .await?;
        }
        Ok(SessionControl::Continue)
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
