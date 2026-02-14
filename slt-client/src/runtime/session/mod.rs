//! Client session: manages TCP/UDP transport lifecycle and data flow.
//!
//! This module is organized into submodules by responsibility:
//! - `state`: UDP state machine types
//! - `event`: Event and control enums
//! - `tcp`: TCP message handlers
//! - `udp`: UDP message handlers
//! - `upgrade`: Discovery and registration logic
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
use state::{ActiveTransport, UdpState};
use tokio::task::JoinHandle;
use tokio::time;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use super::{ReconnectBackoff, limits};
use crate::metrics::Metrics;
use crate::transport::quic_discovery as quic;
use crate::transport::tcp::{TcpSession, TcpTransport};
use crate::tun::TunChannels;

/// Session managing a single VPN connection.
pub(super) struct ClientSession<'a> {
    config: &'a ClientConfig,
    tcp: TcpTransport,
    peer: Option<SocketAddr>,
    tun_channels: &'a mut TunChannels,
    active_transport: ActiveTransport,
    cancel: CancellationToken,
    limits: MessageLimits,
    last_tcp_rx: Instant,
    last_udp_rx: Instant,
    udp_state: UdpState,
    discovery_task: Option<JoinHandle<Option<quic::QuicIds>>>,
    metrics: Arc<Metrics>,
    /// Whether the TCP connection is still usable. Set to false when TCP closes
    /// while UDP-QSP is active, allowing the session to continue on UDP alone.
    tcp_alive: bool,
}

impl<'a> ClientSession<'a> {
    /// Create a new session from an authenticated TCP connection.
    pub(super) fn new(
        config: &'a ClientConfig,
        tcp: TcpSession,
        tun_channels: &'a mut TunChannels,
        cancel: CancellationToken,
        metrics: Arc<Metrics>,
    ) -> Self {
        let now = Instant::now();
        let limits = limits::message_limits_from_mtu(config.tun.tun_mtu);

        let udp_state = if config.enable_upgrade {
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
            discovery_task: None,
            metrics,
            tcp_alive: true,
        }
    }

    /// Run the session event loop until shutdown or error.
    pub(super) async fn run(&mut self) -> SessionExit {
        let mut next_ping_at = self.schedule_next_ping();
        let result = loop {
            if self.tcp_alive && self.tcp.has_buffered_input() {
                match self.handle_tcp_read().await {
                    Ok(SessionControl::Continue) => {}
                    Ok(SessionControl::Close(exit)) => break exit,
                    Err(err) => break Self::classify_error(&err),
                }
            }

            let event = match self.poll_event(next_ping_at).await {
                Ok(event) => event,
                Err(err) => break Self::classify_error(&err),
            };
            match self.handle_event(event, &mut next_ping_at).await {
                Ok(SessionControl::Continue) => {}
                Ok(SessionControl::Close(exit)) => break exit,
                Err(err) => break Self::classify_error(&err),
            }
        };

        self.shutdown_background_tasks().await;
        result
    }

    /// Classify an I/O error into the appropriate exit variant.
    fn classify_error(err: &io::Error) -> SessionExit {
        match err.kind() {
            io::ErrorKind::InvalidData | io::ErrorKind::InvalidInput => SessionExit::ProtocolError,
            io::ErrorKind::PermissionDenied => SessionExit::PermissionDenied,
            _ => SessionExit::ConnectionError,
        }
    }

    /// Poll for the next session event.
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

        tokio::select! {
            () = self.cancel.cancelled() => Ok(SessionEvent::Shutdown),
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
        }
    }

    /// Dispatch a session event to the appropriate handler.
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
                    if let Err(err) = self.send_close(CloseCode::Normal).await {
                        debug!(error = %err, "failed to send close after tun shutdown");
                    }
                    return Ok(SessionControl::Close(SessionExit::TunClosed));
                };
                self.handle_tun_packet(packet).await
            }
            SessionEvent::UdpResult(udp_res) => match udp_res {
                Ok(msg_buf) => {
                    let result = self.handle_udp_message(msg_buf.message()).await;
                    let control = match result {
                        Ok(control) => control,
                        Err(err) => {
                            if err.kind() == io::ErrorKind::ConnectionAborted {
                                return Err(err);
                            }
                            if !self.handle_udp_error(&err) {
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
                    warn!("udp-qsp idle timeout; switching to tcp");
                    self.metrics.inc_transport_udp_to_tcp();
                    self.active_transport = ActiveTransport::Tcp;
                    self.note_tcp_activity();
                    Ok(SessionControl::Continue)
                }
            },
            SessionEvent::UdpReconnectTick => {
                match &self.udp_state {
                    UdpState::NeedDiscovery { .. } => {
                        debug!("udp reconnect tick; spawning quic discovery task");
                        self.discovery_task = Some(self.spawn_quic_discovery());
                    }
                    UdpState::Pending { .. } => {
                        debug!("udp reconnect tick; attempting registration");
                        self.attempt_udp_registration().await;
                    }
                    _ => {}
                }
                Ok(SessionControl::Continue)
            }
            SessionEvent::RegisterTimeout => {
                if matches!(
                    &self.udp_state,
                    UdpState::Pending {
                        registration: Some(_),
                        ..
                    }
                ) {
                    warn!("register_cid timed out; scheduling retry");
                    self.schedule_registration_retry();
                }
                Ok(SessionControl::Continue)
            }
            SessionEvent::DiscoveryResult(maybe_ids) => {
                self.discovery_task = None; // Clear the completed task
                match maybe_ids {
                    Some(ids) => {
                        self.udp_state = UdpState::Pending {
                            quic_ids: ids,
                            backoff: ReconnectBackoff::new(
                                self.config.timing.reconnect_min,
                                self.config.timing.reconnect_max,
                            ),
                            reconnect_at: Instant::now(),
                            registration: None,
                        };
                    }
                    None => {
                        self.schedule_discovery_retry();
                    }
                }
                Ok(SessionControl::Continue)
            }
        }
    }

    /// Forward a TUN packet to the active transport.
    async fn handle_tun_packet(&mut self, packet: Vec<u8>) -> io::Result<SessionControl> {
        if packet.is_empty() {
            return Ok(SessionControl::Continue);
        }
        if packet.len() > self.limits.max_data_len {
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
