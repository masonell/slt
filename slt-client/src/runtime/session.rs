use crate::metrics::Metrics;
use crate::transport::quic_discovery as quic;
use crate::transport::tcp::TcpSession;
use crate::transport::tcp::TcpTransport;
use crate::transport::udp_qsp::UdpQspTransport;
use crate::tun::TunChannels;
use slt_core::config::ClientConfig;
use slt_core::proto::MessageLimits;
use slt_core::proto::{
    CloseCode, ClosePayload, Message, PingPayload, PongPayload, RegisterFailPayload,
    RegisterOkPayload,
};
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::task::JoinHandle;
use tokio::time;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, trace, warn};

use super::ReconnectBackoff;

/// UDP transport lifecycle state.
enum UdpState {
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
struct PendingUdpQspRegistration {
    prepared: super::register::PreparedUdpQspRegistration,
    deadline: Instant,
}

impl UdpState {
    /// Returns true if waiting for reconnect timer (`NeedDiscovery` or `Pending` without in-flight registration).
    const fn is_waiting(&self) -> bool {
        match self {
            Self::NeedDiscovery { .. } => true,
            Self::Pending { registration, .. } => registration.is_none(),
            Self::Disabled | Self::Active(_) => false,
        }
    }

    fn reconnect_at(&self) -> Option<Instant> {
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

    const fn register_deadline(&self) -> Option<Instant> {
        match self {
            Self::Pending {
                registration: Some(registration),
                ..
            } => Some(registration.deadline),
            _ => None,
        }
    }

    const fn as_active(&self) -> Option<&UdpQspTransport> {
        match self {
            Self::Active(transport) => Some(transport),
            _ => None,
        }
    }

    fn as_active_mut(&mut self) -> Option<&mut UdpQspTransport> {
        match self {
            Self::Active(transport) => Some(transport),
            _ => None,
        }
    }
}

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
    exit: Option<SessionExit>,
    metrics: Arc<Metrics>,
}

impl<'a> ClientSession<'a> {
    pub(super) fn new(
        config: &'a ClientConfig,
        tcp: TcpSession,
        tun_channels: &'a mut TunChannels,
        cancel: CancellationToken,
        metrics: Arc<Metrics>,
    ) -> Self {
        let now = Instant::now();
        let limits = super::limits::message_limits_from_mtu(config.tun.tun_mtu);

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
            exit: None,
            metrics,
        }
    }

    pub(super) async fn run(&mut self) -> io::Result<SessionExit> {
        let mut next_ping_at = self.schedule_next_ping();
        let result = loop {
            if self.tcp.has_buffered_input() {
                match self.handle_tcp_read().await {
                    Ok(SessionControl::Close) => break Ok(self.exit_or_default()),
                    Ok(SessionControl::Continue) => {}
                    Err(err) => break Err(err),
                }
            }

            let event = match self.poll_event(next_ping_at).await {
                Ok(event) => event,
                Err(err) => break Err(err),
            };
            match self.handle_event(event, &mut next_ping_at).await {
                Ok(SessionControl::Close) => break Ok(self.exit_or_default()),
                Ok(SessionControl::Continue) => {}
                Err(err) => break Err(err),
            }
        };

        self.shutdown_background_tasks().await;
        result
    }

    /// Spawn QUIC discovery task. Returns a `JoinHandle`.
    fn spawn_quic_discovery(&self) -> JoinHandle<Option<quic::QuicIds>> {
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
    async fn attempt_udp_registration(&mut self) {
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

        match super::register::start_udp_qsp_registration(&mut self.tcp, &quic_ids).await {
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

    fn schedule_discovery_retry(&mut self) {
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

    fn schedule_registration_retry(&mut self) {
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
            res = self.tcp.read_more() => Ok(SessionEvent::TcpRead(res?)),
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
                self.exit = Some(SessionExit::Shutdown);
                if let Err(err) = self.send_close(CloseCode::Normal).await {
                    debug!(error = %err, "failed to send close on shutdown");
                }
                Ok(SessionControl::Close)
            }
            SessionEvent::TcpRead(n) => {
                if n == 0 {
                    info!("tcp connection closed");
                    self.metrics.inc_disconnect_close();
                    self.exit = Some(SessionExit::TcpClosed);
                    return Ok(SessionControl::Close);
                }
                self.note_tcp_activity();
                self.handle_tcp_read().await
            }
            SessionEvent::TunPacket(maybe) => {
                let Some(packet) = maybe else {
                    info!("tun channel closed");
                    self.exit = Some(SessionExit::TunClosed);
                    if let Err(err) = self.send_close(CloseCode::Normal).await {
                        debug!(error = %err, "failed to send close after tun shutdown");
                    }
                    return Ok(SessionControl::Close);
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
                            self.handle_udp_error(&err);
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
                    self.handle_udp_error(&err);
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
                    self.exit = Some(SessionExit::IdleTimeout);
                    if let Err(err) = self.send_close(CloseCode::IdleTimeout).await {
                        debug!(error = %err, "failed to send idle close");
                    }
                    Ok(SessionControl::Close)
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

    fn handle_udp_error(&mut self, err: &io::Error) {
        // Transient errors (replay, too_old, crypto) can be retried
        // InvalidData is typically packet-level issues that should be dropped, not fatal
        if err.kind() == io::ErrorKind::InvalidData {
            trace!(error = %err, "dropping udp-qsp packets");
            return;
        }

        let was_udp_active = self.active_transport == ActiveTransport::UdpQsp;
        warn!(
            kind = ?err.kind(),
            error = %err,
            "udp-qsp io error; falling back to tcp and scheduling retry"
        );
        if was_udp_active {
            self.metrics.inc_transport_udp_to_tcp();
        }
        self.active_transport = ActiveTransport::Tcp;
        self.note_tcp_activity();

        // Transition to NeedDiscovery state to re-discover quic_ids
        self.schedule_discovery_retry();
    }

    async fn handle_tcp_read(&mut self) -> io::Result<SessionControl> {
        loop {
            let Some(msg_buf) = self
                .tcp
                .try_pop_message(self.limits)
                .map_err(crate::wire::map_message_error)?
            else {
                return Ok(SessionControl::Continue);
            };

            if self.handle_tcp_message(msg_buf.message()).await? == SessionControl::Close {
                return Ok(SessionControl::Close);
            }
        }
    }

    async fn handle_tcp_message(&mut self, message: Message<'_>) -> io::Result<SessionControl> {
        match message {
            Message::RegisterOk { payload } => self.handle_register_ok(payload),
            Message::RegisterFail { payload } => self.handle_register_fail(payload),
            Message::Data { packet } => {
                if self.active_transport != ActiveTransport::Tcp {
                    debug!("tcp data received while udp-qsp is active; switching to tcp");
                    self.metrics.inc_transport_udp_to_tcp();
                    self.active_transport = ActiveTransport::Tcp;
                }
                if self
                    .tun_channels
                    .to_tun_tx
                    .send(packet.to_vec())
                    .await
                    .is_err()
                {
                    self.exit = Some(SessionExit::TunClosed);
                    return Ok(SessionControl::Close);
                }
                Ok(SessionControl::Continue)
            }
            Message::Ping { payload } => {
                let ping_in =
                    PingPayload::decode(payload).map_err(crate::wire::map_payload_error)?;
                if self.active_transport != ActiveTransport::Tcp {
                    debug!("tcp ping received while udp-qsp is active; switching to tcp");
                    self.metrics.inc_transport_udp_to_tcp();
                    self.active_transport = ActiveTransport::Tcp;
                }
                let pong_out = PongPayload {
                    nonce: ping_in.nonce,
                };
                let mut pong_buf = Vec::with_capacity(8);
                pong_out.encode(&mut pong_buf);
                self.tcp
                    .write_message(Message::Pong { payload: &pong_buf })
                    .await?;
                Ok(SessionControl::Continue)
            }
            Message::Pong { payload } => {
                let pong_in =
                    PongPayload::decode(payload).map_err(crate::wire::map_payload_error)?;
                trace!(nonce = pong_in.nonce, "received pong");
                Ok(SessionControl::Continue)
            }
            Message::Close { payload } => {
                let close =
                    ClosePayload::decode(payload).map_err(crate::wire::map_payload_error)?;
                info!(code = ?close.code, "received close");
                self.exit = Some(SessionExit::RemoteClose(close.code));
                Ok(SessionControl::Close)
            }
            Message::RegisterCid { .. }
            | Message::Auth { .. }
            | Message::AuthOk { .. }
            | Message::AuthFail { .. } => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unexpected control message on established session",
            )),
        }
    }

    fn handle_register_ok(&mut self, payload: &[u8]) -> io::Result<SessionControl> {
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

    fn handle_register_fail(&mut self, payload: &[u8]) -> io::Result<SessionControl> {
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
        self.schedule_registration_retry();
        Ok(SessionControl::Continue)
    }

    async fn handle_udp_message(&mut self, message: Message<'_>) -> io::Result<SessionControl> {
        match message {
            Message::RegisterOk { .. } => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unexpected register_ok on udp-qsp transport",
            )),
            Message::RegisterFail { .. } => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unexpected register_fail on udp-qsp transport",
            )),
            Message::Ping { payload } => {
                let ping_in =
                    PingPayload::decode(payload).map_err(crate::wire::map_payload_error)?;
                let pong_payload = ping_in.nonce.to_be_bytes();
                self.write_udp_message(Message::Pong {
                    payload: &pong_payload,
                })
                .await?;
                trace!(nonce = ping_in.nonce, "responded to udp ping");
                Ok(SessionControl::Continue)
            }
            Message::Pong { payload } => {
                let pong_in =
                    PongPayload::decode(payload).map_err(crate::wire::map_payload_error)?;
                trace!(nonce = pong_in.nonce, "received udp pong");
                Ok(SessionControl::Continue)
            }
            Message::Data { packet } => {
                if self.active_transport != ActiveTransport::UdpQsp {
                    self.metrics.inc_transport_tcp_to_udp();
                    self.active_transport = ActiveTransport::UdpQsp;
                    info!("udp-qsp data received; switching to udp");
                }
                if self
                    .tun_channels
                    .to_tun_tx
                    .send(packet.to_vec())
                    .await
                    .is_err()
                {
                    self.exit = Some(SessionExit::TunClosed);
                    return Ok(SessionControl::Close);
                }
                Ok(SessionControl::Continue)
            }
            Message::Close { payload } => {
                let close =
                    ClosePayload::decode(payload).map_err(crate::wire::map_payload_error)?;
                info!(code = ?close.code, "received udp close");
                self.exit = Some(SessionExit::RemoteClose(close.code));
                Ok(SessionControl::Close)
            }
            Message::RegisterCid { .. }
            | Message::Auth { .. }
            | Message::AuthOk { .. }
            | Message::AuthFail { .. } => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unexpected control message on udp-qsp transport",
            )),
        }
    }

    async fn handle_tun_packet(&mut self, packet: Vec<u8>) -> io::Result<SessionControl> {
        if packet.is_empty() {
            return Ok(SessionControl::Continue);
        }
        if packet.len() > self.limits.max_data_len {
            trace!(
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
            self.handle_udp_error(&err);
            self.tcp
                .write_message(Message::Data {
                    packet: packet.as_slice(),
                })
                .await?;
        }
        Ok(SessionControl::Continue)
    }

    async fn handle_ping_tick(&mut self) -> io::Result<()> {
        let nonce = fastrand::u64(..);
        let ping = PingPayload { nonce };
        let mut buf = Vec::with_capacity(8);
        ping.encode(&mut buf);
        trace!(nonce, "sending ping");
        let active = self.active_transport;
        if let Err(err) = self
            .write_active_message(Message::Ping { payload: &buf })
            .await
        {
            if active != ActiveTransport::UdpQsp {
                return Err(err);
            }
            self.handle_udp_error(&err);
            self.tcp
                .write_message(Message::Ping { payload: &buf })
                .await?;
        }
        Ok(())
    }

    async fn send_close(&mut self, code: CloseCode) -> io::Result<()> {
        let payload = ClosePayload { code };
        let mut buf = Vec::with_capacity(1);
        payload.encode(&mut buf);
        let active = self.active_transport;
        if let Err(err) = self
            .write_active_message(Message::Close { payload: &buf })
            .await
        {
            if active != ActiveTransport::UdpQsp {
                return Err(err);
            }
            self.handle_udp_error(&err);
            self.tcp
                .write_message(Message::Close { payload: &buf })
                .await?;
        }
        Ok(())
    }

    async fn write_active_message(&mut self, message: Message<'_>) -> io::Result<()> {
        match self.active_transport {
            ActiveTransport::Tcp => self.tcp.write_message(message).await,
            ActiveTransport::UdpQsp => {
                let udp = self.udp_state.as_active_mut().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::BrokenPipe, "udp-qsp transport missing")
                })?;
                udp.write_message(message).await
            }
        }
    }

    async fn write_udp_message(&mut self, message: Message<'_>) -> io::Result<()> {
        let udp = self.udp_state.as_active_mut().ok_or_else(|| {
            io::Error::new(io::ErrorKind::BrokenPipe, "udp-qsp transport missing")
        })?;
        udp.write_message(message).await
    }

    fn exit_or_default(&mut self) -> SessionExit {
        self.exit.take().unwrap_or(SessionExit::TcpClosed)
    }

    async fn shutdown_background_tasks(&mut self) {
        if let Some(task) = self.discovery_task.take() {
            task.abort();
            if let Err(err) = task.await
                && !err.is_cancelled()
            {
                warn!(error = %err, "quic discovery task failed on shutdown");
            }
        }
    }

    fn schedule_next_ping(&self) -> Instant {
        let min_ms = u64::try_from(self.config.timing.ping_min.as_millis()).unwrap_or(u64::MAX);
        let max_ms = u64::try_from(self.config.timing.ping_max.as_millis()).unwrap_or(u64::MAX);
        let jitter_ms = if max_ms > min_ms {
            fastrand::u64(0..=(max_ms - min_ms))
        } else {
            0
        };
        Instant::now() + Duration::from_millis(min_ms + jitter_ms)
    }

    fn note_tcp_activity(&mut self) {
        self.last_tcp_rx = Instant::now();
    }

    fn note_udp_activity(&mut self) {
        self.last_udp_rx = Instant::now();
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Session termination reason used by the runtime to decide reconnect behavior.
pub(super) enum SessionExit {
    Shutdown,
    TcpClosed,
    TunClosed,
    IdleTimeout,
    RemoteClose(CloseCode),
}

enum SessionEvent {
    Shutdown,
    TcpRead(usize),
    TunPacket(Option<Vec<u8>>),
    UdpResult(io::Result<crate::wire::OwnedMessageBuf>),
    PingTick,
    IdleTimeout,
    UdpReconnectTick,
    RegisterTimeout,
    DiscoveryResult(Option<quic::QuicIds>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SessionControl {
    Continue,
    Close,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ActiveTransport {
    Tcp,
    UdpQsp,
}
