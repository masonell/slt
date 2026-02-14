use crate::metrics::Metrics;
use crate::transport::quic_discovery as quic;
use crate::transport::tcp::TcpSession;
use crate::transport::tcp::TcpTransport;
use crate::transport::udp_qsp::UdpQspTransport;
use crate::tun::TunChannels;
use slt_core::config::ClientConfig;
use slt_core::proto::MessageLimits;
use slt_core::proto::{CloseCode, ClosePayload, Message, PingPayload, PongPayload};
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::time;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, trace, warn};

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
    quic_ids: Option<quic::QuicIds>,
    udp_session: Option<UdpQspTransport>,
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
            quic_ids: None,
            udp_session: None,
            exit: None,
            metrics,
        }
    }

    pub(super) async fn run(&mut self) -> io::Result<SessionExit> {
        // Discover QUIC IDs for potential UDP-QSP upgrade
        self.quic_ids = self.discover_quic_ids().await;

        if let Some(ids) = &self.quic_ids {
            debug!(
                dcid_len = ids.dcid.len(),
                scid_len = ids.scid.len(),
                "quic ids ready for registration"
            );

            // Attempt UDP registration
            self.try_register_udp_qsp().await;
        }

        let mut next_ping_at = self.schedule_next_ping();

        loop {
            if self.tcp.has_buffered_input()
                && self.handle_tcp_read().await? == SessionControl::Close
            {
                return Ok(self.exit.take().unwrap_or(SessionExit::TcpClosed));
            }

            let event = self.poll_event(next_ping_at).await?;
            if self.handle_event(event, &mut next_ping_at).await? == SessionControl::Close {
                return Ok(self.exit.take().unwrap_or(SessionExit::TcpClosed));
            }
        }
    }

    /// Discover QUIC connection IDs for UDP-QSP upgrade.
    async fn discover_quic_ids(&self) -> Option<quic::QuicIds> {
        if !self.config.enable_upgrade {
            debug!("upgrade disabled; skipping quic dcid discovery");
            return None;
        }

        tokio::select! {
            () = self.cancel.cancelled() => None,
            result = quic::discover_quic_ids(self.config, &self.cancel, self.peer) => match result {
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
        }
    }

    /// Attempt UDP-QSP registration (one-time attempt, fallback to TCP on failure).
    async fn try_register_udp_qsp(&mut self) {
        let Some(ids) = &self.quic_ids else {
            return;
        };

        match super::register::register_udp_qsp(
            &mut self.tcp,
            self.limits,
            &self.tun_channels.to_tun_tx,
            ids,
            &self.cancel,
            self.config.timing.register_timeout,
        )
        .await
        {
            Ok(session) => {
                info!(
                    dcid_len = ids.dcid.len(),
                    scid_len = ids.scid.len(),
                    peer = %ids.peer,
                    "register_cid accepted"
                );
                self.udp_session = Some(UdpQspTransport::new(session, self.metrics.clone()));
                self.active_transport = ActiveTransport::UdpQsp;
                self.metrics.inc_transport_tcp_to_udp();
            }
            Err(err) => {
                warn!(error = %err, "register_cid failed; continuing with tcp");
            }
        }
    }

    async fn poll_event(&mut self, next_ping_at: Instant) -> io::Result<SessionEvent> {
        let idle_deadline = match self.active_transport {
            ActiveTransport::Tcp => self.last_tcp_rx + self.config.timing.idle_timeout,
            ActiveTransport::UdpQsp => self.last_udp_rx + self.config.timing.idle_timeout,
        };
        let udp_enabled = self.udp_session.is_some();

        tokio::select! {
            () = self.cancel.cancelled() => Ok(SessionEvent::Shutdown),
            res = self.tcp.read_more() => Ok(SessionEvent::TcpRead(res?)),
            maybe = self.tun_channels.to_session_rx.recv() => Ok(SessionEvent::TunPacket(maybe)),
            udp_res = async {
                let udp = self.udp_session.as_mut().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::BrokenPipe, "udp-qsp transport missing")
                })?;
                udp.read_next_message(self.limits).await
            }, if udp_enabled => Ok(SessionEvent::UdpResult(udp_res)),
            () = time::sleep_until(next_ping_at.into()) => Ok(SessionEvent::PingTick),
            () = time::sleep_until(idle_deadline.into()) => Ok(SessionEvent::IdleTimeout),
        }
    }

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
        }
    }

    fn handle_udp_error(&mut self, err: &io::Error) {
        if err.kind() == io::ErrorKind::InvalidData {
            trace!(error = %err, "dropping udp-qsp packets");
            return;
        }

        let was_udp_active = self.active_transport == ActiveTransport::UdpQsp;
        warn!(
            kind = ?err.kind(),
            error = %err,
            "udp-qsp io error; falling back to tcp"
        );
        if was_udp_active {
            self.metrics.inc_transport_udp_to_tcp();
        }
        self.udp_session = None;
        self.active_transport = ActiveTransport::Tcp;
        self.note_tcp_activity();
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
            Message::RegisterOk { .. } => {
                debug!("unexpected register_ok on established session");
                Ok(SessionControl::Continue)
            }
            Message::RegisterFail { .. } => {
                debug!("unexpected register_fail on established session");
                Ok(SessionControl::Continue)
            }
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
                let udp = self.udp_session.as_mut().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::BrokenPipe, "udp-qsp transport missing")
                })?;
                udp.write_message(message).await
            }
        }
    }

    async fn write_udp_message(&mut self, message: Message<'_>) -> io::Result<()> {
        let udp = self.udp_session.as_mut().ok_or_else(|| {
            io::Error::new(io::ErrorKind::BrokenPipe, "udp-qsp transport missing")
        })?;
        udp.write_message(message).await
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
