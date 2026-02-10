use crate::transport::quic_discovery as quic;
use crate::transport::tcp::TcpTransport;
use crate::transport::udp_qsp::UdpQspTransport;
use slt_core::proto::{CloseCode, ClosePayload, Message, MessageLimits, PingPayload, PongPayload};
use std::io;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tokio::time;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, trace, warn};

const UDP_VERIFY_TIMEOUT: Duration = Duration::from_secs(5);
const UDP_VERIFY_PONG_RETRANSMIT_INTERVAL: Duration = Duration::from_millis(100);
const UDP_VERIFY_PONG_MAX_SENDS: u8 = 3;

#[derive(Debug, Clone, Copy)]
struct UdpVerifySwitch {
    pong_payload: [u8; 8],
    next_send_at: Instant,
    sent: u8,
}

pub(super) struct ClientSession {
    tcp: TcpTransport,
    active_transport: ActiveTransport,
    to_session_rx: mpsc::Receiver<Vec<u8>>,
    to_tun_tx: mpsc::Sender<Vec<u8>>,
    cancel: CancellationToken,
    limits: MessageLimits,
    last_activity: Instant,
    ping_min: Duration,
    ping_max: Duration,
    idle_timeout: Duration,
    quic_ids: Option<quic::QuicIds>,
    udp_session: Option<UdpQspTransport>,
    udp_expect_ping_deadline: Option<Instant>,
    udp_verify: Option<UdpVerifySwitch>,
}

impl ClientSession {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        tcp: TcpTransport,
        to_session_rx: mpsc::Receiver<Vec<u8>>,
        to_tun_tx: mpsc::Sender<Vec<u8>>,
        cancel: CancellationToken,
        limits: MessageLimits,
        ping_min: Duration,
        ping_max: Duration,
        idle_timeout: Duration,
        quic_ids: Option<quic::QuicIds>,
        udp_session: Option<UdpQspTransport>,
    ) -> Self {
        Self {
            tcp,
            active_transport: ActiveTransport::Tcp,
            to_session_rx,
            to_tun_tx,
            cancel,
            limits,
            last_activity: Instant::now(),
            ping_min,
            ping_max,
            idle_timeout,
            quic_ids,
            udp_session,
            udp_expect_ping_deadline: None,
            udp_verify: None,
        }
    }

    pub(super) async fn run(&mut self) -> io::Result<()> {
        if let Some(ids) = &self.quic_ids {
            debug!(
                dcid_len = ids.dcid.len(),
                scid_len = ids.scid.len(),
                "quic ids ready for registration"
            );
        }
        self.maybe_start_udp_verify().await;
        let mut next_ping_at = self.schedule_next_ping();

        loop {
            if self.tcp.has_buffered_input()
                && self.handle_tcp_read().await? == SessionControl::Close
            {
                return Ok(());
            }

            let event = self.poll_event(next_ping_at).await?;
            if self.handle_event(event, &mut next_ping_at).await? == SessionControl::Close {
                return Ok(());
            }
        }
    }

    async fn maybe_start_udp_verify(&mut self) {
        let Some(session) = &self.udp_session else {
            return;
        };
        debug!(
            dcid_len = session.dcid().len(),
            scid_len = session.scid().len(),
            "udp-qsp session initialized"
        );
        self.udp_expect_ping_deadline = Some(Instant::now() + UDP_VERIFY_TIMEOUT);
        self.udp_verify = None;
        if let Err(err) = self.send_udp_probe_ping().await {
            warn!(error = %err, "failed to send udp-qsp probe ping; staying on tcp");
            self.udp_session = None;
            self.udp_expect_ping_deadline = None;
            self.udp_verify = None;
        }
    }

    async fn poll_event(&mut self, next_ping_at: Instant) -> io::Result<SessionEvent> {
        let idle_deadline = self.last_activity + self.idle_timeout;
        let udp_enabled = self.udp_session.is_some();
        let verify_deadline = if udp_enabled {
            self.udp_expect_ping_deadline
        } else {
            None
        };
        let retransmit_at = self.udp_verify.as_ref().map(|verify| verify.next_send_at);
        let retransmit_sleep = async move {
            if let Some(at) = retransmit_at {
                time::sleep_until(at.into()).await;
            } else {
                std::future::pending::<()>().await;
            }
        };
        let verify_sleep = async move {
            if let Some(deadline) = verify_deadline {
                time::sleep_until(deadline.into()).await;
            } else {
                std::future::pending::<()>().await;
            }
        };

        tokio::select! {
            () = self.cancel.cancelled() => Ok(SessionEvent::Shutdown),
            res = self.tcp.read_more() => Ok(SessionEvent::TcpRead(res?)),
            maybe = self.to_session_rx.recv() => Ok(SessionEvent::TunPacket(maybe)),
            udp_res = async {
                let udp = self.udp_session.as_mut().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::BrokenPipe, "udp-qsp transport missing")
                })?;
                udp.read_next_message(self.limits).await
            }, if udp_enabled => Ok(SessionEvent::UdpResult(udp_res)),
            () = retransmit_sleep => Ok(SessionEvent::UdpVerifyRetransmit),
            () = time::sleep_until(next_ping_at.into()) => Ok(SessionEvent::PingTick),
            () = time::sleep_until(idle_deadline.into()) => Ok(SessionEvent::IdleTimeout),
            () = verify_sleep => Ok(SessionEvent::UdpVerifyTimeout),
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
                if let Err(err) = self.send_close(CloseCode::Normal).await {
                    debug!(error = %err, "failed to send close on shutdown");
                }
                Ok(SessionControl::Close)
            }
            SessionEvent::TcpRead(n) => {
                if n == 0 {
                    info!("tcp connection closed");
                    return Ok(SessionControl::Close);
                }
                self.note_activity();
                self.handle_tcp_read().await
            }
            SessionEvent::TunPacket(maybe) => {
                let Some(packet) = maybe else {
                    info!("tun channel closed");
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
                            self.handle_udp_error(&err);
                            return Ok(SessionControl::Continue);
                        }
                    };
                    self.note_activity();
                    Ok(control)
                }
                Err(err) => {
                    self.handle_udp_error(&err);
                    Ok(SessionControl::Continue)
                }
            },
            SessionEvent::UdpVerifyRetransmit => {
                if let Err(err) = self.handle_udp_verify_retransmit().await {
                    self.handle_udp_error(&err);
                }
                Ok(SessionControl::Continue)
            }
            SessionEvent::PingTick => {
                self.handle_ping_tick().await?;
                *next_ping_at = self.schedule_next_ping();
                Ok(SessionControl::Continue)
            }
            SessionEvent::IdleTimeout => {
                info!("idle timeout reached");
                if let Err(err) = self.send_close(CloseCode::IdleTimeout).await {
                    debug!(error = %err, "failed to send idle close");
                }
                Ok(SessionControl::Close)
            }
            SessionEvent::UdpVerifyTimeout => {
                warn!("udp-qsp verification timed out; staying on tcp");
                self.udp_session = None;
                self.udp_expect_ping_deadline = None;
                self.udp_verify = None;
                self.active_transport = ActiveTransport::Tcp;
                Ok(SessionControl::Continue)
            }
        }
    }

    fn handle_udp_error(&mut self, err: &io::Error) {
        if err.kind() == io::ErrorKind::InvalidData {
            trace!(error = %err, "dropping udp-qsp packet");
            return;
        }

        warn!(
            kind = ?err.kind(),
            error = %err,
            "udp-qsp io error; falling back to tcp"
        );
        self.udp_session = None;
        self.udp_expect_ping_deadline = None;
        self.udp_verify = None;
        self.active_transport = ActiveTransport::Tcp;
    }

    async fn handle_udp_verify_retransmit(&mut self) -> io::Result<()> {
        let Some(mut verify) = self.udp_verify else {
            return Ok(());
        };

        if verify.sent >= UDP_VERIFY_PONG_MAX_SENDS {
            self.udp_verify = None;
            return Ok(());
        }

        let now = Instant::now();
        if now < verify.next_send_at {
            return Ok(());
        }

        let res = self
            .write_udp_message(Message::Pong {
                payload: &verify.pong_payload,
            })
            .await;
        verify.sent = verify.sent.saturating_add(1);
        verify.next_send_at = now + UDP_VERIFY_PONG_RETRANSMIT_INTERVAL;

        if verify.sent >= UDP_VERIFY_PONG_MAX_SENDS {
            self.udp_verify = None;
        } else {
            self.udp_verify = Some(verify);
        }

        res
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
            Message::Data { packet } => {
                if self.active_transport != ActiveTransport::Tcp {
                    debug!("tcp data received while udp-qsp is active; switching to tcp");
                    self.active_transport = ActiveTransport::Tcp;
                }
                if self.to_tun_tx.send(packet.to_vec()).await.is_err() {
                    return Ok(SessionControl::Close);
                }
                Ok(SessionControl::Continue)
            }
            Message::Ping { payload } => {
                let ping_in =
                    PingPayload::decode(payload).map_err(crate::wire::map_payload_error)?;
                if self.active_transport != ActiveTransport::Tcp {
                    debug!("tcp ping received while udp-qsp is active; switching to tcp");
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
                Ok(SessionControl::Close)
            }
            Message::RegisterCid { .. }
            | Message::RegisterOk { .. }
            | Message::RegisterFail { .. }
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
            Message::Ping { payload } => {
                let ping_in =
                    PingPayload::decode(payload).map_err(crate::wire::map_payload_error)?;
                let pong_payload = ping_in.nonce.to_be_bytes();
                self.write_udp_message(Message::Pong {
                    payload: &pong_payload,
                })
                .await?;

                if self.udp_expect_ping_deadline.is_some() {
                    self.udp_expect_ping_deadline = None;
                    self.udp_verify = Some(UdpVerifySwitch {
                        pong_payload,
                        next_send_at: Instant::now() + UDP_VERIFY_PONG_RETRANSMIT_INTERVAL,
                        sent: 1,
                    });
                    if self.active_transport == ActiveTransport::UdpQsp {
                        info!(nonce = ping_in.nonce, "udp-qsp verify ping received");
                    } else {
                        self.active_transport = ActiveTransport::UdpQsp;
                        info!(
                            nonce = ping_in.nonce,
                            "udp-qsp verify ping received; switching to udp"
                        );
                    }
                } else if self.active_transport == ActiveTransport::Tcp {
                    self.active_transport = ActiveTransport::UdpQsp;
                    info!(
                        nonce = ping_in.nonce,
                        "udp-qsp ping received; switching to udp"
                    );
                }

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
                    self.active_transport = ActiveTransport::UdpQsp;
                    info!("udp-qsp data received; switching to udp");
                }
                if self.to_tun_tx.send(packet.to_vec()).await.is_err() {
                    return Ok(SessionControl::Close);
                }
                Ok(SessionControl::Continue)
            }
            Message::Close { payload } => {
                let close =
                    ClosePayload::decode(payload).map_err(crate::wire::map_payload_error)?;
                info!(code = ?close.code, "received udp close");
                Ok(SessionControl::Close)
            }
            Message::RegisterCid { .. }
            | Message::RegisterOk { .. }
            | Message::RegisterFail { .. }
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

    async fn send_udp_probe_ping(&mut self) -> io::Result<()> {
        if self.udp_session.is_none() {
            return Ok(());
        }
        let nonce = fastrand::u64(..);
        let ping = PingPayload { nonce };
        let mut buf = Vec::with_capacity(8);
        ping.encode(&mut buf);
        trace!(nonce, "sending udp-qsp probe ping");
        self.write_udp_message(Message::Ping { payload: &buf })
            .await
    }

    fn schedule_next_ping(&self) -> Instant {
        let min_ms = u64::try_from(self.ping_min.as_millis()).unwrap_or(u64::MAX);
        let max_ms = u64::try_from(self.ping_max.as_millis()).unwrap_or(u64::MAX);
        let jitter_ms = if max_ms > min_ms {
            fastrand::u64(0..=(max_ms - min_ms))
        } else {
            0
        };
        Instant::now() + Duration::from_millis(min_ms + jitter_ms)
    }

    fn note_activity(&mut self) {
        self.last_activity = Instant::now();
    }
}

enum SessionEvent {
    Shutdown,
    TcpRead(usize),
    TunPacket(Option<Vec<u8>>),
    UdpResult(io::Result<crate::wire::OwnedMessageBuf>),
    UdpVerifyRetransmit,
    PingTick,
    IdleTimeout,
    UdpVerifyTimeout,
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
