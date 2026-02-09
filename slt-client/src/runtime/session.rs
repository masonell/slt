use crate::transport::quic_discovery as quic;
use crate::transport::tcp::TcpTransport;
use crate::transport::udp_qsp::UdpQspTransport;
use slt_core::proto::{CloseCode, ClosePayload, Message, MessageLimits, PingPayload, PongPayload};
use std::io;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tokio::time;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, trace};

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
        }
    }

    pub(super) async fn run(&mut self) -> io::Result<()> {
        // Keep the UDP-QSP transport methods and enum variant compiled/used even before
        // transport switching is implemented.
        let _ = ActiveTransport::UdpQsp;

        if let Some(ids) = &self.quic_ids {
            debug!(
                dcid_len = ids.dcid.len(),
                scid_len = ids.scid.len(),
                "quic ids ready for registration"
            );
        }
        if let Some(session) = &self.udp_session {
            debug!(
                dcid_len = session.dcid().len(),
                scid_len = session.scid().len(),
                "udp-qsp session initialized"
            );
        }
        let mut next_ping_at = self.schedule_next_ping();

        loop {
            self.maybe_read_udp_one().await?;

            if self.tcp.has_buffered_input()
                && self.handle_tcp_read().await? == SessionControl::Close
            {
                return Ok(());
            }

            let idle_deadline = self.last_activity + self.idle_timeout;

            tokio::select! {
                () = self.cancel.cancelled() => {
                    info!("shutdown requested");
                    if let Err(err) = self.send_close(CloseCode::Normal).await {
                        debug!(error = %err, "failed to send close on shutdown");
                    }
                    return Ok(());
                }
                res = self.tcp.read_more() => {
                    let n = res?;
                    if n == 0 {
                        info!("tcp connection closed");
                        return Ok(());
                    }
                    self.note_activity();
                    if self.handle_tcp_read().await? == SessionControl::Close {
                        return Ok(());
                    }
                }
                maybe = self.to_session_rx.recv() => {
                    let Some(packet) = maybe else {
                        info!("tun channel closed");
                        if let Err(err) = self.send_close(CloseCode::Normal).await {
                            debug!(error = %err, "failed to send close after tun shutdown");
                        }
                        return Ok(());
                    };
                    if self.handle_tun_packet(packet).await? == SessionControl::Close {
                        return Ok(());
                    }
                }
                () = time::sleep_until(next_ping_at.into()) => {
                    self.handle_ping_tick().await?;
                    next_ping_at = self.schedule_next_ping();
                }
                () = time::sleep_until(idle_deadline.into()) => {
                    info!("idle timeout reached");
                    if let Err(err) = self.send_close(CloseCode::IdleTimeout).await {
                        debug!(error = %err, "failed to send idle close");
                    }
                    return Ok(());
                }
            }
        }
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
        self.note_activity();
        match message {
            Message::Data { packet } => {
                if self.to_tun_tx.send(packet.to_vec()).await.is_err() {
                    return Ok(SessionControl::Close);
                }
                Ok(SessionControl::Continue)
            }
            Message::Ping { payload } => {
                let ping_in =
                    PingPayload::decode(payload).map_err(crate::wire::map_payload_error)?;
                let pong_out = PongPayload {
                    nonce: ping_in.nonce,
                };
                let mut pong_buf = Vec::with_capacity(8);
                pong_out.encode(&mut pong_buf);
                self.write_active_message(Message::Pong { payload: &pong_buf })
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

        self.write_active_message(Message::Data {
            packet: packet.as_slice(),
        })
        .await?;
        Ok(SessionControl::Continue)
    }

    async fn handle_ping_tick(&mut self) -> io::Result<()> {
        let nonce = fastrand::u64(..);
        let ping = PingPayload { nonce };
        let mut buf = Vec::with_capacity(8);
        ping.encode(&mut buf);
        trace!(nonce, "sending ping");
        self.write_active_message(Message::Ping { payload: &buf })
            .await
    }

    async fn send_close(&mut self, code: CloseCode) -> io::Result<()> {
        let payload = ClosePayload { code };
        let mut buf = Vec::with_capacity(1);
        payload.encode(&mut buf);
        self.write_active_message(Message::Close { payload: &buf })
            .await
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

    async fn maybe_read_udp_one(&mut self) -> io::Result<()> {
        if self.active_transport != ActiveTransport::UdpQsp {
            return Ok(());
        }

        let udp = self.udp_session.as_mut().ok_or_else(|| {
            io::Error::new(io::ErrorKind::BrokenPipe, "udp-qsp transport missing")
        })?;
        let _ = udp.read_next_message(self.limits).await?;
        Ok(())
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
