//! Session lifecycle: ping/pong, idle timeout, shutdown, and write helpers.

use std::io;
use std::time::{Duration, Instant};

use slt_core::proto::{CloseCode, ClosePayload, Message, PingPayload};
use tracing::{trace, warn};

use super::{ClientSession, SessionExit};
use crate::runtime::session::state::ActiveTransport;

impl ClientSession<'_> {
    /// Send a ping on the active transport.
    pub(super) async fn handle_ping_tick(&mut self) -> io::Result<()> {
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

    /// Send a close frame on the active transport.
    pub(super) async fn send_close(&mut self, code: CloseCode) -> io::Result<()> {
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

    /// Write a message on the active transport.
    pub(super) async fn write_active_message(&mut self, message: Message<'_>) -> io::Result<()> {
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

    /// Write a message on the UDP-QSP transport.
    pub(super) async fn write_udp_message(&mut self, message: Message<'_>) -> io::Result<()> {
        let udp = self.udp_state.as_active_mut().ok_or_else(|| {
            io::Error::new(io::ErrorKind::BrokenPipe, "udp-qsp transport missing")
        })?;
        udp.write_message(message).await
    }

    /// Get the stored exit reason or a default.
    pub(super) fn exit_or_default(&mut self) -> SessionExit {
        self.exit.take().unwrap_or(SessionExit::TcpClosed)
    }

    /// Abort and await the discovery task if running.
    pub(super) async fn shutdown_background_tasks(&mut self) {
        if let Some(task) = self.discovery_task.take() {
            task.abort();
            if let Err(err) = task.await
                && !err.is_cancelled()
            {
                warn!(error = %err, "quic discovery task failed on shutdown");
            }
        }
    }

    /// Schedule the next ping with jitter.
    pub(super) fn schedule_next_ping(&self) -> Instant {
        let min_ms = u64::try_from(self.config.timing.ping_min.as_millis()).unwrap_or(u64::MAX);
        let max_ms = u64::try_from(self.config.timing.ping_max.as_millis()).unwrap_or(u64::MAX);
        let jitter_ms = if max_ms > min_ms {
            fastrand::u64(0..=(max_ms - min_ms))
        } else {
            0
        };
        Instant::now() + Duration::from_millis(min_ms + jitter_ms)
    }

    /// Update last TCP activity timestamp.
    pub(super) fn note_tcp_activity(&mut self) {
        self.last_tcp_rx = Instant::now();
    }

    /// Update last UDP activity timestamp.
    pub(super) fn note_udp_activity(&mut self) {
        self.last_udp_rx = Instant::now();
    }
}
