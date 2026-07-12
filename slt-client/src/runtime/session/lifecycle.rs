//! Session lifecycle: ping/pong, idle timeout, shutdown, and write helpers.

use std::io;
use std::time::{Duration, Instant};

use slt_core::proto::{CloseCode, ClosePayload, Message, OwnedMessageBuf, PingPayload};
use slt_core::transport::tcp::TcpWriteError;
use tokio::time;
use tracing::{debug, trace, warn};

use super::error::SessionError;
use super::{ClientSession, ClientTcpIo, SessionControl, SessionExit};
use crate::runtime::services::ClientRuntimeServices;
use crate::runtime::session::state::ActiveTransport;
use crate::transport::tcp::write_message_with_timeout;
use crate::tun::TunTask;

const BEST_EFFORT_IO_TIMEOUT: Duration = Duration::from_secs(1);

impl<S: ClientRuntimeServices, T: ClientTcpIo> ClientSession<'_, S, T> {
    /// Sends a server-originated DATA frame to the TUN writer queue.
    pub(super) async fn send_to_tun_or_shutdown(&self, msg_buf: OwnedMessageBuf) -> SessionControl {
        tokio::select! {
            biased;

            () = self.cancel.cancelled() => {
                self.metrics.inc_disconnect_shutdown();
                SessionControl::Close(SessionExit::Shutdown)
            }
            result = self.tun_channels.to_tun_tx.send(msg_buf) => {
                if result.is_err() {
                    SessionControl::Close(SessionExit::TunClosed(TunTask::Writer))
                } else {
                    SessionControl::Continue
                }
            }
        }
    }

    /// Sends CLOSE without allowing clean-exit signaling to stall shutdown.
    pub(super) async fn send_close_best_effort(&mut self, code: CloseCode, reason: &'static str) {
        match time::timeout(BEST_EFFORT_IO_TIMEOUT, self.send_close(code)).await {
            Ok(Ok(())) => {}
            Ok(Err(err)) => {
                debug!(error = %err, reason, "failed to send close");
            }
            Err(_) => {
                debug!(reason, "timed out sending close");
            }
        }
    }

    /// Sends a ping on the preferred transport.
    ///
    /// Generates a random nonce, encodes a `PING` message, and writes it
    /// to the preferred transport. If the preferred transport is UDP-QSP and the
    /// write fails, attempts TCP fallback if available.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Active transport write fails
    /// - TCP fallback also fails
    /// - Both transports are dead
    pub(super) async fn handle_ping_tick(&mut self) -> Result<(), SessionError> {
        let nonce = fastrand::u64(..);
        let ping = PingPayload { nonce };
        let mut buf = Vec::with_capacity(8);
        ping.encode(&mut buf);
        trace!(nonce, "sending ping");
        let active = self.active_transport;
        let result = if active == ActiveTransport::UdpQsp {
            self.write_udp_message_and_flush(Message::Ping { payload: &buf })
                .await
        } else {
            self.write_tcp_message(Message::Ping { payload: &buf })
                .await
        };
        if let Err(err) = result {
            if active != ActiveTransport::UdpQsp {
                return Err(err);
            }
            if err.is_udp_path_transport_error() {
                // A UDP-QSP transport condition (typed UdpQspError, or a raw
                // socket I/O error from flush): hand it to `handle_udp_error`,
                // which drops recoverable failures and falls back to TCP (or
                // closes if TCP is also dead) for the rest.
                if !self.handle_udp_error(&err).await? {
                    return Err(SessionError::Connection {
                        source: io::Error::new(io::ErrorKind::NotConnected, "both transports dead"),
                    });
                }
            } else {
                // Typed non-transport session error (proto decode failure,
                // protocol violation, crypto) from the UDP path; propagate.
                return Err(err);
            }
            self.write_tcp_message(Message::Ping { payload: &buf })
                .await?;
        }
        Ok(())
    }

    /// Sends a close frame on the preferred transport.
    ///
    /// Encodes a `CLOSE` message with the given code and writes it to the
    /// preferred transport. If the preferred transport is UDP-QSP and the write
    /// fails, attempts TCP fallback if available.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Active transport write fails
    /// - TCP fallback also fails
    /// - Both transports are dead
    async fn send_close(&mut self, code: CloseCode) -> Result<(), SessionError> {
        let payload = ClosePayload { code };
        let mut buf = Vec::with_capacity(1);
        payload.encode(&mut buf);
        let active = self.active_transport;
        let result = if active == ActiveTransport::UdpQsp {
            self.write_udp_message_and_flush(Message::Close { payload: &buf })
                .await
        } else {
            self.write_tcp_message_best_effort(Message::Close { payload: &buf })
                .await
        };
        if let Err(err) = result {
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
                return Err(err);
            }
            self.write_tcp_message_best_effort(Message::Close { payload: &buf })
                .await?;
        }
        Ok(())
    }

    /// Writes a message on the preferred transport.
    ///
    /// Dispatches to TCP or UDP-QSP based on the preferred transport.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - UDP-QSP is active but transport is missing
    /// - Transport write fails
    pub(super) async fn write_active_message(
        &mut self,
        message: Message<'_>,
    ) -> Result<(), SessionError> {
        match self.active_transport {
            ActiveTransport::Tcp => self.write_tcp_message(message).await,
            ActiveTransport::UdpQsp => {
                let udp = self.udp_state.as_active_mut().ok_or_else(|| {
                    SessionError::ProtocolViolation {
                        detail: "udp-qsp transport missing".into(),
                    }
                })?;
                udp.write_message(message).await.map_err(SessionError::from)
            }
        }
    }

    /// Writes one regular session message on TCP using the configured deadline.
    pub(super) async fn write_tcp_message(
        &mut self,
        message: Message<'_>,
    ) -> Result<(), SessionError> {
        self.write_tcp_message_with_timeout(message, self.config.timing.tcp_write_timeout)
            .await
    }

    // The caller's one-second timeout bounds the complete close attempt,
    // including a UDP failure followed by TCP fallback.
    async fn write_tcp_message_best_effort(
        &mut self,
        message: Message<'_>,
    ) -> Result<(), SessionError> {
        self.tcp
            .write_message(message)
            .await
            .map_err(SessionError::from)
    }

    async fn write_tcp_message_with_timeout(
        &mut self,
        message: Message<'_>,
        tcp_write_timeout: Duration,
    ) -> Result<(), SessionError> {
        let result = write_message_with_timeout(&mut self.tcp, message, tcp_write_timeout).await;
        if matches!(
            &result,
            Err(TcpWriteError::Io(source)) if source.kind() == io::ErrorKind::TimedOut
        ) {
            warn!(
                peer = ?self.peer,
                timeout_ms = tcp_write_timeout.as_millis(),
                "tcp message write timed out"
            );
        }
        result.map_err(SessionError::from)
    }

    /// Writes a message on UDP-QSP and immediately flushes buffered packets.
    ///
    /// Use this for client control messages that must not wait behind data
    /// batching in the socket backend.
    ///
    /// # Errors
    ///
    /// Returns an error if UDP-QSP is inactive, write fails, or flush fails.
    pub(super) async fn write_udp_message_and_flush(
        &mut self,
        message: Message<'_>,
    ) -> Result<(), SessionError> {
        let udp =
            self.udp_receive_transport_mut()
                .ok_or_else(|| SessionError::ProtocolViolation {
                    detail: "udp-qsp transport missing".into(),
                })?;
        udp.write_message(message).await?;
        udp.flush().await.map_err(SessionError::from)
    }

    /// Flushes any pending UDP-QSP socket backend packets.
    ///
    /// # Errors
    ///
    /// Returns an error if UDP-QSP is inactive or the socket backend fails.
    pub(super) async fn flush_udp_transport(&mut self) -> Result<(), SessionError> {
        let udp =
            self.udp_state
                .as_active_mut()
                .ok_or_else(|| SessionError::ProtocolViolation {
                    detail: "udp-qsp transport missing".into(),
                })?;
        udp.flush().await.map_err(SessionError::from)
    }

    /// Flushes pending UDP-QSP packets without changing the session exit reason.
    pub(super) async fn flush_pending_udp_transport_best_effort(&mut self) {
        if self.active_transport != ActiveTransport::UdpQsp {
            return;
        }
        let Some(udp) = self.udp_state.as_active_mut() else {
            return;
        };
        if !udp.has_pending_flush() {
            return;
        }
        match time::timeout(BEST_EFFORT_IO_TIMEOUT, udp.flush()).await {
            Ok(Ok(())) => {}
            Ok(Err(err)) => {
                debug!(
                    error = %err,
                    "failed to flush pending udp-qsp packets during shutdown"
                );
            }
            Err(_) => {
                debug!("timed out flushing pending udp-qsp packets during shutdown");
            }
        }
    }

    /// Aborts and awaits the discovery task if running.
    ///
    /// If a discovery task is active, aborts it and awaits completion.
    /// Logs an error if the task failed (as opposed to being cancelled).
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

    /// Schedules the next ping with jitter.
    ///
    /// Returns a deadline in the range `[ping_min, ping_max]` using
    /// uniform jitter. If `ping_min == ping_max`, no jitter is applied.
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

    /// Records an accepted inbound message for session-idle accounting.
    pub(super) const fn note_activity(&mut self, received_at: Instant) {
        self.last_activity = received_at;
    }

    /// Records accepted authenticated UDP-QSP ingress for both session-idle and
    /// UDP path-liveness accounting.
    pub(super) const fn note_authenticated_udp_activity(&mut self, received_at: Instant) {
        self.last_activity = received_at;
        self.last_authenticated_udp_activity = Some(received_at);
    }
}

#[cfg(test)]
mod tests;
