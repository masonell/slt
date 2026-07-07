//! Session lifecycle loop and scheduling.

use std::time::{Duration, Instant};

use fastrand;
use slt_core::proto::{CloseCode, Message, PingPayload};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time;
use tracing::{debug, error, info};

use super::error::SessionError;
use super::types::{SessionControl, SessionEvent};
use super::{ActiveTransport, ClientSessionBase, UdpSessionIo};
use crate::tun::TunDeviceIo;

impl<T: TunDeviceIo, S: AsyncRead + AsyncWrite + Unpin + Send + 'static, I: UdpSessionIo>
    ClientSessionBase<T, S, I>
{
    /// Run the session event loop until shutdown.
    ///
    /// # Errors
    ///
    /// Returns a typed `SessionError` if the TCP stream, UDP-QSP transport,
    /// TUN device, or a protocol decode fails. The structured failure flows to
    /// the caller unchanged (the session's terminal log renders `{:#}` with the
    /// preserved source chain).
    pub async fn run(mut self) -> Result<(), SessionError> {
        info!(
            session_id = self.session_id,
            client_id = %self.client_id,
            assigned_ip = %self.assigned_ipv4,
            "session created"
        );
        let result = self.run_inner().await;
        self.flush_pending_udp_session_best_effort().await;
        if let Err(err) = result.as_ref() {
            self.metrics.inc_disconnect_error();
            error!(
                session_id = self.session_id,
                client_id = %self.client_id,
                error = %err,
                "session terminated with error"
            );
        } else {
            debug!(
                session_id = self.session_id,
                client_id = %self.client_id,
                "session terminated normally"
            );
        }
        self.cleanup();
        result
    }

    async fn run_inner(&mut self) -> Result<(), SessionError> {
        let mut next_ping_at = self.schedule_next_ping();

        loop {
            if self.tcp_alive
                && self.tcp.has_buffered_input()
                && self.handle_tcp_read().await? == SessionControl::Close
            {
                return Ok(());
            }

            let idle_deadline = self.last_activity + self.timeouts.idle_timeout;
            let should_flush_udp = self.has_pending_udp_flush();

            // Keep UDP-QSP flush last on purpose. Session events and timers get
            // priority; full GSO slabs flush inline, and this branch sends only
            // partial batches once the session has no immediately-ready work.
            tokio::select! {
                biased;

                res = self.tcp.read_more(), if self.tcp_alive => {
                    let n = res.map_err(|source| SessionError::Connection { source })?;
                    if n == 0 {
                        if self.active_transport == ActiveTransport::UdpQsp {
                            info!(
                                session_id = self.session_id,
                                client_id = %self.client_id,
                                "tcp connection closed; continuing on udp"
                            );
                            self.tcp_alive = false;
                            continue;
                        }
                        self.metrics.inc_disconnect_close();
                        info!(
                            session_id = self.session_id,
                            client_id = %self.client_id,
                            reason = "tcp_close",
                            "session disconnect"
                        );
                        return Ok(());
                    }
                    if self.handle_tcp_read().await? == SessionControl::Close {
                        return Ok(());
                    }
                }
                Some(event) = self.rx.recv() => {
                    if self.handle_event(event).await? == SessionControl::Close {
                        return Ok(());
                    }
                }
                () = time::sleep_until(next_ping_at.into()) => {
                    self.handle_ping_tick().await?;
                    next_ping_at = self.schedule_next_ping();
                }
                () = time::sleep_until(idle_deadline.into()) => {
                    self.metrics.inc_disconnect_idle_timeout();
                    info!(
                        session_id = self.session_id,
                        client_id = %self.client_id,
                        reason = "idle_timeout",
                        "session disconnect"
                    );
                    let _ = self.send_close(CloseCode::IdleTimeout).await;
                    return Ok(());
                }
                res = async {
                    if let Some(session) = self.udp_session.as_mut() {
                        session.flush().await?;
                    }
                    Ok::<(), std::io::Error>(())
                }, if should_flush_udp => {
                    res.map_err(|source| SessionError::Connection { source })?;
                }
            }
        }
    }

    async fn handle_event(&mut self, event: SessionEvent) -> Result<SessionControl, SessionError> {
        self.note_activity();
        match event {
            SessionEvent::TunPacket(packet) => self.handle_tun_packet(packet).await,
            SessionEvent::Udp(claim) => self.handle_udp_claim(claim).await,
            SessionEvent::Shutdown => {
                self.metrics.inc_disconnect_shutdown();
                info!(
                    session_id = self.session_id,
                    client_id = %self.client_id,
                    reason = "shutdown_request",
                    "session disconnect"
                );
                Ok(SessionControl::Close)
            }
        }
    }

    async fn handle_ping_tick(&mut self) -> Result<(), SessionError> {
        let nonce = fastrand::u64(..);
        let ping = PingPayload { nonce };
        let mut buf = Vec::new();
        ping.encode(&mut buf);
        match self.active_transport {
            ActiveTransport::Tcp => self.send_tcp_message(Message::Ping { payload: &buf }).await,
            ActiveTransport::UdpQsp => {
                self.send_udp_message_and_flush(Message::Ping { payload: &buf })
                    .await
            }
        }
    }

    fn schedule_next_ping(&self) -> Instant {
        let min = self.timeouts.ping_min;
        let max = self.timeouts.ping_max;

        // Config validation ensures timeouts <= 1 hour (fits in u64) and min <= max.
        #[allow(
            unknown_lints,
            renamed_and_removed_lints,
            clippy::cast_possible_truncation,
            clippy::unchecked_time_subtraction,
            clippy::unchecked_duration_subtraction
        )]
        let range_ms = (max - min).as_millis() as u64;
        let jitter = if range_ms > 0 {
            Duration::from_millis(fastrand::u64(0..=range_ms))
        } else {
            Duration::ZERO
        };

        Instant::now() + min + jitter
    }

    pub(super) fn note_activity(&mut self) {
        self.last_activity = Instant::now();
    }
}
