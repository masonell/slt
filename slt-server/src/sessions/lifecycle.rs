//! Session lifecycle loop and scheduling.

use std::io;
use std::time::{Duration, Instant};

use fastrand;
use slt_core::proto::{CloseCode, Message, PingPayload};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time;
use tracing::{debug, error, info};

use super::types::{SessionControl, SessionEvent};
use super::{ActiveTransport, ClientSessionBase, UdpSocketIo};
use crate::tun::TunDeviceIo;

impl<T: TunDeviceIo, S: AsyncRead + AsyncWrite + Unpin + Send + 'static, U: UdpSocketIo>
    ClientSessionBase<T, S, U>
{
    /// Run the session event loop until shutdown.
    ///
    /// # Errors
    ///
    /// Returns an error if the TCP stream or TUN device fails.
    pub async fn run(mut self) -> io::Result<()> {
        info!(
            session_id = self.session_id,
            client_id = %self.client_id,
            assigned_ip = %self.assigned_ipv4,
            "session created"
        );
        let result = self.run_inner().await;
        if result.is_err() {
            self.metrics.inc_disconnect_error();
            error!(
                session_id = self.session_id,
                client_id = %self.client_id,
                error = ?result.as_ref().err(),
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

    async fn run_inner(&mut self) -> io::Result<()> {
        let mut next_ping_at = self.schedule_next_ping();

        loop {
            if self.tcp_alive
                && self.tcp.has_buffered_input()
                && self.handle_tcp_read().await? == SessionControl::Close
            {
                return Ok(());
            }

            let idle_deadline = self.last_activity + self.timeouts.idle_timeout;

            tokio::select! {
                res = self.tcp.read_more(), if self.tcp_alive => {
                    let n = res?;
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
                    self.note_activity();
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
            }
        }
    }

    async fn handle_event(&mut self, event: SessionEvent) -> io::Result<SessionControl> {
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

    async fn handle_ping_tick(&mut self) -> io::Result<()> {
        let nonce = fastrand::u64(..);
        let ping = PingPayload { nonce };
        let mut buf = Vec::new();
        ping.encode(&mut buf);
        match self.active_transport {
            ActiveTransport::Tcp => self.send_tcp_message(Message::Ping { payload: &buf }).await,
            ActiveTransport::UdpQsp => self.send_udp_message(Message::Ping { payload: &buf }).await,
        }
    }

    fn schedule_next_ping(&self) -> Instant {
        let min = self.timeouts.ping_min;
        let max = self.timeouts.ping_max;

        // Config validation ensures timeouts <= 1 hour (fits in u64) and min <= max.
        #[allow(clippy::cast_possible_truncation, clippy::unchecked_time_subtraction)]
        let range_ms = (max - min).as_millis() as u64;
        let jitter = if range_ms > 0 {
            Duration::from_millis(fastrand::u64(0..=range_ms))
        } else {
            Duration::ZERO
        };

        Instant::now() + min + jitter
    }

    fn note_activity(&mut self) {
        self.last_activity = Instant::now();
    }
}
