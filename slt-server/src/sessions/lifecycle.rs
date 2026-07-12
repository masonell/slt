//! Session lifecycle loop and scheduling.

use std::io;
use std::time::{Duration, Instant};

use fastrand;
use slt_core::proto::{CloseCode, Message, PingPayload};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time;
use tracing::{debug, error, info};

use super::error::SessionError;
use super::types::{SessionControl, SessionEvent, SessionShutdownReason};
use super::{
    ActiveTransport, BEST_EFFORT_IO_TIMEOUT, ClientSessionBase, UdpFailureRecovery, UdpSessionIo,
};
use crate::tun::TunDeviceIo;

#[derive(Clone, Copy)]
enum SessionTimer {
    Ping,
    UdpLiveness,
    Idle,
}

enum SessionRunOutcome {
    Completed(Result<(), SessionError>),
    Shutdown(SessionShutdownReason),
    ShutdownSignalUnavailable,
}

enum SessionWork {
    TcpRead(io::Result<usize>),
    Event(SessionEvent),
    UdpFlush(io::Result<()>),
    Timer,
}

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
        let outcome = match self.shutdown.take() {
            Some(mut shutdown) => tokio::select! {
                biased;

                reason = &mut shutdown => reason.map_or(
                    SessionRunOutcome::ShutdownSignalUnavailable,
                    SessionRunOutcome::Shutdown,
                ),
                result = self.run_inner() => SessionRunOutcome::Completed(result),
            },
            None => SessionRunOutcome::ShutdownSignalUnavailable,
        };
        let result = match outcome {
            SessionRunOutcome::Completed(result) => result,
            SessionRunOutcome::Shutdown(reason) => {
                self.handle_managed_shutdown(reason).await;
                Ok(())
            }
            SessionRunOutcome::ShutdownSignalUnavailable => Err(SessionError::Io(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "session shutdown signal unavailable without a reason",
            ))),
        };
        if result
            .as_ref()
            .is_err_and(SessionError::is_peer_protocol_error)
        {
            self.send_close_best_effort(CloseCode::ProtocolError, "protocol_error")
                .await;
        }
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
        let mut flush_before_next_event = false;

        loop {
            if self.tcp_alive
                && self.tcp.has_buffered_input()
                && self.handle_tcp_read().await? == SessionControl::Close
            {
                return Ok(());
            }

            let should_flush_udp = self.has_pending_udp_flush();
            flush_before_next_event &= should_flush_udp;
            let (timer_at, timer) = self.next_session_timer(next_ping_at);
            let timer_due = time::Instant::from_std(timer_at) <= time::Instant::now();

            if timer_due {
                if self.handle_session_timer(timer, &mut next_ping_at).await?
                    == SessionControl::Close
                {
                    return Ok(());
                }
                continue;
            }

            let work = self
                .wait_for_work(!flush_before_next_event, should_flush_udp, timer_at)
                .await;
            let control = match work {
                SessionWork::TcpRead(result) => self.handle_tcp_read_result(result).await?,
                SessionWork::Event(event) => {
                    let extends_udp_batch = self.event_extends_udp_batch(&event);
                    let control = self.handle_event(event).await?;

                    // One non-batching event may retarget the buffered batch;
                    // gate further events until that batch drains.
                    flush_before_next_event =
                        should_flush_udp && !extends_udp_batch && self.has_pending_udp_flush();
                    control
                }
                SessionWork::UdpFlush(result) => {
                    flush_before_next_event = false;
                    if let Err(source) = result {
                        self.recover_from_udp_flush_error(
                            None,
                            UdpFailureRecovery::SignalTcpFallback,
                            source,
                        )
                        .await?;
                    }
                    SessionControl::Continue
                }
                SessionWork::Timer => self.handle_session_timer(timer, &mut next_ping_at).await?,
            };
            if control == SessionControl::Close {
                return Ok(());
            }
        }
    }

    async fn wait_for_work(
        &mut self,
        can_receive_event: bool,
        should_flush_udp: bool,
        timer_at: Instant,
    ) -> SessionWork {
        let session_work = async {
            // Ready TUN packets extend the batch, and one queued UDP claim may
            // authenticate a migrated peer before the partial flush.
            tokio::select! {
                biased;

                Some(event) = self.rx.recv(), if can_receive_event => {
                    SessionWork::Event(event)
                }
                result = async {
                    if let Some(session) = self.udp_session.as_mut() {
                        session.flush().await?;
                    }
                    Ok::<(), io::Error>(())
                }, if should_flush_udp => SessionWork::UdpFlush(result),
                else => std::future::pending().await,
            }
        };
        let io_work = async {
            tokio::select! {
                result = self.tcp.read_more(), if self.tcp_alive => {
                    SessionWork::TcpRead(result)
                }
                work = session_work => work,
            }
        };

        // Fair I/O selection is nested ahead of the future timer. Ready packet
        // work completes without registering a timer, while idle I/O polls it
        // once so the session wakes at its deadline.
        tokio::select! {
            biased;

            work = io_work => work,
            () = time::sleep_until(timer_at.into()) => SessionWork::Timer,
        }
    }

    async fn handle_tcp_read_result(
        &mut self,
        result: io::Result<usize>,
    ) -> Result<SessionControl, SessionError> {
        let n = result.map_err(|source| SessionError::Connection { source })?;
        if n != 0 {
            return self.handle_tcp_read().await;
        }
        if self.active_transport == ActiveTransport::UdpQsp {
            info!(
                session_id = self.session_id,
                client_id = %self.client_id,
                "tcp connection closed; continuing on udp"
            );
            self.tcp_alive = false;
            return Ok(SessionControl::Continue);
        }
        self.metrics.inc_disconnect_close();
        info!(
            session_id = self.session_id,
            client_id = %self.client_id,
            reason = "tcp_close",
            "session disconnect"
        );
        Ok(SessionControl::Close)
    }

    fn event_extends_udp_batch(&self, event: &SessionEvent) -> bool {
        self.active_transport == ActiveTransport::UdpQsp
            && matches!(
                event,
                SessionEvent::TunPacket(packet) if packet.len() <= self.limits.max_data_len
            )
    }

    fn next_session_timer(&self, next_ping_at: Instant) -> (Instant, SessionTimer) {
        let idle_deadline = self.last_activity + self.timeouts.idle_timeout;
        let (mut timer_at, mut timer) = if idle_deadline <= next_ping_at {
            (idle_deadline, SessionTimer::Idle)
        } else {
            (next_ping_at, SessionTimer::Ping)
        };
        if self.active_transport == ActiveTransport::UdpQsp
            && self.tcp_alive
            && let Some(last_authenticated) = self.last_authenticated_udp_activity
        {
            let udp_liveness_deadline = last_authenticated + self.timeouts.udp_liveness_timeout;
            if udp_liveness_deadline < timer_at {
                timer_at = udp_liveness_deadline;
                timer = SessionTimer::UdpLiveness;
            }
        }
        (timer_at, timer)
    }

    async fn handle_session_timer(
        &mut self,
        timer: SessionTimer,
        next_ping_at: &mut Instant,
    ) -> Result<SessionControl, SessionError> {
        match timer {
            SessionTimer::Ping => {
                self.handle_ping_tick().await?;
                *next_ping_at = self.schedule_next_ping();
                Ok(SessionControl::Continue)
            }
            SessionTimer::UdpLiveness => self.handle_udp_liveness_timeout().await,
            SessionTimer::Idle => {
                self.metrics.inc_disconnect_idle_timeout();
                info!(
                    session_id = self.session_id,
                    client_id = %self.client_id,
                    reason = "idle_timeout",
                    "session disconnect"
                );
                let _ = self.send_close(CloseCode::IdleTimeout).await;
                Ok(SessionControl::Close)
            }
        }
    }

    async fn handle_udp_liveness_timeout(&mut self) -> Result<SessionControl, SessionError> {
        if self.active_transport != ActiveTransport::UdpQsp || !self.tcp_alive {
            return Ok(SessionControl::Continue);
        }

        self.metrics.inc_udp_qsp_liveness_timeout();
        info!(
            session_id = self.session_id,
            client_id = %self.client_id,
            timeout_ms = self.timeouts.udp_liveness_timeout.as_millis(),
            "UDP-QSP authenticated liveness timeout; falling back to tcp"
        );
        self.set_active_transport(ActiveTransport::Tcp);
        self.retire_udp_transport();
        self.send_tcp_fallback_request().await?;
        Ok(SessionControl::Continue)
    }

    async fn handle_event(&mut self, event: SessionEvent) -> Result<SessionControl, SessionError> {
        match event {
            SessionEvent::TunPacket(packet) => self.handle_tun_packet(packet).await,
            SessionEvent::Udp(claim) => self.handle_udp_claim(claim).await,
        }
    }

    async fn handle_managed_shutdown(&mut self, reason: SessionShutdownReason) {
        self.metrics.inc_disconnect_shutdown();
        let close_code = reason.close_code();
        info!(
            session_id = self.session_id,
            client_id = %self.client_id,
            reason = reason.as_str(),
            ?close_code,
            "session disconnect"
        );

        self.send_close_best_effort(close_code, reason.as_str())
            .await;
    }

    async fn send_close_best_effort(&mut self, close_code: CloseCode, reason: &'static str) {
        let tcp_available = self.tcp_alive && !self.tcp_write_interrupted;
        if tcp_available {
            match time::timeout(BEST_EFFORT_IO_TIMEOUT, self.send_close_over_tcp(close_code)).await
            {
                Ok(Ok(())) => return,
                Ok(Err(err)) => {
                    debug!(
                        session_id = self.session_id,
                        client_id = %self.client_id,
                        reason,
                        error = %err,
                        "failed to send CLOSE over TCP"
                    );
                }
                Err(_) => {
                    debug!(
                        session_id = self.session_id,
                        client_id = %self.client_id,
                        reason,
                        timeout_ms = BEST_EFFORT_IO_TIMEOUT.as_millis(),
                        "timed out sending CLOSE over TCP"
                    );
                }
            }
        }

        if self.udp_session.is_none() {
            if !tcp_available {
                debug!(
                    session_id = self.session_id,
                    client_id = %self.client_id,
                    reason,
                    "no usable transport for CLOSE"
                );
            }
            return;
        }

        match time::timeout(BEST_EFFORT_IO_TIMEOUT, self.send_close_over_udp(close_code)).await {
            Ok(Ok(())) => {}
            Ok(Err(err)) => {
                debug!(
                    session_id = self.session_id,
                    client_id = %self.client_id,
                    reason,
                    error = %err,
                    "failed to send CLOSE over UDP-QSP"
                );
            }
            Err(_) => {
                debug!(
                    session_id = self.session_id,
                    client_id = %self.client_id,
                    reason,
                    timeout_ms = BEST_EFFORT_IO_TIMEOUT.as_millis(),
                    "timed out sending CLOSE over UDP-QSP"
                );
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
                self.send_udp_message_and_flush(
                    Message::Ping { payload: &buf },
                    UdpFailureRecovery::RetryMessageOnTcp,
                )
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

    pub(super) const fn note_activity(&mut self, received_at: Instant) {
        self.last_activity = received_at;
    }
}
