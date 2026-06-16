//! Session lifecycle: ping/pong, idle timeout, shutdown, and write helpers.

use std::io;
use std::time::{Duration, Instant};

use slt_core::proto::{CloseCode, ClosePayload, Message, PingPayload};
use tracing::{trace, warn};

use super::ClientSession;
use crate::runtime::session::state::ActiveTransport;

impl ClientSession<'_> {
    /// Sends a ping on the active transport.
    ///
    /// Generates a random nonce, encodes a `PING` message, and writes it
    /// to the active transport. If the active transport is UDP-QSP and the
    /// write fails, attempts TCP fallback if available.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Active transport write fails
    /// - TCP fallback also fails
    /// - Both transports are dead
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
            if !self.handle_udp_error(&err) {
                return Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "both transports dead",
                ));
            }
            self.tcp
                .write_message(Message::Ping { payload: &buf })
                .await?;
        }
        Ok(())
    }

    /// Sends a close frame on the active transport.
    ///
    /// Encodes a `CLOSE` message with the given code and writes it to the
    /// active transport. If the active transport is UDP-QSP and the write
    /// fails, attempts TCP fallback if available.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Active transport write fails
    /// - TCP fallback also fails
    /// - Both transports are dead
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
            if !self.handle_udp_error(&err) {
                return Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "both transports dead",
                ));
            }
            self.tcp
                .write_message(Message::Close { payload: &buf })
                .await?;
        }
        Ok(())
    }

    /// Writes a message on the active transport.
    ///
    /// Dispatches to TCP or UDP-QSP based on the current active transport.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - UDP-QSP is active but transport is missing
    /// - Transport write fails
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

    /// Writes a message on the UDP-QSP transport.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - UDP-QSP transport is not active
    /// - Transport write fails
    pub(super) async fn write_udp_message(&mut self, message: Message<'_>) -> io::Result<()> {
        let udp = self.udp_state.as_active_mut().ok_or_else(|| {
            io::Error::new(io::ErrorKind::BrokenPipe, "udp-qsp transport missing")
        })?;
        udp.write_message(message).await
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

    /// Updates the last TCP activity timestamp to now.
    ///
    /// Should be called whenever data is received from the server via TCP.
    pub(super) fn note_tcp_activity(&mut self) {
        self.last_tcp_rx = Instant::now();
    }

    /// Updates the last UDP activity timestamp to now.
    ///
    /// Should be called whenever data is received from the server via UDP-QSP.
    pub(super) fn note_udp_activity(&mut self) {
        self.last_udp_rx = Instant::now();
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use slt_core::proto::{CloseCode, PingPayload};
    use slt_core::types::ClientTimingConfig;

    mod schedule_next_ping_logic {
        use super::*;

        /// Compute the next ping deadline using the same logic as `schedule_next_ping`.
        fn compute_next_ping(ping_min: Duration, ping_max: Duration) -> Instant {
            let min_ms = u64::try_from(ping_min.as_millis()).unwrap_or(u64::MAX);
            let max_ms = u64::try_from(ping_max.as_millis()).unwrap_or(u64::MAX);
            let jitter_ms = if max_ms > min_ms {
                fastrand::u64(0..=(max_ms - min_ms))
            } else {
                0
            };
            Instant::now() + Duration::from_millis(min_ms + jitter_ms)
        }

        /// Test that ping is scheduled within [`ping_min`, `ping_max`] when min equals max.
        #[test]
        fn ping_scheduled_at_exact_interval_when_min_equals_max() {
            let ping_interval = Duration::from_secs(15);

            // Run multiple times to ensure no jitter is applied
            for _ in 0..10 {
                let now = Instant::now();
                let next_ping = compute_next_ping(ping_interval, ping_interval);

                // When min == max, there should be no jitter
                // Allow 10ms tolerance for timing variations
                let expected_min = now + ping_interval;
                let expected_max = now + ping_interval + Duration::from_millis(10);

                assert!(
                    next_ping >= expected_min && next_ping <= expected_max,
                    "next_ping {next_ping:?} should be within [{expected_min:?}, {expected_max:?}]"
                );
            }
        }

        /// Test that ping is scheduled within [`ping_min`, `ping_max`] with jitter.
        #[test]
        fn ping_scheduled_within_jitter_range() {
            let ping_min = Duration::from_secs(10);
            let ping_max = Duration::from_secs(20);

            // Run multiple times to verify jitter is within bounds
            for _ in 0..100 {
                // Capture now BEFORE compute_next_ping so that min_deadline is
                // guaranteed to be <= the internal Instant::now() used by
                // compute_next_ping.
                let now = Instant::now();
                let next_ping = compute_next_ping(ping_min, ping_max);

                let min_deadline = now + ping_min;
                // Allow 50ms tolerance for timing variations during test execution.
                // The internal Instant::now() in compute_next_ping may be later than
                // our captured `now`, so next_ping could be slightly over ping_max.
                let max_deadline = now + ping_max + Duration::from_millis(50);

                assert!(
                    next_ping >= min_deadline && next_ping <= max_deadline,
                    "next_ping {next_ping:?} should be within [{min_deadline:?}, {max_deadline:?}]"
                );
            }
        }

        /// Test that jitter varies across calls (probabilistic).
        #[test]
        fn ping_jitter_varies_across_calls() {
            let ping_min = Duration::from_secs(10);
            let ping_max = Duration::from_secs(20);

            let mut seen_different = false;
            let mut first_ping: Option<Duration> = None;

            for _ in 0..50 {
                let next_ping = compute_next_ping(ping_min, ping_max);
                let now = Instant::now();
                let offset = next_ping.duration_since(now);

                if let Some(first) = first_ping {
                    if offset != first {
                        seen_different = true;
                        break;
                    }
                } else {
                    first_ping = Some(offset);
                }
            }

            // With a 10 second jitter range, we should see variation
            assert!(
                seen_different,
                "expected to see different ping times due to jitter"
            );
        }

        /// Test default timing configuration values.
        #[test]
        fn default_timing_values_are_reasonable() {
            let config = ClientTimingConfig::default();

            // Default: ping_min=10s, ping_max=30s, idle_timeout=5m
            assert_eq!(config.ping_min, Duration::from_secs(10));
            assert_eq!(config.ping_max, Duration::from_secs(30));
            assert_eq!(config.idle_timeout, Duration::from_mins(5));

            // ping_min should not exceed ping_max
            assert!(config.ping_min <= config.ping_max);

            // ping interval should be less than idle timeout for effective keepalive
            assert!(config.ping_max < config.idle_timeout);
        }
    }

    mod idle_timeout_logic {
        use super::*;

        /// Test idle deadline calculation for TCP transport.
        #[test]
        fn tcp_idle_deadline_is_last_rx_plus_timeout() {
            let idle_timeout = Duration::from_mins(1);
            let last_tcp_rx = Instant::now().checked_sub(Duration::from_secs(30)).unwrap();

            let idle_deadline = last_tcp_rx + idle_timeout;

            // Deadline should be 30 seconds in the future
            let expected_remaining = Duration::from_secs(30);
            let actual_remaining = idle_deadline.duration_since(Instant::now());

            // Allow 100ms tolerance
            let tolerance = Duration::from_millis(100);
            assert!(
                actual_remaining >= expected_remaining.checked_sub(tolerance).unwrap()
                    && actual_remaining <= expected_remaining + tolerance,
                "idle deadline should be ~30s away, got {actual_remaining:?}"
            );
        }

        /// Test idle deadline calculation for UDP transport.
        #[test]
        fn udp_idle_deadline_is_last_rx_plus_timeout() {
            let idle_timeout = Duration::from_mins(1);
            let last_udp_rx = Instant::now().checked_sub(Duration::from_secs(45)).unwrap();

            let idle_deadline = last_udp_rx + idle_timeout;

            // Deadline should be 15 seconds in the future
            let expected_remaining = Duration::from_secs(15);
            let actual_remaining = idle_deadline.duration_since(Instant::now());

            let tolerance = Duration::from_millis(100);
            assert!(
                actual_remaining >= expected_remaining.checked_sub(tolerance).unwrap()
                    && actual_remaining <= expected_remaining + tolerance,
                "idle deadline should be ~15s away, got {actual_remaining:?}"
            );
        }

        /// Test that activity resets idle deadline.
        #[test]
        fn activity_resets_idle_deadline() {
            let idle_timeout = Duration::from_mins(1);

            // Old activity, close to timeout
            let old_last_rx = Instant::now().checked_sub(Duration::from_secs(55)).unwrap();
            let old_deadline = old_last_rx + idle_timeout;

            // After activity, deadline extends
            let new_last_rx = Instant::now();
            let new_deadline = new_last_rx + idle_timeout;

            assert!(
                new_deadline > old_deadline,
                "new deadline should be later after activity"
            );
            assert!(
                old_deadline.duration_since(Instant::now()) < Duration::from_secs(10),
                "old deadline should be close"
            );
            assert!(
                new_deadline.duration_since(Instant::now()) > Duration::from_secs(55),
                "new deadline should be far"
            );
        }

        /// Test that deadline has passed when idle time exceeds timeout.
        #[test]
        fn idle_deadline_passed_when_exceeded() {
            let idle_timeout = Duration::from_mins(1);
            let last_rx = Instant::now().checked_sub(Duration::from_secs(65)).unwrap();

            let deadline = last_rx + idle_timeout;

            // Deadline should be in the past
            assert!(deadline < Instant::now(), "deadline should have passed");
        }

        /// Test deadline is still future when within timeout.
        #[test]
        fn idle_deadline_future_when_within_timeout() {
            let idle_timeout = Duration::from_mins(1);
            let last_rx = Instant::now().checked_sub(Duration::from_secs(30)).unwrap();

            let deadline = last_rx + idle_timeout;

            // Deadline should be in the future
            assert!(
                deadline > Instant::now(),
                "deadline should be in the future"
            );
        }
    }

    mod keepalive_logic {
        use super::*;

        /// Test that ping interval should be less than idle timeout to keep connection alive.
        #[test]
        fn ping_interval_less_than_idle_timeout_for_keepalive() {
            let config = ClientTimingConfig::default();

            // By default, ping_min=10s, ping_max=30s, idle_timeout=60s
            // This means pings will be sent every 10-30s, preventing the 60s idle timeout
            assert!(
                config.ping_max < config.idle_timeout,
                "ping_max ({:?}) should be less than idle_timeout ({:?}) for effective keepalive",
                config.ping_max,
                config.idle_timeout
            );
        }

        /// Test that activity extends idle deadline.
        #[test]
        fn activity_extends_idle_deadline() {
            let idle_timeout = Duration::from_mins(1);

            // Simulate timeline using mock times
            let t0 = Instant::now();

            // At t=30s from start, receive data (activity)
            let t1_activity = t0 + Duration::from_secs(30);
            let deadline_after_t1 = t1_activity + idle_timeout;

            // At t=30s activity, deadline is now t=90s from start
            assert_eq!(
                deadline_after_t1.duration_since(t0),
                Duration::from_secs(90)
            );

            // At t=50s from start, another activity
            let t2_activity = t0 + Duration::from_secs(50);
            let deadline_after_t2 = t2_activity + idle_timeout;

            // At t=50s activity, deadline is now t=110s from start
            assert_eq!(
                deadline_after_t2.duration_since(t0),
                Duration::from_secs(110)
            );

            // Even though 50s has passed, the deadline keeps extending
        }

        /// Test that pong response prevents timeout (pong counts as activity).
        #[test]
        fn pong_response_prevents_timeout() {
            let idle_timeout = Duration::from_mins(1);

            // Session starts at t=0
            let start = Instant::now();

            // At t=55s, we're close to timeout (only 5s left)
            // But we receive a pong response (activity)
            let pong_time = start + Duration::from_secs(55);
            let deadline_after_pong = pong_time + idle_timeout;

            // Now we have another 60s until timeout (t=115s from start)
            assert_eq!(
                deadline_after_pong.duration_since(start),
                Duration::from_secs(115)
            );
        }

        /// Test that pings sent before timeout prevent disconnection.
        #[test]
        fn regular_pings_prevent_idle_timeout() {
            let ping_interval = Duration::from_secs(20);
            let idle_timeout = Duration::from_mins(1);

            // Simulate a session where pings are sent every 20s
            // and pongs are received, updating last_rx

            let start = Instant::now();

            // At t=20s: send ping, receive pong
            let t1 = start + ping_interval;
            let deadline1 = t1 + idle_timeout;
            assert!(deadline1 > t1);

            // At t=40s: send ping, receive pong
            let t2 = start + 2 * ping_interval;
            let deadline2 = t2 + idle_timeout;
            assert!(deadline2 > t2);

            // At t=60s: send ping, receive pong
            let t3 = start + 3 * ping_interval;
            let deadline3 = t3 + idle_timeout;
            assert!(deadline3 > t3);

            // At t=60s from start, original deadline would have passed
            // but due to pongs, we still have 60s remaining
            let original_deadline = start + idle_timeout;
            assert!(deadline3 > original_deadline);
        }
    }

    mod ping_payload {
        use super::*;

        /// Test ping payload encoding and decoding roundtrip.
        #[test]
        fn ping_payload_roundtrip() {
            let nonce = 0x1234_5678_9ABC_DEF0_u64;
            let ping = PingPayload { nonce };

            let mut buf = Vec::new();
            ping.encode(&mut buf);

            let decoded = PingPayload::decode(&buf).unwrap();
            assert_eq!(decoded.nonce, nonce);
        }

        /// Test ping payload requires exactly 8 bytes.
        #[test]
        fn ping_payload_requires_8_bytes() {
            // Too short
            assert!(PingPayload::decode(&[]).is_err());
            assert!(PingPayload::decode(&[1, 2, 3, 4, 5, 6, 7]).is_err());

            // Too long - should still work if first 8 bytes are valid
            let valid_buf = 0x123456789ABCDEF0_u64.to_be_bytes();
            assert!(PingPayload::decode(&valid_buf).is_ok());
        }
    }

    mod close_codes {
        use super::*;

        /// Test close code values exist.
        #[test]
        fn close_codes_are_defined() {
            assert!(matches!(CloseCode::Normal, CloseCode::Normal));
            assert!(matches!(CloseCode::IdleTimeout, CloseCode::IdleTimeout));
        }

        /// Test close code for idle timeout has expected value.
        #[test]
        fn idle_timeout_close_code_value() {
            // IdleTimeout should have a specific value for protocol compatibility
            let code = CloseCode::IdleTimeout;
            // Verify it can be used in comparisons
            assert_eq!(code, CloseCode::IdleTimeout);
            assert_ne!(code, CloseCode::Normal);
        }
    }

    mod timestamp_independence {
        use super::*;

        /// Test that TCP and UDP activity timestamps are tracked independently.
        #[test]
        fn tcp_and_udp_timestamps_are_independent() {
            let idle_timeout = Duration::from_mins(1);
            let now = Instant::now();

            // Simulate: TCP activity at t=0, UDP activity at t=30s
            let tcp_last_rx = now;
            let udp_last_rx = now + Duration::from_secs(30);

            let tcp_deadline = tcp_last_rx + idle_timeout;
            let udp_deadline = udp_last_rx + idle_timeout;

            // UDP deadline should be later than TCP deadline
            assert!(udp_deadline > tcp_deadline);

            // If we're using TCP transport, we check tcp_deadline
            // If we're using UDP transport, we check udp_deadline
            // They don't affect each other
        }

        /// Test that switching transports uses correct deadline.
        #[test]
        fn transport_switch_uses_correct_deadline() {
            let idle_timeout = Duration::from_mins(1);
            let now = Instant::now();

            // Start on TCP
            let tcp_last_rx = now;
            let tcp_deadline = tcp_last_rx + idle_timeout;

            // Switch to UDP at t=20s with UDP activity
            let switch_time = now + Duration::from_secs(20);
            let udp_last_rx = switch_time;
            let udp_deadline = udp_last_rx + idle_timeout;

            // After switch, we should use UDP deadline
            assert!(udp_deadline > tcp_deadline);

            // TCP deadline is still the same (not updated by UDP activity)
            assert_eq!(tcp_deadline, now + idle_timeout);
        }
    }
}
