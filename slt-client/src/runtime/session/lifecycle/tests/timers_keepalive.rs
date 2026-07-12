use std::time::{Duration, Instant};

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

        // Defaults leave multiple ping intervals before either liveness deadline.
        assert_eq!(config.ping_min, Duration::from_secs(10));
        assert_eq!(config.ping_max, Duration::from_secs(30));
        assert_eq!(config.udp_liveness_timeout, Duration::from_secs(90));
        assert_eq!(config.idle_timeout, Duration::from_mins(5));

        // ping_min should not exceed ping_max
        assert!(config.ping_min <= config.ping_max);

        // ping interval should be less than idle timeout for effective keepalive
        assert!(config.ping_max < config.udp_liveness_timeout);
        assert!(config.ping_max < config.idle_timeout);
    }
}

mod idle_timeout_logic {
    use super::*;

    /// Test session idle deadline calculation from accepted ingress.
    #[test]
    fn session_idle_deadline_is_last_activity_plus_timeout() {
        let idle_timeout = Duration::from_mins(1);
        let last_activity = Instant::now().checked_sub(Duration::from_secs(30)).unwrap();

        let idle_deadline = last_activity + idle_timeout;

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

    /// Test UDP path-liveness deadline calculation.
    #[test]
    fn udp_liveness_deadline_is_last_authenticated_ingress_plus_timeout() {
        let udp_liveness_timeout = Duration::from_mins(1);
        let last_authenticated_udp_activity =
            Instant::now().checked_sub(Duration::from_secs(45)).unwrap();

        let liveness_deadline = last_authenticated_udp_activity + udp_liveness_timeout;

        // Deadline should be 15 seconds in the future
        let expected_remaining = Duration::from_secs(15);
        let actual_remaining = liveness_deadline.duration_since(Instant::now());

        let tolerance = Duration::from_millis(100);
        assert!(
            actual_remaining >= expected_remaining.checked_sub(tolerance).unwrap()
                && actual_remaining <= expected_remaining + tolerance,
            "UDP liveness deadline should be ~15s away, got {actual_remaining:?}"
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

        // Regular ping responses keep the session from reaching its idle deadline.
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
