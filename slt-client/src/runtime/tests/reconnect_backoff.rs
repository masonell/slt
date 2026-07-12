use std::time::Duration;

use super::super::ReconnectBackoff;
use crate::test_support::test_config;

fn millis(duration: Duration) -> u64 {
    duration.as_millis() as u64
}

#[test]
fn reconnect_backoff_initial_state() {
    let base = Duration::from_millis(100);
    let max = Duration::from_secs(10);
    let backoff = ReconnectBackoff::new(base, max);

    assert_eq!(backoff.base, base);
    assert_eq!(backoff.max, max);
    assert_eq!(backoff.current, base);
}

#[test]
fn reconnect_backoff_reset_returns_to_base() {
    let base = Duration::from_millis(100);
    let max = Duration::from_secs(10);
    let mut backoff = ReconnectBackoff::new(base, max);

    // Advance the backoff a few times
    let _ = backoff.next_delay();
    let _ = backoff.next_delay();
    let _ = backoff.next_delay();

    // Current should have increased
    assert!(backoff.current > base);

    // Reset should return to base
    backoff.reset();
    assert_eq!(backoff.current, base);
}

#[test]
fn reconnect_backoff_delay_doubles_each_call() {
    let base = Duration::from_millis(100);
    let max = Duration::from_mins(1);
    let mut backoff = ReconnectBackoff::new(base, max);

    // Use deterministic seed for reproducible jitter
    fastrand::seed(42);

    // First call: current is 100ms, delay is in [50, 100]ms
    let d1 = backoff.next_delay();
    assert!(millis(d1) >= 50 && millis(d1) <= 100);

    // After first call, current should be 200ms (doubled)
    assert_eq!(millis(backoff.current), 200);

    // Second call: current is 200ms, delay is in [100, 200]ms
    let d2 = backoff.next_delay();
    assert!(millis(d2) >= 100 && millis(d2) <= 200);

    // After second call, current should be 400ms
    assert_eq!(millis(backoff.current), 400);

    // Third call: current is 400ms, delay is in [200, 400]ms
    let d3 = backoff.next_delay();
    assert!(millis(d3) >= 200 && millis(d3) <= 400);

    // After third call, current should be 800ms
    assert_eq!(millis(backoff.current), 800);
}

#[test]
fn reconnect_backoff_capped_at_max() {
    let base = Duration::from_millis(100);
    let max = Duration::from_millis(500);
    let mut backoff = ReconnectBackoff::new(base, max);

    fastrand::seed(42);

    // Call next_delay multiple times until we hit max
    let _ = backoff.next_delay(); // current becomes 200
    let _ = backoff.next_delay(); // current becomes 400
    let _ = backoff.next_delay(); // current would be 800, but capped at 500

    // Current should be capped at max
    assert_eq!(backoff.current, max);

    // Further calls should stay at max
    let _ = backoff.next_delay();
    assert_eq!(backoff.current, max);
    let _ = backoff.next_delay();
    assert_eq!(backoff.current, max);
}

#[test]
fn reconnect_backoff_jitter_bounds() {
    let base = Duration::from_millis(100);
    let max = Duration::from_mins(1);

    // Test jitter bounds over many samples
    // With equal-jitter: delay is in [current/2, current]
    for expected_current_ms in [100u64, 200, 400, 800, 1600] {
        let half = expected_current_ms / 2;
        let mut min_seen = u64::MAX;
        let mut max_seen = 0u64;

        // Sample many times to exercise jitter range
        for seed in 0..1000 {
            fastrand::seed(seed);
            let mut test_backoff = ReconnectBackoff::new(base, max);

            // Advance to the expected current value
            for _ in 0..match expected_current_ms {
                100 => 0,
                200 => 1,
                400 => 2,
                800 => 3,
                1600 => 4,
                _ => 5,
            } {
                let _ = test_backoff.next_delay();
            }

            let delay = test_backoff.next_delay();
            let delay_ms = millis(delay);
            min_seen = min_seen.min(delay_ms);
            max_seen = max_seen.max(delay_ms);
        }

        // Verify jitter bounds: [half, current]
        assert!(
            min_seen >= half,
            "min_seen ({min_seen}) should be >= half ({half}) for current {expected_current_ms}"
        );
        assert!(
            max_seen <= expected_current_ms,
            "max_seen ({max_seen}) should be <= current ({expected_current_ms})"
        );

        // With enough samples, we should see values near both bounds
        assert!(
            min_seen <= half + 5,
            "should see values near lower bound half={half}, got min={min_seen}"
        );
        assert!(
            max_seen >= expected_current_ms.saturating_sub(5),
            "should see values near upper bound current={expected_current_ms}, got max={max_seen}"
        );
    }
}

#[test]
fn reconnect_backoff_unvalidated_zero_base_remains_zero() {
    // This input is rejected by ClientConfig validation and the run_client boundary.
    let base = Duration::ZERO;
    let max = Duration::from_secs(10);
    let mut backoff = ReconnectBackoff::new(base, max);

    fastrand::seed(42);

    // First delay should be zero (cap=0, half=0, jitter=0)
    let d1 = backoff.next_delay();
    assert_eq!(millis(d1), 0);

    // Current doubles: 0 * 2 = 0
    assert_eq!(millis(backoff.current), 0);
}

#[test]
fn reconnect_backoff_from_validated_config_never_returns_zero() {
    let mut config = test_config();
    config.timing.reconnect_min = slt_core::config::MIN_INTERVAL;
    config.timing.reconnect_max = slt_core::config::MIN_INTERVAL;
    config.validate().unwrap();

    let mut backoff =
        ReconnectBackoff::new(config.timing.reconnect_min, config.timing.reconnect_max);
    for _ in 0..10 {
        assert!(!backoff.next_delay().is_zero());
    }
}

#[test]
fn reconnect_backoff_small_base_doubling() {
    // Test that very small values still double correctly
    let base = Duration::from_millis(1);
    let max = Duration::from_secs(10);
    let mut backoff = ReconnectBackoff::new(base, max);

    fastrand::seed(42);

    let _ = backoff.next_delay();
    assert_eq!(millis(backoff.current), 2);

    let _ = backoff.next_delay();
    assert_eq!(millis(backoff.current), 4);

    let _ = backoff.next_delay();
    assert_eq!(millis(backoff.current), 8);
}

#[test]
fn reconnect_backoff_overflow_protection() {
    // Test that overflow is handled by falling back to max
    let base = Duration::from_secs(1);
    let max = Duration::from_secs(10);
    let mut backoff = ReconnectBackoff::new(base, max);

    // Manually set current to a very large value that would overflow when doubled
    backoff.current = Duration::from_secs(u64::MAX / 2 + 1);

    let _ = backoff.next_delay();

    // Should cap at max due to overflow protection
    assert_eq!(backoff.current, max);
}
