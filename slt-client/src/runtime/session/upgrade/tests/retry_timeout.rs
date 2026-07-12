use std::time::Duration;

mod backoff_timing {
    use super::*;
    use crate::runtime::ReconnectBackoff;

    #[test]
    fn discovery_backoff_doubles_on_failure() {
        let base = Duration::from_millis(100);
        let max = Duration::from_secs(30);
        let mut backoff = ReconnectBackoff::new(base, max);

        fastrand::seed(42);

        let d1 = backoff.next_delay();
        assert!(d1 >= Duration::from_millis(50) && d1 <= Duration::from_millis(100));

        let d2 = backoff.next_delay();
        assert!(d2 >= Duration::from_millis(100) && d2 <= Duration::from_millis(200));

        let d3 = backoff.next_delay();
        assert!(d3 >= Duration::from_millis(200) && d3 <= Duration::from_millis(400));
    }

    #[test]
    fn registration_backoff_doubles_on_failure() {
        let base = Duration::from_millis(100);
        let max = Duration::from_secs(30);
        let mut backoff = ReconnectBackoff::new(base, max);

        fastrand::seed(123);

        // Simulate multiple registration failures
        let delays: Vec<_> = (0..5).map(|_| backoff.next_delay()).collect();

        // Each delay should be in a valid range for the current backoff level
        assert!(delays[0] >= Duration::from_millis(50) && delays[0] <= Duration::from_millis(100));
        assert!(delays[1] >= Duration::from_millis(100) && delays[1] <= Duration::from_millis(200));
        assert!(delays[2] >= Duration::from_millis(200) && delays[2] <= Duration::from_millis(400));
    }

    #[test]
    fn backoff_capped_at_max() {
        let base = Duration::from_millis(100);
        let max = Duration::from_millis(500);
        let mut backoff = ReconnectBackoff::new(base, max);

        fastrand::seed(42);

        // Exhaust the backoff until it hits the cap
        for _ in 0..10 {
            let _ = backoff.next_delay();
        }

        // Current should be at max
        assert_eq!(backoff.current, max);
    }

    #[test]
    fn backoff_reset_returns_to_base() {
        let base = Duration::from_millis(100);
        let max = Duration::from_secs(30);
        let mut backoff = ReconnectBackoff::new(base, max);

        // Advance backoff
        let _ = backoff.next_delay();
        let _ = backoff.next_delay();
        assert!(backoff.current > base);

        // Reset
        backoff.reset();
        assert_eq!(backoff.current, base);
    }
}

mod timeout_deadline {
    use std::time::Instant;

    use super::*;

    #[test]
    fn deadline_in_future() {
        let now = Instant::now();
        let timeout = Duration::from_secs(5);
        let deadline = now + timeout;

        // Deadline should be in the future
        assert!(deadline > now);
        assert!(deadline.duration_since(now) <= timeout);
    }

    #[test]
    fn deadline_elapsed_check() {
        let now = Instant::now();
        let past_deadline = now.checked_sub(Duration::from_secs(1)).unwrap();
        let future_deadline = now + Duration::from_secs(1);

        // Past deadline should be before now
        assert!(past_deadline < now);
        // Future deadline should be after now
        assert!(future_deadline > now);
    }
}
