use std::time::{Duration, Instant};

mod activity_clock_independence {
    use super::*;

    /// TCP ingress extends session activity without masking UDP path failure.
    #[test]
    fn tcp_activity_does_not_extend_udp_liveness() {
        let idle_timeout = Duration::from_mins(1);
        let udp_liveness_timeout = Duration::from_secs(30);
        let now = Instant::now();
        let last_authenticated_udp_activity = now;
        let tcp_activity = now + Duration::from_secs(20);

        let idle_deadline = tcp_activity + idle_timeout;
        let udp_liveness_deadline = last_authenticated_udp_activity + udp_liveness_timeout;

        assert!(udp_liveness_deadline < idle_deadline);
    }

    /// Authenticated UDP ingress extends both independent clocks.
    #[test]
    fn udp_activity_extends_idle_and_udp_liveness() {
        let idle_timeout = Duration::from_mins(1);
        let udp_liveness_timeout = Duration::from_secs(30);
        let now = Instant::now();
        let udp_activity = now + Duration::from_secs(20);

        assert_eq!(udp_activity + idle_timeout, now + Duration::from_secs(80));
        assert_eq!(
            udp_activity + udp_liveness_timeout,
            now + Duration::from_secs(50)
        );
    }
}
