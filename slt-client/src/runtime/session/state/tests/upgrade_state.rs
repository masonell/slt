use std::time::{Duration, Instant};

use super::*;

#[test]
fn upgrading_with_probe_acked_uses_deadline() {
    let deadline = Instant::now() + Duration::from_secs(5);
    let state = UdpUpgradeState::Upgrading {
        upgrade_id: 7,
        deadline,
        attempts: 2,
        next_probe_at: Instant::now() + Duration::from_secs(1),
        probe_nonce: 11,
        probe_acked: true,
        ready_sent: true,
        probe_backoff: ReconnectBackoff::new(Duration::from_secs(1), Duration::from_secs(2)),
    };
    assert_eq!(state.timer_at(), Some(deadline));
}
