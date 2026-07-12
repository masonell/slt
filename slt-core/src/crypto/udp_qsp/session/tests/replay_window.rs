use super::*;

#[test]
fn replay_window_rejects_replay() {
    let mut window = ReplayWindow::new(0);
    window.check_and_update(10).unwrap();
    assert_eq!(window.check_and_update(10), Err(ReplayError::Replay));
}

#[test]
fn replay_window_rejects_too_old() {
    let mut window = ReplayWindow::new(0);
    window.check_and_update(2000).unwrap();
    assert_eq!(
        window.check_and_update(2000 - PN_REPLAY_WINDOW as u64),
        Err(ReplayError::TooOld)
    );
}

#[test]
fn replay_window_rejects_first_packet_below_initial_expected() {
    let mut window = ReplayWindow::new(1000);
    assert_eq!(window.check_and_update(999), Err(ReplayError::TooOld));
    assert_eq!(window.largest_pn(), None);
}

#[test]
fn replay_window_accepts_out_of_order() {
    let mut window = ReplayWindow::new(0);
    window.check_and_update(100).unwrap();
    window.check_and_update(99).unwrap();
    window.check_and_update(98).unwrap();
    assert_eq!(window.largest_pn(), Some(100));
}

#[test]
fn replay_window_drops_oldest_on_advance() {
    let mut window = ReplayWindow::new(0);
    window.check_and_update(1000).unwrap();
    window.check_and_update(1500).unwrap();
    assert_eq!(window.check_and_update(0), Err(ReplayError::TooOld));
}

#[test]
fn replay_window_shift_with_various_deltas() {
    // Test window shift with delta smaller than window size
    let mut window = ReplayWindow::new(0);
    window.check_and_update(100).unwrap();
    assert!(window.check_and_update(50).is_ok()); // within window

    // Test window shift with delta equal to window size
    let mut window = ReplayWindow::new(0);
    window.check_and_update(0).unwrap();
    window.check_and_update(PN_REPLAY_WINDOW as u64).unwrap();
    // Now 0 should be TooOld since window shifted completely
    assert_eq!(window.check_and_update(0), Err(ReplayError::TooOld));

    // Test window shift with delta larger than window size (full reset)
    let mut window = ReplayWindow::new(0);
    window.check_and_update(0).unwrap();
    window
        .check_and_update((PN_REPLAY_WINDOW * 2) as u64)
        .unwrap();
    // Window should be completely reset
    assert_eq!(window.largest_pn(), Some((PN_REPLAY_WINDOW * 2) as u64));
}

#[test]
fn replay_window_with_large_packet_numbers() {
    let mut window = ReplayWindow::new(u64::MAX / 2);

    // Accept first packet
    window.check_and_update(u64::MAX / 2).unwrap();
    assert_eq!(window.largest_pn(), Some(u64::MAX / 2));

    // Accept later packet
    window.check_and_update(u64::MAX / 2 + 100).unwrap();
    assert_eq!(window.largest_pn(), Some(u64::MAX / 2 + 100));

    // Accept earlier packet within window
    window.check_and_update(u64::MAX / 2 + 50).unwrap();

    // Reject too old
    let too_old = u64::MAX / 2 - PN_REPLAY_WINDOW as u64 - 1;
    assert_eq!(window.check_and_update(too_old), Err(ReplayError::TooOld));
}

// =========================================================================
// Edge case tests for next_rekey_after
// =========================================================================
