use tokio_util::sync::CancellationToken;

use super::super::{ConnectOutcome, handle_connect_command};
use super::RecordingObserver;
use crate::runtime::control::ClientCommand;
use crate::runtime::observer::{ClientEventKind, ObserverSink};

fn recording_sink() -> (ObserverSink<RecordingObserver>, RecordingObserver) {
    let observer = RecordingObserver::default();
    let sink = ObserverSink::new(7, observer.clone());
    (sink, observer)
}

#[test]
fn network_change_during_connect_requests_reconnect() {
    let cancel = CancellationToken::new();
    let (sink, observer) = recording_sink();

    let outcome = handle_connect_command(Some(ClientCommand::NetworkChanged), &cancel, &sink);

    assert!(matches!(outcome, ConnectOutcome::Reconnect));
    assert!(!cancel.is_cancelled());
    let events = observer.snapshot();
    assert_eq!(events.len(), 1);
    assert!(matches!(
        &events[0].kind,
        ClientEventKind::NetworkChanged { detail }
            if detail == "underlying network changed"
    ));
}

#[test]
fn stop_during_connect_requests_shutdown() {
    let cancel = CancellationToken::new();
    let (sink, observer) = recording_sink();

    let outcome = handle_connect_command(Some(ClientCommand::Stop), &cancel, &sink);

    assert!(matches!(outcome, ConnectOutcome::Shutdown));
    assert!(cancel.is_cancelled());
    assert!(observer.snapshot().is_empty());
}

#[test]
fn closed_control_channel_requests_shutdown() {
    let cancel = CancellationToken::new();
    let (sink, observer) = recording_sink();

    let outcome = handle_connect_command(None, &cancel, &sink);

    assert!(matches!(outcome, ConnectOutcome::Shutdown));
    assert!(cancel.is_cancelled());
    assert!(observer.snapshot().is_empty());
}
