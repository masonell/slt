use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::{mpsc, oneshot};
use tokio::time;
use tokio_util::sync::CancellationToken;

use super::observer::{ClientEvent, ClientEventKind, ClientObserver, ObserverSink};
use super::services::ClientRuntimeServices;
use super::{
    RuntimeError, SessionAction, SessionOutcome, handle_session_exit, resolve_tun_channel_failure,
    run_client_with_metrics, session,
};
use crate::metrics::{Metrics, MetricsSnapshot};
use crate::transport::host_resolver::{HostResolver, HostResolverFuture};
use crate::transport::socket_protector::NoopSocketProtector;
use crate::tun::{TunChannels, TunHandles, TunTask, TunTaskError};

#[derive(Clone, Copy)]
struct PendingResolver;

impl HostResolver for PendingResolver {
    fn resolve<'a>(&'a self, _hostname: &'a str, _port: u16) -> HostResolverFuture<'a> {
        Box::pin(std::future::pending())
    }
}

#[derive(Clone, Default)]
struct RecordingObserver {
    events: Arc<Mutex<Vec<ClientEvent>>>,
}

impl RecordingObserver {
    fn snapshot(&self) -> Vec<ClientEvent> {
        self.events.lock().unwrap().clone()
    }
}

impl ClientObserver for RecordingObserver {
    fn on_event(&self, event: &ClientEvent) {
        self.events.lock().unwrap().push(event.clone());
    }
}

struct TestServices {
    socket_protector: NoopSocketProtector,
    host_resolver: PendingResolver,
    observer: ObserverSink<RecordingObserver>,
}

impl ClientRuntimeServices for TestServices {
    type SocketProtector = NoopSocketProtector;
    type HostResolver = PendingResolver;
    type Observer = RecordingObserver;

    fn socket_protector(&self) -> &Self::SocketProtector {
        &self.socket_protector
    }

    fn host_resolver(&self) -> &Self::HostResolver {
        &self.host_resolver
    }

    fn observer(&self) -> &ObserverSink<Self::Observer> {
        &self.observer
    }
}

#[derive(Clone, Copy)]
enum TunTaskBehavior {
    Clean,
    UnexpectedExit,
    IoError(&'static str),
    Panic(&'static str),
}

fn spawn_test_tun_task(
    behavior: TunTaskBehavior,
    cancel: CancellationToken,
) -> tokio::task::JoinHandle<io::Result<()>> {
    tokio::spawn(async move {
        match behavior {
            TunTaskBehavior::Clean => {
                cancel.cancelled().await;
                Ok(())
            }
            TunTaskBehavior::UnexpectedExit => Ok(()),
            TunTaskBehavior::IoError(message) => Err(io::Error::other(message)),
            TunTaskBehavior::Panic(message) => panic!("{message}"),
        }
    })
}

fn test_tun_handles(
    reader: TunTaskBehavior,
    writer: TunTaskBehavior,
    cancel: &CancellationToken,
) -> TunHandles {
    TunHandles::new(
        spawn_test_tun_task(reader, cancel.clone()),
        spawn_test_tun_task(writer, cancel.clone()),
    )
}

async fn run_test_client(
    tun_handles: TunHandles,
    cancel: CancellationToken,
) -> (anyhow::Result<()>, Vec<ClientEvent>) {
    let (result, events, _) = run_test_client_with_metrics(tun_handles, cancel).await;
    (result, events)
}

async fn run_test_client_with_metrics(
    tun_handles: TunHandles,
    cancel: CancellationToken,
) -> (anyhow::Result<()>, Vec<ClientEvent>, MetricsSnapshot) {
    let (to_session_tx, to_session_rx) = mpsc::channel(1);
    let (to_tun_tx, to_tun_rx) = mpsc::channel(1);
    let tun_channels = TunChannels {
        to_session_rx,
        to_tun_tx,
    };
    let _channel_peers = (to_session_tx, to_tun_rx);

    let observer = RecordingObserver::default();
    let services = TestServices {
        socket_protector: NoopSocketProtector,
        host_resolver: PendingResolver,
        observer: ObserverSink::new(7, observer.clone()),
    };
    let metrics = Arc::new(Metrics::default());

    let result = time::timeout(
        Duration::from_secs(1),
        run_client_with_metrics(
            crate::test_support::test_config(),
            tun_handles,
            tun_channels,
            cancel,
            services,
            None,
            metrics.clone(),
        ),
    )
    .await
    .expect("test client terminates promptly");

    (result, observer.snapshot(), metrics.snapshot())
}

fn assert_terminal_error(events: &[ClientEvent], expected_detail: &str) {
    let mut terminal = events.iter().filter(|event| {
        matches!(
            event.kind,
            ClientEventKind::Stopped | ClientEventKind::Error { .. }
        )
    });
    let event = terminal.next().expect("terminal event missing");
    assert!(
        terminal.next().is_none(),
        "multiple terminal events emitted"
    );
    match &event.kind {
        ClientEventKind::Error { detail, retryable } => {
            assert!(detail.contains(expected_detail), "detail: {detail}");
            assert!(!retryable, "TUN task failures must be terminal");
        }
        other => panic!("expected Error terminal event, got {other:?}"),
    }
}

#[tokio::test]
async fn tun_reader_io_error_is_terminal() {
    let cancel = CancellationToken::new();
    let handles = test_tun_handles(
        TunTaskBehavior::IoError("synthetic TUN read failure"),
        TunTaskBehavior::Clean,
        &cancel,
    );

    let (result, events, metrics) = run_test_client_with_metrics(handles, cancel).await;

    let err = result.expect_err("TUN reader failure must fail the runtime");
    match err.downcast_ref::<RuntimeError>() {
        Some(RuntimeError::Tun(TunTaskError::Io {
            task: TunTask::Reader,
            source,
        })) => assert_eq!(source.to_string(), "synthetic TUN read failure"),
        other => panic!("unexpected runtime error: {other:?}"),
    }
    assert_terminal_error(
        &events,
        "TUN reader task failed: synthetic TUN read failure",
    );
    assert_eq!(metrics.disconnect_error, 1);
    assert_eq!(metrics.disconnect_shutdown, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn channel_close_race_preserves_reader_error() {
    let cancel = CancellationToken::new();
    let (packet_tx, mut packet_rx) = mpsc::channel::<Vec<u8>>(1);
    let (closed_tx, closed_rx) = oneshot::channel();
    let (release_tx, release_rx) = oneshot::channel();
    let reader = tokio::spawn(async move {
        drop(packet_tx);
        closed_tx.send(()).unwrap();
        let _ = release_rx.await;
        Err(io::Error::other("reader failed after channel closure"))
    });
    let writer = spawn_test_tun_task(TunTaskBehavior::Clean, cancel.clone());
    let mut handles = TunHandles::new(reader, writer);

    closed_rx.await.unwrap();
    assert!(packet_rx.recv().await.is_none());

    let result = {
        let resolve = resolve_tun_channel_failure(
            Err(RuntimeError::Tun(TunTaskError::ChannelClosed {
                task: TunTask::Reader,
            })),
            &mut handles,
        );
        tokio::pin!(resolve);
        tokio::select! {
            biased;

            result = &mut resolve => panic!("task result resolved before release: {result:?}"),
            () = tokio::task::yield_now() => {}
        }
        release_tx.send(()).unwrap();
        time::timeout(Duration::from_secs(1), resolve)
            .await
            .expect("reader result becomes available after release")
    };

    match result {
        Err(RuntimeError::Tun(TunTaskError::Io {
            task: TunTask::Reader,
            source,
        })) => assert_eq!(source.to_string(), "reader failed after channel closure"),
        other => panic!("unexpected resolved result: {other:?}"),
    }

    cancel.cancel();
    handles.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn channel_close_race_preserves_writer_error() {
    let cancel = CancellationToken::new();
    let (packet_tx, packet_rx) = mpsc::channel::<Vec<u8>>(1);
    let (closed_tx, closed_rx) = oneshot::channel();
    let (release_tx, release_rx) = oneshot::channel();
    let reader = spawn_test_tun_task(TunTaskBehavior::Clean, cancel.clone());
    let writer = tokio::spawn(async move {
        drop(packet_rx);
        closed_tx.send(()).unwrap();
        let _ = release_rx.await;
        Err(io::Error::other("writer failed after channel closure"))
    });
    let mut handles = TunHandles::new(reader, writer);

    closed_rx.await.unwrap();
    assert!(packet_tx.send(vec![1]).await.is_err());

    let result = {
        let resolve = resolve_tun_channel_failure(
            Err(RuntimeError::Tun(TunTaskError::ChannelClosed {
                task: TunTask::Writer,
            })),
            &mut handles,
        );
        tokio::pin!(resolve);
        tokio::select! {
            biased;

            result = &mut resolve => panic!("task result resolved before release: {result:?}"),
            () = tokio::task::yield_now() => {}
        }
        release_tx.send(()).unwrap();
        time::timeout(Duration::from_secs(1), resolve)
            .await
            .expect("writer result becomes available after release")
    };

    match result {
        Err(RuntimeError::Tun(TunTaskError::Io {
            task: TunTask::Writer,
            source,
        })) => assert_eq!(source.to_string(), "writer failed after channel closure"),
        other => panic!("unexpected resolved result: {other:?}"),
    }

    cancel.cancel();
    handles.shutdown().await;
}

#[tokio::test]
async fn tun_writer_io_error_is_terminal_without_inbound_data() {
    let cancel = CancellationToken::new();
    let handles = test_tun_handles(
        TunTaskBehavior::Clean,
        TunTaskBehavior::IoError("synthetic TUN write failure"),
        &cancel,
    );

    let (result, events) = run_test_client(handles, cancel).await;

    let err = result.expect_err("TUN writer failure must fail the runtime");
    match err.downcast_ref::<RuntimeError>() {
        Some(RuntimeError::Tun(TunTaskError::Io {
            task: TunTask::Writer,
            source,
        })) => assert_eq!(source.to_string(), "synthetic TUN write failure"),
        other => panic!("unexpected runtime error: {other:?}"),
    }
    assert_terminal_error(
        &events,
        "TUN writer task failed: synthetic TUN write failure",
    );
}

#[tokio::test]
async fn tun_task_panic_is_terminal() {
    let cancel = CancellationToken::new();
    let handles = test_tun_handles(
        TunTaskBehavior::Panic("synthetic TUN reader panic"),
        TunTaskBehavior::Clean,
        &cancel,
    );

    let (result, events) = run_test_client(handles, cancel).await;

    let err = result.expect_err("TUN task panic must fail the runtime");
    match err.downcast_ref::<RuntimeError>() {
        Some(RuntimeError::Tun(TunTaskError::Panic {
            task: TunTask::Reader,
            source,
        })) => assert!(source.is_panic()),
        other => panic!("unexpected runtime error: {other:?}"),
    }
    assert_terminal_error(&events, "synthetic TUN reader panic");
}

#[tokio::test]
async fn active_tun_task_clean_exit_is_terminal() {
    let cancel = CancellationToken::new();
    let handles = test_tun_handles(
        TunTaskBehavior::UnexpectedExit,
        TunTaskBehavior::Clean,
        &cancel,
    );

    let (result, events) = run_test_client(handles, cancel).await;

    let err = result.expect_err("active TUN task exit must fail the runtime");
    assert!(matches!(
        err.downcast_ref::<RuntimeError>(),
        Some(RuntimeError::Tun(TunTaskError::UnexpectedExit {
            task: TunTask::Reader
        }))
    ));
    assert_terminal_error(&events, "TUN reader task exited unexpectedly");
}

#[test]
fn tun_channel_closure_is_runtime_failure() {
    let outcome = SessionOutcome {
        exit: session::SessionExit::TunClosed(TunTask::Reader),
        error: None,
    };

    assert!(matches!(
        handle_session_exit(outcome, &CancellationToken::new()),
        SessionAction::TunChannelClosed(TunTask::Reader)
    ));
}

#[tokio::test]
async fn tun_tasks_exit_cleanly_after_deliberate_cancellation() {
    let cancel = CancellationToken::new();
    let handles = test_tun_handles(TunTaskBehavior::Clean, TunTaskBehavior::Clean, &cancel);
    cancel.cancel();

    let (result, events) = run_test_client(handles, cancel).await;

    result.expect("deliberate cancellation must stop cleanly");
    let mut terminal = events.iter().filter(|event| {
        matches!(
            event.kind,
            ClientEventKind::Stopped | ClientEventKind::Error { .. }
        )
    });
    assert!(matches!(
        terminal.next().map(|event| &event.kind),
        Some(ClientEventKind::Stopped)
    ));
    assert!(
        terminal.next().is_none(),
        "multiple terminal events emitted"
    );
}
