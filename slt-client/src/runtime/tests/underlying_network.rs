use std::io;
use std::sync::Arc;
use std::time::Duration;

use tokio_util::sync::CancellationToken;

use super::super::{ConnectOutcome, ReconnectBackoff, RuntimeSignals, try_connect};
use super::RecordingObserver;
use crate::metrics::Metrics;
use crate::runtime::observer::{ClientEventKind, ObserverSink};
use crate::runtime::services::ClientRuntimeServices;
use crate::test_support::test_config;
use crate::transport::host_resolver::TokioHostResolver;
use crate::transport::socket_protector::{SocketKind, SocketProtectionResult, SocketProtector};

#[derive(Clone, Copy)]
struct NoUnderlyingNetworkProtector;

impl SocketProtector for NoUnderlyingNetworkProtector {
    fn protect(&self, fd: i32, kind: SocketKind) -> io::Result<()> {
        SocketProtectionResult::NoUnderlyingNetwork.into_io_result(fd, kind)
    }
}

struct SocketProtectionTestServices {
    socket_protector: NoUnderlyingNetworkProtector,
    host_resolver: TokioHostResolver,
    observer: ObserverSink<RecordingObserver>,
}

impl ClientRuntimeServices for SocketProtectionTestServices {
    type SocketProtector = NoUnderlyingNetworkProtector;
    type HostResolver = TokioHostResolver;
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

#[tokio::test]
async fn no_underlying_network_before_auth_schedules_reconnect() {
    let mut config = test_config();
    config.network.ip = Some("127.0.0.1".parse().unwrap());
    config.timing.reconnect_min = Duration::from_millis(1);
    config.timing.reconnect_max = Duration::from_millis(1);

    let observer = RecordingObserver::default();
    let services = SocketProtectionTestServices {
        socket_protector: NoUnderlyingNetworkProtector,
        host_resolver: TokioHostResolver,
        observer: ObserverSink::new(7, observer.clone()),
    };
    let shutdown = CancellationToken::new();
    let tun_fault = CancellationToken::new();
    let signals = RuntimeSignals {
        shutdown: &shutdown,
        tun_fault: &tun_fault,
    };
    let metrics = Arc::new(Metrics::default());
    let mut backoff =
        ReconnectBackoff::new(config.timing.reconnect_min, config.timing.reconnect_max);
    let mut attempt = 0;
    let mut control_rx = None;

    let outcome = try_connect(
        &config,
        signals,
        &metrics,
        &mut backoff,
        &mut attempt,
        &services,
        &mut control_rx,
    )
    .await;

    assert!(matches!(outcome, ConnectOutcome::Reconnect));
    let events = observer.events.lock().unwrap();
    assert!(events.iter().any(|event| {
        matches!(
            &event.kind,
            ClientEventKind::ReconnectFailed { attempt: 1, .. }
        )
    }));
    assert!(events.iter().any(|event| {
        matches!(
            &event.kind,
            ClientEventKind::ReconnectScheduled { attempt: 2, .. }
        )
    }));
    assert!(
        !events
            .iter()
            .any(|event| matches!(&event.kind, ClientEventKind::Error { .. }))
    );
}
