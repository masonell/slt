use std::future::Future;
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use slt_server::auth::AuthHandlerBase;
use slt_server::metrics::Metrics;
use slt_server::quic::QuicEndpoint;
use slt_server::tcp::TcpFrontDoor;
use slt_server::tun::TunDeviceIo;
use tokio::net::TcpStream;
use tokio::time::{self, Duration};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tracing::{debug, error, info, warn};

use super::{RuntimeComponents, tun_workers};

const GRACEFUL_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);

pub(super) async fn run(components: RuntimeComponents) -> io::Result<()> {
    let RuntimeComponents {
        frontdoor,
        quic,
        auth_handler,
        sessions,
        tun,
        metrics,
        metrics_interval,
    } = components;
    let cancel = CancellationToken::new();
    let auth_tasks = AuthTaskTracker::new();

    spawn_ctrl_c(cancel.clone());
    debug!("server runtime: spawning worker tasks");

    let mut tcp_task = spawn_tcp_task(frontdoor, auth_handler, cancel.clone(), auth_tasks.clone());
    let mut udp_task = spawn_udp_task(quic, cancel.clone());
    let (mut tun_reader_task, mut tun_writer_task) =
        tun_workers::spawn(tun, metrics.clone(), cancel.clone());
    let mut metrics_task = spawn_metrics_task(metrics, cancel.clone(), metrics_interval);

    let trigger = tokio::select! {
        res = &mut tcp_task => ShutdownTrigger::WorkerFailed { task: "tcp", result: res },
        res = &mut udp_task => ShutdownTrigger::WorkerFailed { task: "udp", result: res },
        res = &mut tun_reader_task => ShutdownTrigger::WorkerFailed { task: "tun_reader", result: res },
        res = &mut tun_writer_task => ShutdownTrigger::WorkerFailed { task: "tun_writer", result: res },
        res = &mut metrics_task => ShutdownTrigger::WorkerFailed { task: "metrics", result: res },
        () = cancel.cancelled() => ShutdownTrigger::Cancelled,
    };
    let worker_failure = trigger.worker_failure_context();

    await_graceful_shutdown(
        async move {
            let shutdown_result = match trigger {
                ShutdownTrigger::WorkerFailed { task, result } => {
                    info!(
                        reason = task_failure_reason(task),
                        "graceful shutdown initiated"
                    );
                    cancel.cancel();
                    sessions.start_shutdown();
                    auth_tasks.close();

                    let mut shutdown_result = classify_task_result(task, result);
                    if task != "tcp" {
                        merge_task_result(&mut shutdown_result, "tcp", tcp_task.await);
                    }
                    if task != "udp" {
                        merge_task_result(&mut shutdown_result, "udp", udp_task.await);
                    }
                    if task != "tun_reader" {
                        merge_task_result(
                            &mut shutdown_result,
                            "tun_reader",
                            tun_reader_task.await,
                        );
                    }
                    if task != "tun_writer" {
                        merge_task_result(
                            &mut shutdown_result,
                            "tun_writer",
                            tun_writer_task.await,
                        );
                    }
                    if task != "metrics" {
                        merge_task_result(&mut shutdown_result, "metrics", metrics_task.await);
                    }
                    shutdown_result
                }
                ShutdownTrigger::Cancelled => {
                    info!(reason = "ctrl_c", "graceful shutdown initiated");
                    sessions.start_shutdown();
                    auth_tasks.close();
                    join_ignoring_result(tcp_task).await;
                    join_ignoring_result(udp_task).await;
                    join_ignoring_result(tun_reader_task).await;
                    join_ignoring_result(tun_writer_task).await;
                    join_ignoring_result(metrics_task).await;
                    Ok(())
                }
            };

            auth_tasks.wait().await;
            sessions.wait_for_shutdown().await;
            info!("server shutdown complete");
            shutdown_result
        },
        GRACEFUL_SHUTDOWN_TIMEOUT,
        worker_failure.as_deref(),
    )
    .await
}

async fn await_graceful_shutdown<F>(
    shutdown: F,
    timeout: Duration,
    worker_failure: Option<&str>,
) -> io::Result<()>
where
    F: Future<Output = io::Result<()>>,
{
    time::timeout(timeout, shutdown).await.unwrap_or_else(|_| {
        error!(
            timeout_ms = timeout.as_millis(),
            worker_failure = ?worker_failure,
            "graceful shutdown timed out"
        );
        let message = worker_failure.map_or_else(
            || "server graceful shutdown timed out".to_owned(),
            |failure| format!("server graceful shutdown timed out after {failure}"),
        );
        Err(io::Error::new(io::ErrorKind::TimedOut, message))
    })
}

#[derive(Clone)]
struct AuthTaskTracker {
    accepting: Arc<AtomicBool>,
    tasks: TaskTracker,
}

impl AuthTaskTracker {
    fn new() -> Self {
        Self {
            accepting: Arc::new(AtomicBool::new(true)),
            tasks: TaskTracker::new(),
        }
    }

    fn spawn<F>(&self, task: F) -> bool
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let token = self.tasks.token();
        // Reserving ownership before checking the gate makes a concurrent
        // close visible to wait() even if spawning races with shutdown.
        if !self.accepting.load(Ordering::Acquire) {
            drop(token);
            return false;
        }

        drop(self.tasks.spawn(async move {
            let task_reservation = token;
            task.await;
            drop(task_reservation);
        }));
        true
    }

    fn close(&self) {
        self.accepting.store(false, Ordering::Release);
        self.tasks.close();
    }

    async fn wait(&self) {
        self.tasks.wait().await;
    }
}

fn spawn_ctrl_c(cancel: CancellationToken) {
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            debug!("received ctrl_c signal");
            cancel.cancel();
        }
    });
}

fn spawn_tcp_task<T: TunDeviceIo>(
    frontdoor: TcpFrontDoor,
    auth_handler: Arc<AuthHandlerBase<T>>,
    cancel: CancellationToken,
    auth_tasks: AuthTaskTracker,
) -> tokio::task::JoinHandle<io::Result<()>> {
    tokio::spawn(async move {
        let auth_cancel = cancel.clone();
        frontdoor
            .run(cancel, move |stream: TcpStream, addr| {
                if auth_cancel.is_cancelled() {
                    debug!(peer = %addr, "dropping claimed tcp connection during shutdown");
                    return;
                }
                let auth_handler = auth_handler.clone();
                let auth_cancel = auth_cancel.clone();
                if !auth_tasks.spawn(async move {
                    info!(peer = %addr, "claimed tcp connection");
                    tokio::select! {
                        () = auth_cancel.cancelled() => {
                            debug!(peer = %addr, "auth handler cancelled during shutdown");
                        }
                        result = auth_handler.handle(stream) => {
                            if let Err(err) = result {
                                warn!(peer = %addr, error = %err, "auth handler error");
                            }
                        }
                    }
                }) {
                    debug!(peer = %addr, "dropping claimed tcp connection during shutdown");
                }
            })
            .await
    })
}

enum ShutdownTrigger {
    WorkerFailed {
        task: &'static str,
        result: Result<io::Result<()>, tokio::task::JoinError>,
    },
    Cancelled,
}

impl ShutdownTrigger {
    fn worker_failure_context(&self) -> Option<String> {
        let Self::WorkerFailed { task, result } = self else {
            return None;
        };
        Some(match result {
            Ok(Ok(())) => format!("{task} worker exited unexpectedly"),
            Ok(Err(err)) => format!("{task} worker failed: {err}"),
            Err(err) => format!("{task} worker task failed: {err}"),
        })
    }
}

fn task_failure_reason(task: &'static str) -> &'static str {
    match task {
        "tcp" => "tcp_task_failure",
        "udp" => "udp_task_failure",
        "tun_reader" => "tun_reader_task_failure",
        "tun_writer" => "tun_writer_task_failure",
        "metrics" => "metrics_task_failure",
        _ => "worker_task_failure",
    }
}

fn classify_task_result(
    task: &'static str,
    result: Result<io::Result<()>, tokio::task::JoinError>,
) -> io::Result<()> {
    match result {
        Ok(Ok(())) => Ok(()),
        Ok(Err(err)) => {
            error!(task, error = %err, "worker task failed");
            Err(err)
        }
        Err(err) => {
            error!(task, error = %err, "worker task failed");
            Err(io::Error::other(err))
        }
    }
}

fn merge_task_result(
    shutdown_result: &mut io::Result<()>,
    task: &'static str,
    result: Result<io::Result<()>, tokio::task::JoinError>,
) {
    let task_result = classify_task_result(task, result);
    if shutdown_result.is_ok() {
        *shutdown_result = task_result;
    }
}

async fn join_ignoring_result(handle: tokio::task::JoinHandle<io::Result<()>>) {
    let _ = handle.await;
}

fn spawn_udp_task(
    mut quic: QuicEndpoint,
    cancel: CancellationToken,
) -> tokio::task::JoinHandle<io::Result<()>> {
    tokio::spawn(async move { quic.run(cancel).await })
}

fn spawn_metrics_task(
    metrics: Arc<Metrics>,
    cancel: CancellationToken,
    metrics_interval: Duration,
) -> tokio::task::JoinHandle<io::Result<()>> {
    tokio::spawn(async move {
        let mut interval = time::interval(metrics_interval);
        loop {
            tokio::select! {
                () = cancel.cancelled() => return Ok(()),
                _ = interval.tick() => {
                    let snap = metrics.snapshot();
                    info!(
                        tcp_accepted = snap.tcp_accepted,
                        udp_accepted = snap.udp_accepted,
                        claimed = snap.claimed,
                        passed = snap.passed,
                        dropped = snap.dropped,
                        tcp_frontdoor_cap_drops = snap.tcp_frontdoor_cap_drops,
                        tcp_empty_classification_evictions = snap.tcp_empty_classification_evictions,
                        tcp_classification_timeouts = snap.tcp_classification_timeouts,
                        upstream_send_failures = snap.upstream_send_failures,
                        udp_upstream_setup_failure_drops = snap.udp_upstream_setup_failure_drops,
                        tun_session_queue_full_drops = snap.tun_session_queue_full_drops,
                        tun_writer_queue_full_drops = snap.tun_writer_queue_full_drops,
                        udp_claim_channel_full_drops = snap.udp_claim_channel_full_drops,
                        auth_successes = snap.auth_successes,
                        auth_failures = snap.auth_failures,
                        auth_rejections = snap.auth_rejections,
                        auth_limit_drops = snap.auth_limit_drops,
                        tcp_to_udp = snap.transport_tcp_to_udp,
                        udp_to_tcp = snap.transport_udp_to_tcp,
                        disconnect_idle = snap.disconnect_idle_timeout,
                        disconnect_close = snap.disconnect_close,
                        disconnect_shutdown = snap.disconnect_shutdown,
                        disconnect_error = snap.disconnect_error,
                        tls_key_update_requested = snap.tls_key_update_requested,
                        tls_key_update_applied = snap.tls_key_update_applied,
                        udp_qsp_tx_phase = snap.udp_qsp_tx_key_phase_transitions,
                        udp_qsp_rx_phase = snap.udp_qsp_rx_key_phase_transitions,
                        udp_qsp_decrypt_replay = snap.udp_qsp_decrypt_fail_replay,
                        udp_qsp_decrypt_too_old = snap.udp_qsp_decrypt_fail_too_old,
                        udp_qsp_decrypt_crypto = snap.udp_qsp_decrypt_fail_crypto,
                        udp_qsp_decrypt_other = snap.udp_qsp_decrypt_fail_other,
                        udp_qsp_liveness_timeouts = snap.udp_qsp_liveness_timeouts,
                        "metrics snapshot"
                    );
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use std::io;

    use tokio::time::Duration;

    use super::await_graceful_shutdown;

    #[tokio::test]
    async fn graceful_shutdown_wait_is_bounded() {
        let err = await_graceful_shutdown(
            std::future::pending::<io::Result<()>>(),
            Duration::from_millis(10),
            Some("udp worker failed: root cause"),
        )
        .await
        .unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        assert!(err.to_string().contains("udp worker failed: root cause"));
    }
}
