use std::io;
use std::net::{IpAddr, SocketAddr};
use std::os::fd::RawFd;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use slt_core::config::ClientConfig;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info};

use super::uniffi_api::{NativeSessionCallback, PlatformServices, SltInteropError};
use crate::runtime::control::{
    ClientCommand, ClientCommandReceiver, ClientCommandSender, client_command_channel,
};
use crate::runtime::observer::{ClientEvent, ClientEventKind, ClientObserver, ObserverSink};
use crate::runtime::services::ClientRuntimeServices;
use crate::transport::host_resolver::{HostResolver, HostResolverFuture, ensure_non_empty};
use crate::transport::socket_protector::{SocketKind, SocketProtector};

const RUNTIME_SHUTDOWN_TIMEOUT: Duration = Duration::from_millis(250);

type NativeHandle = u64;

static NEXT_HANDLE: AtomicU64 = AtomicU64::new(1);

pub(super) fn start_session(
    config_toml: String,
    tun_fd: i32,
    mtu: i32,
    platform_services: Arc<dyn PlatformServices>,
    callback: Arc<dyn NativeSessionCallback>,
) -> Result<Arc<NativeSession>, SltInteropError> {
    if tun_fd < 0 {
        return Err(SltInteropError::InvalidArgument {
            detail: format!("invalid Android TUN fd: {tun_fd}"),
        });
    }

    let handle = NEXT_HANDLE.fetch_add(1, Ordering::Relaxed);
    if handle == 0 {
        return Err(SltInteropError::SessionStart {
            detail: "native handle counter wrapped".to_string(),
        });
    }

    let sink = ObserverSink::new(handle, AndroidObserver::new(callback));
    let cancel = CancellationToken::new();
    let (command_tx, command_rx) = client_command_channel();
    let worker_cancel = cancel.clone();
    let worker_sink = sink;
    let worker = thread::Builder::new()
        .name(format!("slt-android-{handle}"))
        .spawn(move || {
            // Catch panics inside the worker so a runtime bug still produces a
            // terminal event instead of leaving Android with no Stopped/Error.
            let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                run_native_session(
                    &config_toml,
                    tun_fd,
                    mtu,
                    worker_cancel,
                    command_rx,
                    &worker_sink,
                    handle,
                    platform_services,
                );
            }))
            .is_err();
            if panicked {
                error!("native client worker panicked; handle={handle}");
                worker_sink.emit(ClientEventKind::Error {
                    detail: "native client worker panicked".to_string(),
                });
            }
        })
        .map_err(|err| SltInteropError::SessionStart {
            detail: format!("spawn native client thread: {err}"),
        })?;

    Ok(Arc::new(NativeSession {
        handle,
        cancel,
        command_tx,
        worker: Mutex::new(Some(worker)),
    }))
}

#[derive(Debug, uniffi::Object)]
pub struct NativeSession {
    handle: NativeHandle,
    cancel: CancellationToken,
    command_tx: ClientCommandSender,
    worker: Mutex<Option<JoinHandle<()>>>,
}

#[uniffi::export]
impl NativeSession {
    pub fn handle(&self) -> i64 {
        i64::try_from(self.handle).unwrap_or(i64::MAX)
    }

    pub fn stop(&self) {
        self.stop_inner();
    }

    pub fn network_changed(&self) {
        if self.command_tx.send(ClientCommand::NetworkChanged).is_err() {
            debug!(
                handle = self.handle,
                "network_changed command dropped; runtime already stopped"
            );
        }
    }
}

impl NativeSession {
    fn stop_inner(&self) {
        if self.command_tx.send(ClientCommand::Stop).is_err() {
            debug!(
                handle = self.handle,
                "stop command dropped; runtime already stopped"
            );
        }
        self.cancel.cancel();
        let Ok(mut worker) = self.worker.lock() else {
            return;
        };
        if let Some(worker) = worker.take() {
            let _ = worker.join();
        }
    }
}

impl Drop for NativeSession {
    fn drop(&mut self) {
        self.stop_inner();
    }
}

/// Bridges typed [`ClientEvent`]s from the runtime to the `UniFFI` foreign callback.
///
/// The runtime (via [`ObserverSink`]) owns the session handle, monotonic
/// sequence counter, and tracked transport; this observer only forwards each
/// fully-formed event to Kotlin.
struct AndroidObserver {
    callback: Arc<dyn NativeSessionCallback>,
}

impl AndroidObserver {
    fn new(callback: Arc<dyn NativeSessionCallback>) -> Self {
        Self { callback }
    }
}

impl ClientObserver for AndroidObserver {
    fn on_event(&self, event: &ClientEvent) {
        self.callback.on_event(event.clone());
    }
}

#[derive(Clone)]
struct AndroidSocketProtector {
    platform_services: Arc<dyn PlatformServices>,
}

impl AndroidSocketProtector {
    fn new(platform_services: Arc<dyn PlatformServices>) -> Self {
        Self { platform_services }
    }
}

impl SocketProtector for AndroidSocketProtector {
    fn protect(&self, fd: RawFd, kind: SocketKind) -> io::Result<()> {
        // `RawFd` is `i32` on Android, so it maps directly to the UniFFI
        // `protect_socket(fd: i32)` signature — no range conversion needed.
        let protected = self.platform_services.protect_socket(fd, kind);
        if protected {
            debug!(fd, kind = ?kind, "Android socket protected");
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("Android protectSocket returned false for {kind:?} fd {fd}"),
            ))
        }
    }
}

#[derive(Clone)]
struct AndroidHostResolver {
    platform_services: Arc<dyn PlatformServices>,
}

impl AndroidHostResolver {
    fn new(platform_services: Arc<dyn PlatformServices>) -> Self {
        Self { platform_services }
    }
}

impl HostResolver for AndroidHostResolver {
    fn resolve<'a>(&'a self, hostname: &'a str, port: u16) -> HostResolverFuture<'a> {
        let platform_services = self.platform_services.clone();
        let hostname = hostname.to_string();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || resolve_host(&platform_services, &hostname, port))
                .await
                .map_err(|err| io::Error::other(format!("Android DNS task failed: {err}")))?
        })
    }
}

/// Android [`ClientRuntimeServices`] bundle: socket protection and DNS through
/// the active underlying network, plus the typed event sink forwarding to the
/// foreign callback.
struct AndroidServices {
    socket_protector: AndroidSocketProtector,
    host_resolver: AndroidHostResolver,
    observer: ObserverSink<AndroidObserver>,
}

impl AndroidServices {
    fn new(
        platform_services: Arc<dyn PlatformServices>,
        observer: ObserverSink<AndroidObserver>,
    ) -> Self {
        Self {
            socket_protector: AndroidSocketProtector::new(platform_services.clone()),
            host_resolver: AndroidHostResolver::new(platform_services),
            observer,
        }
    }
}

impl ClientRuntimeServices for AndroidServices {
    type SocketProtector = AndroidSocketProtector;
    type HostResolver = AndroidHostResolver;
    type Observer = AndroidObserver;

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

fn resolve_host(
    platform_services: &Arc<dyn PlatformServices>,
    hostname: &str,
    port: u16,
) -> io::Result<Vec<SocketAddr>> {
    let resolved = platform_services
        .resolve_host(hostname.to_string())
        .map_err(|err| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("call Android resolveHost for {hostname}: {err}"),
            )
        })?;

    let mut addrs = Vec::with_capacity(resolved.len());
    for address in resolved {
        let ip = address.parse::<IpAddr>().map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Android resolveHost returned non-IP address {address}: {err}"),
            )
        })?;
        addrs.push(SocketAddr::new(ip, port));
    }

    ensure_non_empty(addrs)
}

fn run_native_session(
    raw_config: &str,
    tun_fd: i32,
    mtu: i32,
    cancel: CancellationToken,
    control_rx: ClientCommandReceiver,
    sink: &ObserverSink<AndroidObserver>,
    handle: NativeHandle,
    platform_services: Arc<dyn PlatformServices>,
) {
    info!("[session start] handle={handle} fd={tun_fd} android_mtu={mtu}");
    // The runtime (run_client) owns the lifecycle event stream: Starting..
    // Stopped/Error. Only pre-run_client setup failures (config parse, mtu,
    // runtime creation, TUN spawn) are reported here as Error.
    match run_native_client(
        raw_config,
        tun_fd,
        mtu,
        cancel,
        control_rx,
        sink,
        platform_services,
    ) {
        Ok(()) => {
            info!("[session stop] handle={handle}");
        }
        Err(err) => {
            error!("Android client setup failed: {err}");
            info!("[session stop reason=error] handle={handle}");
            sink.emit(ClientEventKind::Error { detail: err });
        }
    }
}

fn run_native_client(
    raw_config: &str,
    tun_fd: i32,
    mtu: i32,
    cancel: CancellationToken,
    control_rx: ClientCommandReceiver,
    sink: &ObserverSink<AndroidObserver>,
    platform_services: Arc<dyn PlatformServices>,
) -> Result<(), String> {
    let config = ClientConfig::from_toml_str(raw_config)
        .map_err(|err| format!("parse Android client config: {err}"))?;
    validate_android_mtu(mtu, config.tun.tun_mtu)?;

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .map_err(|err| format!("create Android client runtime: {err}"))?;

    // Returns Err only for pre-run_client setup (TUN spawn) failures, which the
    // bridge reports as Error. run_client owns its own terminal events, so its
    // result is logged here but not propagated (avoiding a double Error).
    let setup_result = runtime.block_on(async move {
        let (tun_handles, tun_channels) =
            crate::tun::spawn_from_fd(&config, tun_fd, cancel.clone())
                .map_err(|err| format!("start Android TUN backend: {err}"))?;
        info!("Android TUN backend started");

        let services = AndroidServices::new(platform_services, sink.clone());
        if let Err(err) = crate::run_client(
            config,
            tun_handles,
            tun_channels,
            cancel,
            services,
            Some(control_rx),
        )
        .await
        {
            error!("client runtime exited with error: {err}");
        }
        Ok::<(), String>(())
    });
    runtime.shutdown_timeout(RUNTIME_SHUTDOWN_TIMEOUT);
    setup_result
}

fn validate_android_mtu(mtu: i32, config_mtu: u16) -> Result<(), String> {
    let Ok(mtu) = u16::try_from(mtu) else {
        return Err(format!("invalid Android TUN mtu: {mtu}"));
    };
    if mtu == 0 {
        return Err("invalid Android TUN mtu: 0".to_string());
    }
    if mtu != config_mtu {
        return Err(format!(
            "Android TUN mtu {mtu} does not match config tun_mtu {config_mtu}"
        ));
    }
    Ok(())
}
