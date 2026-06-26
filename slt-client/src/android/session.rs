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

use super::uniffi_api::{
    NativeEvent, NativeEventKind, NativeSessionCallback, PlatformServices, SltInteropError,
    SocketKind as UniFfiSocketKind,
};
use crate::transport::host_resolver::{HostResolver, HostResolverFuture, ensure_non_empty};
use crate::transport::socket_protector::{SocketKind as RuntimeSocketKind, SocketProtector};

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

    let sink = EventSink::new(handle, callback, platform_services);
    let cancel = CancellationToken::new();
    let worker_cancel = cancel.clone();
    let worker_sink = sink;
    let worker = thread::Builder::new()
        .name(format!("slt-android-{handle}"))
        .spawn(move || {
            run_native_session(
                &config_toml,
                tun_fd,
                mtu,
                worker_cancel,
                &worker_sink,
                handle,
            );
        })
        .map_err(|err| SltInteropError::SessionStart {
            detail: format!("spawn native client thread: {err}"),
        })?;

    Ok(Arc::new(NativeSession {
        handle,
        cancel,
        worker: Mutex::new(Some(worker)),
    }))
}

#[derive(Debug, uniffi::Object)]
pub struct NativeSession {
    handle: NativeHandle,
    cancel: CancellationToken,
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
}

impl NativeSession {
    fn stop_inner(&self) {
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

#[derive(Clone)]
struct EventSink {
    inner: Arc<EventSinkInner>,
}

struct EventSinkInner {
    handle: NativeHandle,
    seq: AtomicU64,
    callback: Arc<dyn NativeSessionCallback>,
    platform_services: Arc<dyn PlatformServices>,
}

impl EventSink {
    fn new(
        handle: NativeHandle,
        callback: Arc<dyn NativeSessionCallback>,
        platform_services: Arc<dyn PlatformServices>,
    ) -> Self {
        Self {
            inner: Arc::new(EventSinkInner {
                handle,
                seq: AtomicU64::new(1),
                callback,
                platform_services,
            }),
        }
    }

    fn event(&self, kind: NativeEventKind, detail: Option<String>) {
        let event = NativeEvent {
            session_handle: i64::try_from(self.inner.handle).unwrap_or(i64::MAX),
            seq: i64::try_from(self.inner.seq.fetch_add(1, Ordering::Relaxed)).unwrap_or(i64::MAX),
            kind,
            detail,
        };
        self.inner.callback.on_event(event);
    }
}

struct AndroidSocketProtector {
    sink: EventSink,
}

impl AndroidSocketProtector {
    fn new(sink: EventSink) -> Self {
        Self { sink }
    }
}

impl SocketProtector for AndroidSocketProtector {
    fn protect(&self, fd: RawFd, kind: RuntimeSocketKind) -> io::Result<()> {
        let fd = i32::try_from(fd).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("socket fd out of Android int range: {fd}"),
            )
        })?;
        let protected = self
            .sink
            .inner
            .platform_services
            .protect_socket(fd, UniFfiSocketKind::from(kind));
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

struct AndroidHostResolver {
    sink: EventSink,
}

impl AndroidHostResolver {
    fn new(sink: EventSink) -> Self {
        Self { sink }
    }
}

impl HostResolver for AndroidHostResolver {
    fn resolve<'a>(&'a self, hostname: &'a str, port: u16) -> HostResolverFuture<'a> {
        let sink = self.sink.clone();
        let hostname = hostname.to_string();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || sink.resolve_host(&hostname, port))
                .await
                .map_err(|err| io::Error::other(format!("Android DNS task failed: {err}")))?
        })
    }
}

impl EventSink {
    fn resolve_host(&self, hostname: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        let resolved = self
            .inner
            .platform_services
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
}

fn run_native_session(
    raw_config: &str,
    tun_fd: i32,
    mtu: i32,
    cancel: CancellationToken,
    sink: &EventSink,
    handle: NativeHandle,
) {
    let startup_detail = format!("handle={handle} fd={tun_fd} android_mtu={mtu}");
    info!("[session start] handle={handle}");
    sink.event(NativeEventKind::Starting, Some(startup_detail));

    match run_native_client(raw_config, tun_fd, mtu, cancel, sink, handle) {
        Ok(stop_detail) => {
            info!("[session stop] handle={handle}");
            sink.event(NativeEventKind::Stopping, Some(stop_detail.clone()));
            sink.event(NativeEventKind::Stopped, Some(stop_detail));
        }
        Err(err) => {
            error!("Android client runtime failed: {err}");
            info!("[session stop reason=error] handle={handle}");
            sink.event(NativeEventKind::Error, Some(err));
        }
    }
}

fn run_native_client(
    raw_config: &str,
    tun_fd: i32,
    mtu: i32,
    cancel: CancellationToken,
    sink: &EventSink,
    handle: NativeHandle,
) -> Result<String, String> {
    let config = ClientConfig::from_toml_str(raw_config)
        .map_err(|err| format!("parse Android client config: {err}"))?;
    let android_mtu = validate_android_mtu(mtu, config.tun.tun_mtu)?;
    let summary = SessionSummary::new(handle, tun_fd, android_mtu, &config);

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .map_err(|err| format!("create Android client runtime: {err}"))?;

    let detail = summary.detail.clone();
    let stop_detail = summary.handle_detail();
    let result = runtime.block_on(async move {
        let (tun_handles, tun_channels) =
            crate::tun::spawn_from_fd(&config, tun_fd, cancel.clone())
                .map_err(|err| format!("start Android TUN backend: {err}"))?;
        info!("Android TUN backend started");
        sink.event(NativeEventKind::Ready, Some(detail));

        let socket_protector = Arc::new(AndroidSocketProtector::new(sink.clone()));
        let host_resolver = Arc::new(AndroidHostResolver::new(sink.clone()));
        crate::run_client(
            config,
            tun_handles,
            tun_channels,
            cancel,
            socket_protector,
            host_resolver,
        )
        .await
        .map_err(|err| format!("client runtime exited with error: {err}"))
    });
    runtime.shutdown_timeout(RUNTIME_SHUTDOWN_TIMEOUT);
    result?;

    Ok(stop_detail)
}

fn validate_android_mtu(mtu: i32, config_mtu: u16) -> Result<u16, String> {
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
    Ok(mtu)
}

struct SessionSummary {
    handle: NativeHandle,
    detail: String,
}

impl SessionSummary {
    fn new(handle: NativeHandle, tun_fd: i32, mtu: u16, config: &ClientConfig) -> Self {
        Self {
            handle,
            detail: format!(
                "handle={handle} fd={tun_fd} mtu={mtu} client_id={} assigned_ipv4={} server={}:{}",
                config.identity.client_id,
                config.identity.assigned_ipv4,
                config.network.hostname,
                config.network.port
            ),
        }
    }

    fn handle_detail(&self) -> String {
        format!("handle={}", self.handle)
    }
}
