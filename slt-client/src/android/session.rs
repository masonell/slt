use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use jni::JNIEnv;
use jni::objects::{JObject, JString};
use jni::sys::jint;
use slt_core::config::ClientConfig;
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

use super::event_sink::{AndroidHostResolver, AndroidSocketProtector, EventSink};

const RUNTIME_SHUTDOWN_TIMEOUT: Duration = Duration::from_millis(250);

pub(super) type NativeHandle = u64;

static NEXT_HANDLE: AtomicU64 = AtomicU64::new(1);
static SESSIONS: OnceLock<Mutex<HashMap<NativeHandle, NativeSession>>> = OnceLock::new();

pub(super) fn start_native_session(
    env: &mut JNIEnv<'_>,
    config_toml: &JString<'_>,
    tun_fd: jint,
    mtu: jint,
    callback: JObject<'_>,
) -> Result<NativeHandle, String> {
    if tun_fd < 0 {
        return Err(format!("invalid Android TUN fd: {tun_fd}"));
    }

    let raw_config: String = env
        .get_string(config_toml)
        .map_err(|err| format!("read config TOML from JNI: {err}"))?
        .into();
    let callback = env
        .new_global_ref(callback)
        .map_err(|err| format!("create native callback reference: {err}"))?;
    let vm = env
        .get_java_vm()
        .map_err(|err| format!("get Java VM: {err}"))?;

    let handle = NEXT_HANDLE.fetch_add(1, Ordering::Relaxed);
    if handle == 0 {
        return Err("native handle counter wrapped".to_string());
    }

    let sink = EventSink::new(vm, callback);
    let cancel = CancellationToken::new();
    let worker_cancel = cancel.clone();
    let worker_sink = sink;
    let worker = thread::Builder::new()
        .name(format!("slt-android-{handle}"))
        .spawn(move || {
            run_native_session(
                &raw_config,
                tun_fd,
                mtu,
                worker_cancel,
                &worker_sink,
                handle,
            );
        })
        .map_err(|err| format!("spawn native client thread: {err}"))?;

    let session = NativeSession { cancel, worker };
    register_session(handle, session)?;
    Ok(handle)
}

pub(super) fn stop_native_session(handle: NativeHandle) {
    if let Some(session) = remove_session(handle) {
        session.stop();
    }
}

fn run_native_session(
    raw_config: &str,
    tun_fd: jint,
    mtu: jint,
    cancel: CancellationToken,
    sink: &EventSink,
    handle: NativeHandle,
) {
    let startup_detail = format!("handle={handle} fd={tun_fd} android_mtu={mtu}");
    info!("[session start] handle={handle}");
    sink.status("starting", Some(&startup_detail));

    match run_native_client(raw_config, tun_fd, mtu, cancel, sink, handle) {
        Ok(stop_detail) => {
            info!("[session stop] handle={handle}");
            sink.status("stopping", Some(&stop_detail));
            sink.status("stopped", Some(&stop_detail));
        }
        Err(err) => {
            error!("Android client runtime failed: {err}");
            info!("[session stop reason=error] handle={handle}");
            sink.status("error", Some(&err));
        }
    }
}

fn run_native_client(
    raw_config: &str,
    tun_fd: jint,
    mtu: jint,
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
        sink.status("ready", Some(&detail));

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

fn validate_android_mtu(mtu: jint, config_mtu: u16) -> Result<u16, String> {
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

fn sessions() -> &'static Mutex<HashMap<NativeHandle, NativeSession>> {
    SESSIONS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn register_session(handle: NativeHandle, session: NativeSession) -> Result<(), String> {
    let Ok(mut sessions) = sessions().lock() else {
        session.stop();
        return Err("native session registry poisoned".to_string());
    };
    if sessions.contains_key(&handle) {
        session.stop();
        return Err(format!("duplicate native handle: {handle}"));
    }
    sessions.insert(handle, session);
    drop(sessions);
    Ok(())
}

fn remove_session(handle: NativeHandle) -> Option<NativeSession> {
    sessions().lock().ok()?.remove(&handle)
}

struct NativeSession {
    cancel: CancellationToken,
    worker: JoinHandle<()>,
}

impl NativeSession {
    fn stop(self) {
        self.cancel.cancel();
        let _ = self.worker.join();
    }
}

struct SessionSummary {
    handle: NativeHandle,
    detail: String,
}

impl SessionSummary {
    fn new(handle: NativeHandle, tun_fd: jint, mtu: u16, config: &ClientConfig) -> Self {
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
