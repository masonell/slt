//! Android native library entrypoints and JNI bridge.

use std::collections::HashMap;
use std::ffi::c_void;
use std::io;
use std::os::fd::RawFd;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread::{self, JoinHandle};

use jni::objects::{GlobalRef, JClass, JObject, JString, JValue, JValueGen};
use jni::sys::{JNI_FALSE, JNI_TRUE, jboolean, jint, jlong, jstring};
use jni::{JNIEnv, JavaVM};
use slt_core::config::ClientConfig;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info};

use crate::transport::socket_protector::{SocketKind, SocketProtector};

const JNI_VERSION_1_6: i32 = 0x0001_0006;
type NativeHandle = u64;

static NEXT_HANDLE: AtomicU64 = AtomicU64::new(1);
static SESSIONS: OnceLock<Mutex<HashMap<NativeHandle, NativeSession>>> = OnceLock::new();

/// Android VM load hook for `libslt_client.so`.
///
/// This symbol makes the shared library loadable and gives Android a stable
/// place to initialize native state.
#[unsafe(no_mangle)]
pub const extern "C" fn JNI_OnLoad(_vm: *mut c_void, _reserved: *mut c_void) -> i32 {
    JNI_VERSION_1_6
}

/// Initialize the file-backed Rust log sink.
///
/// Kotlin passes a log file path once per process. Returns `true` when logging
/// is active after the call (this call succeeded or an earlier one did); `false`
/// on failure, in which case Kotlin may retry or `Log.e` the failure.
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_slt_android_SltNative_nativeInitLogSink(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    file_path: JString<'_>,
) -> jboolean {
    let path: String = match env.get_string(&file_path) {
        Ok(path) => path.into(),
        Err(_) => return JNI_FALSE,
    };
    if crate::android_logging::init(&path) {
        JNI_TRUE
    } else {
        JNI_FALSE
    }
}

/// Validate a client config and return a small non-secret JSON summary.
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_slt_android_SltNative_nativeValidateClientConfig(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    config_toml: JString<'_>,
) -> jstring {
    match validate_client_config(&mut env, &config_toml) {
        Ok(summary) => match env.new_string(summary) {
            Ok(summary) => summary.into_raw(),
            Err(err) => {
                throw_runtime_exception(&mut env, &format!("create config summary: {err}"));
                std::ptr::null_mut()
            }
        },
        Err(err) => {
            throw_runtime_exception(&mut env, &err);
            std::ptr::null_mut()
        }
    }
}

/// Start a native Android client bridge session.
///
/// The session starts the Rust client runtime on top of Android's `VpnService`
/// TUN file descriptor.
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_slt_android_SltNative_nativeStart(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    config_toml: JString<'_>,
    tun_fd: jint,
    mtu: jint,
    callback: JObject<'_>,
) -> jlong {
    match start_native_session(&mut env, &config_toml, tun_fd, mtu, callback) {
        Ok(handle) => handle_to_jlong(handle),
        Err(err) => {
            throw_runtime_exception(&mut env, &err);
            0
        }
    }
}

/// Stop a native Android client bridge session.
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_slt_android_SltNative_nativeStop(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
) {
    let Some(handle) = jlong_to_handle(handle) else {
        throw_runtime_exception(&mut env, "invalid native handle");
        return;
    };

    if let Some(session) = remove_session(handle) {
        session.stop();
    }
}

fn start_native_session(
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

fn validate_client_config(
    env: &mut JNIEnv<'_>,
    config_toml: &JString<'_>,
) -> Result<String, String> {
    let raw_config: String = env
        .get_string(config_toml)
        .map_err(|err| format!("read config TOML from JNI: {err}"))?
        .into();
    let config = ClientConfig::from_toml_str(&raw_config)
        .map_err(|err| format!("validate client config: {err}"))?;
    Ok(client_config_summary_json(&config))
}

fn client_config_summary_json(config: &ClientConfig) -> String {
    format!(
        r#"{{"assignedIpv4":"{}","tunMtu":{},"serverHost":"{}","serverPort":{},"clientId":"{}"}}"#,
        json_escape(&config.identity.assigned_ipv4.to_string()),
        config.tun.tun_mtu,
        json_escape(&config.network.hostname),
        config.network.port,
        json_escape(&config.identity.client_id.to_string()),
    )
}

fn json_escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
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
    runtime.block_on(async move {
        let (tun_handles, tun_channels) =
            crate::tun::spawn_from_fd(&config, tun_fd, cancel.clone())
                .map_err(|err| format!("start Android TUN backend: {err}"))?;
        info!("Android TUN backend started");
        sink.status("ready", Some(&detail));

        let socket_protector = Arc::new(AndroidSocketProtector { sink: sink.clone() });
        crate::run_client(config, tun_handles, tun_channels, cancel, socket_protector)
            .await
            .map_err(|err| format!("client runtime exited with error: {err}"))
    })?;

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

struct EventSink {
    inner: Arc<EventSinkInner>,
}

struct EventSinkInner {
    vm: JavaVM,
    callback: GlobalRef,
}

struct AndroidSocketProtector {
    sink: EventSink,
}

impl SocketProtector for AndroidSocketProtector {
    fn protect(&self, fd: RawFd, kind: SocketKind) -> io::Result<()> {
        self.sink.protect_socket(fd, kind)
    }
}

impl EventSink {
    fn new(vm: JavaVM, callback: GlobalRef) -> Self {
        Self {
            inner: Arc::new(EventSinkInner { vm, callback }),
        }
    }
}

impl Clone for EventSink {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl EventSink {
    fn status(&self, status: &str, detail: Option<&str>) {
        self.call(
            "onStatus",
            "(Ljava/lang/String;Ljava/lang/String;)V",
            status,
            detail,
        );
    }

    fn protect_socket(&self, fd: RawFd, kind: SocketKind) -> io::Result<()> {
        let mut env = self.inner.vm.attach_current_thread().map_err(|err| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("attach JNI thread for socket protection: {err}"),
            )
        })?;
        let fd = jint::try_from(fd).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("socket fd out of JNI int range: {fd}"),
            )
        })?;

        let protected = env
            .call_method(
                self.inner.callback.as_obj(),
                "protectSocket",
                "(I)Z",
                &[JValue::Int(fd)],
            )
            .and_then(JValueGen::z)
            .map_err(|err| {
                io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!("call Android protectSocket for {kind:?} fd {fd}: {err}"),
                )
            })?;

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

    fn call(&self, method: &str, signature: &str, first: &str, second: Option<&str>) {
        let Ok(mut env) = self.inner.vm.attach_current_thread() else {
            return;
        };
        let Ok(first) = env.new_string(first) else {
            return;
        };
        let second = match second {
            Some(second) => {
                let Ok(second) = env.new_string(second) else {
                    return;
                };
                JObject::from(second)
            }
            None => JObject::null(),
        };

        let first = JObject::from(first);
        let args = [JValue::Object(&first), JValue::Object(&second)];
        let _ = env.call_method(self.inner.callback.as_obj(), method, signature, &args);
    }
}

fn handle_to_jlong(handle: NativeHandle) -> jlong {
    i64::try_from(handle).unwrap_or(i64::MAX)
}

fn jlong_to_handle(handle: jlong) -> Option<NativeHandle> {
    u64::try_from(handle).ok().filter(|handle| *handle != 0)
}

fn throw_runtime_exception(env: &mut JNIEnv<'_>, message: &str) {
    let _ = env.throw_new("java/lang/RuntimeException", message);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jlong_to_handle_rejects_non_positive_values() {
        assert_eq!(jlong_to_handle(0), None);
        assert_eq!(jlong_to_handle(-1), None);
    }

    #[test]
    fn jlong_to_handle_accepts_positive_values() {
        assert_eq!(jlong_to_handle(7), Some(7));
    }
}
