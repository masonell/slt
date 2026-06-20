//! Android native library entrypoints and JNI bridge.

use std::collections::HashMap;
use std::ffi::c_void;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread::{self, JoinHandle};

use jni::objects::{GlobalRef, JClass, JObject, JString, JValue};
use jni::sys::{jint, jlong};
use jni::{JNIEnv, JavaVM};
use slt_core::config::ClientConfig;
use tokio_util::sync::CancellationToken;

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

fn run_native_session(
    raw_config: &str,
    tun_fd: jint,
    mtu: jint,
    cancel: CancellationToken,
    sink: &EventSink,
    handle: NativeHandle,
) {
    let startup_detail = format!("handle={handle} fd={tun_fd} android_mtu={mtu}");
    sink.status("starting", Some(&startup_detail));

    match run_native_client(raw_config, tun_fd, mtu, cancel, sink, handle) {
        Ok(stop_detail) => {
            sink.status("stopping", Some(&stop_detail));
            sink.status("stopped", Some(&stop_detail));
        }
        Err(err) => {
            sink.log("error", &format!("Android client runtime failed: {err}"));
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
        sink.log("info", "Android TUN backend started");
        sink.status("ready", Some(&detail));

        crate::run_client(config, tun_handles, tun_channels, cancel)
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

    fn log(&self, level: &str, message: &str) {
        self.call(
            "onLog",
            "(Ljava/lang/String;Ljava/lang/String;)V",
            level,
            Some(message),
        );
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
