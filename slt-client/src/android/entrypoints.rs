use std::ffi::c_void;

use jni::JNIEnv;
use jni::objects::{JClass, JObject, JString};
use jni::sys::{JNI_FALSE, JNI_TRUE, jboolean, jint, jlong};

use super::session::{NativeHandle, start_native_session, stop_native_session};

const JNI_VERSION_1_6: i32 = 0x0001_0006;

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
    if super::logging::init(&path) {
        JNI_TRUE
    } else {
        JNI_FALSE
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

    stop_native_session(handle);
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
