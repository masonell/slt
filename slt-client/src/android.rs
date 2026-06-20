//! Android native library entrypoints.

use std::ffi::c_void;

const JNI_VERSION_1_6: i32 = 0x0001_0006;

/// Android VM load hook for `libslt_client.so`.
///
/// The bridge API is intentionally added later; this symbol makes the shared
/// library loadable and gives Android a stable place to initialize native state.
#[unsafe(no_mangle)]
pub extern "C" fn JNI_OnLoad(_vm: *mut c_void, _reserved: *mut c_void) -> i32 {
    JNI_VERSION_1_6
}
