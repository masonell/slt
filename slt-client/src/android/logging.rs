//! Process-lifetime file-backed tracing subscriber for the Android build.
//!
//! Android has no tracing subscriber on the `cdylib` path, so every `tracing!`
//! call is a silent no-op until [`init`] is called. [`init`] installs a
//! `tracing_appender::non_blocking` writer that appends formatted lines to a
//! file path supplied by Kotlin (`<filesDir>/logs/slt-<ts>-<pid>.log`). The
//! resulting `WorkerGuard` is held in a process-lifetime slot so the background
//! writer thread keeps draining for the whole process.
//!
//! First successful init wins; later calls are no-ops. A failed init leaves the
//! slot empty so the next call may retry (a transient failure such as a missing
//! parent directory is recoverable). This is why the slot is a
//! `Mutex<Option<…>>` rather than a `OnceLock`: `OnceLock::get_or_try_init` is
//! nightly-only, and an infallible `OnceLock` cannot express retriable failure.

use std::fs::OpenOptions;
use std::sync::{Mutex, OnceLock};

use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::filter::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;

/// Process-lifetime slot holding the writer-thread guard once init succeeds.
///
/// Only the presence matters, not the value: nothing reads the guard back. It
/// lives here purely so it is not dropped (dropping it stops the writer thread).
static LOGGING: OnceLock<Mutex<Option<WorkerGuard>>> = OnceLock::new();

fn logging() -> &'static Mutex<Option<WorkerGuard>> {
    LOGGING.get_or_init(|| Mutex::new(None))
}

/// Initialize the file-backed tracing subscriber once per process.
///
/// Returns `true` when logging is active after the call (this call just
/// succeeded, or an earlier call already succeeded). Returns `false` on failure;
/// because the slot stays empty, the caller may retry.
pub fn init(path: &str) -> bool {
    let Ok(mut slot) = logging().lock() else {
        // Poisoned only if a holder panicked while locked; try_init never panics.
        return false;
    };
    if slot.is_some() {
        return true;
    }
    try_init(path).is_ok_and(|guard| {
        *slot = Some(guard);
        true
    })
}

/// Build and install the subscriber. On failure the `WorkerGuard` is dropped,
/// stopping the writer thread so it cannot keep writing to an unrouted file.
fn try_init(path: &str) -> Result<WorkerGuard, String> {
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|err| format!("open Android log file {path}: {err}"))?;

    let (writer, guard) = tracing_appender::non_blocking(file);
    let filter = EnvFilter::new(DEFAULT_FILTER);
    let subscriber = tracing_subscriber::registry().with(filter).with(
        tracing_subscriber::fmt::layer()
            .with_ansi(false)
            .with_writer(writer),
    );
    tracing::subscriber::set_global_default(subscriber)
        .map_err(|_| "a global tracing subscriber is already installed".to_string())?;
    Ok(guard)
}

/// Default filter: the slt crates at `info`, everything else at `warn`.
const DEFAULT_FILTER: &str = "slt_client=info,slt_core=info,warn";
