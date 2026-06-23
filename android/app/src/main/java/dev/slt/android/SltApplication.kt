package dev.slt.android

import android.app.Application
import android.util.Log
import dev.slt.android.log.LogStore

/**
 * Application entry point. Initializes the Rust file-backed log sink once per
 * process (Application.onCreate runs exactly once per process) and trims old log
 * files so only the active file plus a few recent ones are kept.
 */
class SltApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        val logStore = LogStore(this)
        val path = logStore.newFilePath()
        if (!SltNative.initLogSink(path)) {
            // The only Logcat use: surface an init failure (the old per-message
            // Rust -> Logcat path is gone; Rust logs go to the file).
            Log.e(TAG, "Failed to initialize Rust log sink at $path")
        }
        logStore.sweep()
    }

    private companion object {
        const val TAG = "SltApplication"
    }
}
