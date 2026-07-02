package dev.slt.android.vpn

import android.os.Handler
import android.util.Log
import dev.slt.android.SltNative
import dev.slt.android.uniffi.ClientEvent
import dev.slt.android.uniffi.ClientEventKind
import dev.slt.android.uniffi.NativeSession
import dev.slt.android.uniffi.NativeSessionCallback
import dev.slt.android.uniffi.PlatformServices

internal data class NativeSessionConfig(
    val clientToml: String,
    val tunFd: Int,
    val tunMtu: Int,
)

internal class NativeSessionSupervisor(
    private val mainHandler: Handler,
    private val platformServices: () -> PlatformServices,
    private val callbacks: Callbacks,
    private val logTag: String,
) {
    @Volatile private var nativeSession: NativeSession? = null
    @Volatile private var nativeHandle: Long = 0

    private var restartConfig: NativeSessionConfig? = null
    private var nativeRestartAttempt = 0
    // Once this Start request has authenticated, later native terminal errors
    // should keep the VPN route installed and retry at the Android boundary.
    private var authenticatedSinceStart = false
    private val nativeRestartRunnable = Runnable { restartNativeSessionAfterTerminalError() }

    val handle: Long
        get() = nativeHandle

    val hasSession: Boolean
        get() = nativeSession != null

    fun start(config: NativeSessionConfig): NativeSession {
        cancelRestart()
        authenticatedSinceStart = false
        restartConfig = config
        return startSession(config)
    }

    fun stop() {
        cancelRestart()
        authenticatedSinceStart = false
        restartConfig = null
        stopNativeClient()
    }

    fun notifyNetworkChanged() {
        val session = nativeSession ?: return
        Log.i(logTag, "Underlying network changed; notifying native runtime")
        SltNative.networkChanged(session)
    }

    private fun stopNativeClient() {
        val session = nativeSession
        val handle = nativeHandle
        nativeSession = null
        nativeHandle = 0L
        if (session == null) {
            return
        }

        try {
            SltNative.stop(session)
            Log.i(logTag, "SLT native client stopped: handle=$handle")
        } catch (error: RuntimeException) {
            Log.w(logTag, "Failed to stop SLT native client: handle=$handle", error)
        }
    }

    private fun cancelRestart() {
        mainHandler.removeCallbacks(nativeRestartRunnable)
        nativeRestartAttempt = 0
    }

    private fun startSession(config: NativeSessionConfig): NativeSession {
        val session = SltNative.start(
            config.clientToml,
            config.tunFd,
            config.tunMtu,
            platformServices(),
            buildNativeCallback(),
        )
        nativeSession = session
        nativeHandle = session.handle()
        return session
    }

    private fun buildNativeCallback(): NativeSessionCallback =
        object : NativeSessionCallback {
            override fun onEvent(event: ClientEvent) {
                mainHandler.post {
                    // The event `handle` is the sole identity source: stale
                    // callbacks from a previous session carry a different handle
                    // (Rust assigns globally unique handles from a monotonic
                    // counter), so a mismatch safely rejects them. The current
                    // session's own events always see the correct handle because
                    // `nativeHandle` is assigned on this main thread right after
                    // `start_session` returns, and `mainHandler.post` defers
                    // every callback until the current main-thread work (such as
                    // `startVpn`) finishes, so the assignment always wins the
                    // race. After a stop, `nativeHandle` is 0 and all events are
                    // rejected (status is already terminal).
                    if (event.handle.toLong() != nativeHandle) {
                        return@post
                    }
                    handleNativeEvent(event)
                }
            }
        }

    private fun handleNativeEvent(event: ClientEvent) {
        when (val terminal = SltVpnStatusBus.applyEvent(event)) {
            NativeTerminal.None -> callbacks.onNotificationRefresh()
            NativeTerminal.Stopped -> {
                Log.i(logTag, "Native client stopped: handle=${event.handle}")
                callbacks.onStopped(event.handle)
            }
            is NativeTerminal.Errored -> {
                if (shouldRestartAfterTerminalError(terminal)) {
                    Log.w(
                        logTag,
                        "Native client terminal error will restart: " +
                            "retryable=${terminal.retryable} authenticatedSinceStart=$authenticatedSinceStart",
                    )
                    scheduleNativeRestartAfterError(event)
                } else {
                    Log.e(logTag, "Native client reported a non-retryable terminal error; stopping")
                    callbacks.onFatalError((event.kind as? ClientEventKind.Error)?.detail ?: "Native client error")
                }
            }
        }

        if (event.kind is ClientEventKind.Authenticated) {
            authenticatedSinceStart = true
            nativeRestartAttempt = 0
        }
    }

    private fun shouldRestartAfterTerminalError(terminal: NativeTerminal.Errored): Boolean =
        shouldRestartTerminalNativeError(
            retryable = terminal.retryable,
            authenticatedSinceStart = authenticatedSinceStart,
        )

    private fun scheduleNativeRestartAfterError(event: ClientEvent) {
        val detail = (event.kind as? ClientEventKind.Error)?.detail ?: "Native client error"
        stopNativeClient()

        if (restartConfig == null) {
            callbacks.onFatalError("VPN tunnel unavailable after native error: $detail")
            return
        }

        nativeRestartAttempt += 1
        val delayMs = nativeRestartDelayMs(nativeRestartAttempt)
        callbacks.onRetryScheduled(detail, nativeRestartAttempt, delayMs)
        mainHandler.removeCallbacks(nativeRestartRunnable)
        mainHandler.postDelayed(nativeRestartRunnable, delayMs)
    }

    private fun restartNativeSessionAfterTerminalError() {
        val config = restartConfig
        if (nativeSession != null) {
            return
        }
        if (config == null) {
            callbacks.onFatalError("VPN tunnel unavailable before native restart")
            return
        }

        try {
            startSession(config)
            Log.i(logTag, "Restarted SLT native client: handle=$nativeHandle attempt=$nativeRestartAttempt")
            callbacks.onNotificationRefresh()
        } catch (error: Exception) {
            callbacks.onFatalError(error.message ?: error::class.java.simpleName)
        }
    }

    private fun nativeRestartDelayMs(attempt: Int): Long {
        val shift = (attempt - 1).coerceIn(0, MAX_NATIVE_RESTART_SHIFT)
        val delay = INITIAL_NATIVE_RESTART_DELAY_MS * (1L shl shift)
        return delay.coerceAtMost(MAX_NATIVE_RESTART_DELAY_MS)
    }

    internal interface Callbacks {
        fun onStopped(handle: ULong)

        fun onFatalError(detail: String)

        fun onRetryScheduled(detail: String, attempt: Int, delayMs: Long)

        fun onNotificationRefresh()
    }

    companion object {
        private const val INITIAL_NATIVE_RESTART_DELAY_MS = 1_000L
        private const val MAX_NATIVE_RESTART_DELAY_MS = 60_000L
        private const val MAX_NATIVE_RESTART_SHIFT = 6
    }
}

internal fun shouldRestartTerminalNativeError(
    retryable: Boolean,
    authenticatedSinceStart: Boolean,
): Boolean = retryable || authenticatedSinceStart
