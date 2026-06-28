package dev.slt.android.vpn

import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.Network
import android.net.VpnService
import android.os.Handler
import android.os.ParcelFileDescriptor
import android.os.Looper
import android.util.Log
import dev.slt.android.ConfigValidationResult
import dev.slt.android.SltNative
import dev.slt.android.profile.SltProfile
import dev.slt.android.profile.store.ProfileRepository
import dev.slt.android.uniffi.ClientConfigSummary
import dev.slt.android.uniffi.ClientEvent
import dev.slt.android.uniffi.NativeSession
import dev.slt.android.uniffi.NativeSessionCallback
import dev.slt.android.uniffi.PlatformServices
import dev.slt.android.uniffi.SltInteropException
import dev.slt.android.uniffi.SocketKind
import kotlinx.coroutines.runBlocking

class SltVpnService : VpnService() {
    @Volatile private var tunFd: ParcelFileDescriptor? = null
    @Volatile private var nativeSession: NativeSession? = null
    @Volatile private var nativeHandle: Long = 0
    @Volatile private var activeUnderlyingNetwork: Network? = null
    private var terminalStatusReported = false
    private var tornDown = false

    private val stateLock = Any()
    private val mainHandler by lazy { Handler(Looper.getMainLooper()) }
    private val profileApplier by lazy { VpnProfileApplier(this, TAG) }
    private val notificationFactory by lazy { VpnNotificationFactory(this) }
    private var networkWatcher: NetworkChangeWatcher? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                stopVpn("Stopped")
                stopSelf()
            }

            else -> startVpn()
        }

        return START_NOT_STICKY
    }

    override fun onRevoke() {
        stopVpn("Permission revoked")
        stopSelf()
        super.onRevoke()
    }

    override fun onDestroy() {
        if (terminalStatusReported) {
            teardown()
        } else {
            stopVpn("Service destroyed")
        }
        super.onDestroy()
    }

    private fun startVpn() {
        terminalStatusReported = false
        notificationFactory.ensureChannel()

        if (tunFd != null) {
            // Tunnel is already established; refresh the foreground notification
            // and stay in the current (possibly Reconnecting/Starting) status.
            val status = SltVpnStatusBus.state.value.status
            if (status != VpnStatus.Reconnecting && status != VpnStatus.Starting) {
                SltVpnStatusBus.markRunningForeground()
            }
            updateNotification()
            return
        }

        try {
            SltVpnStatusBus.markStarting()
            startForeground(
                VpnNotificationFactory.NOTIFICATION_ID,
                notificationFactory.build(notificationText(VpnStatus.Starting)),
            )
            SltNative.load()
            val profile = loadActiveProfile()
            val summary = validateProfile(profile)
            val initialUnderlyingNetwork =
                getSystemService(ConnectivityManager::class.java)?.activeNetwork
            activeUnderlyingNetwork = initialUnderlyingNetwork

            val builder = Builder()
                .setSession(profile.metadata.name)
                .setMtu(summary.tunMtu)
                .addAddress(summary.assignedIpv4, CLIENT_ADDRESS_PREFIX)
            profileApplier.apply(builder, profile)

            val fd = builder.establish()

            if (fd == null) {
                failVpn("Android did not return a TUN fd")
                return
            }

            tunFd = fd
            val session = startNativeSession(profile.clientToml, fd.fd, summary.tunMtu)
            nativeSession = session
            nativeHandle = session.handle()
            Log.i(
                TAG,
                "SLT VPN tunnel established; awaiting native auth: " +
                    "profile=${profile.metadata.name} fd=${fd.fd} " +
                    "${summary.assignedIpv4}/$CLIENT_ADDRESS_PREFIX native=$nativeHandle",
            )
            // Stay Starting until the runtime emits Authenticated (-> Running).
            updateNotification()

            startNetworkWatcher(initialUnderlyingNetwork)
        } catch (error: Exception) {
            failVpn(error.message ?: error::class.java.simpleName)
        }
    }

    private fun startNetworkWatcher(initialNetwork: Network?) {
        networkWatcher = NetworkChangeWatcher(
            this,
            initialNetwork,
            ::publishUnderlyingNetwork,
        ) { network -> notifyNetworkChanged(network) }
        networkWatcher?.start()
    }

    private fun publishUnderlyingNetwork(network: Network?) {
        synchronized(stateLock) {
            if (tunFd == null && nativeSession == null) {
                return
            }
            activeUnderlyingNetwork = network
        }
    }

    private fun loadActiveProfile(): SltProfile =
        runBlocking {
            ProfileRepository(applicationContext).loadState().activeProfile
        } ?: error("No active profile")

    private fun validateProfile(profile: SltProfile): ClientConfigSummary {
        return when (val result = SltNative.validateClientConfig(profile.clientToml)) {
            is ConfigValidationResult.Valid -> result.summary
            is ConfigValidationResult.Invalid -> error(result.message)
        }
    }

    private fun stopVpn(detail: String) {
        SltVpnStatusBus.markStopped(detail)
        teardown()
        terminalStatusReported = true
    }

    /// Tear down all platform resources without touching UI state. Idempotent:
    /// the terminal-event path, `stopVpn`, and `onDestroy` can all drive a tear
    /// down, so the first call does the work and later calls are no-ops (rather
    /// than relying on every sub-helper being null-safe). The store
    /// ([SltVpnStatusBus]) owns status; this owns the VPN/TUN/native lifecycle.
    private fun teardown() {
        if (tornDown) {
            return
        }
        tornDown = true
        networkWatcher?.stop()
        networkWatcher = null
        activeUnderlyingNetwork = null
        stopNativeClient()
        closeTunFd()
        stopForegroundCompat()
    }

    /// Platform-initiated failure: record the terminal error, tear down, and stop.
    private fun failVpn(message: String) {
        Log.e(TAG, "SLT VPN failed: $message")
        SltVpnStatusBus.markError(message)
        teardownAndStopSelf()
    }

    /// Tear down platform resources and stop the service once a terminal status
    /// has been recorded (by the store via `applyEvent`, or by `failVpn`/`stopVpn`).
    private fun teardownAndStopSelf() {
        teardown()
        terminalStatusReported = true
        stopSelf()
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
            Log.i(TAG, "SLT native client stopped: handle=$handle")
        } catch (error: RuntimeException) {
            Log.w(TAG, "Failed to stop SLT native client: handle=$handle", error)
        }
    }

    /// Start a fresh native client session. Rust owns the session handle/seq
    /// identity; stale callbacks are rejected by `handle` in `buildNativeCallback`.
    private fun startNativeSession(configToml: String, tunFd: Int, mtu: Int): NativeSession {
        val platformServices = buildPlatformServices()
        return SltNative.start(configToml, tunFd, mtu, platformServices, buildNativeCallback())
    }

    /// Notify Rust that the underlying network changed. Rust owns reconnect and
    /// path recovery policy; Kotlin only maintains Android platform state.
    private fun notifyNetworkChanged(network: Network?) {
        val session = synchronized(stateLock) {
            val current = nativeSession ?: return
            if (tunFd == null) {
                return
            }
            activeUnderlyingNetwork = network
            current
        }
        Log.i(TAG, "Underlying network changed; notifying native runtime")
        SltNative.networkChanged(session)
    }

    private fun buildPlatformServices(): PlatformServices =
        object : PlatformServices {
            override fun protectSocket(fd: Int, kind: SocketKind): Boolean =
                try {
                    protectAndBindSocket(fd, kind)
                } catch (error: RuntimeException) {
                    Log.w(TAG, "Failed to protect SLT socket: fd=$fd kind=$kind", error)
                    false
                } catch (error: Exception) {
                    Log.w(TAG, "Failed to bind SLT socket: fd=$fd kind=$kind", error)
                    false
                }

            override fun resolveHost(hostname: String): List<String> {
                val network = activeUnderlyingNetwork
                    ?: throw SltInteropException.Platform("No underlying network available for DNS")
                return try {
                    val addresses = network.getAllByName(hostname)
                        .mapNotNull { it.hostAddress }
                    if (addresses.isEmpty()) {
                        throw SltInteropException.Platform("No addresses returned for $hostname")
                    }
                    addresses
                } catch (error: Exception) {
                    Log.w(TAG, "Failed to resolve $hostname on underlying network", error)
                    throw SltInteropException.Platform(
                        "Failed to resolve $hostname on underlying network: ${error.message}",
                    )
                }
            }
        }

    private fun protectAndBindSocket(fd: Int, kind: SocketKind): Boolean {
        val protected = protect(fd)
        if (!protected) {
            Log.w(TAG, "Android refused to protect SLT socket: fd=$fd kind=$kind")
            return false
        }

        val network = activeUnderlyingNetwork
        if (network == null) {
            Log.w(TAG, "No underlying network available for SLT socket binding: fd=$fd kind=$kind")
            return false
        }

        ParcelFileDescriptor.fromFd(fd).use { dup ->
            network.bindSocket(dup.fileDescriptor)
        }
        return true
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
                    // `startVpn`) finishes — so the assignment always wins the
                    // race. After a stop, `nativeHandle` is 0 and all events are
                    // rejected (status is already terminal).
                    if (event.handle.toLong() != nativeHandle) {
                        return@post
                    }
                    handleNativeEvent(event)
                }
            }
        }

    /// Reduce a typed native event to UI state (owned by [SltVpnStatusBus]) and
    /// perform platform teardown for terminal events. Non-terminal events only
    /// refine the status/phase/transport shown to the user.
    private fun handleNativeEvent(event: ClientEvent) {
        when (SltVpnStatusBus.applyEvent(event)) {
            NativeTerminal.None -> updateNotification()
            NativeTerminal.Stopped -> {
                Log.i(TAG, "Native client stopped: handle=${event.handle}")
                teardownAndStopSelf()
            }
            NativeTerminal.Errored -> {
                Log.e(TAG, "Native client reported a terminal error; stopping")
                teardownAndStopSelf()
            }
        }
    }

    private fun closeTunFd() {
        val fd = tunFd ?: return
        tunFd = null

        try {
            fd.close()
            Log.i(TAG, "SLT VPN fd closed")
        } catch (error: RuntimeException) {
            Log.w(TAG, "Failed to close SLT VPN fd", error)
        }
    }

    /// Refresh the foreground notification from the current status. Notification
    /// text is derived from typed [VpnStatus] rather than scattered literals.
    private fun updateNotification() {
        notificationFactory.update(notificationText(SltVpnStatusBus.state.value.status))
    }

    /// Terse notification wording. Deliberately shorter than the in-app
    /// `StatusLine.statusLabel` (e.g. "Starting" vs "Connecting…"); the
    /// foreground notification is a platform surface, so its text is derived
    /// here rather than in the UI layer.
    private fun notificationText(status: VpnStatus): String =
        when (status) {
            VpnStatus.Idle -> "Idle"
            VpnStatus.PermissionRequired -> "Permission required"
            VpnStatus.Starting -> "Starting"
            VpnStatus.Running -> "Running"
            VpnStatus.Reconnecting -> "Reconnecting"
            VpnStatus.Stopped -> "Stopped"
            VpnStatus.Error -> "Error"
        }

    private fun stopForegroundCompat() {
        stopForeground(STOP_FOREGROUND_REMOVE)
    }

    companion object {
        const val ACTION_START = "dev.slt.android.action.START"
        const val ACTION_STOP = "dev.slt.android.action.STOP"

        private const val TAG = "SltVpnService"
        private const val CLIENT_ADDRESS_PREFIX = 32

        fun startIntent(context: Context): Intent =
            Intent(context, SltVpnService::class.java).setAction(ACTION_START)

        fun stopIntent(context: Context): Intent =
            Intent(context, SltVpnService::class.java).setAction(ACTION_STOP)
    }
}
