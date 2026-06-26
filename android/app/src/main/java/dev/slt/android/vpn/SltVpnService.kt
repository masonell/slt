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
import dev.slt.android.SltNative
import dev.slt.android.profile.SltProfile
import dev.slt.android.profile.store.ProfileRepository
import dev.slt.android.uniffi.ClientConfigSummary
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlin.coroutines.coroutineContext

class SltVpnService : VpnService() {
    @Volatile private var tunFd: ParcelFileDescriptor? = null
    @Volatile private var nativeHandle: Long = 0
    @Volatile private var sessionGeneration: Int = 0
    @Volatile private var reconnecting: Boolean = false
    @Volatile private var reconnectAttempt: Int = 0
    @Volatile private var activeUnderlyingNetwork: Network? = null
    private var terminalStatusReported = false
    private var activeProfileToml: String? = null
    private var activeTunMtu: Int = 0

    private val stateLock = Any()
    private val mainHandler by lazy { Handler(Looper.getMainLooper()) }
    private val profileApplier by lazy { VpnProfileApplier(this, TAG) }
    private val notificationFactory by lazy { VpnNotificationFactory(this) }
    private var reconnectScope = newReconnectScope()
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
            cleanupVpn()
        } else {
            stopVpn("Service destroyed")
        }
        super.onDestroy()
    }

    private fun startVpn() {
        terminalStatusReported = false
        SltVpnStatusBus.update(VpnStatus.Starting)
        notificationFactory.ensureChannel()
        startForeground(VpnNotificationFactory.NOTIFICATION_ID, notificationFactory.build("Starting"))

        if (tunFd != null) {
            if (reconnecting) {
                SltVpnStatusBus.update(VpnStatus.Reconnecting, "Network changed")
                updateNotification("Reconnecting")
            } else {
                SltVpnStatusBus.update(VpnStatus.Running, "fd=${tunFd?.fd} native=$nativeHandle")
                updateNotification("Running")
            }
            return
        }

        try {
            reconnectScope = newReconnectScope()
            SltNative.load()
            val profile = loadActiveProfile()
            val summary = validateProfile(profile)
            val initialUnderlyingNetwork =
                getSystemService(ConnectivityManager::class.java)?.activeNetwork
            activeUnderlyingNetwork = initialUnderlyingNetwork

            activeProfileToml = profile.clientToml
            activeTunMtu = summary.tunMtu

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
            nativeHandle = startNativeSession(profile.clientToml, fd.fd, summary.tunMtu)
            val detail = "profile=${profile.metadata.name} fd=${fd.fd} ${summary.assignedIpv4}/$CLIENT_ADDRESS_PREFIX"
            Log.i(TAG, "SLT VPN established: $detail")
            SltVpnStatusBus.update(VpnStatus.Running, "$detail native=$nativeHandle")
            updateNotification("Running")

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
        ) { network -> reconnect(network) }
        networkWatcher?.start()
    }

    private fun publishUnderlyingNetwork(network: Network?) {
        synchronized(stateLock) {
            if (tunFd == null && nativeHandle == 0L && !reconnecting) {
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
        val result = SltNative.validateClientConfig(profile.clientToml)
        return result.summary ?: error(result.error ?: "Invalid active profile config")
    }

    private fun stopVpn(detail: String) {
        cleanupVpn()
        terminalStatusReported = true
        SltVpnStatusBus.update(VpnStatus.Stopped, detail)
    }

    private fun cleanupVpn() {
        networkWatcher?.stop()
        networkWatcher = null
        activeUnderlyingNetwork = null
        reconnectScope.cancel()
        synchronized(stateLock) { reconnecting = false }
        stopNativeClient()
        closeTunFd()
        stopForegroundCompat()
    }

    private fun newReconnectScope(): CoroutineScope =
        CoroutineScope(SupervisorJob() + Dispatchers.IO.limitedParallelism(1))

    private fun failVpn(message: String) {
        Log.e(TAG, "SLT VPN failed: $message")
        cleanupVpn()
        terminalStatusReported = true
        SltVpnStatusBus.update(VpnStatus.Error, message)
        stopSelf()
    }

    private fun stopNativeClient() {
        val handle = nativeHandle
        nativeHandle = 0
        if (handle == 0L) {
            return
        }

        try {
            SltNative.stop(handle)
            Log.i(TAG, "SLT native client stopped: handle=$handle")
        } catch (error: RuntimeException) {
            Log.w(TAG, "Failed to stop SLT native client: handle=$handle", error)
        }
    }

    /// Start a fresh native client session, bumping the generation so stale
    /// callbacks from any previous session are ignored by the callback guard.
    /// Used for both the initial connect and reconnects. Returns the new handle.
    private fun startNativeSession(configToml: String, tunFd: Int, mtu: Int): Long {
        sessionGeneration += 1
        val gen = sessionGeneration
        return SltNative.start(configToml, tunFd, mtu, buildNativeCallback(gen))
    }

    /// Reconnect over the existing TUN fd after the underlying network changed.
    /// Guards run on the main thread; the blocking stop/start runs on the
    /// reconnect scope. The TUN interface, routes, and app rules are left intact.
    private fun reconnect(network: Network?) {
        synchronized(stateLock) {
            if (tunFd == null || (nativeHandle == 0L && !reconnecting)) {
                return
            }
            activeUnderlyingNetwork = network
            if (reconnecting) {
                return
            }
            if (SltVpnStatusBus.state.value.status != VpnStatus.Running) {
                return
            }
            reconnecting = true
        }

        Log.i(TAG, "Underlying network changed; reconnecting")
        SltVpnStatusBus.update(VpnStatus.Reconnecting, "Network changed")
        updateNotification("Reconnecting")
        startReconnectAttempt(RECONNECT_FIRST_ATTEMPT)
    }

    /// Launch a reconnect attempt on the background scope, recording its number so
    /// an asynchronous native "error" attributes the failure to the right attempt.
    private fun startReconnectAttempt(attempt: Int) {
        reconnectAttempt = attempt
        reconnectScope.launch { runReconnectAttempt(attempt) }
    }

    private suspend fun runReconnectAttempt(attempt: Int) {
        try {
            // Stop any prior session but keep the TUN fd open.
            stopNativeClient()
            coroutineContext.ensureActive()

            val fd = tunFd ?: error("TUN fd closed during reconnect")
            val configToml = activeProfileToml ?: error("No active profile for reconnect")
            val handle = startNativeSession(configToml, fd.fd, activeTunMtu)
            nativeHandle = handle

            // The new session reports "ready" (success) or "error" (failure)
            // asynchronously via handleNativeStatus; this coroutine does not wait.
        } catch (cancellation: kotlinx.coroutines.CancellationException) {
            throw cancellation
        } catch (error: Exception) {
            Log.w(TAG, "Reconnect attempt $attempt failed: ${error.message}")
            handleReconnectFailureOnMain(attempt, error.message ?: error::class.java.simpleName)
        }
    }

    /// Route reconnect-failure handling to the main thread so attempt accounting
    /// and terminal teardown stay single-threaded. Called from background
    /// coroutines (synchronous start failure) and from the main thread (async
    /// native "error" during reconnect).
    private fun handleReconnectFailureOnMain(attempt: Int, reason: String) {
        mainHandler.post {
            if (!reconnecting || attempt != reconnectAttempt) {
                return@post
            }

            if (attempt < MAX_RECONNECT_ATTEMPTS) {
                reconnectAttempt = attempt + 1
                val backoffMs = RECONNECT_BACKOFF_MS
                    .getOrElse(attempt - RECONNECT_FIRST_ATTEMPT) { RECONNECT_BACKOFF_MS.last() }
                Log.i(TAG, "Scheduling reconnect attempt ${attempt + 1} in ${backoffMs}ms")
                reconnectScope.launch {
                    delay(backoffMs)
                    ensureActive()
                    startReconnectAttempt(attempt + 1)
                }
            } else {
                reconnecting = false
                failVpn("Reconnect failed after $attempt attempts: $reason")
            }
        }
    }

    private fun buildNativeCallback(gen: Int): SltNative.NativeCallback =
        object : SltNative.NativeCallback {
            override fun onStatus(status: String, detail: String?) {
                // Capture gen by value and drop stale callbacks from any prior
                // session before touching service state. This guard is what keeps
                // an old session's "stopping"/"stopped"/"error" from tearing the
                // service down during a reconnect.
                mainHandler.post {
                    if (gen != sessionGeneration) {
                        return@post
                    }
                    handleNativeStatus(status, detail)
                }
            }

            override fun protectSocket(fd: Int): Boolean =
                try {
                    val protected = protect(fd)
                    if (!protected) {
                        Log.w(TAG, "Android refused to protect SLT socket: fd=$fd")
                    }
                    protected
                } catch (error: RuntimeException) {
                    Log.w(TAG, "Failed to protect SLT socket: fd=$fd", error)
                    false
                }

            override fun resolveHost(hostname: String): Array<String> {
                val network = activeUnderlyingNetwork
                    ?: throw IllegalStateException("No underlying network available for DNS")
                return try {
                    val addresses = network.getAllByName(hostname)
                        .mapNotNull { it.hostAddress }
                        .toTypedArray()
                    if (addresses.isEmpty()) {
                        throw IllegalStateException("No addresses returned for $hostname")
                    }
                    addresses
                } catch (error: Exception) {
                    Log.w(TAG, "Failed to resolve $hostname on underlying network", error)
                    throw RuntimeException("Failed to resolve $hostname on underlying network", error)
                }
            }
        }

    private fun handleNativeStatus(status: String, detail: String?) {
        when (status) {
            "starting" -> {
                // During a reconnect keep the Reconnecting state rather than
                // flickering back to Starting while the new session comes up.
                if (!reconnecting) {
                    SltVpnStatusBus.update(VpnStatus.Starting, detail)
                    updateNotification("Starting")
                }
            }
            "ready" -> {
                reconnecting = false
                SltVpnStatusBus.update(VpnStatus.Running, detail)
                updateNotification("Running")
            }
            "stopping" -> {
                if (nativeHandle != 0L) {
                    updateNotification("Stopping")
                }
            }
            "stopped" -> {
                if (nativeHandle != 0L) {
                    stopVpn(detail ?: "Native client stopped")
                    stopSelf()
                }
            }
            "error" -> {
                if (reconnecting) {
                    handleReconnectFailureOnMain(reconnectAttempt, detail ?: "Reconnect attempt failed")
                } else if (nativeHandle != 0L || tunFd != null) {
                    failVpn(detail ?: "Native client failed")
                } else {
                    SltVpnStatusBus.update(VpnStatus.Error, detail)
                }
            }
            else -> Log.w(TAG, "Unknown native status: $status ${detail.orEmpty()}")
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

    private fun updateNotification(status: String) {
        notificationFactory.update(status)
    }

    private fun stopForegroundCompat() {
        stopForeground(STOP_FOREGROUND_REMOVE)
    }

    companion object {
        const val ACTION_START = "dev.slt.android.action.START"
        const val ACTION_STOP = "dev.slt.android.action.STOP"

        private const val TAG = "SltVpnService"
        private const val CLIENT_ADDRESS_PREFIX = 32

        private const val RECONNECT_FIRST_ATTEMPT = 1
        private const val MAX_RECONNECT_ATTEMPTS = 5

        /// Backoff before retries 2..N (1s, 2s, 4s, 8s); total wait ~15s, under the
        /// design's 30s ceiling.
        private val RECONNECT_BACKOFF_MS = longArrayOf(1_000, 2_000, 4_000, 8_000)

        fun startIntent(context: Context): Intent =
            Intent(context, SltVpnService::class.java).setAction(ACTION_START)

        fun stopIntent(context: Context): Intent =
            Intent(context, SltVpnService::class.java).setAction(ACTION_STOP)
    }
}
