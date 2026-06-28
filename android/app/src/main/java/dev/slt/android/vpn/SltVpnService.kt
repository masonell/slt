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
import dev.slt.android.uniffi.ClientEventKind
import dev.slt.android.uniffi.NativeSession
import dev.slt.android.uniffi.NativeSessionCallback
import dev.slt.android.uniffi.PlatformServices
import dev.slt.android.uniffi.SltInteropException
import dev.slt.android.uniffi.SocketKind
import dev.slt.android.uniffi.Transport
import kotlinx.coroutines.runBlocking

class SltVpnService : VpnService() {
    @Volatile private var tunFd: ParcelFileDescriptor? = null
    @Volatile private var nativeSession: NativeSession? = null
    @Volatile private var nativeHandle: Long = 0
    @Volatile private var sessionGeneration: Int = 0
    @Volatile private var activeUnderlyingNetwork: Network? = null
    private var terminalStatusReported = false

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
            cleanupVpn()
        } else {
            stopVpn("Service destroyed")
        }
        super.onDestroy()
    }

    private fun startVpn() {
        terminalStatusReported = false
        notificationFactory.ensureChannel()

        if (tunFd != null) {
            when (SltVpnStatusBus.state.value.status) {
                VpnStatus.Reconnecting -> updateNotification("Reconnecting")
                VpnStatus.Starting -> updateNotification("Starting")
                else -> {
                    SltVpnStatusBus.update(VpnStatus.Running, "fd=${tunFd?.fd} native=${nativeHandle}")
                    updateNotification("Running")
                }
            }
            return
        }

        try {
            SltVpnStatusBus.update(VpnStatus.Starting)
            startForeground(VpnNotificationFactory.NOTIFICATION_ID, notificationFactory.build("Starting"))
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
            updateNotification("Starting")

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
        cleanupVpn()
        terminalStatusReported = true
        SltVpnStatusBus.update(VpnStatus.Stopped, detail)
    }

    private fun cleanupVpn() {
        networkWatcher?.stop()
        networkWatcher = null
        activeUnderlyingNetwork = null
        stopNativeClient()
        closeTunFd()
        stopForegroundCompat()
    }

    private fun failVpn(message: String) {
        Log.e(TAG, "SLT VPN failed: $message")
        cleanupVpn()
        terminalStatusReported = true
        SltVpnStatusBus.update(VpnStatus.Error, message)
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

    /// Start a fresh native client session, bumping the generation so stale
    /// callbacks from any previous session are ignored by the callback guard.
    private fun startNativeSession(configToml: String, tunFd: Int, mtu: Int): NativeSession {
        sessionGeneration += 1
        val gen = sessionGeneration
        val platformServices = buildPlatformServices()
        return SltNative.start(configToml, tunFd, mtu, platformServices, buildNativeCallback(gen))
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

    private fun buildNativeCallback(gen: Int): NativeSessionCallback =
        object : NativeSessionCallback {
            override fun onEvent(event: ClientEvent) {
                mainHandler.post {
                    val currentHandle = nativeHandle
                    if (
                        gen != sessionGeneration ||
                        (currentHandle != 0L && event.handle.toLong() != currentHandle)
                    ) {
                        return@post
                    }
                    handleNativeEvent(event)
                }
            }
        }

    /// Map a typed native event to VPN UI/service state. Lifecycle, auth, and
    /// reconnect events drive [VpnStatus]; connected-phase events (UDP upgrade,
    /// transport switches, handoff probes) only refine the transport indicator
    /// while the session stays Running.
    private fun handleNativeEvent(event: ClientEvent) {
        when (event.kind) {
            is ClientEventKind.Starting -> {
                SltVpnStatusBus.update(VpnStatus.Starting)
                updateNotification("Starting")
            }
            is ClientEventKind.TunReady,
            is ClientEventKind.Connecting,
            is ClientEventKind.ConnectedTcp,
            is ClientEventKind.Authenticating -> {
                // Still establishing the session. Hold Reconnecting if Rust is
                // in backoff/recovery; otherwise show Starting from Idle.
                if (SltVpnStatusBus.state.value.status == VpnStatus.Idle) {
                    SltVpnStatusBus.update(VpnStatus.Starting)
                }
            }
            is ClientEventKind.Authenticated -> {
                SltVpnStatusBus.update(VpnStatus.Running, transport = transportLabel(event.transport))
                updateNotification("Running")
            }
            is ClientEventKind.ReconnectScheduled -> {
                SltVpnStatusBus.update(
                    VpnStatus.Reconnecting,
                    "Reconnect in ${event.kind.delayMs}ms (attempt ${event.kind.attempt})",
                )
                updateNotification("Reconnecting")
            }
            is ClientEventKind.ReconnectFailed -> {
                SltVpnStatusBus.update(
                    VpnStatus.Reconnecting,
                    "Attempt ${event.kind.attempt} failed",
                )
                updateNotification("Reconnecting")
            }
            is ClientEventKind.TransportChanged -> {
                SltVpnStatusBus.updateTransport(transportLabel(event.transport))
            }
            is ClientEventKind.NetworkChanged -> {
                SltVpnStatusBus.update(VpnStatus.Reconnecting, "Network changed")
                updateNotification("Reconnecting")
            }
            is ClientEventKind.UdpDiscoveryStarted,
            is ClientEventKind.UdpDiscoveryFailed,
            is ClientEventKind.UdpRegisterStarted,
            is ClientEventKind.UdpRegistered,
            is ClientEventKind.UdpRegisterFailed,
            is ClientEventKind.UdpUpgradeStarted,
            is ClientEventKind.UdpPathValidated,
            is ClientEventKind.UdpSwitchCommitted,
            is ClientEventKind.UdpPathRefreshStarted,
            is ClientEventKind.UdpPathRefreshSucceeded,
            is ClientEventKind.UdpPathRefreshFailed -> {
                // Connected-phase detail; status stays Running. Logged via Rust.
            }
            is ClientEventKind.Stopping -> {
                if (nativeHandle != 0L) {
                    updateNotification("Stopping")
                }
            }
            is ClientEventKind.Stopped -> {
                if (nativeHandle != 0L) {
                    stopVpn("Native client stopped")
                    stopSelf()
                }
            }
            is ClientEventKind.Error -> {
                val errorDetail = event.kind.detail
                if (nativeHandle != 0L || tunFd != null) {
                    failVpn(errorDetail)
                } else {
                    SltVpnStatusBus.update(VpnStatus.Error, errorDetail)
                }
            }
        }
    }

    private fun transportLabel(transport: Transport?): String? =
        when (transport) {
            Transport.TCP -> "TCP"
            Transport.UDP_QSP -> "UDP-QSP"
            null -> null
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

        fun startIntent(context: Context): Intent =
            Intent(context, SltVpnService::class.java).setAction(ACTION_START)

        fun stopIntent(context: Context): Intent =
            Intent(context, SltVpnService::class.java).setAction(ACTION_STOP)
    }
}
