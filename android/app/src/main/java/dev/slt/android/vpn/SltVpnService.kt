package dev.slt.android.vpn

import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.Network
import android.net.VpnService
import android.os.Handler
import android.os.Looper
import android.os.ParcelFileDescriptor
import android.util.Log
import dev.slt.android.ConfigValidationResult
import dev.slt.android.SltNative
import dev.slt.android.profile.SltProfile
import dev.slt.android.profile.store.ProfileRepository
import dev.slt.android.uniffi.ClientConfigSummary
import dev.slt.android.uniffi.SocketKind
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch

class SltVpnService : VpnService() {
    @Volatile private var activeTunnel: ActiveTunnel? = null
    @Volatile private var tornDown = false
    private var terminalStatusReported = false

    private val stateLock = Any()
    private val underlyingNetworkPublicationSequencer = UnderlyingNetworkPublicationSequencer()
    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.Main)
    private var startJob: Job? = null
    private val mainHandler by lazy { Handler(Looper.getMainLooper()) }
    private val profileApplier by lazy { VpnProfileApplier(this, TAG) }
    private val notificationFactory by lazy { VpnNotificationFactory(this) }
    private val dnsCache by lazy {
        DnsResolutionCache(
            getSharedPreferences(DnsResolutionCache.PREFS_NAME, Context.MODE_PRIVATE),
            TAG,
        )
    }
    private val dnsResolver by lazy {
        UnderlyingNetworkDnsResolver(
            cache = dnsCache,
            currentUnderlyingNetworks = ::currentUnderlyingNetworks,
            publishUnderlyingNetwork = ::publishUnderlyingNetwork,
            logTag = TAG,
        )
    }
    private val platformServices by lazy {
        VpnRuntimePlatformServices(
            protect = ::protect,
            currentUnderlyingNetworks = ::currentUnderlyingNetworks,
            onSocketBound = ::recordSocketBinding,
            dnsResolver = dnsResolver,
            logTag = TAG,
        )
    }
    private val nativeController by lazy {
        NativeSessionSupervisor(
            mainHandler = mainHandler,
            platformServices = platformServices::build,
            callbacks = object : NativeSessionSupervisor.Callbacks {
                override fun onStopped(handle: ULong) {
                    teardownAndStopSelf()
                }

                override fun onFatalError(detail: String) {
                    if (SltVpnStatusBus.state.value.status != VpnStatus.Error) {
                        SltVpnStatusBus.markError(detail)
                    }
                    teardownAndStopSelf()
                }

                override fun onRetryScheduled(detail: String, attempt: Int, delayMs: Long) {
                    SltVpnStatusBus.markNativeRestartScheduled(
                        detail = detail,
                        attempt = attempt.toULong(),
                        delayMs = delayMs.toULong(),
                    )
                    updateNotification()
                }

                override fun onNotificationRefresh() {
                    updateNotification()
                }
            },
            logTag = TAG,
        )
    }
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
        serviceScope.cancel()
        super.onDestroy()
    }

    private fun startVpn() {
        terminalStatusReported = false
        notificationFactory.ensureChannel()

        if (activeTunnel != null || startJob?.isActive == true) {
            // Tunnel is already established; refresh the foreground notification
            // and stay in the current (possibly Reconnecting/Starting/Handoff) status.
            val status = SltVpnStatusBus.state.value.status
            if (
                status != VpnStatus.Reconnecting &&
                status != VpnStatus.Starting &&
                status != VpnStatus.Handoff
            ) {
                SltVpnStatusBus.markRunningForeground()
            }
            updateNotification()
            return
        }

        try {
            tornDown = false
            SltVpnStatusBus.markStarting()
            startForeground(
                VpnNotificationFactory.NOTIFICATION_ID,
                notificationFactory.build(notificationText(VpnStatus.Starting)),
            )

            val job = serviceScope.launch {
                try {
                    startVpnAsync()
                } catch (cancel: CancellationException) {
                    throw cancel
                } catch (error: Exception) {
                    failVpn(error.message ?: error::class.java.simpleName)
                } finally {
                    if (startJob === coroutineContext[Job]) {
                        startJob = null
                    }
                }
            }
            startJob = job
        } catch (error: Exception) {
            failVpn(error.message ?: error::class.java.simpleName)
        }
    }

    private suspend fun startVpnAsync() {
        SltNative.load()
        val profile = loadActiveProfile()
        val summary = validateProfile(profile)
        dnsResolver.warmAsync(summary.serverHost)
        val connectivityManager = getSystemService(ConnectivityManager::class.java)
        val preEstablishUnderlyingNetwork =
            connectivityManager.findInitialUnderlyingNetwork(TAG)

        val builder = Builder()
            .setSession(profile.metadata.name)
            .setMtu(summary.tunMtu)
            .addAddress(summary.assignedIpv4, CLIENT_ADDRESS_PREFIX)
        configureInitialUnderlyingNetwork(preEstablishUnderlyingNetwork) { networks ->
            builder.setUnderlyingNetworks(networks.toTypedArray())
        }
        profileApplier.apply(builder, profile)

        val fd = builder.establish()

        if (fd == null) {
            failVpn("Android did not return a TUN fd")
            return
        }

        val initialUnderlyingNetwork =
            connectivityManager.findInitialUnderlyingNetwork(TAG)
                ?: preEstablishUnderlyingNetwork
        if (initialUnderlyingNetwork == null) {
            try {
                fd.close()
            } catch (error: RuntimeException) {
                Log.w(TAG, "Failed to close unused VPN fd after startup network failure", error)
            }
            failVpn("No non-VPN network available; stop the other VPN and try again")
            return
        }

        synchronized(stateLock) {
            activeTunnel = ActiveTunnel(
                fd = fd,
                clientToml = profile.clientToml,
                tunMtu = summary.tunMtu,
                underlyingNetwork = initialUnderlyingNetwork,
                boundUnderlyingNetworks = emptyMap(),
            )
        }
        val selectedUnderlyingNetwork = startNetworkWatcher(initialUnderlyingNetwork)
        if (selectedUnderlyingNetwork == null) {
            failVpn("No non-VPN network available; stop the other VPN and try again")
            return
        }
        publishUnderlyingNetwork(selectedUnderlyingNetwork)

        val session = nativeController.start(
            NativeSessionConfig(
                clientToml = profile.clientToml,
                tunFd = fd.fd,
                tunMtu = summary.tunMtu,
            ),
        )
        Log.i(
            TAG,
            "SLT VPN tunnel established; awaiting native auth: " +
                "profile=${profile.metadata.name} fd=${fd.fd} " +
                "${summary.assignedIpv4}/$CLIENT_ADDRESS_PREFIX native=${session.handle()}",
        )
        // Stay Starting until the runtime emits Authenticated (-> Running).
        updateNotification()
    }

    private suspend fun startNetworkWatcher(initialNetwork: Network?): Network? {
        val initialSelection = CompletableDeferred<Network?>()
        val watcher = NetworkChangeWatcher(
            context = this,
            initialNetwork = initialNetwork,
            onInitialUnderlyingNetworkChanged = ::publishUnderlyingNetwork,
            onInitialSelectionReady = { network -> initialSelection.complete(network) },
            onReconnect = ::notifyNetworkChanged,
        )
        networkWatcher = watcher
        watcher.start()
        return initialSelection.await()
    }

    private fun publishUnderlyingNetwork(network: Network?) {
        publishUnderlyingNetworkIfActive(network)
    }

    private fun publishUnderlyingNetworkIfActive(network: Network?): Boolean =
        updateUnderlyingNetworkPublication { tunnel ->
            tunnel.copy(underlyingNetwork = network)
        }

    private fun recordSocketBinding(kind: SocketKind, network: Network) {
        updateUnderlyingNetworkPublication { tunnel ->
            tunnel.copy(
                boundUnderlyingNetworks = tunnel.boundUnderlyingNetworks + (kind to network),
            )
        }
    }

    private fun updateUnderlyingNetworkPublication(
        update: (ActiveTunnel) -> ActiveTunnel,
    ): Boolean = underlyingNetworkPublicationSequencer.sequence {
        val networks = synchronized(stateLock) {
            val tunnel = activeTunnel
            if (tunnel == null || tornDown) {
                null
            } else {
                val updated = update(tunnel)
                activeTunnel = updated
                liveUnderlyingNetworks(
                    selectedNetwork = updated.underlyingNetwork,
                    boundNetworks = updated.boundUnderlyingNetworks,
                )
            }
        } ?: return@sequence false

        try {
            val published = publishLiveUnderlyingNetworks(networks) { currentNetworks ->
                setUnderlyingNetworks(currentNetworks.toTypedArray())
            }
            if (!published) {
                Log.w(TAG, "Android rejected the VPN underlying-network update")
            }
        } catch (error: RuntimeException) {
            Log.w(TAG, "Failed to publish the VPN underlying network", error)
        }
        true
    }

    private suspend fun loadActiveProfile(): SltProfile =
        ProfileRepository(applicationContext).loadActiveProfile() ?: error("No active profile")

    private fun validateProfile(profile: SltProfile): ClientConfigSummary {
        return when (val result = SltNative.validateClientConfig(profile.clientToml)) {
            is ConfigValidationResult.Valid -> result.summary
            is ConfigValidationResult.Invalid -> error(result.message)
        }
    }

    private fun stopVpn(detail: String) {
        startJob?.cancel()
        startJob = null
        SltVpnStatusBus.markStopped(detail)
        teardown()
        terminalStatusReported = true
    }

    /// Tear down all platform resources without touching UI state. Idempotent:
    /// the terminal-event path, `stopVpn`, and `onDestroy` can all drive a tear
    /// down, so the first call does the work and later calls are no-ops (rather
    /// than relying on every sub-helper being null-safe). The store
    /// ([SltVpnStatusBus]) owns status; this owns the VPN/TUN lifecycle.
    private fun teardown() {
        if (tornDown) {
            return
        }
        tornDown = true
        networkWatcher?.stop()
        networkWatcher = null
        nativeController.stop()
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

    /// Notify Rust that the underlying network changed. Rust owns reconnect and
    /// path recovery policy; Kotlin only maintains Android platform state.
    private fun notifyNetworkChanged(network: Network?) {
        if (!publishUnderlyingNetworkIfActive(network)) {
            return
        }
        nativeController.notifyNetworkChanged()
    }

    private fun currentUnderlyingNetworks(): List<Network> {
        val tunnelNetwork = synchronized(stateLock) {
            if (tornDown) {
                return emptyList()
            }
            activeTunnel?.underlyingNetwork
        }

        return (
            listOfNotNull(tunnelNetwork) +
                getSystemService(ConnectivityManager::class.java).findUnderlyingNetworks(TAG)
            ).distinct()
    }

    private fun closeTunFd() {
        val tunnel = synchronized(stateLock) {
            val current = activeTunnel ?: return
            activeTunnel = null
            current
        }

        try {
            tunnel.fd.close()
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
    /// `StatusLine.statusLabel` (e.g. "Starting" vs "Connecting..."); the
    /// foreground notification is a platform surface, so its text is derived
    /// here rather than in the UI layer.
    private fun notificationText(status: VpnStatus): String =
        when (status) {
            VpnStatus.Idle -> "Idle"
            VpnStatus.PermissionRequired -> "Permission required"
            VpnStatus.Starting -> "Starting"
            VpnStatus.Running -> "Running"
            VpnStatus.Reconnecting -> "Reconnecting"
            VpnStatus.Handoff -> "Switching network"
            VpnStatus.Stopped -> "Stopped"
            VpnStatus.Error -> "Error"
        }

    private fun stopForegroundCompat() {
        stopForeground(STOP_FOREGROUND_REMOVE)
    }

    private data class ActiveTunnel(
        val fd: ParcelFileDescriptor,
        val clientToml: String,
        val tunMtu: Int,
        val underlyingNetwork: Network?,
        val boundUnderlyingNetworks: Map<SocketKind, Network>,
    )

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
