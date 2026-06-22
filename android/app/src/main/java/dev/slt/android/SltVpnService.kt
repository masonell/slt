package dev.slt.android

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.IpPrefix
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.ParcelFileDescriptor
import android.os.Looper
import android.util.Log
import androidx.core.app.NotificationCompat
import kotlinx.coroutines.runBlocking
import java.net.InetAddress

class SltVpnService : VpnService() {
    private var tunFd: ParcelFileDescriptor? = null
    private var nativeHandle: Long = 0
    private var terminalStatusReported = false
    private val mainHandler by lazy { Handler(Looper.getMainLooper()) }

    private val nativeCallback = object : SltNative.NativeCallback {
        override fun onStatus(status: String, detail: String?) {
            mainHandler.post {
                handleNativeStatus(status, detail)
            }
        }

        override fun onLog(level: String, message: String) {
            Log.println(androidLogPriority(level), TAG, message)
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
    }

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
        ensureNotificationChannel()
        startForeground(NOTIFICATION_ID, buildNotification("Starting"))

        if (tunFd != null) {
            SltVpnStatusBus.update(VpnStatus.Running, "fd=${tunFd?.fd} native=$nativeHandle")
            updateNotification("Running")
            return
        }

        try {
            SltNative.load()
            val profile = loadActiveProfile()
            val summary = validateProfile(profile)

            val builder = Builder()
                .setSession(profile.metadata.name)
                .setMtu(summary.tunMtu)
                .addAddress(summary.assignedIpv4, CLIENT_ADDRESS_PREFIX)
            applyProfileSettings(builder, profile)

            val fd = builder.establish()

            if (fd == null) {
                failVpn("Android did not return a TUN fd")
                return
            }

            tunFd = fd
            nativeHandle = SltNative.start(profile.clientToml, fd.fd, summary.tunMtu, nativeCallback)
            val detail = "profile=${profile.metadata.name} fd=${fd.fd} ${summary.assignedIpv4}/$CLIENT_ADDRESS_PREFIX"
            Log.i(TAG, "SLT VPN established: $detail")
            SltVpnStatusBus.update(VpnStatus.Running, "$detail native=$nativeHandle")
            updateNotification("Running")
        } catch (error: Exception) {
            failVpn(error.message ?: error::class.java.simpleName)
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

    private fun applyProfileSettings(builder: Builder, profile: SltProfile) {
        applyRoutes(builder, profile.metadata.routes)
        applyDns(builder, profile.metadata.dns)
        applyAppRules(builder, profile.metadata.appRules)
    }

    private fun applyRoutes(builder: Builder, routes: List<VpnRouteRule>) {
        if (routes.isEmpty()) {
            error("Active profile has no VPN routes configured")
        }

        routes.forEach { route ->
            val prefix = route.cidr.toIpPrefix()
            if (route.excluded) {
                builder.excludeRoute(prefix)
            } else {
                builder.addRoute(prefix)
            }
        }
    }

    private fun applyDns(builder: Builder, dns: DnsSettings) {
        if (dns.mode != DnsMode.Custom) {
            return
        }

        dns.servers.forEach { server ->
            builder.addDnsServer(InetAddress.getByName(server))
        }
    }

    private fun applyAppRules(builder: Builder, appRules: AppVpnRules) {
        when (appRules.mode) {
            AppVpnMode.All -> Unit
            AppVpnMode.Allowlist -> {
                val packages = (appRules.packageNames + packageName).distinct().filterInstalled()
                packages.forEach { builder.addAllowedApplication(it) }
            }
            AppVpnMode.Blocklist -> {
                val packages = appRules.packageNames
                    .filterNot { it == packageName }
                    .distinct()
                    .filterInstalled()
                packages.forEach { builder.addDisallowedApplication(it) }
            }
        }
    }

    private fun List<String>.filterInstalled(): List<String> =
        filter { packageName ->
            try {
                packageManager.getPackageInfo(packageName, PackageManager.PackageInfoFlags.of(0))
                true
            } catch (_: PackageManager.NameNotFoundException) {
                Log.w(TAG, "Profile references missing Android package: $packageName")
                false
            }
        }

    private fun String.toIpPrefix(): IpPrefix {
        val parts = split('/', limit = 2)
        require(parts.size == 2) { "invalid CIDR route: $this" }
        val address = InetAddress.getByName(parts[0])
        val prefixLength = parts[1].toIntOrNull()
            ?: error("invalid CIDR prefix length: $this")
        return IpPrefix(address, prefixLength)
    }

    private fun stopVpn(detail: String) {
        cleanupVpn()
        terminalStatusReported = true
        SltVpnStatusBus.update(VpnStatus.Stopped, detail)
    }

    private fun cleanupVpn() {
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

    private fun handleNativeStatus(status: String, detail: String?) {
        when (status) {
            "starting" -> {
                SltVpnStatusBus.update(VpnStatus.Starting, detail)
                updateNotification("Starting")
            }
            "ready" -> {
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
                if (nativeHandle != 0L || tunFd != null) {
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

    private fun ensureNotificationChannel() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) {
            return
        }

        val channel = NotificationChannel(
            NOTIFICATION_CHANNEL_ID,
            getString(R.string.vpn_notification_channel),
            NotificationManager.IMPORTANCE_LOW,
        )
        val manager = getSystemService(NotificationManager::class.java)
        manager.createNotificationChannel(channel)
    }

    private fun updateNotification(status: String) {
        val manager = getSystemService(NotificationManager::class.java)
        manager.notify(NOTIFICATION_ID, buildNotification(status))
    }

    private fun buildNotification(status: String): Notification {
        val openIntent = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val stopIntent = PendingIntent.getService(
            this,
            1,
            Intent(this, SltVpnService::class.java).setAction(ACTION_STOP),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )

        return NotificationCompat.Builder(this, NOTIFICATION_CHANNEL_ID)
            .setSmallIcon(android.R.drawable.stat_sys_upload_done)
            .setContentTitle("SLT VPN")
            .setContentText(status)
            .setContentIntent(openIntent)
            .setOngoing(true)
            .setSilent(true)
            .addAction(android.R.drawable.ic_menu_close_clear_cancel, "Stop", stopIntent)
            .build()
    }

    private fun stopForegroundCompat() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            stopForeground(STOP_FOREGROUND_REMOVE)
        } else {
            @Suppress("DEPRECATION")
            stopForeground(true)
        }
    }

    companion object {
        const val ACTION_START = "dev.slt.android.action.START"
        const val ACTION_STOP = "dev.slt.android.action.STOP"

        private const val TAG = "SltVpnService"
        private const val NOTIFICATION_ID = 1001
        private const val NOTIFICATION_CHANNEL_ID = "slt_vpn"
        private const val CLIENT_ADDRESS_PREFIX = 32

        fun startIntent(context: Context): Intent =
            Intent(context, SltVpnService::class.java).setAction(ACTION_START)

        fun stopIntent(context: Context): Intent =
            Intent(context, SltVpnService::class.java).setAction(ACTION_STOP)
    }
}

private fun androidLogPriority(level: String): Int =
    when (level) {
        "error" -> Log.ERROR
        "warn" -> Log.WARN
        "debug" -> Log.DEBUG
        "trace" -> Log.VERBOSE
        else -> Log.INFO
    }
