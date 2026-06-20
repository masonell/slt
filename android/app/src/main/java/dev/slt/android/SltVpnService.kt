package dev.slt.android

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat

class SltVpnService : VpnService() {
    private var tunFd: ParcelFileDescriptor? = null

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
        stopVpn("Service destroyed")
        super.onDestroy()
    }

    private fun startVpn() {
        SltVpnStatusBus.update(VpnStatus.Starting)
        ensureNotificationChannel()
        startForeground(NOTIFICATION_ID, buildNotification("Starting"))

        if (tunFd != null) {
            SltVpnStatusBus.update(VpnStatus.Running, "fd=${tunFd?.fd}")
            updateNotification("Running")
            return
        }

        try {
            SltNative.load()

            val fd = Builder()
                .setSession(DEBUG_SESSION)
                .setMtu(DEBUG_MTU)
                .addAddress(DEBUG_ADDRESS, DEBUG_ADDRESS_PREFIX)
                .addRoute(DEBUG_ROUTE, DEBUG_ROUTE_PREFIX)
                .addDnsServer(DEBUG_DNS)
                .establish()

            if (fd == null) {
                failVpn("Android did not return a TUN fd")
                return
            }

            tunFd = fd
            val detail = "fd=${fd.fd} $DEBUG_ADDRESS/$DEBUG_ADDRESS_PREFIX $DEBUG_ROUTE/$DEBUG_ROUTE_PREFIX"
            Log.i(TAG, "SLT VPN established: $detail")
            SltVpnStatusBus.update(VpnStatus.Running, detail)
            updateNotification("Running")
        } catch (error: RuntimeException) {
            failVpn(error.message ?: error::class.java.simpleName)
        }
    }

    private fun stopVpn(detail: String) {
        closeTunFd()
        stopForegroundCompat()
        SltVpnStatusBus.update(VpnStatus.Stopped, detail)
    }

    private fun failVpn(message: String) {
        Log.e(TAG, "SLT VPN failed: $message")
        closeTunFd()
        stopForegroundCompat()
        SltVpnStatusBus.update(VpnStatus.Error, message)
        stopSelf()
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

        private const val DEBUG_SESSION = "SLT"
        private const val DEBUG_MTU = 1280
        private const val DEBUG_ADDRESS = "10.10.0.2"
        private const val DEBUG_ADDRESS_PREFIX = 32
        private const val DEBUG_ROUTE = "0.0.0.0"
        private const val DEBUG_ROUTE_PREFIX = 0
        private const val DEBUG_DNS = "1.1.1.1"

        fun startIntent(context: Context): Intent =
            Intent(context, SltVpnService::class.java).setAction(ACTION_START)

        fun stopIntent(context: Context): Intent =
            Intent(context, SltVpnService::class.java).setAction(ACTION_STOP)
    }
}
