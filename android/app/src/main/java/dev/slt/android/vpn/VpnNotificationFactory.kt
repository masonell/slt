package dev.slt.android.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import androidx.core.app.NotificationCompat
import dev.slt.android.MainActivity
import dev.slt.android.R

internal class VpnNotificationFactory(
    private val context: Context,
) {
    fun ensureChannel() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) {
            return
        }

        val channel = NotificationChannel(
            NOTIFICATION_CHANNEL_ID,
            context.getString(R.string.vpn_notification_channel),
            NotificationManager.IMPORTANCE_LOW,
        )
        val manager = context.getSystemService(NotificationManager::class.java)
        manager.createNotificationChannel(channel)
    }

    fun update(status: String) {
        val manager = context.getSystemService(NotificationManager::class.java)
        manager.notify(NOTIFICATION_ID, build(status))
    }

    fun build(status: String): Notification {
        val openIntent = PendingIntent.getActivity(
            context,
            0,
            Intent(context, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val stopIntent = PendingIntent.getService(
            context,
            1,
            Intent(context, SltVpnService::class.java).setAction(SltVpnService.ACTION_STOP),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )

        return NotificationCompat.Builder(context, NOTIFICATION_CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_stat_vpn)
            .setContentTitle(status)
            .setContentIntent(openIntent)
            .setOngoing(true)
            .setSilent(true)
            .addAction(android.R.drawable.ic_menu_close_clear_cancel, context.getString(R.string.vpn_action_stop), stopIntent)
            .build()
    }

    companion object {
        const val NOTIFICATION_ID = 1001

        private const val NOTIFICATION_CHANNEL_ID = "slt_vpn"
    }
}
