package dev.slt.android.ui.components

import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import dev.slt.android.ui.theme.StatusConnectingDark
import dev.slt.android.ui.theme.StatusConnectingLight
import dev.slt.android.vpn.VpnStatus

/**
 * Centered connection-status line: a colored dot + state word + an optional
 * transport / duration line (shown once wired), and the error detail when the
 * status is [VpnStatus.Error]. Raw debug detail is intentionally not shown.
 */
@Composable
internal fun StatusLine(
    status: VpnStatus,
    detail: String? = null,
    transport: String? = null,
    duration: String? = null,
    modifier: Modifier = Modifier,
) {
    Column(
        modifier = modifier,
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(4.dp),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Box(
                modifier = Modifier
                    .size(8.dp)
                    .background(statusColor(status), CircleShape),
            )
            Text(
                text = statusLabel(status),
                style = MaterialTheme.typography.titleMedium,
                color = statusColor(status),
            )
            val meta = listOfNotNull(transport, duration).joinToString(" · ")
            if (meta.isNotEmpty()) {
                Text(
                    text = meta,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
        if ((status == VpnStatus.Error || status == VpnStatus.PermissionRequired) && !detail.isNullOrBlank()) {
            Text(
                text = detail,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.error,
            )
        }
    }
}

@Composable
private fun statusColor(status: VpnStatus): Color {
    val target = when (status) {
        VpnStatus.Running -> MaterialTheme.colorScheme.primary
        VpnStatus.Starting, VpnStatus.Reconnecting ->
            if (isSystemInDarkTheme()) StatusConnectingDark else StatusConnectingLight
        VpnStatus.Error -> MaterialTheme.colorScheme.error
        else -> MaterialTheme.colorScheme.onSurfaceVariant
    }
    return animateColorAsState(target, tween(300), label = "statusColor").value
}

private fun statusLabel(status: VpnStatus): String =
    when (status) {
        VpnStatus.Idle -> "Disconnected"
        VpnStatus.PermissionRequired -> "Permission required"
        VpnStatus.Starting -> "Connecting…"
        VpnStatus.Running -> "Connected"
        VpnStatus.Reconnecting -> "Reconnecting…"
        VpnStatus.Stopped -> "Stopped"
        VpnStatus.Error -> "Error"
    }
