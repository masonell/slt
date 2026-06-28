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
import dev.slt.android.uniffi.Transport
import dev.slt.android.vpn.VpnPhase
import dev.slt.android.vpn.VpnStatus
import dev.slt.android.vpn.VpnUiState

/**
 * Centered connection-status line driven by typed [VpnUiState]: a colored dot +
 * status word, an active-transport indicator, the current runtime phase/step
 * (connecting, authenticating, upgrading to UDP, reconnect attempt, ...), and
 * the last error detail when the status is [VpnStatus.Error] or
 * [VpnStatus.PermissionRequired].
 */
@Composable
internal fun StatusLine(
    state: VpnUiState,
    modifier: Modifier = Modifier,
    duration: String? = null,
) {
    val status = state.status
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
            val meta = listOfNotNull(transportLabel(state.transport), duration).joinToString(" · ")
            if (meta.isNotEmpty()) {
                Text(
                    text = meta,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
        val step = stepLabel(state)
        if (step != null) {
            Text(
                text = step,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        if ((status == VpnStatus.Error || status == VpnStatus.PermissionRequired) && !state.lastError.isNullOrBlank()) {
            Text(
                text = state.lastError,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.error,
            )
        }
    }
}

/**
 * Human label for the current runtime step, or null when the status word alone
 * is enough. Surfaces non-default phases while Starting, the reconnect
 * attempt/delay while Reconnecting, and UDP upgrade / handoff steps while
 * Running.
 */
private fun stepLabel(state: VpnUiState): String? =
    when (state.status) {
        VpnStatus.Starting -> if (state.phase != VpnPhase.Starting) state.phase.label else null
        VpnStatus.Reconnecting -> buildString {
            append(state.phase.label)
            state.reconnectAttempt?.let { append(" · attempt $it") }
            state.reconnectDelayMs?.let { append(" · in ${it}ms") }
        }
        VpnStatus.Running ->
            when (state.phase) {
                VpnPhase.UdpDiscovering,
                VpnPhase.UdpRegistering,
                VpnPhase.UdpUpgrading,
                VpnPhase.NetworkHandoff,
                -> state.phase.label
                else -> null
            }
        else -> null
    }

private fun transportLabel(transport: Transport?): String? =
    when (transport) {
        Transport.TCP -> "TCP"
        Transport.UDP_QSP -> "UDP-QSP"
        null -> null
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
