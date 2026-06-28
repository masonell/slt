package dev.slt.android.ui.components

import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.produceState
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import dev.slt.android.R
import dev.slt.android.ui.theme.StatusConnectingDark
import dev.slt.android.ui.theme.StatusConnectingLight
import dev.slt.android.uniffi.Transport
import dev.slt.android.vpn.VpnPhase
import dev.slt.android.vpn.VpnStatus
import dev.slt.android.vpn.VpnUiState
import kotlinx.coroutines.delay

/// Minimum height reserved for a single status line, present whether or not the
/// line has text. Keeping every line's slot constant makes the whole [StatusLine]
/// a fixed height, so the hero (and the Start/Stop button above it) never shifts
/// as lines appear and disappear.
private val ReservedLineHeight = 20.dp

/// Cap on a status line's width so long errors wrap instead of running off-screen.
private val MaxLineWidth = 280.dp

/**
 * Centered connection-status line driven by typed [VpnUiState].
 *
 * One hero row — a colored dot, the status word, the active-transport badge, and
 * an optional duration — followed by two *reserved* lines:
 *
 * - a *detail* line shown only while something is actively happening
 *   (establishing the link, authenticating, the UDP upgrade steps, re-establishing
 *   the path after a network change), or, while [VpnStatus.Reconnecting], the
 *   attempt — a live backoff countdown while waiting, "Attempt N" while trying;
 * - the failure reason, verbatim and untrimmed, while [VpnStatus.Reconnecting]
 *   (recoverable) or [VpnStatus.Error] (terminal).
 *
 * Both lower lines reserve [ReservedLineHeight] even when empty, so the hero —
 * and the Start/Stop button above it — stays vertically fixed as lines come and
 * go. Handoff ([VpnStatus.Handoff]) is a calm green, distinct from the amber
 * reconnect. All labels resolve through [R.string] so they localize.
 */
@Composable
internal fun StatusLine(
    state: VpnUiState,
    modifier: Modifier = Modifier,
    duration: String? = null,
) {
    val status = state.status
    val color = statusColor(status)
    val detail = subtitleFor(state)
    val error =
        if (status == VpnStatus.Reconnecting || status == VpnStatus.Error) {
            state.lastError
        } else {
            null
        }
    Column(
        modifier = modifier.fillMaxWidth(),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(4.dp),
    ) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Box(
                modifier = Modifier
                    .size(8.dp)
                    .background(color, CircleShape),
            )
            Text(
                text = statusLabel(status),
                style = MaterialTheme.typography.titleMedium,
                color = color,
            )
            val transport = transportFor(state)
            if (transport != null) {
                TransportBadge(
                    transport = transport,
                    faded = status == VpnStatus.Handoff,
                )
            }
            if (duration != null) {
                Text(
                    text = duration,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }

        ReservedLine(detail, color = MaterialTheme.colorScheme.onSurfaceVariant)
        ReservedLine(error, color = MaterialTheme.colorScheme.error)
    }
}

/**
 * A status line that always occupies [ReservedLineHeight] (growing if the text
 * wraps), so an absent line leaves its slot in place instead of collapsing the
 * layout. Empty when [text] is null/blank.
 */
@Composable
private fun ReservedLine(text: String?, color: Color, modifier: Modifier = Modifier) {
    Box(
        modifier = modifier
            .widthIn(max = MaxLineWidth)
            .heightIn(min = ReservedLineHeight),
        contentAlignment = Alignment.Center,
    ) {
        if (!text.isNullOrBlank()) {
            Text(
                text = text,
                style = MaterialTheme.typography.bodySmall,
                color = color,
                textAlign = TextAlign.Center,
            )
        }
    }
}

/**
 * Active data-path transport to badge, or null when there is nothing meaningful
 * to show (not yet connected, or mid-connect). Kept visible through handoff so
 * the user sees which path is being refreshed.
 */
private fun transportFor(state: VpnUiState): Transport? =
    if (state.status == VpnStatus.Running || state.status == VpnStatus.Handoff) {
        state.transport
    } else {
        null
    }

/**
 * Small pill stating the active transport. UDP-QSP reads as the fast path
 * (primary container); TCP is neutral. [faded] dims it during handoff, since the
 * path is in flux rather than confidently active.
 */
@Composable
private fun TransportBadge(transport: Transport, faded: Boolean) {
    val isUdp = transport == Transport.UDP_QSP
    val container =
        if (isUdp) MaterialTheme.colorScheme.primaryContainer else MaterialTheme.colorScheme.surfaceContainerHigh
    val content =
        if (isUdp) MaterialTheme.colorScheme.onPrimaryContainer else MaterialTheme.colorScheme.onSurfaceVariant
    Box(
        modifier = Modifier
            .alpha(if (faded) 0.5f else 1f)
            .background(container, RoundedCornerShape(50))
            .padding(horizontal = 8.dp, vertical = 2.dp),
    ) {
        Text(
            text = when (transport) {
                Transport.TCP -> stringResource(R.string.transport_tcp)
                Transport.UDP_QSP -> stringResource(R.string.transport_udp_qsp)
            },
            style = MaterialTheme.typography.labelSmall,
            color = content,
            fontWeight = FontWeight.SemiBold,
        )
    }
}

/**
 * The detail line's text, or null when the status word alone is enough (idle,
 * fully connected, stopped). Maps the fine-grained [VpnPhase] to a phrase only
 * while work is in progress; while [VpnStatus.Reconnecting] the attempt line
 * takes over (see [reconnectLine]).
 */
@Composable
private fun subtitleFor(state: VpnUiState): String? =
    when (state.status) {
        VpnStatus.PermissionRequired -> stringResource(R.string.sub_permission)
        VpnStatus.Starting, VpnStatus.Running, VpnStatus.Handoff -> phaseStep(state.phase)
        VpnStatus.Reconnecting -> reconnectLine(state)
        VpnStatus.Idle, VpnStatus.Stopped, VpnStatus.Error -> null
    }

/**
 * Phrase for the runtime's current sub-step, shared across the Starting / Running
 * / Handoff / reconnect-attempting states. Null when [phase] has no in-progress
 * step to describe (idle, fully connected, terminal).
 */
@Composable
private fun phaseStep(phase: VpnPhase): String? =
    when (phase) {
        VpnPhase.ConnectingTcp -> stringResource(R.string.sub_link)
        VpnPhase.Authenticating -> stringResource(R.string.sub_auth)
        VpnPhase.UdpDiscovering -> stringResource(R.string.sub_udp_discovering)
        VpnPhase.UdpRegistering -> stringResource(R.string.sub_udp_registering)
        VpnPhase.UdpUpgrading -> stringResource(R.string.sub_udp_upgrading)
        VpnPhase.NetworkHandoff -> stringResource(R.string.sub_handoff)
        VpnPhase.Idle,
        VpnPhase.Starting,
        VpnPhase.Connected,
        VpnPhase.Reconnecting,
        VpnPhase.Stopping,
        VpnPhase.Stopped,
        VpnPhase.Error,
        -> null
    }

/**
 * While [VpnStatus.Reconnecting], the attempt line — always present so it never
 * blinks out. While a backoff is scheduled ([VpnUiState.reconnectDelayMs] set) it
 * counts down from the delay; once the attempt is underway (delay consumed) it
 * shows the bare attempt. Returns null only if no attempt has been recorded.
 */
@Composable
private fun reconnectLine(state: VpnUiState): String? {
    val attempt = state.reconnectAttempt ?: return null
    val delayMs = state.reconnectDelayMs
    return if (delayMs != null) {
        val totalSeconds = ((delayMs + 999UL) / 1000UL).toLong()
        val remainingSeconds by produceState(initialValue = totalSeconds, attempt, delayMs) {
            var left = totalSeconds
            while (left > 0L) {
                delay(1000)
                left -= 1L
                value = left
            }
        }
        stringResource(R.string.reconnect_retry, attempt.toLong(), remainingSeconds)
    } else {
        // Actively attempting: the backoff has been consumed, so keep the attempt
        // visible without a countdown.
        stringResource(R.string.reconnect_attempt, attempt.toLong())
    }
}

@Composable
private fun statusColor(status: VpnStatus): Color {
    val target = when (status) {
        VpnStatus.Running, VpnStatus.Handoff -> MaterialTheme.colorScheme.primary
        VpnStatus.Starting, VpnStatus.Reconnecting, VpnStatus.PermissionRequired ->
            if (isSystemInDarkTheme()) StatusConnectingDark else StatusConnectingLight
        VpnStatus.Error -> MaterialTheme.colorScheme.error
        VpnStatus.Idle, VpnStatus.Stopped -> MaterialTheme.colorScheme.onSurfaceVariant
    }
    return animateColorAsState(target, tween(300), label = "statusColor").value
}

@Composable
private fun statusLabel(status: VpnStatus): String =
    when (status) {
        VpnStatus.Idle -> stringResource(R.string.status_disconnected)
        VpnStatus.PermissionRequired -> stringResource(R.string.status_permission_required)
        VpnStatus.Starting -> stringResource(R.string.status_connecting)
        VpnStatus.Running -> stringResource(R.string.status_connected)
        VpnStatus.Reconnecting -> stringResource(R.string.status_reconnecting)
        VpnStatus.Handoff -> stringResource(R.string.status_switching_network)
        VpnStatus.Stopped -> stringResource(R.string.status_stopped)
        VpnStatus.Error -> stringResource(R.string.status_error)
    }
