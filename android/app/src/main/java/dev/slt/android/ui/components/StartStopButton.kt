package dev.slt.android.ui.components

import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import dev.slt.android.vpn.VpnStatus

/**
 * Hero Start/Stop toggle — a wide pill. Renders "Stop" (and runs [onStop])
 * while the VPN is connecting or running so a stuck connect is always
 * abortable, and "Start" (running [onStart]) otherwise. The container color
 * animates between primary (Start) and error (Stop), and a spinner shows during
 * connecting.
 */
@Composable
internal fun StartStopButton(
    status: VpnStatus,
    canStart: Boolean,
    onStart: () -> Unit,
    onStop: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val stopping = status == VpnStatus.Starting ||
        status == VpnStatus.Running ||
        status == VpnStatus.Reconnecting
    val connecting = status == VpnStatus.Starting ||
        status == VpnStatus.Reconnecting

    val containerColor by animateColorAsState(
        targetValue = if (stopping) {
            MaterialTheme.colorScheme.error
        } else {
            MaterialTheme.colorScheme.primary
        },
        animationSpec = tween(300),
        label = "containerColor",
    )
    val contentColor by animateColorAsState(
        targetValue = if (stopping) {
            MaterialTheme.colorScheme.onError
        } else {
            MaterialTheme.colorScheme.onPrimary
        },
        animationSpec = tween(300),
        label = "contentColor",
    )

    Button(
        onClick = if (stopping) onStop else onStart,
        enabled = stopping || canStart,
        shape = RoundedCornerShape(50),
        colors = ButtonDefaults.buttonColors(
            containerColor = containerColor,
            contentColor = contentColor,
        ),
        modifier = modifier.fillMaxWidth(),
    ) {
        if (connecting) {
            CircularProgressIndicator(
                modifier = Modifier.size(20.dp),
                strokeWidth = 2.dp,
                color = contentColor,
            )
        } else {
            Text(
                text = if (stopping) "Stop" else "Start",
                style = MaterialTheme.typography.headlineSmall,
                fontWeight = FontWeight.SemiBold,
            )
        }
    }
}
