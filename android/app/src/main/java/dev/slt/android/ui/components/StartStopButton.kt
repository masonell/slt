package dev.slt.android.ui.components

import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import dev.slt.android.vpn.VpnStatus

/**
 * Hero Start/Stop toggle — a wide pill. Renders "Stop" (and runs [onStop])
 * while the VPN is connecting or running so a stuck connect is always
 * abortable, and "Start" (running [onStart]) otherwise. The label is the action
 * it performs; the connection state is shown by the status line, not here.
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
    Button(
        onClick = if (stopping) onStop else onStart,
        enabled = stopping || canStart,
        shape = RoundedCornerShape(50),
        colors = ButtonDefaults.buttonColors(
            containerColor = if (stopping) {
                MaterialTheme.colorScheme.error
            } else {
                MaterialTheme.colorScheme.primary
            },
            contentColor = if (stopping) {
                MaterialTheme.colorScheme.onError
            } else {
                MaterialTheme.colorScheme.onPrimary
            },
        ),
        modifier = modifier.fillMaxWidth(),
    ) {
        Text(
            text = if (stopping) "Stop" else "Start",
            style = MaterialTheme.typography.headlineSmall,
            fontWeight = FontWeight.SemiBold,
        )
    }
}
