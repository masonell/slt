package dev.slt.android.ui.components

import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import dev.slt.android.R
import dev.slt.android.vpn.VpnStatus

/**
 * Hero Start/Stop toggle — a wide pill that always states what pressing it will
 * do. Renders "Stop" (and runs [onStop]) for the entire time the session is
 * coming up or up — [VpnStatus.Starting], [VpnStatus.Reconnecting],
 * [VpnStatus.Handoff], [VpnStatus.Running] — so a stuck connect is always
 * abortable, and "Start" (running [onStart]) otherwise.
 *
 * The label is always shown: progress (connecting, handoff, reconnect backoff)
 * is the status line's job, not this button's. A bare spinner here would read as
 * "busy, don't touch" — the opposite of the cancel affordance a hung connect
 * needs. The container color animates between primary (Start) and error (Stop).
 *
 * Enabled whenever there is a valid action: always while stopping, and while
 * [canStart] holds otherwise. [VpnStatus.PermissionRequired] keeps it enabled
 * (pressing Start re-runs the Android VPN consent flow) unless there is no
 * active profile.
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
        status == VpnStatus.Reconnecting ||
        status == VpnStatus.Handoff

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
        Text(
            text = stringResource(if (stopping) R.string.action_stop else R.string.action_start),
            style = MaterialTheme.typography.headlineSmall,
            fontWeight = FontWeight.SemiBold,
        )
    }
}
