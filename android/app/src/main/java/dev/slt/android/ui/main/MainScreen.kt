package dev.slt.android.ui.main

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import dev.slt.android.ui.profile.ProfileStoreState
import dev.slt.android.vpn.VpnStatus
import dev.slt.android.vpn.VpnUiState
import dev.slt.android.ui.UiMessage
import dev.slt.android.ui.uiMessageColor

@Composable
internal fun MainScreen(
    vpnState: VpnUiState,
    profileState: ProfileStoreState?,
    message: UiMessage?,
    canStop: Boolean,
    onStart: () -> Unit,
    onStop: () -> Unit,
    onOpenProfiles: () -> Unit,
) {
    val activeProfile = profileState?.activeProfile
    val canStart = activeProfile != null &&
        vpnState.status != VpnStatus.Starting &&
        vpnState.status != VpnStatus.Running

    Column(
        modifier = Modifier
            .fillMaxSize()
            .statusBarsPadding()
            .navigationBarsPadding()
            .padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(18.dp),
    ) {
        Text(
            text = "SLT",
            style = MaterialTheme.typography.headlineLarge,
            fontWeight = FontWeight.SemiBold,
        )
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .clickable(onClick = onOpenProfiles),
        ) {
            Text(
                text = "Active profile",
                style = MaterialTheme.typography.labelLarge,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Text(
                text = activeProfile?.metadata?.name ?: "No active profile",
                style = MaterialTheme.typography.titleLarge,
            )
        }
        Column {
            Text(
                text = statusLabel(vpnState),
                style = MaterialTheme.typography.titleMedium,
            )
            vpnState.detail?.let { detail ->
                Spacer(modifier = Modifier.height(6.dp))
                Text(
                    text = detail,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
        message?.let {
            Text(
                text = it.text,
                style = MaterialTheme.typography.bodyMedium,
                color = uiMessageColor(it),
            )
        }
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(12.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Button(
                onClick = onStart,
                enabled = canStart,
                modifier = Modifier.weight(1f),
            ) {
                Text("Connect")
            }
            OutlinedButton(
                onClick = onStop,
                enabled = canStop,
                modifier = Modifier.weight(1f),
            ) {
                Text("Disconnect")
            }
        }
    }
}

private fun statusLabel(state: VpnUiState): String =
    when (state.status) {
        VpnStatus.Idle -> "Idle"
        VpnStatus.PermissionRequired -> "Permission required"
        VpnStatus.Starting -> "Connecting"
        VpnStatus.Running -> "Connected"
        VpnStatus.Stopped -> "Stopped"
        VpnStatus.Error -> "Error"
    }
