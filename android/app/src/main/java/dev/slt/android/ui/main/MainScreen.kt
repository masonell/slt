package dev.slt.android.ui.main

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowDropDown
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Snackbar
import androidx.compose.material3.SnackbarDuration
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import dev.slt.android.profile.ProfileStoreState
import dev.slt.android.ui.UiMessage
import dev.slt.android.ui.components.StartStopButton
import dev.slt.android.ui.components.StatusLine
import dev.slt.android.vpn.VpnStatus
import dev.slt.android.vpn.VpnUiState

@Composable
internal fun MainScreen(
    vpnState: VpnUiState,
    profileState: ProfileStoreState?,
    message: UiMessage?,
    connectionTestInProgress: Boolean,
    onStart: () -> Unit,
    onStop: () -> Unit,
    onRunConnectionTests: () -> Unit,
    onSelectProfile: (String) -> Unit,
    onOpenProfiles: () -> Unit,
    onOpenLogs: () -> Unit,
    onDismissMessage: () -> Unit,
) {
    val activeProfile = profileState?.activeProfile
    val profiles = profileState?.profiles.orEmpty()
    val status = vpnState.status
    val stopping = status == VpnStatus.Starting ||
        status == VpnStatus.Running ||
        status == VpnStatus.Reconnecting
    val canStart = activeProfile != null && !stopping
    val canTest = activeProfile != null && !connectionTestInProgress
    val otherProfiles = remember(profiles) { profiles.filter { !it.isActive } }
    val switchable = !stopping && otherProfiles.isNotEmpty()
    val activeName = activeProfile?.metadata?.name ?: "No profile"
    var showProfileMenu by remember { mutableStateOf(false) }

    val snackbarHostState = remember { SnackbarHostState() }
    LaunchedEffect(message) {
        message?.let {
            snackbarHostState.showSnackbar(
                message = it.text,
                actionLabel = "Dismiss",
                duration = SnackbarDuration.Short,
            )
            onDismissMessage()
        }
    }

    Scaffold(
        containerColor = MaterialTheme.colorScheme.background,
        snackbarHost = {
            SnackbarHost(snackbarHostState) { snackbarData ->
                Snackbar(
                    snackbarData = snackbarData,
                    containerColor = MaterialTheme.colorScheme.surfaceContainerHigh,
                    contentColor = MaterialTheme.colorScheme.onSurface,
                    actionColor = MaterialTheme.colorScheme.primary,
                )
            }
        },
    ) { innerPadding ->
        Column(modifier = Modifier.fillMaxSize().padding(innerPadding)) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp, vertical = 8.dp),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Box(modifier = Modifier.weight(1f, fill = false)) {
                    Surface(
                        shape = RoundedCornerShape(50),
                        color = MaterialTheme.colorScheme.surfaceVariant,
                        contentColor = MaterialTheme.colorScheme.onSurface,
                    ) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Row(
                                modifier = Modifier
                                    .clickable(enabled = switchable) { showProfileMenu = true }
                                    .padding(start = 14.dp, end = 4.dp, top = 6.dp, bottom = 6.dp),
                                horizontalArrangement = Arrangement.spacedBy(6.dp),
                                verticalAlignment = Alignment.CenterVertically,
                            ) {
                                Text(
                                    text = "Profile",
                                    style = MaterialTheme.typography.labelSmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                )
                                Text(
                                    text = activeName,
                                    style = MaterialTheme.typography.labelLarge,
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis,
                                )
                                if (switchable) {
                                    Icon(
                                        imageVector = Icons.Filled.ArrowDropDown,
                                        contentDescription = null,
                                        modifier = Modifier.size(18.dp),
                                        tint = MaterialTheme.colorScheme.onSurfaceVariant,
                                    )
                                }
                            }
                            if (!stopping) {
                                IconButton(
                                    onClick = onOpenProfiles,
                                    modifier = Modifier.size(40.dp),
                                ) {
                                    Icon(
                                        imageVector = Icons.Filled.Settings,
                                        contentDescription = "Manage profiles",
                                    )
                                }
                            } else {
                                Box(modifier = Modifier.size(width = 12.dp, height = 40.dp))
                            }
                        }
                    }
                    DropdownMenu(
                        expanded = showProfileMenu,
                        onDismissRequest = { showProfileMenu = false },
                    ) {
                        otherProfiles.forEach { profile ->
                            DropdownMenuItem(
                                text = { Text(profile.name) },
                                onClick = {
                                    onSelectProfile(profile.id)
                                    showProfileMenu = false
                                },
                            )
                        }
                    }
                }
                Row(verticalAlignment = Alignment.CenterVertically) {
                    TextButton(
                        onClick = onRunConnectionTests,
                        enabled = canTest,
                        contentPadding = PaddingValues(8.dp),
                    ) {
                        Text(if (connectionTestInProgress) "Testing…" else "Test")
                    }
                    TextButton(
                        onClick = onOpenLogs,
                        contentPadding = PaddingValues(8.dp),
                    ) {
                        Text("Logs")
                    }
                }
            }

            Column(
                modifier = Modifier
                    .weight(1f)
                    .fillMaxWidth()
                    .padding(horizontal = 20.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(16.dp, Alignment.CenterVertically),
            ) {
                StartStopButton(
                    status = status,
                    canStart = canStart,
                    onStart = onStart,
                    onStop = onStop,
                )
                StatusLine(status = status, detail = vpnState.detail, transport = vpnState.transport)
            }
        }
    }
}
