package dev.slt.android.ui.main

import android.content.Context
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.platform.LocalContext
import dev.slt.android.connection.ConnectionTestRunner
import dev.slt.android.profile.ProfileStoreState
import dev.slt.android.ui.UiMessage
import dev.slt.android.vpn.VpnStatus
import dev.slt.android.vpn.VpnUiState
import kotlinx.coroutines.launch

@Composable
internal fun MainScreenRoute(
    vpnState: VpnUiState,
    profileState: ProfileStoreState?,
    message: UiMessage?,
    onMessageChange: (UiMessage?) -> Unit,
    onStart: () -> Unit,
    onStop: () -> Unit,
    onOpenProfiles: () -> Unit,
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val connectionTestRunner = remember { ConnectionTestRunner() }
    var connectionTestState by remember { mutableStateOf(ConnectionTestUiState()) }

    MainScreen(
        vpnState = vpnState,
        profileState = profileState,
        message = message,
        canStop = context.canStopVpn(vpnState.status),
        connectionTestState = connectionTestState,
        onStart = onStart,
        onStop = onStop,
        onRunConnectionTests = {
            when (
                val result = prepareConnectionTestStart(
                    state = connectionTestState,
                    vpnStatus = vpnState.status,
                    activeProfile = profileState?.activeProfile,
                )
            ) {
                is ConnectionTestStartResult.Blocked -> {
                    connectionTestState = result.state
                    onMessageChange(result.message)
                }
                is ConnectionTestStartResult.Ready -> {
                    connectionTestState = result.state
                    onMessageChange(result.message)
                    scope.launch {
                        val finishResult = try {
                            completeConnectionTestSuccess(connectionTestRunner.run(result.profile))
                        } catch (error: Exception) {
                            completeConnectionTestFailure(error)
                        }
                        connectionTestState = finishResult.state
                        onMessageChange(finishResult.message)
                    }
                }
            }
        },
        onOpenProfiles = {
            connectionTestState = connectionTestState.copy(results = null)
            onMessageChange(null)
            onOpenProfiles()
        },
    )
}

private fun Context.canStopVpn(status: VpnStatus): Boolean =
    status == VpnStatus.Starting || status == VpnStatus.Running
