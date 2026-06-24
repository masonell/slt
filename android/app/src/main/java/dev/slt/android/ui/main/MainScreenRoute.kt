package dev.slt.android.ui.main

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import dev.slt.android.connection.ConnectionTestRunner
import dev.slt.android.profile.ProfileStoreState
import dev.slt.android.ui.UiMessage
import dev.slt.android.vpn.VpnUiState
import kotlinx.coroutines.launch

@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun MainScreenRoute(
    vpnState: VpnUiState,
    profileState: ProfileStoreState?,
    message: UiMessage?,
    onMessageChange: (UiMessage?) -> Unit,
    onStart: () -> Unit,
    onStop: () -> Unit,
    onSelectProfile: (String) -> Unit,
    onOpenProfiles: () -> Unit,
    onOpenLogs: () -> Unit,
) {
    val scope = rememberCoroutineScope()
    val connectionTestRunner = remember { ConnectionTestRunner() }
    var connectionTestState by remember { mutableStateOf(ConnectionTestUiState()) }
    var showResultsSheet by remember { mutableStateOf(false) }

    MainScreen(
        vpnState = vpnState,
        profileState = profileState,
        message = message,
        connectionTestInProgress = connectionTestState.inProgress,
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
                    showResultsSheet = true
                    scope.launch {
                        try {
                            val results = connectionTestRunner.run(result.profile)
                            connectionTestState = completeConnectionTestSuccess(results).state
                            onMessageChange(null)
                        } catch (error: Exception) {
                            val failure = completeConnectionTestFailure(error)
                            connectionTestState = failure.state
                            onMessageChange(failure.message)
                        }
                    }
                }
            }
        },
        onSelectProfile = onSelectProfile,
        onOpenProfiles = {
            connectionTestState = connectionTestState.copy(results = null)
            onMessageChange(null)
            onOpenProfiles()
        },
        onOpenLogs = onOpenLogs,
        onDismissMessage = { onMessageChange(null) },
    )

    if (showResultsSheet) {
        ModalBottomSheet(onDismissRequest = { showResultsSheet = false }) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .verticalScroll(rememberScrollState())
                    .padding(horizontal = 24.dp)
                    .padding(bottom = 24.dp),
            ) {
                ConnectionTestResultsView(
                    results = connectionTestState.results,
                    inProgress = connectionTestState.inProgress,
                )
            }
        }
    }
}
