package dev.slt.android.ui.main

import dev.slt.android.connection.ConnectionTestResult
import dev.slt.android.profile.SltProfile
import dev.slt.android.ui.UiMessage
import dev.slt.android.vpn.VpnStatus

internal sealed interface ConnectionTestStartResult {
    val state: ConnectionTestUiState
    val message: UiMessage

    data class Ready(
        override val state: ConnectionTestUiState,
        override val message: UiMessage,
        val profile: SltProfile,
    ) : ConnectionTestStartResult

    data class Blocked(
        override val state: ConnectionTestUiState,
        override val message: UiMessage,
    ) : ConnectionTestStartResult
}

internal data class ConnectionTestFinishResult(
    val state: ConnectionTestUiState,
    val message: UiMessage,
)

internal fun prepareConnectionTestStart(
    state: ConnectionTestUiState,
    vpnStatus: VpnStatus,
    activeProfile: SltProfile?,
): ConnectionTestStartResult =
    when {
        activeProfile == null -> ConnectionTestStartResult.Blocked(
            state = state.copy(results = null),
            message = UiMessage.error("No active profile"),
        )
        vpnStatus != VpnStatus.Running -> ConnectionTestStartResult.Blocked(
            state = state.copy(results = null),
            message = UiMessage.warning("Connect the VPN before running tests"),
        )
        activeProfile.metadata.testUrls.isEmpty() -> ConnectionTestStartResult.Blocked(
            state = state.copy(results = null),
            message = UiMessage.warning("Active profile has no test URLs"),
        )
        state.inProgress -> ConnectionTestStartResult.Blocked(
            state = state,
            message = UiMessage.info("Connection tests already running"),
        )
        else -> ConnectionTestStartResult.Ready(
            state = ConnectionTestUiState(inProgress = true),
            message = UiMessage.info("Running connection tests"),
            profile = activeProfile,
        )
    }

internal fun completeConnectionTestSuccess(
    results: List<ConnectionTestResult>,
): ConnectionTestFinishResult =
    ConnectionTestFinishResult(
        state = ConnectionTestUiState(results = results),
        message = UiMessage.info("Connection tests finished"),
    )

internal fun completeConnectionTestFailure(error: Throwable): ConnectionTestFinishResult =
    ConnectionTestFinishResult(
        state = ConnectionTestUiState(),
        message = UiMessage.error(error.message ?: error::class.java.simpleName),
    )
