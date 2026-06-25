package dev.slt.android.ui.main

import dev.slt.android.connection.ConnectionTestEntry
import dev.slt.android.connection.ConnectionTestPhase
import dev.slt.android.profile.SltProfile
import dev.slt.android.ui.UiMessage
import dev.slt.android.vpn.VpnStatus

internal sealed interface ConnectionTestStartResult {
    val state: ConnectionTestUiState

    data class Ready(
        override val state: ConnectionTestUiState,
        val profile: SltProfile,
    ) : ConnectionTestStartResult

    data class Blocked(
        override val state: ConnectionTestUiState,
        val message: UiMessage,
    ) : ConnectionTestStartResult
}

internal fun prepareConnectionTestStart(
    state: ConnectionTestUiState,
    vpnStatus: VpnStatus,
    activeProfile: SltProfile?,
): ConnectionTestStartResult {
    val cleared = state.copy(entries = emptyList())
    return when {
        activeProfile == null -> ConnectionTestStartResult.Blocked(
            state = cleared,
            message = UiMessage.error("No active profile"),
        )
        vpnStatus != VpnStatus.Running -> ConnectionTestStartResult.Blocked(
            state = cleared,
            message = UiMessage.warning("Connect the VPN before running tests"),
        )
        activeProfile.metadata.testUrls.isEmpty() -> ConnectionTestStartResult.Blocked(
            state = cleared,
            message = UiMessage.warning("Active profile has no test URLs"),
        )
        state.inProgress -> ConnectionTestStartResult.Blocked(
            state = state,
            message = UiMessage.info("Connection tests already running"),
        )
        else -> ConnectionTestStartResult.Ready(
            state = ConnectionTestUiState(
                inProgress = true,
                entries = activeProfile.metadata.testUrls.map {
                    ConnectionTestEntry(url = it, phase = ConnectionTestPhase.Resolving)
                },
            ),
            profile = activeProfile,
        )
    }
}
