package dev.slt.android

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

enum class VpnStatus {
    Idle,
    PermissionRequired,
    Starting,
    Running,
    Stopped,
    Error,
}

data class VpnUiState(
    val status: VpnStatus = VpnStatus.Idle,
    val detail: String? = null,
)

object SltVpnStatusBus {
    private val mutableState = MutableStateFlow(VpnUiState())

    val state: StateFlow<VpnUiState> = mutableState.asStateFlow()

    fun update(status: VpnStatus, detail: String? = null) {
        mutableState.value = VpnUiState(status, detail)
    }
}
