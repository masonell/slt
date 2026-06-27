package dev.slt.android.vpn

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

enum class VpnStatus {
    Idle,
    PermissionRequired,
    Starting,
    Running,
    Reconnecting,
    Stopped,
    Error,
}

data class VpnUiState(
    val status: VpnStatus = VpnStatus.Idle,
    val detail: String? = null,
    /// Active transport label ("TCP" / "UDP-QSP") surfaced from typed
    /// `TransportChanged` events while the session is Running.
    val transport: String? = null,
)

object SltVpnStatusBus {
    private val mutableState = MutableStateFlow(VpnUiState())

    val state: StateFlow<VpnUiState> = mutableState.asStateFlow()

    /// Update status and optional detail. The transport indicator is preserved
    /// across updates while Running and cleared on any other status unless an
    /// explicit `transport` is supplied.
    fun update(status: VpnStatus, detail: String? = null, transport: String? = null) {
        val resolvedTransport = when {
            transport != null -> transport
            status == VpnStatus.Running -> mutableState.value.transport
            else -> null
        }
        mutableState.value = VpnUiState(status, detail, resolvedTransport)
    }

    /// Refine only the transport indicator, leaving status/detail untouched.
    fun updateTransport(transport: String?) {
        mutableState.value = mutableState.value.copy(transport = transport)
    }
}
