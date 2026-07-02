package dev.slt.android.vpn

import dev.slt.android.uniffi.ClientEvent
import dev.slt.android.uniffi.ClientEventKind
import dev.slt.android.uniffi.Transport
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

enum class VpnStatus {
    Idle,
    PermissionRequired,
    Starting,
    Running,
    Reconnecting,
    Handoff,
    Stopped,
    Error,
}

/**
 * Fine-grained runtime phase derived from typed [ClientEventKind]s. Coarser than
 * the full event stream but richer than [VpnStatus]: it tracks what the runtime
 * is doing right now (connecting, authenticating, upgrading to UDP, ...). The UI
 * surfaces it as the connection's current step.
 */
enum class VpnPhase {
    Idle,
    Starting,
    ConnectingTcp,
    Authenticating,
    Connected,
    UdpDiscovering,
    UdpRegistering,
    UdpUpgrading,
    Reconnecting,
    NetworkHandoff,
    Stopping,
    Stopped,
    Error,
}

/**
 * Connection UI state.
 *
 * `status` is the coarse lifecycle (drives button state / color); `phase` is the
 * fine runtime step (drives the subtitle). They are independent: `phase` may
 * advance while `status` is held — e.g. `status = Handoff` with
 * `phase = NetworkHandoff`, or `status = Running` with `phase = UdpUpgrading`.
 */
data class VpnUiState(
    val status: VpnStatus = VpnStatus.Idle,
    val phase: VpnPhase = VpnPhase.Idle,
    /** Most recently reported active data-path transport (surfaced while Running). */
    val transport: Transport? = null,
    /** Most recent reconnect attempt number. */
    val reconnectAttempt: ULong? = null,
    /** Most recent backoff delay (ms) before a reconnect attempt. */
    val reconnectDelayMs: ULong? = null,
    /** Most recent error/failure detail (terminal or recoverable). */
    val lastError: String? = null,
)

/**
 * Terminal outcome of reducing an event, so [SltVpnService] can run platform
 * teardown. The store owns UI state; the service owns the VPN/TUN lifecycle, so
 * it — not the store — performs the side effects these signal.
 */
sealed interface NativeTerminal {
    data object None : NativeTerminal
    data object Stopped : NativeTerminal
    data class Errored(val retryable: Boolean) : NativeTerminal
}

/**
 * Single source of truth for VPN UI state.
 *
 * Runtime events are reduced via [applyEvent]; platform-initiated transitions
 * (the service starting/stopping the tunnel, a denied VPN permission) go through
 * the `mark*` setters since they have no corresponding runtime event.
 *
 * Extension contract: a new [ClientEventKind] variant requires a new arm in
 * [applyEvent] (the `when` is exhaustive, so the build fails otherwise) and, if
 * the variant is terminal, a `NativeTerminal` mapping in the same function.
 */
object SltVpnStatusBus {
    private val mutableState = MutableStateFlow(VpnUiState())

    val state: StateFlow<VpnUiState> = mutableState.asStateFlow()

    /**
     * Reduce one typed native event to a new [VpnUiState], owning all
     * event-derived state including terminal status. Returns whether the event
     * is terminal so the service can react with platform teardown.
     */
    fun applyEvent(event: ClientEvent): NativeTerminal {
        val current = mutableState.value
        val kind = event.kind
        // Terminal status is sticky: a stale in-flight non-terminal event (e.g.
        // `TransportChanged`, `UdpRegistered`) arriving after `Stopped`/`Error`
        // must not resurrect a non-terminal status. The handle guard in
        // [SltVpnService] already rejects cross-session staleness; this makes
        // terminal sticky within a session too. A new session clears terminal
        // status via [markStarting], not through this reducer.
        if (current.status == VpnStatus.Stopped || current.status == VpnStatus.Error) {
            return NativeTerminal.None
        }
        mutableState.value = when (kind) {
            is ClientEventKind.Starting -> current.reset(VpnStatus.Starting, VpnPhase.Starting)
            is ClientEventKind.TunReady ->
                current.withStatusHeld().copy(phase = VpnPhase.Starting)
            is ClientEventKind.Connecting ->
                current
                    .withStatusHeld()
                    .copy(phase = VpnPhase.ConnectingTcp, reconnectDelayMs = null)
            is ClientEventKind.ConnectedTcp ->
                current.withStatusHeld().copy(phase = VpnPhase.ConnectingTcp)
            is ClientEventKind.Authenticating ->
                current.withStatusHeld().copy(phase = VpnPhase.Authenticating)
            is ClientEventKind.Authenticated ->
                current.copy(
                    status = VpnStatus.Running,
                    phase = VpnPhase.Connected,
                    transport = event.transport,
                    reconnectAttempt = null,
                    reconnectDelayMs = null,
                )
            is ClientEventKind.ReconnectScheduled ->
                current.copy(
                    status = VpnStatus.Reconnecting,
                    phase = VpnPhase.Reconnecting,
                    reconnectAttempt = kind.attempt,
                    reconnectDelayMs = kind.delayMs,
                )
            is ClientEventKind.ReconnectFailed ->
                current.copy(
                    status = VpnStatus.Reconnecting,
                    phase = VpnPhase.Reconnecting,
                    reconnectAttempt = kind.attempt,
                    lastError = kind.detail,
                )
            is ClientEventKind.TransportChanged ->
                // A working transport is active again. This is also the fallback
                // path when a UDP path refresh fails but TCP survives: recover any
                // stuck Handoff via recoveredStatus().
                current.copy(status = current.recoveredStatus(), transport = event.transport)
            is ClientEventKind.NetworkChanged ->
                // Distinct from Reconnecting: the tunnel is merely re-establishing its
                // UDP path on a new underlying network, not failing. Keep the transport so
                // the badge stays visible (faded) while the path refreshes. If recovery
                // later fails outright, a subsequent ReconnectScheduled flips this to
                // Reconnecting; if TCP survives, a follow-on operating event below
                // (TransportChanged / UdpDiscovery* / UdpSwitchCommitted / ...) promotes
                // the Handoff back to Running via recoveredStatus().
                current.copy(
                    status = VpnStatus.Handoff,
                    phase = VpnPhase.NetworkHandoff,
                )
            is ClientEventKind.UdpDiscoveryStarted ->
                current.copy(status = current.recoveredStatus(), phase = VpnPhase.UdpDiscovering)
            is ClientEventKind.UdpDiscoveryFailed ->
                // Optional failure (require_udp=false): a retry is scheduled and
                // the session continues on TCP, so drop the in-progress step back
                // to Connected instead of leaving a stale "discovering" phase
                // through the backoff. (With require_udp=true the session closes
                // after this event, so the terminal event overrides the phase.)
                current.copy(
                    status = current.recoveredStatus(),
                    phase = VpnPhase.Connected,
                    lastError = kind.detail,
                )
            is ClientEventKind.UdpRegisterStarted ->
                current.copy(status = current.recoveredStatus(), phase = VpnPhase.UdpRegistering)
            // Registration succeeded (`REGISTER_OK`); the upgrade attempt
            // starts immediately after, so advance to the upgrading phase
            // instead of holding the now-stale "registering" step.
            is ClientEventKind.UdpRegistered ->
                current.copy(status = current.recoveredStatus(), phase = VpnPhase.UdpUpgrading)
            is ClientEventKind.UdpRegisterFailed ->
                // Same as UdpDiscoveryFailed: optional registration failure
                // schedules a retry while staying on TCP.
                current.copy(
                    status = current.recoveredStatus(),
                    phase = VpnPhase.Connected,
                    lastError = kind.detail,
                )
            is ClientEventKind.UdpUpgradeStarted ->
                current.copy(status = current.recoveredStatus(), phase = VpnPhase.UdpUpgrading)
            is ClientEventKind.UdpPathValidated ->
                current.copy(status = current.recoveredStatus(), phase = VpnPhase.UdpUpgrading)
            is ClientEventKind.UdpSwitchCommitted ->
                current.copy(
                    status = current.recoveredStatus(),
                    phase = VpnPhase.Connected,
                    transport = event.transport,
                )
            is ClientEventKind.UdpPathRefreshStarted ->
                current.copy(status = VpnStatus.Handoff, phase = VpnPhase.NetworkHandoff)
            is ClientEventKind.UdpPathRefreshSucceeded ->
                current.copy(status = VpnStatus.Running, phase = VpnPhase.Connected)
            is ClientEventKind.UdpPathRefreshFailed ->
                current.copy(
                    status = VpnStatus.Handoff,
                    phase = VpnPhase.NetworkHandoff,
                    lastError = kind.detail,
                )
            is ClientEventKind.Stopping -> current.copy(phase = VpnPhase.Stopping)
            is ClientEventKind.Stopped ->
                current.reset(VpnStatus.Stopped, VpnPhase.Stopped).copy(transport = null)
            is ClientEventKind.Error ->
                if (kind.retryable) {
                    current.copy(
                        status = VpnStatus.Reconnecting,
                        phase = VpnPhase.Reconnecting,
                        lastError = kind.detail,
                    )
                } else {
                    current.copy(
                        status = VpnStatus.Error,
                        phase = VpnPhase.Error,
                        lastError = kind.detail,
                    )
                }
        }
        return when (kind) {
            is ClientEventKind.Stopped -> NativeTerminal.Stopped
            is ClientEventKind.Error -> NativeTerminal.Errored(kind.retryable)
            else -> NativeTerminal.None
        }
    }

    // --- Platform-initiated transitions (no corresponding runtime event) ---

    /** Tunnel establishment is beginning (foreground service up, awaiting runtime). */
    fun markStarting() {
        mutableState.value = VpnUiState(status = VpnStatus.Starting, phase = VpnPhase.Starting)
    }

    /**
     * Tunnel is already up and the service is resuming into Running. An in-progress
     * sub-phase (e.g. [VpnPhase.UdpUpgrading], [VpnPhase.NetworkHandoff]) is
     * preserved across a service restart; only Idle/Connected phases are promoted.
     */
    fun markRunningForeground() {
        val current = mutableState.value
        mutableState.value =
            if (current.phase == VpnPhase.Idle || current.phase == VpnPhase.Connected) {
                current.copy(status = VpnStatus.Running, phase = VpnPhase.Connected)
            } else {
                current.copy(status = VpnStatus.Running)
            }
    }

    /** Tunnel stopped (user-initiated or revoked). */
    fun markStopped(detail: String) {
        mutableState.value =
            VpnUiState(status = VpnStatus.Stopped, phase = VpnPhase.Stopped, lastError = detail)
    }

    /** Tunnel failed terminally (platform/setup error). */
    fun markError(detail: String) {
        mutableState.value =
            VpnUiState(status = VpnStatus.Error, phase = VpnPhase.Error, lastError = detail)
    }

    /** Native runtime exited but requested Android-level restart after backoff. */
    fun markNativeRestartScheduled(detail: String, attempt: ULong, delayMs: ULong) {
        mutableState.value =
            mutableState.value.copy(
                status = VpnStatus.Reconnecting,
                phase = VpnPhase.Reconnecting,
                reconnectAttempt = attempt,
                reconnectDelayMs = delayMs,
                lastError = detail,
            )
    }

    /** VPN permission was denied or revoked. */
    fun markPermissionRequired(detail: String?) {
        mutableState.value =
            VpnUiState(
                status = VpnStatus.PermissionRequired,
                phase = VpnPhase.Idle,
                lastError = detail,
            )
    }
}

/** Drop all transient fields and start fresh from `status` / `phase`. */
private fun VpnUiState.reset(status: VpnStatus, phase: VpnPhase): VpnUiState =
    VpnUiState(status = status, phase = phase)

/**
 * Hold any already-set non-Idle status, only promoting Idle -> Starting. This
 * matches the runtime's reconnect loop: an in-flight connect attempt must not
 * demote an in-progress Reconnecting back to Starting.
 */
private fun VpnUiState.withStatusHeld(): VpnUiState =
    if (status == VpnStatus.Idle) copy(status = VpnStatus.Starting) else this

/**
 * Status to apply on an event that resumes ordinary connected operation
 * (transport fallback, UDP rediscovery / registration / upgrade / commit). A
 * UDP path refresh that fails while TCP survives is followed by exactly these
 * events, none of which would otherwise change status — leaving the UI stuck on
 * "Switching network…" and profile controls disabled. Any such event promotes a
 * stuck [VpnStatus.Handoff] back to [VpnStatus.Running]; every other status is
 * held as-is, so this is a no-op outside the post-handoff fallback path.
 */
private fun VpnUiState.recoveredStatus(): VpnStatus =
    if (status == VpnStatus.Handoff) VpnStatus.Running else status
