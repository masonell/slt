package dev.slt.android.vpn

import dev.slt.android.uniffi.ClientEvent
import dev.slt.android.uniffi.ClientEventKind
import dev.slt.android.uniffi.Transport
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Before
import org.junit.Test

/**
 * Exercises the pure [SltVpnStatusBus.applyEvent] reducer: terminal detection,
 * reconnect attempt/delay capture, the Idle→Starting / hold-Reconnecting rule,
 * and transport surfacing. `applyEvent(Starting)` resets to a fresh state, so
 * each test begins from a known point on the shared singleton.
 */
class VpnStatusReducerTest {
    @Before
    fun resetState() {
        SltVpnStatusBus.applyEvent(event(ClientEventKind.Starting))
    }

    @Test
    fun starting_resets_transient_fields_and_is_non_terminal() {
        SltVpnStatusBus.applyEvent(
            event(ClientEventKind.ReconnectScheduled(attempt = 3UL, delayMs = 750UL)),
        )

        val terminal = SltVpnStatusBus.applyEvent(event(ClientEventKind.Starting))
        val state = SltVpnStatusBus.state.value

        assertEquals(VpnStatus.Starting, state.status)
        assertEquals(VpnPhase.Starting, state.phase)
        assertNull(state.reconnectAttempt)
        assertNull(state.reconnectDelayMs)
        assertNull(state.lastError)
        assertEquals(NativeTerminal.None, terminal)
    }

    @Test
    fun authenticated_transitions_to_running_with_transport() {
        val terminal =
            SltVpnStatusBus.applyEvent(event(ClientEventKind.Authenticated, transport = Transport.TCP))
        val state = SltVpnStatusBus.state.value

        assertEquals(VpnStatus.Running, state.status)
        assertEquals(VpnPhase.Connected, state.phase)
        assertEquals(Transport.TCP, state.transport)
        assertEquals(NativeTerminal.None, terminal)
    }

    @Test
    fun reconnectScheduled_captures_attempt_and_delay() {
        SltVpnStatusBus.applyEvent(
            event(ClientEventKind.ReconnectScheduled(attempt = 2UL, delayMs = 500UL)),
        )

        val state = SltVpnStatusBus.state.value
        assertEquals(VpnStatus.Reconnecting, state.status)
        assertEquals(VpnPhase.Reconnecting, state.phase)
        assertEquals(2UL, state.reconnectAttempt)
        assertEquals(500UL, state.reconnectDelayMs)
    }

    @Test
    fun reconnectFailed_records_attempt_and_error() {
        SltVpnStatusBus.applyEvent(
            event(ClientEventKind.ReconnectFailed(attempt = 2UL, detail = "timed out")),
        )

        val state = SltVpnStatusBus.state.value
        assertEquals(VpnStatus.Reconnecting, state.status)
        assertEquals(2UL, state.reconnectAttempt)
        assertEquals("timed out", state.lastError)
    }

    @Test
    fun connecting_holds_reconnecting_and_clears_delay() {
        SltVpnStatusBus.applyEvent(
            event(ClientEventKind.ReconnectScheduled(attempt = 2UL, delayMs = 500UL)),
        )
        SltVpnStatusBus.applyEvent(event(ClientEventKind.Connecting(attempt = 2UL)))

        val state = SltVpnStatusBus.state.value
        assertEquals(VpnStatus.Reconnecting, state.status)
        assertEquals(VpnPhase.ConnectingTcp, state.phase)
        assertEquals(2UL, state.reconnectAttempt)
        assertNull(state.reconnectDelayMs)
    }

    @Test
    fun stopped_is_terminal_and_clears_transport() {
        SltVpnStatusBus.applyEvent(event(ClientEventKind.Authenticated, transport = Transport.TCP))

        val terminal = SltVpnStatusBus.applyEvent(event(ClientEventKind.Stopped))
        val state = SltVpnStatusBus.state.value

        assertEquals(VpnStatus.Stopped, state.status)
        assertEquals(VpnPhase.Stopped, state.phase)
        assertNull(state.transport)
        assertEquals(NativeTerminal.Stopped, terminal)
    }

    @Test
    fun error_is_terminal_and_records_detail() {
        val terminal =
            SltVpnStatusBus.applyEvent(event(ClientEventKind.Error(detail = "auth rejected")))
        val state = SltVpnStatusBus.state.value

        assertEquals(VpnStatus.Error, state.status)
        assertEquals(VpnPhase.Error, state.phase)
        assertEquals("auth rejected", state.lastError)
        assertEquals(NativeTerminal.Errored, terminal)
    }

    @Test
    fun udpSwitchCommitted_surfaces_transport_and_connected_phase() {
        SltVpnStatusBus.applyEvent(event(ClientEventKind.Authenticated, transport = Transport.TCP))
        SltVpnStatusBus.applyEvent(
            event(ClientEventKind.UdpSwitchCommitted(upgradeId = 1UL), transport = Transport.UDP_QSP),
        )

        val state = SltVpnStatusBus.state.value
        assertEquals(VpnStatus.Running, state.status)
        assertEquals(VpnPhase.Connected, state.phase)
        assertEquals(Transport.UDP_QSP, state.transport)
    }

    @Test
    fun udpDiscoveryFailed_resets_phase_to_connected_and_keeps_running() {
        SltVpnStatusBus.applyEvent(event(ClientEventKind.Authenticated, transport = Transport.TCP))
        SltVpnStatusBus.applyEvent(event(ClientEventKind.UdpDiscoveryStarted))
        SltVpnStatusBus.applyEvent(event(ClientEventKind.UdpDiscoveryFailed(detail = "no dcid")))

        val state = SltVpnStatusBus.state.value
        assertEquals(VpnStatus.Running, state.status)
        // Not stuck on UdpDiscovering through the backoff: back to Connected.
        assertEquals(VpnPhase.Connected, state.phase)
        assertEquals("no dcid", state.lastError)
    }

    @Test
    fun udpRegisterFailed_resets_phase_to_connected_and_keeps_running() {
        SltVpnStatusBus.applyEvent(event(ClientEventKind.Authenticated, transport = Transport.TCP))
        SltVpnStatusBus.applyEvent(event(ClientEventKind.UdpRegisterStarted))
        SltVpnStatusBus.applyEvent(event(ClientEventKind.UdpRegisterFailed(detail = "rejected")))

        val state = SltVpnStatusBus.state.value
        assertEquals(VpnStatus.Running, state.status)
        assertEquals(VpnPhase.Connected, state.phase)
        assertEquals("rejected", state.lastError)
    }

    private fun event(kind: ClientEventKind, transport: Transport? = null): ClientEvent =
        ClientEvent(handle = 1UL, seq = 1UL, transport = transport, kind = kind)
}
