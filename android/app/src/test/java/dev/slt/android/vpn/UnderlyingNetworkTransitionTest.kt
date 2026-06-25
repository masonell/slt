package dev.slt.android.vpn

import dev.slt.android.vpn.UnderlyingNetworkEvent.Available
import dev.slt.android.vpn.UnderlyingNetworkEvent.Lost
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class UnderlyingNetworkTransitionTest {
    private val unprimed = UnderlyingNetworkState<String>(current = null, primed = false)

    @Test
    fun initialAvailableSetsFallbackBaselineWithoutReconnecting() {
        val transition = applyUnderlyingNetworkEvent(Available("wifi"), unprimed)

        assertFalse(transition.reconnect)
        assertTrue(transition.networkChanged)
        assertFalse(transition.state.primed)
        assertEquals("wifi", transition.state.current)
    }

    @Test
    fun initialLostDoesNotPrimeOrReconnect() {
        val transition = applyUnderlyingNetworkEvent(Lost("wifi"), unprimed)

        assertFalse(transition.reconnect)
        assertFalse(transition.networkChanged)
        assertFalse(transition.state.primed)
        assertNull(transition.state.current)
    }

    @Test
    fun primingCompletePrimesWithoutReconnecting() {
        val transition = applyUnderlyingNetworkEvent(
            UnderlyingNetworkEvent.PrimingComplete,
            UnderlyingNetworkState(current = "wifi", primed = false),
        )

        assertFalse(transition.reconnect)
        assertFalse(transition.networkChanged)
        assertTrue(transition.state.primed)
        assertEquals("wifi", transition.state.current)
    }

    @Test
    fun initialExtraAvailableDoesNotReplaceCapturedBaselineOrReconnect() {
        val capturedWifi = UnderlyingNetworkState(current = "wifi", primed = false)

        val transition = applyUnderlyingNetworkEvent(Available("cellular"), capturedWifi)

        assertFalse(transition.reconnect)
        assertFalse(transition.networkChanged)
        assertFalse(transition.state.primed)
        assertEquals("wifi", transition.state.current)
    }

    @Test
    fun initialBurstDoesNotReconnectUntilPrimed() {
        val capturedWifi = UnderlyingNetworkState(current = "wifi", primed = false)
        val extraAvailable = applyUnderlyingNetworkEvent(Available("cellular"), capturedWifi)
        val primed = applyUnderlyingNetworkEvent(
            UnderlyingNetworkEvent.PrimingComplete,
            extraAvailable.state,
        )

        assertFalse(extraAvailable.reconnect)
        assertFalse(extraAvailable.networkChanged)
        assertFalse(primed.reconnect)
        assertFalse(primed.networkChanged)
        assertTrue(primed.state.primed)
        assertEquals("wifi", primed.state.current)
    }

    @Test
    fun availableOfDifferentNetworkReconnectsAndUpdatesBaseline() {
        val primed = UnderlyingNetworkState(current = "wifi", primed = true)

        val transition = applyUnderlyingNetworkEvent(Available("cellular"), primed)

        assertTrue(transition.reconnect)
        assertTrue(transition.networkChanged)
        assertEquals("cellular", transition.state.current)
    }

    @Test
    fun availableOfSameNetworkDoesNotReconnect() {
        val primed = UnderlyingNetworkState(current = "wifi", primed = true)

        val transition = applyUnderlyingNetworkEvent(Available("wifi"), primed)

        assertFalse(transition.reconnect)
        assertFalse(transition.networkChanged)
        assertEquals("wifi", transition.state.current)
    }

    @Test
    fun lostOfCurrentNetworkReconnectsAndClearsBaseline() {
        val primed = UnderlyingNetworkState(current = "wifi", primed = true)

        val transition = applyUnderlyingNetworkEvent(Lost("wifi"), primed)

        assertTrue(transition.reconnect)
        assertTrue(transition.networkChanged)
        assertNull(transition.state.current)
    }

    @Test
    fun lostOfNonCurrentNetworkDoesNotReconnect() {
        // WiFi is the active path; cellular dropping must not spuriously reconnect.
        val primed = UnderlyingNetworkState(current = "wifi", primed = true)

        val transition = applyUnderlyingNetworkEvent(Lost("cellular"), primed)

        assertFalse(transition.reconnect)
        assertFalse(transition.networkChanged)
        assertEquals("wifi", transition.state.current)
    }

    @Test
    fun recoveryFromLostBaselineReconnects() {
        val lost = UnderlyingNetworkState<String>(current = null, primed = true)

        val transition = applyUnderlyingNetworkEvent(Available("cellular"), lost)

        assertTrue(transition.reconnect)
        assertTrue(transition.networkChanged)
        assertEquals("cellular", transition.state.current)
    }

    @Test
    fun handoffThenLostOfOldNetworkDoesNotReconnectAgain() {
        // WiFi -> cellular handoff reconnects; the follow-up onLost(wifi) is a
        // non-current loss and must not fire a second transition.
        val onCellular = UnderlyingNetworkState(current = "cellular", primed = true)

        val transition = applyUnderlyingNetworkEvent(Lost("wifi"), onCellular)

        assertFalse(transition.reconnect)
        assertFalse(transition.networkChanged)
        assertEquals("cellular", transition.state.current)
    }
}
