package dev.slt.android.vpn

import dev.slt.android.vpn.UnderlyingNetworkEvent.Available
import dev.slt.android.vpn.UnderlyingNetworkEvent.Lost
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class UnderlyingNetworkTransitionTest {
    private val unprimed = UnderlyingNetworkState<String>(
        current = null,
        available = emptyList(),
        primed = false,
    )

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
            state(current = "wifi", available = listOf("wifi"), primed = false),
        )

        assertFalse(transition.reconnect)
        assertFalse(transition.networkChanged)
        assertTrue(transition.state.primed)
        assertEquals("wifi", transition.state.current)
    }

    @Test
    fun initialExtraAvailableDoesNotReplaceCapturedBaselineOrReconnect() {
        val capturedWifi = state(current = "wifi", available = listOf("wifi"), primed = false)

        val transition = applyUnderlyingNetworkEvent(Available("cellular"), capturedWifi)

        assertFalse(transition.reconnect)
        assertFalse(transition.networkChanged)
        assertFalse(transition.state.primed)
        assertEquals("wifi", transition.state.current)
        assertEquals(listOf("wifi", "cellular"), transition.state.available)
    }

    @Test
    fun initialBurstDoesNotReconnectUntilPrimed() {
        val capturedWifi = state(current = "wifi", available = listOf("wifi"), primed = false)
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
        assertEquals(listOf("wifi", "cellular"), primed.state.available)
    }

    @Test
    fun availableOfDifferentNetworkReconnectsAndUpdatesBaseline() {
        val primed = state(current = "wifi", available = listOf("wifi"), primed = true)

        val transition = applyUnderlyingNetworkEvent(Available("cellular"), primed)

        assertTrue(transition.reconnect)
        assertTrue(transition.networkChanged)
        assertEquals("cellular", transition.state.current)
        assertEquals(listOf("wifi", "cellular"), transition.state.available)
    }

    @Test
    fun availableOfSameNetworkDoesNotReconnect() {
        val primed = state(current = "wifi", available = listOf("wifi"), primed = true)

        val transition = applyUnderlyingNetworkEvent(Available("wifi"), primed)

        assertFalse(transition.reconnect)
        assertFalse(transition.networkChanged)
        assertEquals("wifi", transition.state.current)
    }

    @Test
    fun lostOfCurrentNetworkReconnectsAndFallsBackToAvailableNetwork() {
        val primed = state(
            current = "wifi",
            available = listOf("wifi", "cellular"),
            primed = true,
        )

        val transition = applyUnderlyingNetworkEvent(Lost("wifi"), primed)

        assertTrue(transition.reconnect)
        assertTrue(transition.networkChanged)
        assertEquals("cellular", transition.state.current)
        assertEquals(listOf("cellular"), transition.state.available)
    }

    @Test
    fun lostOfCurrentNetworkClearsBaselineWhenNoFallbackIsAvailable() {
        val primed = state(current = "wifi", available = listOf("wifi"), primed = true)

        val transition = applyUnderlyingNetworkEvent(Lost("wifi"), primed)

        assertTrue(transition.reconnect)
        assertTrue(transition.networkChanged)
        assertNull(transition.state.current)
        assertEquals(emptyList<String>(), transition.state.available)
    }

    @Test
    fun lostOfNonCurrentNetworkDoesNotReconnect() {
        // WiFi is the active path; cellular dropping must not spuriously reconnect.
        val primed = state(
            current = "wifi",
            available = listOf("wifi", "cellular"),
            primed = true,
        )

        val transition = applyUnderlyingNetworkEvent(Lost("cellular"), primed)

        assertFalse(transition.reconnect)
        assertFalse(transition.networkChanged)
        assertEquals("wifi", transition.state.current)
        assertEquals(listOf("wifi"), transition.state.available)
    }

    @Test
    fun recoveryFromLostBaselineReconnects() {
        val lost = state<String>(current = null, available = emptyList(), primed = true)

        val transition = applyUnderlyingNetworkEvent(Available("cellular"), lost)

        assertTrue(transition.reconnect)
        assertTrue(transition.networkChanged)
        assertEquals("cellular", transition.state.current)
    }

    @Test
    fun handoffThenLostOfOldNetworkDoesNotReconnectAgain() {
        // WiFi -> cellular handoff reconnects; the follow-up onLost(wifi) is a
        // non-current loss and must not fire a second transition.
        val onCellular = state(
            current = "cellular",
            available = listOf("wifi", "cellular"),
            primed = true,
        )

        val transition = applyUnderlyingNetworkEvent(Lost("wifi"), onCellular)

        assertFalse(transition.reconnect)
        assertFalse(transition.networkChanged)
        assertEquals("cellular", transition.state.current)
        assertEquals(listOf("cellular"), transition.state.available)
    }

    private fun <K> state(
        current: K?,
        available: List<K>,
        primed: Boolean,
    ): UnderlyingNetworkState<K> =
        UnderlyingNetworkState(current = current, available = available, primed = primed)
}
