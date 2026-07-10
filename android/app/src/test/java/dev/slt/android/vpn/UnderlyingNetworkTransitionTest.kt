package dev.slt.android.vpn

import dev.slt.android.vpn.UnderlyingNetworkEvent.Lost
import dev.slt.android.vpn.UnderlyingNetworkEvent.Selected
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class UnderlyingNetworkTransitionTest {
    private val unprimed = state<String>(
        current = null,
        reconnectBaseline = null,
        primed = false,
    )

    @Test
    fun initialSelectionSetsBaselineWithoutReconnecting() {
        val transition = applyUnderlyingNetworkEvent(Selected("wifi"), unprimed)

        assertFalse(transition.reconnect)
        assertTrue(transition.networkChanged)
        assertTrue(transition.publishImmediately)
        assertFalse(transition.state.primed)
        assertEquals("wifi", transition.state.current)
        assertEquals("wifi", transition.state.reconnectBaseline)
    }

    @Test
    fun initialLostDoesNotPrimeOrReconnect() {
        val transition = applyUnderlyingNetworkEvent(Lost("wifi"), unprimed)

        assertFalse(transition.reconnect)
        assertFalse(transition.networkChanged)
        assertFalse(transition.publishImmediately)
        assertFalse(transition.state.primed)
        assertNull(transition.state.current)
        assertNull(transition.state.reconnectBaseline)
    }

    @Test
    fun primingCompleteSetsCurrentSelectionAsBaseline() {
        val transition = applyUnderlyingNetworkEvent(
            UnderlyingNetworkEvent.PrimingComplete,
            state(current = "wifi", reconnectBaseline = null, primed = false),
        )

        assertFalse(transition.reconnect)
        assertFalse(transition.networkChanged)
        assertFalse(transition.publishImmediately)
        assertTrue(transition.state.primed)
        assertEquals("wifi", transition.state.current)
        assertEquals("wifi", transition.state.reconnectBaseline)
    }

    @Test
    fun initialBestSelectionReplacesCapturedNetworkWithoutReconnecting() {
        val capturedWifi = state(
            current = "wifi",
            reconnectBaseline = "wifi",
            primed = false,
        )

        val transition = applyUnderlyingNetworkEvent(Selected("cellular"), capturedWifi)

        assertFalse(transition.reconnect)
        assertTrue(transition.networkChanged)
        assertTrue(transition.publishImmediately)
        assertFalse(transition.state.primed)
        assertEquals("cellular", transition.state.current)
        assertEquals("cellular", transition.state.reconnectBaseline)
    }

    @Test
    fun changedBestSelectionReconnectsAndUpdatesCurrentNetwork() {
        val primed = state(
            current = "wifi",
            reconnectBaseline = "wifi",
            primed = true,
        )

        val transition = applyUnderlyingNetworkEvent(Selected("cellular"), primed)

        assertTrue(transition.reconnect)
        assertTrue(transition.networkChanged)
        assertFalse(transition.publishImmediately)
        assertEquals("cellular", transition.state.current)
        assertEquals("wifi", transition.state.reconnectBaseline)
    }

    @Test
    fun unchangedBestSelectionIgnoresBackupAvailability() {
        // Cellular can become available while Android still selects Wi-Fi. The
        // best-matching callback keeps reporting only the Wi-Fi selection.
        val primed = state(
            current = "wifi",
            reconnectBaseline = "wifi",
            primed = true,
        )

        val transition = applyUnderlyingNetworkEvent(Selected("wifi"), primed)

        assertFalse(transition.reconnect)
        assertFalse(transition.networkChanged)
        assertFalse(transition.publishImmediately)
        assertEquals("wifi", transition.state.current)
    }

    @Test
    fun lostCurrentNetworkClearsSelectionAndReconnects() {
        val primed = state(
            current = "wifi",
            reconnectBaseline = "wifi",
            primed = true,
        )

        val transition = applyUnderlyingNetworkEvent(Lost("wifi"), primed)

        assertTrue(transition.reconnect)
        assertTrue(transition.networkChanged)
        assertFalse(transition.publishImmediately)
        assertNull(transition.state.current)
        assertEquals("wifi", transition.state.reconnectBaseline)
    }

    @Test
    fun lostNonCurrentNetworkDoesNotReconnect() {
        val primed = state(
            current = "wifi",
            reconnectBaseline = "wifi",
            primed = true,
        )

        val transition = applyUnderlyingNetworkEvent(Lost("cellular"), primed)

        assertFalse(transition.reconnect)
        assertFalse(transition.networkChanged)
        assertFalse(transition.publishImmediately)
        assertEquals("wifi", transition.state.current)
    }

    @Test
    fun recoveryFromLostSelectionReconnects() {
        val lost = state<String>(
            current = null,
            reconnectBaseline = null,
            primed = true,
        )

        val transition = applyUnderlyingNetworkEvent(Selected("cellular"), lost)

        assertTrue(transition.reconnect)
        assertTrue(transition.networkChanged)
        assertFalse(transition.publishImmediately)
        assertEquals("cellular", transition.state.current)
    }

    @Test
    fun handoffThenLostOldNetworkDoesNotReconnectAgain() {
        val onCellular = state(
            current = "cellular",
            reconnectBaseline = "wifi",
            primed = true,
        )

        val transition = applyUnderlyingNetworkEvent(Lost("wifi"), onCellular)

        assertFalse(transition.reconnect)
        assertFalse(transition.networkChanged)
        assertFalse(transition.publishImmediately)
        assertEquals("cellular", transition.state.current)
    }

    @Test
    fun selectionReturningToBaselineCancelsReconnect() {
        val onWifi = state(
            current = "wifi",
            reconnectBaseline = "wifi",
            primed = true,
        )
        val onCellular = applyUnderlyingNetworkEvent(Selected("cellular"), onWifi)

        val backOnWifi = applyUnderlyingNetworkEvent(Selected("wifi"), onCellular.state)

        assertTrue(onCellular.reconnect)
        assertFalse(onCellular.publishImmediately)
        assertTrue(backOnWifi.networkChanged)
        assertFalse(backOnWifi.publishImmediately)
        assertFalse(backOnWifi.reconnect)
        assertEquals("wifi", backOnWifi.state.current)
        assertEquals("wifi", backOnWifi.state.reconnectBaseline)
    }

    private fun <K> state(
        current: K?,
        reconnectBaseline: K?,
        primed: Boolean,
    ): UnderlyingNetworkState<K> =
        UnderlyingNetworkState(
            current = current,
            reconnectBaseline = reconnectBaseline,
            primed = primed,
        )
}
