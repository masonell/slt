package dev.slt.android.vpn

import dev.slt.android.uniffi.SocketProtectionResult
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test

class VpnRuntimePlatformServicesTest {
    @Test
    fun noUnderlyingNetworkReturnsTransientPlatformResult() {
        val selection = selectSocketBinding<String>(protected = true) { null }

        assertEquals(
            SocketBindingSelection.Failure(SocketProtectionResult.NO_UNDERLYING_NETWORK),
            selection,
        )
    }

    @Test
    fun protectRejectionDoesNotQueryUnderlyingNetworks() {
        var queriedNetwork = false

        val selection = selectSocketBinding(
            protected = false,
            currentUnderlyingNetwork = {
                queriedNetwork = true
                "wifi"
            },
        )

        assertEquals(
            SocketBindingSelection.Failure(SocketProtectionResult.PROTECT_REJECTED),
            selection,
        )
        assertFalse(queriedNetwork)
    }

    @Test
    fun protectedSocketSelectsAvailableUnderlyingNetwork() {
        val selection = selectSocketBinding(protected = true) { "wifi" }

        assertEquals(SocketBindingSelection.Ready("wifi"), selection)
    }
}
