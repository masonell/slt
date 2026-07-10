package dev.slt.android.vpn

import dev.slt.android.uniffi.SocketProtectionResult
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Test

class VpnRuntimePlatformServicesTest {
    @Test
    fun noUnderlyingNetworkReturnsTransientPlatformResult() {
        var bindingAttempted = false
        val result = bindProtectedSocket<String>(
            protected = true,
            currentUnderlyingNetworks = { emptyList() },
            bindSocket = {
                bindingAttempted = true
                SocketProtectionResult.PROTECTED
            },
        )

        assertEquals(SocketProtectionResult.NO_UNDERLYING_NETWORK, result)
        assertFalse(bindingAttempted)
    }

    @Test
    fun protectRejectionDoesNotQueryUnderlyingNetworks() {
        var queriedNetwork = false
        var bindingAttempted = false

        val result = bindProtectedSocket(
            protected = false,
            currentUnderlyingNetworks = {
                queriedNetwork = true
                listOf("wifi")
            },
            bindSocket = {
                bindingAttempted = true
                SocketProtectionResult.PROTECTED
            },
        )

        assertEquals(SocketProtectionResult.PROTECT_REJECTED, result)
        assertFalse(queriedNetwork)
        assertFalse(bindingAttempted)
    }

    @Test
    fun protectedSocketBindsAvailableUnderlyingNetwork() {
        val result = bindProtectedSocket(
            protected = true,
            currentUnderlyingNetworks = { listOf("wifi") },
            bindSocket = { SocketProtectionResult.PROTECTED },
        )

        assertEquals(SocketProtectionResult.PROTECTED, result)
    }

    @Test
    fun bindFailureFallsBackToNextUnderlyingNetwork() {
        val attemptedNetworks = mutableListOf<String>()
        var boundNetwork: String? = null
        val result = bindProtectedSocket(
            protected = true,
            currentUnderlyingNetworks = { listOf("wifi", "cellular") },
            bindSocket = { network ->
                attemptedNetworks += network
                if (network == "wifi") {
                    SocketProtectionResult.BIND_FAILED
                } else {
                    SocketProtectionResult.PROTECTED
                }
            },
            onBound = { network -> boundNetwork = network },
        )

        assertEquals(SocketProtectionResult.PROTECTED, result)
        assertEquals(listOf("wifi", "cellular"), attemptedNetworks)
        assertEquals("cellular", boundNetwork)
    }

    @Test
    fun fallbackBindingDoesNotBecomePreferredForNextSocket() {
        val attemptedNetworks = mutableListOf<String>()
        var wifiAcceptsBinding = false
        val currentUnderlyingNetworks = { listOf("wifi", "cellular") }
        val bindSocket = { network: String ->
            attemptedNetworks += network
            if (network == "wifi" && !wifiAcceptsBinding) {
                SocketProtectionResult.BIND_FAILED
            } else {
                SocketProtectionResult.PROTECTED
            }
        }

        assertEquals(
            SocketProtectionResult.PROTECTED,
            bindProtectedSocket(
                protected = true,
                currentUnderlyingNetworks = currentUnderlyingNetworks,
                bindSocket = bindSocket,
            ),
        )

        wifiAcceptsBinding = true
        assertEquals(
            SocketProtectionResult.PROTECTED,
            bindProtectedSocket(
                protected = true,
                currentUnderlyingNetworks = currentUnderlyingNetworks,
                bindSocket = bindSocket,
            ),
        )
        assertEquals(listOf("wifi", "cellular", "wifi"), attemptedNetworks)
    }

    @Test
    fun allBindFailuresReturnBindFailed() {
        val attemptedNetworks = mutableListOf<String>()
        var boundNetwork: String? = null
        val result = bindProtectedSocket(
            protected = true,
            currentUnderlyingNetworks = { listOf("wifi", "cellular") },
            bindSocket = { network ->
                attemptedNetworks += network
                SocketProtectionResult.BIND_FAILED
            },
            onBound = { network -> boundNetwork = network },
        )

        assertEquals(SocketProtectionResult.BIND_FAILED, result)
        assertEquals(listOf("wifi", "cellular"), attemptedNetworks)
        assertNull(boundNetwork)
    }
}
