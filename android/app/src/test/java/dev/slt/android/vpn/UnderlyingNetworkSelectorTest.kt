package dev.slt.android.vpn

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class UnderlyingNetworkSelectorTest {
    @Test
    fun selectsDefaultNetworkWhenDefaultIsUsableUnderlyingNetwork() {
        val selected = selectInitialUnderlyingNetwork(
            listOf(
                candidate("wifi", isDefault = true, hasInternet = true, isVpn = false),
                candidate("cellular", isDefault = false, hasInternet = true, isVpn = false),
            ),
        )

        assertEquals("wifi", selected)
    }

    @Test
    fun keepsDefaultWifiAheadOfAvailableCellularBackup() {
        val selected = selectUnderlyingNetworks(
            listOf(
                candidate("cellular", isDefault = false, hasInternet = true, isVpn = false),
                candidate("wifi", isDefault = true, hasInternet = true, isVpn = false),
            ),
        )

        assertEquals(listOf("wifi", "cellular"), selected)
    }

    @Test
    fun skipsDefaultVpnAndSelectsNonVpnInternetNetwork() {
        val selected = selectInitialUnderlyingNetwork(
            listOf(
                candidate("other-vpn", isDefault = true, hasInternet = true, isVpn = true),
                candidate("wifi", isDefault = false, hasInternet = true, isVpn = false),
            ),
        )

        assertEquals("wifi", selected)
    }

    @Test
    fun orderedNetworksSkipVpnAndNetworksWithoutInternet() {
        val selected = selectUnderlyingNetworks(
            listOf(
                candidate("other-vpn", isDefault = true, hasInternet = true, isVpn = true),
                candidate("wifi-direct", isDefault = false, hasInternet = false, isVpn = false),
                candidate("cellular", isDefault = false, hasInternet = true, isVpn = false),
                candidate("wifi", isDefault = false, hasInternet = true, isVpn = false),
            ),
        )

        assertEquals(listOf("cellular", "wifi"), selected)
    }

    @Test
    fun skipsNetworksWithoutInternet() {
        val selected = selectInitialUnderlyingNetwork(
            listOf(
                candidate("wifi-direct", isDefault = true, hasInternet = false, isVpn = false),
                candidate("cellular", isDefault = false, hasInternet = true, isVpn = false),
            ),
        )

        assertEquals("cellular", selected)
    }

    @Test
    fun returnsNullWhenOnlyVpnNetworksAreAvailable() {
        val selected = selectInitialUnderlyingNetwork(
            listOf(
                candidate("other-vpn", isDefault = true, hasInternet = true, isVpn = true),
            ),
        )

        assertNull(selected)
    }

    @Test
    fun toleratesUnknownCapabilitiesForStartupFallback() {
        val selected = selectInitialUnderlyingNetwork(
            listOf(
                candidate("unknown", isDefault = true, hasInternet = null, isVpn = null),
            ),
        )

        assertEquals("unknown", selected)
    }

    private fun candidate(
        network: String,
        isDefault: Boolean,
        hasInternet: Boolean?,
        isVpn: Boolean?,
    ): UnderlyingNetworkCandidate<String> =
        UnderlyingNetworkCandidate(
            network = network,
            isDefault = isDefault,
            hasInternet = hasInternet,
            isVpn = isVpn,
        )
}
