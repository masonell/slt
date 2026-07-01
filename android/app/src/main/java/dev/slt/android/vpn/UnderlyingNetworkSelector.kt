package dev.slt.android.vpn

import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.util.Log

internal data class UnderlyingNetworkCandidate<K>(
    val network: K,
    val isDefault: Boolean,
    val hasInternet: Boolean?,
    val isVpn: Boolean?,
)

internal fun <K> selectInitialUnderlyingNetwork(
    candidates: List<UnderlyingNetworkCandidate<K>>,
): K? =
    candidates.firstOrNull { it.isDefault && it.canCarryVpnSocket() }?.network
        ?: candidates.firstOrNull { it.canCarryVpnSocket() }?.network

private fun <K> UnderlyingNetworkCandidate<K>.canCarryVpnSocket(): Boolean =
    hasInternet != false && isVpn != true

// `allNetworks` is deprecated in favor of callback APIs, but startup needs a
// synchronous snapshot before Rust opens the first protected transport socket.
@Suppress("DEPRECATION")
internal fun ConnectivityManager?.findInitialUnderlyingNetwork(logTag: String): Network? {
    val manager = this
    if (manager == null) {
        Log.w(logTag, "No ConnectivityManager; initial underlying network unavailable")
        return null
    }

    val defaultNetwork = manager.activeNetwork
    val networks = (manager.allNetworks.toList() + listOfNotNull(defaultNetwork)).distinct()
    val selected = selectInitialUnderlyingNetwork(
        networks.map { network ->
            val capabilities = try {
                manager.getNetworkCapabilities(network)
            } catch (error: RuntimeException) {
                Log.w(logTag, "Failed to inspect network capabilities", error)
                null
            }
            UnderlyingNetworkCandidate(
                network = network,
                isDefault = network == defaultNetwork,
                hasInternet = capabilities?.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET),
                isVpn = capabilities.isVpnNetwork(),
            )
        },
    )

    if (selected == null) {
        Log.w(logTag, "No initial non-VPN underlying network available")
    }
    return selected
}

private fun NetworkCapabilities?.isVpnNetwork(): Boolean? =
    this?.let { capabilities ->
        capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN) ||
            !capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
    }
