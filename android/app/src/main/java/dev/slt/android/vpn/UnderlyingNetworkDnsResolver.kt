package dev.slt.android.vpn

import android.net.Network
import android.util.Log
import dev.slt.android.uniffi.SltInteropException
import kotlin.concurrent.thread

internal class UnderlyingNetworkDnsResolver(
    private val cache: DnsResolutionCache,
    private val currentUnderlyingNetworks: () -> List<Network>,
    private val publishUnderlyingNetwork: (Network?) -> Unit,
    private val logTag: String,
) {
    fun resolveHost(hostname: String): List<String> {
        val networks = currentUnderlyingNetworks()
        if (networks.isEmpty()) {
            throw SltInteropException.Platform("No underlying network available for DNS")
        }

        val failures = mutableListOf<String>()
        val resolved = resolveHostOnNetworks(hostname, networks, failures)
        if (resolved != null) {
            publishUnderlyingNetwork(resolved.network)
            cache.save(hostname, resolved.addresses)
            return resolved.addresses
        }

        val cached = cache.load(hostname)
        if (cached.isNotEmpty()) {
            Log.w(logTag, "Using cached DNS result for $hostname after live DNS failed")
            return cached
        }

        throw SltInteropException.Platform(
            "Failed to resolve $hostname on underlying networks: ${failures.joinToString("; ")}",
        )
    }

    fun warmAsync(hostname: String) {
        thread(name = "slt-dns-cache-warm", isDaemon = true) {
            try {
                warm(hostname)
            } catch (error: Exception) {
                Log.w(logTag, "DNS cache warmup failed for $hostname", error)
            }
        }
    }

    private fun warm(hostname: String) {
        val failures = mutableListOf<String>()
        val resolved = resolveHostOnNetworks(hostname, currentUnderlyingNetworks(), failures)
        if (resolved != null) {
            cache.save(hostname, resolved.addresses)
            return
        }
        Log.w(logTag, "Could not warm DNS cache for $hostname: ${failures.joinToString("; ")}")
    }

    private fun resolveHostOnNetworks(
        hostname: String,
        networks: List<Network>,
        failures: MutableList<String>,
    ): ResolvedHost? {
        for (network in networks) {
            try {
                val addresses = network.getAllByName(hostname)
                    .mapNotNull { it.hostAddress }
                if (addresses.isNotEmpty()) {
                    return ResolvedHost(network, addresses)
                }
                failures += "network=$network: no addresses returned"
            } catch (error: Exception) {
                Log.w(logTag, "Failed to resolve $hostname on underlying network=$network", error)
                failures += "network=$network: ${error.message ?: error::class.java.simpleName}"
            }
        }
        return null
    }

    private data class ResolvedHost(
        val network: Network,
        val addresses: List<String>,
    )
}
