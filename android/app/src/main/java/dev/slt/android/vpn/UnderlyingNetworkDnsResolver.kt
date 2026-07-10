package dev.slt.android.vpn

import android.util.Log
import dev.slt.android.uniffi.SltInteropException
import kotlin.concurrent.thread

internal class UnderlyingNetworkDnsResolver<N : Any>(
    private val cache: DnsAddressCache,
    private val currentUnderlyingNetworks: () -> List<N>,
    private val publishUnderlyingNetwork: (N?) -> Unit,
    private val resolveHostOnNetwork: (N, String) -> List<String>,
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
            logWarning("Using cached DNS result for $hostname after live DNS failed")
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
                logWarning("DNS cache warmup failed for $hostname", error)
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
        logWarning("Could not warm DNS cache for $hostname: ${failures.joinToString("; ")}")
    }

    private fun resolveHostOnNetworks(
        hostname: String,
        networks: List<N>,
        failures: MutableList<String>,
    ): ResolvedHost<N>? {
        for (network in networks) {
            try {
                val addresses = resolveHostOnNetwork(network, hostname)
                if (addresses.isNotEmpty()) {
                    return ResolvedHost(network, addresses)
                }
                failures += "network=$network: no addresses returned"
            } catch (error: Exception) {
                logWarning("Failed to resolve $hostname on underlying network=$network", error)
                failures += "network=$network: ${error.message ?: error::class.java.simpleName}"
            }
        }
        return null
    }

    private fun logWarning(message: String, error: Throwable? = null) {
        runCatching {
            if (error == null) {
                Log.w(logTag, message)
            } else {
                Log.w(logTag, message, error)
            }
        }
    }

    private data class ResolvedHost<N>(
        val network: N,
        val addresses: List<String>,
    )
}
