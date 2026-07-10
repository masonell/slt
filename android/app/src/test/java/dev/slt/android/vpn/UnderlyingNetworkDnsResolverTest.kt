package dev.slt.android.vpn

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class UnderlyingNetworkDnsResolverTest {
    @Test
    fun fallsThroughStaleNetworkAndPublishesSuccessfulNetwork() {
        val cache = FakeDnsAddressCache()
        val attempts = mutableListOf<String>()
        var published: String? = null
        val resolver = resolver(
            cache = cache,
            networks = { listOf("stale-wifi", "cellular") },
            publish = { published = it },
            resolve = { network, _ ->
                attempts += network
                if (network == "stale-wifi") {
                    throw IllegalStateException("network lost")
                }
                listOf("192.0.2.10", "2001:db8::10")
            },
        )

        val addresses = resolver.resolveHost(HOSTNAME)

        assertEquals(listOf("stale-wifi", "cellular"), attempts)
        assertEquals(listOf("192.0.2.10", "2001:db8::10"), addresses)
        assertEquals("cellular", published)
        assertEquals(addresses, cache.load(HOSTNAME))
    }

    @Test
    fun usesCachedAddressesAfterAllLiveNetworksFail() {
        val cache = FakeDnsAddressCache(
            mutableMapOf(HOSTNAME to listOf("198.51.100.8")),
        )
        var published: String? = null
        val resolver = resolver(
            cache = cache,
            networks = { listOf("wifi", "cellular") },
            publish = { published = it },
            resolve = { _, _ -> throw IllegalStateException("lookup failed") },
        )

        assertEquals(listOf("198.51.100.8"), resolver.resolveHost(HOSTNAME))
        assertNull(published)
    }

    @Test
    fun liveResolutionReplacesCachedAddresses() {
        val cache = FakeDnsAddressCache(
            mutableMapOf(HOSTNAME to listOf("198.51.100.8")),
        )
        val resolver = resolver(
            cache = cache,
            networks = { listOf("wifi") },
            resolve = { _, _ -> listOf("203.0.113.4") },
        )

        assertEquals(listOf("203.0.113.4"), resolver.resolveHost(HOSTNAME))
        assertEquals(listOf("203.0.113.4"), cache.load(HOSTNAME))
    }

    @Test
    fun rechecksNetworkSnapshotWhenConnectivityArrivesLate() {
        val cache = FakeDnsAddressCache()
        var networks = emptyList<String>()
        val resolver = resolver(
            cache = cache,
            networks = { networks },
            resolve = { _, _ -> listOf("192.0.2.22") },
        )

        val initialFailure = runCatching { resolver.resolveHost(HOSTNAME) }.exceptionOrNull()
        assertTrue(initialFailure?.message?.contains("No underlying network available") == true)

        networks = listOf("wifi")

        assertEquals(listOf("192.0.2.22"), resolver.resolveHost(HOSTNAME))
    }

    @Test
    fun reportsEveryFailedNetworkWhenNoCacheExists() {
        val resolver = resolver(
            cache = FakeDnsAddressCache(),
            networks = { listOf("wifi", "cellular") },
            resolve = { network, _ ->
                if (network == "wifi") emptyList() else throw IllegalStateException("offline")
            },
        )

        val failure = runCatching { resolver.resolveHost(HOSTNAME) }.exceptionOrNull()

        assertTrue(failure?.message?.contains("network=wifi: no addresses returned") == true)
        assertTrue(failure?.message?.contains("network=cellular: offline") == true)
    }

    private fun resolver(
        cache: DnsAddressCache,
        networks: () -> List<String>,
        publish: (String?) -> Unit = {},
        resolve: (String, String) -> List<String>,
    ): UnderlyingNetworkDnsResolver<String> =
        UnderlyingNetworkDnsResolver(
            cache = cache,
            currentUnderlyingNetworks = networks,
            publishUnderlyingNetwork = publish,
            resolveHostOnNetwork = resolve,
            logTag = "UnderlyingNetworkDnsResolverTest",
        )

    private class FakeDnsAddressCache(
        private val entries: MutableMap<String, List<String>> = mutableMapOf(),
    ) : DnsAddressCache {
        override fun save(hostname: String, addresses: List<String>) {
            entries[hostname] = addresses
        }

        override fun load(hostname: String): List<String> = entries[hostname].orEmpty()
    }

    private companion object {
        const val HOSTNAME = "server.example"
    }
}
