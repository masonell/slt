package dev.slt.android.vpn

import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class UnderlyingNetworkPublicationTest {
    @Test
    fun configuresKnownInitialNetwork() {
        var configuredNetworks: List<String>? = null

        configureInitialUnderlyingNetwork("wifi") { networks ->
            configuredNetworks = networks
        }

        assertEquals(listOf("wifi"), configuredNetworks)
    }

    @Test
    fun leavesBuilderDefaultWhenInitialNetworkIsUnknown() {
        var configuredNetworks: List<String>? = null

        configureInitialUnderlyingNetwork(null) { networks: List<String> ->
            configuredNetworks = networks
        }

        assertNull(configuredNetworks)
    }

    @Test
    fun publishesLiveUpdatesAndClearsLostNetworkBeforeSocketsBind() {
        val publications = mutableListOf<List<String>>()
        val publish = { networks: List<String> ->
            publications += networks
            true
        }

        assertTrue(
            publishLiveUnderlyingNetworks(
                liveUnderlyingNetworks(
                    "wifi",
                    emptyMap<String, String>(),
                ),
                publish,
            ),
        )
        assertTrue(
            publishLiveUnderlyingNetworks(
                liveUnderlyingNetworks(
                    "cellular",
                    emptyMap<String, String>(),
                ),
                publish,
            ),
        )
        assertTrue(
            publishLiveUnderlyingNetworks(
                liveUnderlyingNetworks(
                    null,
                    emptyMap<String, String>(),
                ),
                publish,
            ),
        )

        assertEquals(
            listOf(listOf("wifi"), listOf("cellular"), emptyList()),
            publications,
        )
    }

    @Test
    fun reportsRejectedLivePublication() {
        val published = publishLiveUnderlyingNetworks(listOf("wifi")) { false }

        assertFalse(published)
    }

    @Test
    fun publishesFallbackNetworkThatAcceptedSocket() {
        val networks = liveUnderlyingNetworks(
            selectedNetwork = "wifi",
            boundNetworks = mapOf("tcp" to "cellular"),
        )

        assertEquals(listOf("cellular"), networks)
    }

    @Test
    fun publishesAllNetworksCarryingTcpAndUdpSockets() {
        val networks = liveUnderlyingNetworks(
            selectedNetwork = "cellular",
            boundNetworks = mapOf(
                "tcp" to "wifi",
                "udp" to "cellular",
            ),
        )

        assertEquals(listOf("cellular", "wifi"), networks)
    }

    @Test
    fun sequencesStateUpdatesWithPlatformPublications() {
        val firstPublicationStarted = CountDownLatch(1)
        val releaseFirstPublication = CountDownLatch(1)
        val secondAttemptStarted = CountDownLatch(1)
        val secondStateUpdated = CountDownLatch(1)
        val state = AtomicReference<String?>()
        val publications = CopyOnWriteArrayList<List<String>>()
        val sequencer = UnderlyingNetworkPublicationSequencer()
        val executor = Executors.newFixedThreadPool(2)

        try {
            val first = executor.submit<Boolean> {
                sequencer.sequence {
                    state.set("wifi")
                    publishLiveUnderlyingNetworks(listOf("wifi")) { networks ->
                        firstPublicationStarted.countDown()
                        check(releaseFirstPublication.await(5, TimeUnit.SECONDS))
                        publications += networks
                        true
                    }
                }
            }
            assertTrue(firstPublicationStarted.await(5, TimeUnit.SECONDS))

            val second = executor.submit<Boolean> {
                secondAttemptStarted.countDown()
                sequencer.sequence {
                    state.set("cellular")
                    secondStateUpdated.countDown()
                    publishLiveUnderlyingNetworks(listOf("cellular")) { networks ->
                        publications += networks
                        true
                    }
                }
            }
            assertTrue(secondAttemptStarted.await(5, TimeUnit.SECONDS))
            assertFalse(secondStateUpdated.await(200, TimeUnit.MILLISECONDS))
            assertEquals("wifi", state.get())

            releaseFirstPublication.countDown()
            assertTrue(first.get(5, TimeUnit.SECONDS))
            assertTrue(second.get(5, TimeUnit.SECONDS))
            assertEquals("cellular", state.get())
            assertEquals(
                listOf(listOf("wifi"), listOf("cellular")),
                publications,
            )
        } finally {
            releaseFirstPublication.countDown()
            executor.shutdownNow()
        }
    }
}
