package dev.slt.android.connection

import dev.slt.android.profile.ProfileMetadata
import dev.slt.android.profile.SltProfile
import dev.slt.android.profile.VpnRouteRule
import java.io.IOException
import java.net.InetAddress
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ConnectionTestRunnerTest {
    @Test
    fun expectedPathUsesMostSpecificRouteForAddress() {
        val routes = listOf(
            VpnRouteRule(cidr = "0.0.0.0/0", excluded = false),
            VpnRouteRule(cidr = "10.0.0.0/8", excluded = true),
            VpnRouteRule(cidr = "10.10.0.0/16", excluded = false),
        )

        assertEquals(ExpectedNetworkPath.Vpn, expectedPathForAddress(routes, "10.10.1.1"))
        assertEquals(ExpectedNetworkPath.Direct, expectedPathForAddress(routes, "10.20.1.1"))
        assertEquals(ExpectedNetworkPath.Vpn, expectedPathForAddress(routes, "8.8.8.8"))
    }

    @Test
    fun expectedPathForAddressesReportsMixedDestinations() {
        val routes = listOf(
            VpnRouteRule(cidr = "0.0.0.0/0", excluded = false),
            VpnRouteRule(cidr = "10.0.0.0/8", excluded = true),
        )

        assertEquals(
            ExpectedNetworkPath.Mixed,
            expectedPathForAddresses(
                routes,
                listOf(
                    InetAddress.getByName("8.8.8.8"),
                    InetAddress.getByName("10.1.2.3"),
                ),
            ),
        )
    }

    @Test
    fun runnerStreamsResolvingCheckingDoneWithResolvedAddressesAndStatus() = runBlocking {
        val runner = ConnectionTestRunner(
            resolver = HostResolver { listOf(InetAddress.getByName("8.8.8.8")) },
            httpClient = TestHttpClient { ConnectionTestOutcome.Success(204) },
        )

        val entries = runner.run(
            profile(
                testUrls = listOf("https://example.com/check"),
                routes = listOf(VpnRouteRule(cidr = "0.0.0.0/0", excluded = false)),
            ),
        ).toList()

        assertEquals(
            listOf(ConnectionTestPhase.Resolving, ConnectionTestPhase.Checking, ConnectionTestPhase.Done),
            entries.map { it.phase },
        )
        val done = entries.single { it.phase == ConnectionTestPhase.Done }
        assertEquals("https://example.com/check", done.url)
        assertEquals(listOf("8.8.8.8"), done.resolvedAddresses)
        assertEquals(ExpectedNetworkPath.Vpn, done.expectedPath)
        assertEquals(ConnectionTestOutcome.Success(204), done.outcome)
    }

    @Test
    fun runnerReportsDnsFailureAsDoneEntry() = runBlocking {
        val runner = ConnectionTestRunner(
            resolver = HostResolver { throw IOException("host not found") },
            httpClient = TestHttpClient { ConnectionTestOutcome.Success(200) },
        )

        val entries = runner.run(
            profile(
                testUrls = listOf("https://example.com/check"),
                routes = emptyList(),
            ),
        ).toList()

        assertEquals(
            listOf(ConnectionTestPhase.Resolving, ConnectionTestPhase.Done),
            entries.map { it.phase },
        )
        val done = entries.single { it.phase == ConnectionTestPhase.Done }
        assertEquals("https://example.com/check", done.url)
        assertTrue(done.resolvedAddresses.isEmpty())
        assertEquals(ConnectionTestOutcome.Failure("DNS failed: host not found"), done.outcome)
    }

    private fun profile(
        testUrls: List<String>,
        routes: List<VpnRouteRule>,
    ): SltProfile =
        SltProfile(
            id = "profile-id",
            clientToml = "",
            metadata = ProfileMetadata(
                name = "Test",
                routes = routes,
                testUrls = testUrls,
            ),
        )
}
