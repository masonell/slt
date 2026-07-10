package dev.slt.android.vpn

import dev.slt.android.profile.DnsMode
import dev.slt.android.profile.DnsSettings
import dev.slt.android.profile.VpnRouteRule
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class VpnBuilderPlanTest {
    @Test
    fun systemDnsLeavesBuilderDnsUnspecified() {
        val plan = createVpnBuilderPlan(
            routes = listOf(VpnRouteRule("0.0.0.0/0", excluded = false)),
            dns = DnsSettings(
                mode = DnsMode.System,
                servers = listOf("1.1.1.1"),
            ),
        )

        assertTrue(plan.dnsServers.isEmpty())
        assertTrue(plan.dnsRouteOperations.isEmpty())
    }

    @Test
    fun customDnsAddsExactConfiguredServers() {
        val plan = createVpnBuilderPlan(
            routes = listOf(VpnRouteRule("0.0.0.0/0", excluded = false)),
            dns = DnsSettings(
                mode = DnsMode.Custom,
                servers = listOf("1.1.1.1", "8.8.8.8"),
            ),
        )

        assertEquals(listOf("1.1.1.1", "8.8.8.8"), plan.dnsServers)
        assertTrue(plan.dnsRouteOperations.isEmpty())
    }

    @Test
    fun plansIncludedExcludedAndRequiredDnsHostRoutes() {
        val plan = createVpnBuilderPlan(
            routes = listOf(
                VpnRouteRule("192.168.1.1/16", excluded = true),
                VpnRouteRule("0.0.0.0/0", excluded = false),
            ),
            dns = DnsSettings(
                mode = DnsMode.Custom,
                servers = listOf("8.8.8.8", "192.168.1.53"),
            ),
        )

        assertEquals(
            listOf(
                VpnRouteOperation(VpnRouteAction.Add, "0.0.0.0/0"),
                VpnRouteOperation(VpnRouteAction.Exclude, "192.168.0.0/16"),
            ),
            plan.profileRouteOperations,
        )
        assertEquals(
            listOf(VpnRouteOperation(VpnRouteAction.Add, "192.168.1.53/32")),
            plan.dnsRouteOperations,
        )
        assertEquals(
            listOf(
                "DNS server 192.168.1.53 is excluded by 192.168.0.0/16; " +
                    "a DNS route will still be added",
            ),
            plan.warnings,
        )
    }
}
