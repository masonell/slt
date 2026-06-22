package dev.slt.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class VpnRouteRulesTest {
    @Test
    fun parsesCanonicalizesDeduplicatesAndSortsRoutes() {
        val routes = parseVpnRouteRules(
            """
            # include through VPN
            10.10.1.8/16
            0.0.0.0/0
            10.10.0.1/16

            # exclude from VPN
            !192.168.1.1/16
            !10.0.0.1/8
            !10.0.0.0/8
            """.trimIndent(),
        )

        assertEquals(
            listOf(
                VpnRouteRule(cidr = "0.0.0.0/0", excluded = false),
                VpnRouteRule(cidr = "10.10.0.0/16", excluded = false),
                VpnRouteRule(cidr = "10.0.0.0/8", excluded = true),
                VpnRouteRule(cidr = "192.168.0.0/16", excluded = true),
            ),
            routes,
        )
    }

    @Test
    fun allowsOverlappingDifferentPrefixRoutes() {
        val routes = parseVpnRouteRules(
            """
            0.0.0.0/0
            !10.0.0.0/8
            10.10.0.0/16
            """.trimIndent(),
        )

        assertEquals(
            listOf(
                VpnRouteRule(cidr = "0.0.0.0/0", excluded = false),
                VpnRouteRule(cidr = "10.10.0.0/16", excluded = false),
                VpnRouteRule(cidr = "10.0.0.0/8", excluded = true),
            ),
            routes,
        )
    }

    @Test
    fun removesSameActionRoutesCoveredByBroaderRoutes() {
        val routes = parseVpnRouteRules(
            """
            2.0.0.0/8
            2.2.2.2/32
            !192.168.0.0/16
            !192.168.1.1/32
            """.trimIndent(),
        )

        assertEquals(
            listOf(
                VpnRouteRule(cidr = "2.0.0.0/8", excluded = false),
                VpnRouteRule(cidr = "192.168.0.0/16", excluded = true),
            ),
            routes,
        )
    }

    @Test
    fun keepsSameActionRouteThatOverridesOppositeActionRoute() {
        val routes = parseVpnRouteRules(
            """
            0.0.0.0/0
            !10.0.0.0/8
            10.10.0.0/16
            10.10.1.0/24
            """.trimIndent(),
        )

        assertEquals(
            listOf(
                VpnRouteRule(cidr = "0.0.0.0/0", excluded = false),
                VpnRouteRule(cidr = "10.10.0.0/16", excluded = false),
                VpnRouteRule(cidr = "10.0.0.0/8", excluded = true),
            ),
            routes,
        )
    }

    @Test
    fun rejectsExactCrossListConflictsAfterCanonicalization() {
        val error = assertThrows(IllegalArgumentException::class.java) {
            parseVpnRouteRules(
                """
                192.168.1.1/16
                !192.168.0.0/16
                """.trimIndent(),
            )
        }

        assertEquals("Route 192.168.0.0/16 cannot be both included and excluded", error.message)
    }

    @Test
    fun rejectsHostnamesWithoutResolvingThem() {
        val error = assertThrows(IllegalArgumentException::class.java) {
            parseVpnRouteRules("example.com/32")
        }

        assertEquals("Line 1: route address must be a numeric IP address", error.message)
    }

    @Test
    fun exportsRouteRules() {
        val text = exportVpnRouteRules(
            listOf(
                VpnRouteRule(cidr = "10.0.0.0/8", excluded = true),
                VpnRouteRule(cidr = "0.0.0.0/0", excluded = false),
            ),
        )

        assertEquals(
            """
            0.0.0.0/0
            !10.0.0.0/8
            """.trimIndent(),
            text,
        )
    }

    @Test
    fun findsMostSpecificRouteActionForAddress() {
        val routes = parseVpnRouteRules(
            """
            0.0.0.0/0
            !10.0.0.0/8
            10.10.0.0/16
            """.trimIndent(),
        )

        assertEquals(
            VpnRouteRule(cidr = "10.10.0.0/16", excluded = false),
            vpnRouteActionForAddress(routes, "10.10.1.1"),
        )
        assertEquals(
            VpnRouteRule(cidr = "10.0.0.0/8", excluded = true),
            vpnRouteActionForAddress(routes, "10.20.1.1"),
        )
    }
}
