package dev.slt.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class DnsSettingsRulesTest {
    @Test
    fun parsesCustomDnsServers() {
        val dns = parseDnsSettings(
            DnsMode.Custom,
            """
            1.1.1.1
            8.8.8.8, 2001:4860:4860::8888
            1.1.1.1
            """.trimIndent(),
        )

        assertEquals(
            DnsSettings(
                mode = DnsMode.Custom,
                servers = listOf(
                    "1.1.1.1",
                    "8.8.8.8",
                    "2001:4860:4860:0:0:0:0:8888",
                ),
            ),
            dns,
        )
    }

    @Test
    fun systemDnsIgnoresServerText() {
        assertEquals(DnsSettings(), parseDnsSettings(DnsMode.System, "1.1.1.1"))
    }

    @Test
    fun customDnsRequiresServers() {
        val error = assertThrows(IllegalArgumentException::class.java) {
            parseDnsSettings(DnsMode.Custom, "")
        }

        assertEquals("At least one DNS server is required", error.message)
    }

    @Test
    fun rejectsHostnamesWithoutResolvingThem() {
        val error = assertThrows(IllegalArgumentException::class.java) {
            parseDnsSettings(DnsMode.Custom, "dns.example.com")
        }

        assertEquals("Line 1: DNS server must be a numeric IP address", error.message)
    }

    @Test
    fun addsDnsHostRoutesWhenRoutesDoNotIncludeServers() {
        val routes = parseVpnRouteRules(
            """
            0.0.0.0/0
            !8.8.8.0/24
            """.trimIndent(),
        )
        val dns = DnsSettings(DnsMode.Custom, listOf("1.1.1.1", "8.8.8.8"))

        assertEquals(
            listOf(VpnRouteRule(cidr = "8.8.8.8/32", excluded = false)),
            dnsHostRoutesToAdd(routes, dns),
        )
    }

    @Test
    fun warnsWhenDnsServerIsExcluded() {
        val routes = parseVpnRouteRules("!8.8.8.0/24")
        val dns = DnsSettings(DnsMode.Custom, listOf("8.8.8.8"))

        assertEquals(
            listOf("DNS server 8.8.8.8 is excluded by 8.8.8.0/24; a DNS route will still be added"),
            dnsExcludedRouteWarnings(routes, dns),
        )
    }
}
