package dev.slt.android.profile.rules

import dev.slt.android.profile.DnsMode
import dev.slt.android.profile.DnsSettings
import dev.slt.android.profile.VpnRouteRule
import dev.slt.android.profile.rules.dnsExcludedRouteWarnings
import dev.slt.android.profile.rules.dnsHostRoutesToAdd
import dev.slt.android.profile.rules.parseDnsSettings
import dev.slt.android.profile.rules.parseVpnRouteRules
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
            8.8.8.8
            1.1.1.1
            """.trimIndent(),
        )

        assertEquals(
            DnsSettings(
                mode = DnsMode.Custom,
                servers = listOf(
                    "1.1.1.1",
                    "8.8.8.8",
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
    fun rejectsIpv6DnsServers() {
        val error = assertThrows(IllegalArgumentException::class.java) {
            parseDnsSettings(DnsMode.Custom, "2001:4860:4860::8888")
        }

        assertEquals("Line 1: IPv6 DNS servers are not supported", error.message)
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
