package dev.slt.android.profile.rules

import dev.slt.android.profile.DnsMode
import dev.slt.android.profile.DnsSettings
import dev.slt.android.profile.VpnRouteRule
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.net.UnknownHostException

fun parseDnsSettings(mode: DnsMode, text: String): DnsSettings {
    if (mode == DnsMode.System) {
        return DnsSettings()
    }

    val servers = parseDnsServers(text)
    require(servers.isNotEmpty()) { "At least one DNS server is required" }
    return DnsSettings(
        mode = DnsMode.Custom,
        servers = servers,
    )
}

fun exportDnsServers(servers: List<String>): String =
    servers.joinToString("\n")

fun dnsHostRoutesToAdd(routes: List<VpnRouteRule>, dns: DnsSettings): List<VpnRouteRule> {
    if (dns.mode != DnsMode.Custom) {
        return emptyList()
    }

    return dns.servers
        .filter { server -> vpnRouteActionForAddress(routes, server)?.excluded != false }
        .map(::hostVpnRouteForAddress)
        .distinct()
}

fun dnsExcludedRouteWarnings(routes: List<VpnRouteRule>, dns: DnsSettings): List<String> {
    if (dns.mode != DnsMode.Custom) {
        return emptyList()
    }

    return dns.servers.mapNotNull { server ->
        val route = vpnRouteActionForAddress(routes, server)
        if (route?.excluded == true) {
            "DNS server $server is excluded by ${route.cidr}; a DNS route will still be added"
        } else {
            null
        }
    }
}

private fun parseDnsServers(text: String): List<String> {
    val servers = linkedSetOf<String>()
    text.lineSequence().forEachIndexed { index, rawLine ->
        val lineNumber = index + 1
        rawLine.substringBefore('#')
            .trim()
            .split(Regex("[,\\s]+"))
            .filter { it.isNotEmpty() }
            .forEach { server ->
                servers.add(parseNumericDnsServer(server, lineNumber))
            }
    }
    return servers.toList()
}

private fun parseNumericDnsServer(server: String, lineNumber: Int): String {
    val address = if (server.contains(':')) {
        require(server.all { it.isDigit() || it.lowercaseChar() in 'a'..'f' || it == ':' || it == '.' }) {
            "Line $lineNumber: DNS server must be a numeric IP address"
        }
        val parsed = try {
            InetAddress.getByName(server)
        } catch (_: UnknownHostException) {
            throw IllegalArgumentException("Line $lineNumber: DNS server is not valid IPv6")
        }
        require(parsed is Inet6Address) { "Line $lineNumber: DNS server is not valid IPv6" }
        parsed
    } else {
        require(server.contains('.')) { "Line $lineNumber: DNS server must be a numeric IP address" }
        require(server.all { it.isDigit() || it == '.' }) {
            "Line $lineNumber: DNS server must be a numeric IP address"
        }
        val octets = server.split('.')
        require(octets.size == 4) { "Line $lineNumber: IPv4 DNS server must have 4 octets" }
        val bytes = octets.map { octet ->
            require(octet.isNotEmpty() && octet.all { it.isDigit() }) {
                "Line $lineNumber: IPv4 DNS server must be numeric"
            }
            val value = octet.toIntOrNull()
                ?: throw IllegalArgumentException("Line $lineNumber: IPv4 DNS server octet is not a number")
            require(value in 0..255) { "Line $lineNumber: IPv4 DNS server octet must be between 0 and 255" }
            value.toByte()
        }.toByteArray()
        InetAddress.getByAddress(bytes)
    }

    require(address is Inet4Address || address is Inet6Address) {
        "Line $lineNumber: DNS server must be a numeric IP address"
    }
    return checkNotNull(address.hostAddress) { "DNS server address has no host address" }
}
