package dev.slt.android

import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.net.UnknownHostException

fun parseVpnRouteRules(text: String): List<VpnRouteRule> {
    val parsedRoutes = buildList {
        text.lineSequence().forEachIndexed { index, rawLine ->
            val lineNumber = index + 1
            val line = rawLine.substringBefore('#').trim()
            if (line.isEmpty()) {
                return@forEachIndexed
            }

            add(parseVpnRouteRuleLine(line, lineNumber))
        }
    }

    val routesByListAndCidr = linkedMapOf<Pair<Boolean, String>, ParsedVpnRouteRule>()
    val routeKindsByCidr = mutableMapOf<String, MutableSet<Boolean>>()
    parsedRoutes.forEach { route ->
        routesByListAndCidr.putIfAbsent(route.rule.excluded to route.rule.cidr, route)
        routeKindsByCidr.getOrPut(route.rule.cidr) { mutableSetOf() }.add(route.rule.excluded)
    }

    val conflict = routeKindsByCidr.entries.firstOrNull { it.value.size > 1 }
    require(conflict == null) {
        "Route ${conflict?.key} cannot be both included and excluded"
    }

    val deduplicatedRoutes = routesByListAndCidr.values.toList()
    return deduplicatedRoutes
        .filterNot { route -> route.isCoveredBySameActionRoute(deduplicatedRoutes) }
        .sortedWith(parsedRouteComparator)
        .map { it.rule }
}

fun exportVpnRouteRules(routes: List<VpnRouteRule>): String =
    routes
        .sortedWith(compareBy<VpnRouteRule> { it.excluded }.thenBy { it.cidr })
        .joinToString("\n") { route ->
            if (route.excluded) {
                "!${route.cidr}"
            } else {
                route.cidr
            }
        }

private data class ParsedVpnRouteRule(
    val rule: VpnRouteRule,
    val addressFamily: Int,
    val networkBytes: ByteArray,
    val prefixLength: Int,
) {
    override fun equals(other: Any?): Boolean =
        other is ParsedVpnRouteRule &&
            rule == other.rule &&
            addressFamily == other.addressFamily &&
            networkBytes.contentEquals(other.networkBytes) &&
            prefixLength == other.prefixLength

    override fun hashCode(): Int {
        var result = rule.hashCode()
        result = 31 * result + addressFamily
        result = 31 * result + networkBytes.contentHashCode()
        result = 31 * result + prefixLength
        return result
    }
}

private val parsedRouteComparator = Comparator<ParsedVpnRouteRule> { left, right ->
    compareValuesBy(left, right, { it.rule.excluded }, { it.addressFamily }, { it.prefixLength })
        .takeIf { it != 0 }
        ?: compareNetworkBytes(left.networkBytes, right.networkBytes)
}

private fun parseVpnRouteRuleLine(line: String, lineNumber: Int): ParsedVpnRouteRule {
    val excluded = line.startsWith('!')
    val cidr = if (excluded) line.drop(1).trim() else line
    require(cidr.isNotEmpty()) { "Line $lineNumber: route CIDR is empty" }
    require(cidr.none { it.isWhitespace() }) { "Line $lineNumber: route CIDR contains whitespace" }

    val parts = cidr.split('/')
    require(parts.size == 2 && parts[0].isNotEmpty() && parts[1].isNotEmpty()) {
        "Line $lineNumber: route must use CIDR notation"
    }

    val address = parseNumericAddress(parts[0], lineNumber)
    val prefixLength = parts[1].toIntOrNull()
        ?: throw IllegalArgumentException("Line $lineNumber: route prefix is not a number")
    val maxPrefixLength = when (address) {
        is Inet4Address -> 32
        is Inet6Address -> 128
        else -> error("unsupported address family")
    }
    require(prefixLength in 0..maxPrefixLength) {
        "Line $lineNumber: route prefix must be between 0 and $maxPrefixLength"
    }

    val networkBytes = maskedNetworkBytes(address.address, prefixLength)
    val canonicalAddress = InetAddress.getByAddress(networkBytes).hostAddress
    val canonicalCidr = "$canonicalAddress/$prefixLength"
    return ParsedVpnRouteRule(
        rule = VpnRouteRule(cidr = canonicalCidr, excluded = excluded),
        addressFamily = maxPrefixLength,
        networkBytes = networkBytes,
        prefixLength = prefixLength,
    )
}

private fun parseNumericAddress(address: String, lineNumber: Int): InetAddress {
    if (address.contains(':')) {
        require(address.all { it.isDigit() || it.lowercaseChar() in 'a'..'f' || it == ':' || it == '.' }) {
            "Line $lineNumber: IPv6 route address must be numeric"
        }
        val parsed = try {
            InetAddress.getByName(address)
        } catch (_: UnknownHostException) {
            throw IllegalArgumentException("Line $lineNumber: route address is not valid IPv6")
        }
        require(parsed is Inet6Address) { "Line $lineNumber: route address is not valid IPv6" }
        return parsed
    }

    require(address.contains('.')) { "Line $lineNumber: route address must be a numeric IP address" }
    require(address.all { it.isDigit() || it == '.' }) {
        "Line $lineNumber: route address must be a numeric IP address"
    }
    val octets = address.split('.')
    require(octets.size == 4) { "Line $lineNumber: IPv4 route address must have 4 octets" }
    val bytes = octets.map { octet ->
        require(octet.isNotEmpty() && octet.all { it.isDigit() }) {
            "Line $lineNumber: IPv4 route address must be numeric"
        }
        val value = octet.toIntOrNull()
            ?: throw IllegalArgumentException("Line $lineNumber: IPv4 route octet is not a number")
        require(value in 0..255) { "Line $lineNumber: IPv4 route octet must be between 0 and 255" }
        value.toByte()
    }.toByteArray()
    return InetAddress.getByAddress(bytes)
}

private fun maskedNetworkBytes(addressBytes: ByteArray, prefixLength: Int): ByteArray {
    val networkBytes = addressBytes.copyOf()
    var remainingPrefixBits = prefixLength
    for (index in networkBytes.indices) {
        when {
            remainingPrefixBits >= 8 -> remainingPrefixBits -= 8
            remainingPrefixBits <= 0 -> networkBytes[index] = 0
            else -> {
                val mask = (0xff shl (8 - remainingPrefixBits)) and 0xff
                networkBytes[index] = (networkBytes[index].toInt() and mask).toByte()
                remainingPrefixBits = 0
            }
        }
    }
    return networkBytes
}

private fun compareNetworkBytes(left: ByteArray, right: ByteArray): Int {
    for (index in left.indices) {
        val comparison = left[index].toUByte().compareTo(right[index].toUByte())
        if (comparison != 0) {
            return comparison
        }
    }
    return 0
}

private fun ParsedVpnRouteRule.isCoveredBySameActionRoute(routes: List<ParsedVpnRouteRule>): Boolean =
    routes.any { candidate ->
        candidate.rule.excluded == rule.excluded &&
            candidate.prefixLength < prefixLength &&
            candidate.covers(this) &&
            !hasOppositeActionRouteBetween(candidate, routes)
    }

private fun ParsedVpnRouteRule.hasOppositeActionRouteBetween(
    coveringRoute: ParsedVpnRouteRule,
    routes: List<ParsedVpnRouteRule>,
): Boolean =
    routes.any { candidate ->
        candidate.rule.excluded != rule.excluded &&
            candidate.prefixLength > coveringRoute.prefixLength &&
            candidate.prefixLength < prefixLength &&
            candidate.covers(this)
    }

private fun ParsedVpnRouteRule.covers(other: ParsedVpnRouteRule): Boolean =
    addressFamily == other.addressFamily &&
        prefixLength <= other.prefixLength &&
        maskedNetworkBytes(other.networkBytes, prefixLength).contentEquals(networkBytes)
