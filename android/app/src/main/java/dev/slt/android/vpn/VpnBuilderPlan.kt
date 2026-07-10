package dev.slt.android.vpn

import dev.slt.android.profile.DnsMode
import dev.slt.android.profile.DnsSettings
import dev.slt.android.profile.VpnRouteRule
import dev.slt.android.profile.rules.dnsExcludedRouteWarnings
import dev.slt.android.profile.rules.dnsHostRoutesToAdd
import dev.slt.android.profile.rules.exportDnsServers
import dev.slt.android.profile.rules.exportVpnRouteRules
import dev.slt.android.profile.rules.parseDnsSettings
import dev.slt.android.profile.rules.parseVpnRouteRules

internal data class VpnBuilderPlan(
    val profileRouteOperations: List<VpnRouteOperation>,
    val dnsRouteOperations: List<VpnRouteOperation>,
    val dnsServers: List<String>,
    val warnings: List<String>,
)

internal data class VpnRouteOperation(
    val action: VpnRouteAction,
    val cidr: String,
)

internal enum class VpnRouteAction {
    Add,
    Exclude,
}

internal fun createVpnBuilderPlan(
    routes: List<VpnRouteRule>,
    dns: DnsSettings,
): VpnBuilderPlan {
    val validatedRoutes = validateRoutes(routes)
    val validatedDns = validateDns(dns)
    if (validatedRoutes.isEmpty()) {
        error("Active profile has no VPN routes configured")
    }

    return VpnBuilderPlan(
        profileRouteOperations = validatedRoutes.map(VpnRouteRule::toOperation),
        dnsRouteOperations = dnsHostRoutesToAdd(validatedRoutes, validatedDns)
            .map(VpnRouteRule::toOperation),
        dnsServers = if (validatedDns.mode == DnsMode.Custom) {
            validatedDns.servers
        } else {
            emptyList()
        },
        warnings = dnsExcludedRouteWarnings(validatedRoutes, validatedDns),
    )
}

private fun validateRoutes(routes: List<VpnRouteRule>): List<VpnRouteRule> =
    try {
        parseVpnRouteRules(exportVpnRouteRules(routes))
    } catch (error: IllegalArgumentException) {
        throw IllegalArgumentException("Invalid VPN routes: ${error.message}", error)
    }

private fun validateDns(dns: DnsSettings): DnsSettings =
    try {
        parseDnsSettings(dns.mode, exportDnsServers(dns.servers))
    } catch (error: IllegalArgumentException) {
        throw IllegalArgumentException("Invalid DNS settings: ${error.message}", error)
    }

private fun VpnRouteRule.toOperation(): VpnRouteOperation =
    VpnRouteOperation(
        action = if (excluded) VpnRouteAction.Exclude else VpnRouteAction.Add,
        cidr = cidr,
    )
