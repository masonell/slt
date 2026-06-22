package dev.slt.android

import android.content.pm.PackageManager
import android.net.IpPrefix
import android.net.VpnService
import android.util.Log
import java.net.InetAddress

internal class VpnProfileApplier(
    private val service: VpnService,
    private val logTag: String,
) {
    private val packageManager: PackageManager
        get() = service.packageManager

    private val ownPackageName: String
        get() = service.packageName

    fun apply(builder: VpnService.Builder, profile: SltProfile) {
        applyRoutes(builder, profile.metadata.routes)
        applyDnsRoutes(builder, profile.metadata.routes, profile.metadata.dns)
        applyDns(builder, profile.metadata.dns)
        applyAppRules(builder, profile.metadata.appRules)
    }

    private fun applyRoutes(builder: VpnService.Builder, routes: List<VpnRouteRule>) {
        if (routes.isEmpty()) {
            error("Active profile has no VPN routes configured")
        }

        routes.forEach { route ->
            val prefix = route.cidr.toIpPrefix()
            if (route.excluded) {
                builder.excludeRoute(prefix)
            } else {
                builder.addRoute(prefix)
            }
        }
    }

    private fun applyDnsRoutes(
        builder: VpnService.Builder,
        routes: List<VpnRouteRule>,
        dns: DnsSettings,
    ) {
        dnsExcludedRouteWarnings(routes, dns).forEach { warning ->
            Log.w(logTag, warning)
        }
        dnsHostRoutesToAdd(routes, dns).forEach { route ->
            builder.addRoute(route.cidr.toIpPrefix())
        }
    }

    private fun applyDns(builder: VpnService.Builder, dns: DnsSettings) {
        if (dns.mode != DnsMode.Custom) {
            return
        }

        dns.servers.forEach { server ->
            builder.addDnsServer(InetAddress.getByName(server))
        }
    }

    private fun applyAppRules(builder: VpnService.Builder, appRules: AppVpnRules) {
        when (appRules.mode) {
            AppVpnMode.All -> Unit
            AppVpnMode.Allowlist -> {
                val packages = (appRules.packageNames + ownPackageName).distinct().filterInstalled()
                packages.forEach { builder.addAllowedApplication(it) }
            }
            AppVpnMode.Blocklist -> {
                val packages = appRules.packageNames
                    .filterNot { it == ownPackageName }
                    .distinct()
                    .filterInstalled()
                packages.forEach { builder.addDisallowedApplication(it) }
            }
        }
    }

    private fun List<String>.filterInstalled(): List<String> =
        filter { packageName ->
            try {
                packageManager.getPackageInfo(packageName, PackageManager.PackageInfoFlags.of(0))
                true
            } catch (_: PackageManager.NameNotFoundException) {
                Log.w(logTag, "Profile references missing Android package: $packageName")
                false
            }
        }

    private fun String.toIpPrefix(): IpPrefix {
        val parts = split('/', limit = 2)
        require(parts.size == 2) { "invalid CIDR route: $this" }
        val address = InetAddress.getByName(parts[0])
        val prefixLength = parts[1].toIntOrNull()
            ?: error("invalid CIDR prefix length: $this")
        return IpPrefix(address, prefixLength)
    }
}
