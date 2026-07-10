package dev.slt.android.vpn

import android.content.pm.PackageManager
import android.net.IpPrefix
import android.net.VpnService
import android.util.Log
import dev.slt.android.profile.AppVpnMode
import dev.slt.android.profile.AppVpnRules
import dev.slt.android.profile.SltProfile
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
        val plan = createVpnBuilderPlan(profile.metadata.routes, profile.metadata.dns)
        applyRouteOperations(builder, plan.profileRouteOperations)
        plan.warnings.forEach { warning -> Log.w(logTag, warning) }
        applyRouteOperations(builder, plan.dnsRouteOperations)
        plan.dnsServers.forEach { server ->
            builder.addDnsServer(InetAddress.getByName(server))
        }
        applyAppRules(builder, profile.metadata.appRules)
    }

    private fun applyRouteOperations(
        builder: VpnService.Builder,
        operations: List<VpnRouteOperation>,
    ) {
        operations.forEach { operation ->
            val prefix = operation.cidr.toIpPrefix()
            when (operation.action) {
                VpnRouteAction.Add -> builder.addRoute(prefix)
                VpnRouteAction.Exclude -> builder.excludeRoute(prefix)
            }
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
