package dev.slt.android.profile.store

import dev.slt.android.profile.AppVpnMode
import dev.slt.android.profile.AppVpnRules
import dev.slt.android.profile.DnsMode
import dev.slt.android.profile.DnsSettings
import dev.slt.android.profile.ProfileMetadata
import dev.slt.android.profile.VpnRouteRule
import org.json.JSONArray
import org.json.JSONObject

private const val PROFILE_METADATA_VERSION = 1

private const val DNS_MODE_SYSTEM = "system"
private const val DNS_MODE_CUSTOM = "custom"

private const val APP_VPN_MODE_ALL = "all"
private const val APP_VPN_MODE_ALLOWLIST = "allowlist"
private const val APP_VPN_MODE_BLOCKLIST = "blocklist"

internal fun ProfileMetadata.toProfileJson(): JSONObject =
    JSONObject()
        .put("version", PROFILE_METADATA_VERSION)
        .put("name", name)
        .put(
            "routes",
            JSONArray().also { routesJson ->
                routes.forEach { route ->
                    routesJson.put(
                        JSONObject()
                            .put("cidr", route.cidr)
                            .put("excluded", route.excluded),
                    )
                }
            },
        )
        .put(
            "dns",
            JSONObject()
                .put("mode", dns.mode.toWireName())
                .put("servers", JSONArray(dns.servers)),
        )
        .put("testUrls", JSONArray(testUrls))
        .put(
            "appRules",
            JSONObject()
                .put("mode", appRules.mode.toWireName())
                .put("packageNames", JSONArray(appRules.packageNames)),
        )

internal fun profileMetadataFromJson(json: JSONObject): ProfileMetadata =
    ProfileMetadata(
        name = json.getString("name"),
        routes = json.optJSONArray("routes").toVpnRouteRules(),
        dns = json.optJSONObject("dns").toDnsSettings(),
        testUrls = json.optJSONArray("testUrls").toStringList(),
        appRules = json.optJSONObject("appRules").toAppVpnRules(),
    )

private fun JSONArray?.toVpnRouteRules(): List<VpnRouteRule> {
    if (this == null) {
        return emptyList()
    }
    return buildList {
        for (index in 0 until length()) {
            val route = getJSONObject(index)
            add(
                VpnRouteRule(
                    cidr = route.getString("cidr"),
                    excluded = route.optBoolean("excluded", false),
                ),
            )
        }
    }
}

private fun JSONObject?.toDnsSettings(): DnsSettings {
    if (this == null) {
        return DnsSettings()
    }
    return DnsSettings(
        mode = dnsModeFromWireName(optString("mode", DNS_MODE_SYSTEM)),
        servers = optJSONArray("servers").toStringList(),
    )
}

private fun JSONObject?.toAppVpnRules(): AppVpnRules {
    if (this == null) {
        return AppVpnRules()
    }
    return AppVpnRules(
        mode = appVpnModeFromWireName(optString("mode", APP_VPN_MODE_ALL)),
        packageNames = optJSONArray("packageNames").toStringList(),
    )
}

private fun JSONArray?.toStringList(): List<String> {
    if (this == null) {
        return emptyList()
    }
    return buildList {
        for (index in 0 until length()) {
            add(getString(index))
        }
    }
}

private fun DnsMode.toWireName(): String =
    when (this) {
        DnsMode.System -> DNS_MODE_SYSTEM
        DnsMode.Custom -> DNS_MODE_CUSTOM
    }

private fun dnsModeFromWireName(wireName: String): DnsMode =
    when (wireName) {
        DNS_MODE_CUSTOM -> DnsMode.Custom
        else -> DnsMode.System
    }

private fun AppVpnMode.toWireName(): String =
    when (this) {
        AppVpnMode.All -> APP_VPN_MODE_ALL
        AppVpnMode.Allowlist -> APP_VPN_MODE_ALLOWLIST
        AppVpnMode.Blocklist -> APP_VPN_MODE_BLOCKLIST
    }

private fun appVpnModeFromWireName(wireName: String): AppVpnMode =
    when (wireName) {
        APP_VPN_MODE_ALLOWLIST -> AppVpnMode.Allowlist
        APP_VPN_MODE_BLOCKLIST -> AppVpnMode.Blocklist
        else -> AppVpnMode.All
    }
