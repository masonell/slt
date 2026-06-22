package dev.slt.android.ui.profile

data class ProfileStoreState(
    val profiles: List<ProfileListItem>,
    val activeProfile: SltProfile?,
)

data class ProfileListItem(
    val id: String,
    val name: String,
    val isActive: Boolean,
)

data class SltProfile(
    val id: String,
    val clientToml: String,
    val metadata: ProfileMetadata,
)

data class ProfileMetadata(
    val name: String,
    val routes: List<VpnRouteRule> = emptyList(),
    val dns: DnsSettings = DnsSettings(),
    val testUrls: List<String> = emptyList(),
    val appRules: AppVpnRules = AppVpnRules(),
)

data class VpnRouteRule(
    val cidr: String,
    val excluded: Boolean,
)

data class DnsSettings(
    val mode: DnsMode = DnsMode.System,
    val servers: List<String> = emptyList(),
)

enum class DnsMode {
    System,
    Custom,
}

data class AppVpnRules(
    val mode: AppVpnMode = AppVpnMode.All,
    val packageNames: List<String> = emptyList(),
)

enum class AppVpnMode {
    All,
    Allowlist,
    Blocklist,
}
