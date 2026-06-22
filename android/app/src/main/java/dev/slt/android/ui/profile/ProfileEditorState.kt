package dev.slt.android.ui.profile

import dev.slt.android.AppVpnMode
import dev.slt.android.ConfigValidationResult
import dev.slt.android.DnsMode
import dev.slt.android.ProfileMetadata
import dev.slt.android.SltProfile
import dev.slt.android.exportDnsServers
import dev.slt.android.exportTestUrls
import dev.slt.android.exportVpnRouteRules

internal data class ProfileEditorState(
    val sourceMetadata: ProfileMetadata? = null,
    val name: String = "",
    val toml: String = "",
    val routeText: String = "",
    val routeMessage: String? = null,
    val dnsMode: DnsMode = DnsMode.System,
    val dnsText: String = "",
    val dnsMessage: String? = null,
    val appMode: AppVpnMode = AppVpnMode.All,
    val selectedPackageNames: List<String> = emptyList(),
    val appMessage: String? = null,
    val testUrlsText: String = "",
    val testUrlsMessage: String? = null,
    val validation: ConfigValidationResult? = null,
    val message: String? = null,
    val activeNestedScreen: ProfileEditorNestedScreen? = null,
) {
    val isEditingNestedScreen: Boolean
        get() = activeNestedScreen != null

    fun withClosedNestedScreen(): ProfileEditorState =
        copy(activeNestedScreen = null)
}

internal enum class ProfileEditorNestedScreen {
    Routes,
    Dns,
    Apps,
    TestUrls,
}

internal fun profileEditorStateFrom(profile: SltProfile?): ProfileEditorState =
    ProfileEditorState(
        sourceMetadata = profile?.metadata,
        name = profile?.metadata?.name.orEmpty(),
        toml = profile?.clientToml.orEmpty(),
        routeText = exportVpnRouteRules(profile?.metadata?.routes.orEmpty()),
        dnsMode = profile?.metadata?.dns?.mode ?: DnsMode.System,
        dnsText = exportDnsServers(profile?.metadata?.dns?.servers.orEmpty()),
        appMode = profile?.metadata?.appRules?.mode ?: AppVpnMode.All,
        selectedPackageNames = profile?.metadata?.appRules?.packageNames.orEmpty(),
        testUrlsText = exportTestUrls(profile?.metadata?.testUrls.orEmpty()),
    )
