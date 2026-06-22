package dev.slt.android.ui.profile

import dev.slt.android.ConfigValidationResult
import dev.slt.android.ui.profile.rules.exportDnsServers
import dev.slt.android.ui.profile.rules.exportTestUrls
import dev.slt.android.ui.profile.rules.exportVpnRouteRules
import dev.slt.android.ui.UiMessage

internal data class ProfileEditorState(
    val sourceMetadata: ProfileMetadata? = null,
    val name: String = "",
    val toml: String = "",
    val routeText: String = "",
    val routeMessage: UiMessage? = null,
    val dnsMode: DnsMode = DnsMode.System,
    val dnsText: String = "",
    val dnsMessage: UiMessage? = null,
    val appMode: AppVpnMode = AppVpnMode.All,
    val selectedPackageNames: List<String> = emptyList(),
    val appMessage: UiMessage? = null,
    val testUrlsText: String = "",
    val testUrlsMessage: UiMessage? = null,
    val validation: ConfigValidationResult? = null,
    val message: UiMessage? = null,
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
