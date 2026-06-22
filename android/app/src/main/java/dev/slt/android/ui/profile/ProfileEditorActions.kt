package dev.slt.android.ui.profile

import dev.slt.android.AppVpnMode
import dev.slt.android.AppVpnRules
import dev.slt.android.ConfigValidationResult
import dev.slt.android.DnsMode
import dev.slt.android.DnsSettings
import dev.slt.android.ProfileMetadata
import dev.slt.android.VpnRouteRule
import dev.slt.android.dnsExcludedRouteWarnings
import dev.slt.android.exportDnsServers
import dev.slt.android.exportTestUrls
import dev.slt.android.exportVpnRouteRules
import dev.slt.android.normalizeAppVpnRules
import dev.slt.android.parseDnsSettings
import dev.slt.android.parseTestUrls
import dev.slt.android.parseVpnRouteRules

internal sealed interface ProfileEditorActionResult<out T> {
    val state: ProfileEditorState

    data class Success<T>(
        override val state: ProfileEditorState,
        val value: T,
    ) : ProfileEditorActionResult<T>

    data class Failure(
        override val state: ProfileEditorState,
    ) : ProfileEditorActionResult<Nothing>
}

internal data class ProfileEditorValidationResult(
    val state: ProfileEditorState,
    val validation: ConfigValidationResult,
)

internal sealed interface ProfileEditorSaveResult {
    val state: ProfileEditorState

    data class Ready(
        override val state: ProfileEditorState,
        val name: String,
        val clientToml: String,
        val metadata: ProfileMetadata,
    ) : ProfileEditorSaveResult

    data class Blocked(
        override val state: ProfileEditorState,
    ) : ProfileEditorSaveResult
}

internal fun validateProfileEditorToml(
    state: ProfileEditorState,
    validateClientConfig: (String) -> ConfigValidationResult,
): ProfileEditorValidationResult {
    val result = validateClientConfig(state.toml)
    return ProfileEditorValidationResult(
        state = state.copy(
            validation = result,
            message = if (result.isValid) {
                "Config is valid"
            } else {
                result.error ?: "Invalid config"
            },
        ),
        validation = result,
    )
}

internal fun parseProfileEditorRoutesForSave(
    state: ProfileEditorState,
): ProfileEditorActionResult<List<VpnRouteRule>> =
    try {
        val routes = parseVpnRouteRules(state.routeText)
        if (routes.isEmpty()) {
            val routeMessage = "At least one VPN route is required"
            ProfileEditorActionResult.Failure(
                state.copy(
                    routeMessage = routeMessage,
                    message = routeMessage,
                ),
            )
        } else {
            ProfileEditorActionResult.Success(
                state = state.copy(
                    routeText = exportVpnRouteRules(routes),
                    routeMessage = "${routes.size} route${pluralSuffix(routes.size)} ready",
                ),
                value = routes,
            )
        }
    } catch (error: IllegalArgumentException) {
        val routeMessage = error.message ?: "Invalid routes"
        ProfileEditorActionResult.Failure(
            state.copy(
                routeMessage = routeMessage,
                message = routeMessage,
            ),
        )
    }

internal fun parseProfileEditorDnsForSave(
    state: ProfileEditorState,
    routes: List<VpnRouteRule>?,
): ProfileEditorActionResult<DnsSettings> =
    try {
        val dns = parseDnsSettings(state.dnsMode, state.dnsText)
        val warnings = routes?.let { dnsExcludedRouteWarnings(it, dns) }.orEmpty()
        val dnsMessage = warnings.firstOrNull()
            ?: when (dns.mode) {
                DnsMode.System -> "System DNS ready"
                DnsMode.Custom -> "${dns.servers.size} DNS server${pluralSuffix(dns.servers.size)} ready"
            }
        ProfileEditorActionResult.Success(
            state = state.copy(
                dnsText = exportDnsServers(dns.servers),
                dnsMessage = dnsMessage,
            ),
            value = dns,
        )
    } catch (error: IllegalArgumentException) {
        val dnsMessage = error.message ?: "Invalid DNS settings"
        ProfileEditorActionResult.Failure(
            state.copy(
                dnsMessage = dnsMessage,
                message = dnsMessage,
            ),
        )
    }

internal fun normalizeProfileEditorAppsForSave(
    state: ProfileEditorState,
    ownPackageName: String,
): ProfileEditorActionResult<AppVpnRules> =
    try {
        val appRules = normalizeAppVpnRules(
            state.appMode,
            state.selectedPackageNames,
            ownPackageName,
        )
        ProfileEditorActionResult.Success(
            state = state.copy(
                appMode = appRules.mode,
                selectedPackageNames = appRules.packageNames,
                appMessage = appRulesSummary(appRules),
            ),
            value = appRules,
        )
    } catch (error: IllegalArgumentException) {
        val appMessage = error.message ?: "Invalid app rules"
        ProfileEditorActionResult.Failure(
            state.copy(
                appMessage = appMessage,
                message = appMessage,
            ),
        )
    }

internal fun parseProfileEditorTestUrlsForSave(
    state: ProfileEditorState,
): ProfileEditorActionResult<List<String>> =
    try {
        val testUrls = parseTestUrls(state.testUrlsText)
        val testUrlsMessage = if (testUrls.isEmpty()) {
            "No test URLs configured"
        } else {
            "${testUrls.size} test URL${pluralSuffix(testUrls.size)} ready"
        }
        ProfileEditorActionResult.Success(
            state = state.copy(
                testUrlsText = exportTestUrls(testUrls),
                testUrlsMessage = testUrlsMessage,
            ),
            value = testUrls,
        )
    } catch (error: IllegalArgumentException) {
        val testUrlsMessage = error.message ?: "Invalid test URLs"
        ProfileEditorActionResult.Failure(
            state.copy(
                testUrlsMessage = testUrlsMessage,
                message = testUrlsMessage,
            ),
        )
    }

internal fun prepareProfileEditorSave(
    state: ProfileEditorState,
    ownPackageName: String,
    validateClientConfig: (String) -> ConfigValidationResult,
): ProfileEditorSaveResult {
    val trimmedName = state.name.trim()
    if (trimmedName.isEmpty()) {
        return ProfileEditorSaveResult.Blocked(state.copy(message = "Profile name is required"))
    }

    val validationResult = validateProfileEditorToml(state, validateClientConfig)
    var currentState = validationResult.state
    if (!validationResult.validation.isValid) {
        return ProfileEditorSaveResult.Blocked(currentState)
    }

    val routes = when (val result = parseProfileEditorRoutesForSave(currentState)) {
        is ProfileEditorActionResult.Success -> {
            currentState = result.state
            result.value
        }
        is ProfileEditorActionResult.Failure -> return ProfileEditorSaveResult.Blocked(result.state)
    }

    val dns = when (val result = parseProfileEditorDnsForSave(currentState, routes)) {
        is ProfileEditorActionResult.Success -> {
            currentState = result.state
            result.value
        }
        is ProfileEditorActionResult.Failure -> return ProfileEditorSaveResult.Blocked(result.state)
    }

    val appRules = when (val result = normalizeProfileEditorAppsForSave(currentState, ownPackageName)) {
        is ProfileEditorActionResult.Success -> {
            currentState = result.state
            result.value
        }
        is ProfileEditorActionResult.Failure -> return ProfileEditorSaveResult.Blocked(result.state)
    }

    val testUrls = when (val result = parseProfileEditorTestUrlsForSave(currentState)) {
        is ProfileEditorActionResult.Success -> {
            currentState = result.state
            result.value
        }
        is ProfileEditorActionResult.Failure -> return ProfileEditorSaveResult.Blocked(result.state)
    }

    val metadata = (state.sourceMetadata ?: ProfileMetadata(name = trimmedName))
        .copy(
            name = trimmedName,
            routes = routes,
            dns = dns,
            testUrls = testUrls,
            appRules = appRules,
        )
    return ProfileEditorSaveResult.Ready(
        state = currentState,
        name = trimmedName,
        clientToml = state.toml,
        metadata = metadata,
    )
}

internal fun appRulesSummary(rules: AppVpnRules): String =
    when (rules.mode) {
        AppVpnMode.All -> "All apps ready"
        AppVpnMode.Allowlist -> "${rules.packageNames.size} allowed app${pluralSuffix(rules.packageNames.size)} ready"
        AppVpnMode.Blocklist -> "${rules.packageNames.size} blocked app${pluralSuffix(rules.packageNames.size)} ready"
    }

private fun pluralSuffix(size: Int): String =
    if (size == 1) "" else "s"
