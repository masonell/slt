package dev.slt.android.ui.profile

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import dev.slt.android.AppVpnMode
import dev.slt.android.AppVpnRules
import dev.slt.android.ConfigValidationResult
import dev.slt.android.DnsMode
import dev.slt.android.DnsSettings
import dev.slt.android.ProfileMetadata
import dev.slt.android.ProfileRepository
import dev.slt.android.SltNative
import dev.slt.android.VpnRouteRule
import dev.slt.android.dnsExcludedRouteWarnings
import dev.slt.android.exportDnsServers
import dev.slt.android.exportTestUrls
import dev.slt.android.exportVpnRouteRules
import dev.slt.android.normalizeAppVpnRules
import dev.slt.android.parseDnsSettings
import dev.slt.android.parseTestUrls
import dev.slt.android.parseVpnRouteRules
import dev.slt.android.ui.copySensitiveText
import dev.slt.android.ui.messageIsError
import kotlinx.coroutines.launch

@Composable
internal fun ProfileEditorScreen(
    profileRepository: ProfileRepository,
    profileId: String?,
    onSaved: () -> Unit,
    onCancel: () -> Unit,
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var editorState by remember(profileId) { mutableStateOf(ProfileEditorState()) }

    LaunchedEffect(profileId) {
        val profile = profileId?.let { profileRepository.loadProfile(it) }
        editorState = profileEditorStateFrom(profile)
    }

    BackHandler(enabled = editorState.isEditingNestedScreen) {
        editorState = editorState.withClosedNestedScreen()
    }

    fun validate(): ConfigValidationResult {
        val result = SltNative.validateClientConfig(editorState.toml)
        editorState = editorState.copy(
            validation = result,
            message = if (result.isValid) "Config is valid" else result.error,
        )
        return result
    }

    fun parseRoutesForSave(): List<VpnRouteRule>? =
        try {
            val routes = parseVpnRouteRules(editorState.routeText)
            if (routes.isEmpty()) {
                val routeMessage = "At least one VPN route is required"
                editorState = editorState.copy(
                    routeMessage = routeMessage,
                    message = routeMessage,
                )
                null
            } else {
                editorState = editorState.copy(
                    routeText = exportVpnRouteRules(routes),
                    routeMessage = "${routes.size} route${if (routes.size == 1) "" else "s"} ready",
                )
                routes
            }
        } catch (error: IllegalArgumentException) {
            val routeMessage = error.message ?: "Invalid routes"
            editorState = editorState.copy(
                routeMessage = routeMessage,
                message = routeMessage,
            )
            null
        }

    fun parseDnsForSave(routes: List<VpnRouteRule>?): DnsSettings? =
        try {
            val dns = parseDnsSettings(editorState.dnsMode, editorState.dnsText)
            val warnings = routes?.let { dnsExcludedRouteWarnings(it, dns) }.orEmpty()
            val dnsMessage = warnings.firstOrNull()
                ?: when (dns.mode) {
                    DnsMode.System -> "System DNS ready"
                    DnsMode.Custom -> "${dns.servers.size} DNS server${if (dns.servers.size == 1) "" else "s"} ready"
                }
            editorState = editorState.copy(
                dnsText = exportDnsServers(dns.servers),
                dnsMessage = dnsMessage,
            )
            dns
        } catch (error: IllegalArgumentException) {
            val dnsMessage = error.message ?: "Invalid DNS settings"
            editorState = editorState.copy(
                dnsMessage = dnsMessage,
                message = dnsMessage,
            )
            null
        }

    fun parseAppsForSave(): AppVpnRules? =
        try {
            val appRules = normalizeAppVpnRules(
                editorState.appMode,
                editorState.selectedPackageNames,
                context.packageName,
            )
            editorState = editorState.copy(
                appMode = appRules.mode,
                selectedPackageNames = appRules.packageNames,
                appMessage = appRulesSummary(appRules),
            )
            appRules
        } catch (error: IllegalArgumentException) {
            val appMessage = error.message ?: "Invalid app rules"
            editorState = editorState.copy(
                appMessage = appMessage,
                message = appMessage,
            )
            null
        }

    fun parseTestUrlsForSave(): List<String>? =
        try {
            val testUrls = parseTestUrls(editorState.testUrlsText)
            val testUrlsMessage = if (testUrls.isEmpty()) {
                "No test URLs configured"
            } else {
                "${testUrls.size} test URL${if (testUrls.size == 1) "" else "s"} ready"
            }
            editorState = editorState.copy(
                testUrlsText = exportTestUrls(testUrls),
                testUrlsMessage = testUrlsMessage,
            )
            testUrls
        } catch (error: IllegalArgumentException) {
            val testUrlsMessage = error.message ?: "Invalid test URLs"
            editorState = editorState.copy(
                testUrlsMessage = testUrlsMessage,
                message = testUrlsMessage,
            )
            null
        }

    if (editorState.activeNestedScreen == ProfileEditorNestedScreen.Routes) {
        RouteEditorScreen(
            routeText = editorState.routeText,
            routeMessage = editorState.routeMessage,
            onRouteTextChange = {
                editorState = editorState.copy(
                    routeText = it,
                    routeMessage = null,
                )
            },
            onApply = {
                val routes = parseRoutesForSave()
                if (routes != null) {
                    editorState = editorState.copy(
                        activeNestedScreen = null,
                        message = null,
                    )
                }
            },
            onCopy = {
                try {
                    val routes = parseVpnRouteRules(editorState.routeText)
                    val normalizedRoutes = exportVpnRouteRules(routes)
                    context.copySensitiveText("SLT routes", normalizedRoutes)
                    editorState = editorState.copy(
                        routeText = normalizedRoutes,
                        routeMessage = "Routes copied",
                    )
                } catch (error: IllegalArgumentException) {
                    editorState = editorState.copy(
                        routeMessage = error.message ?: "Invalid routes",
                    )
                }
            },
            onCancel = {
                editorState = editorState.withClosedNestedScreen()
            },
        )
        return
    }

    if (editorState.activeNestedScreen == ProfileEditorNestedScreen.Dns) {
        DnsEditorScreen(
            dnsMode = editorState.dnsMode,
            dnsText = editorState.dnsText,
            dnsMessage = editorState.dnsMessage,
            onDnsModeChange = {
                editorState = editorState.copy(
                    dnsMode = it,
                    dnsMessage = null,
                )
            },
            onDnsTextChange = {
                editorState = editorState.copy(
                    dnsText = it,
                    dnsMessage = null,
                )
            },
            onApply = {
                val routes = try {
                    parseVpnRouteRules(editorState.routeText)
                } catch (_: IllegalArgumentException) {
                    null
                }
                if (parseDnsForSave(routes) != null) {
                    editorState = editorState.copy(
                        activeNestedScreen = null,
                        message = null,
                    )
                }
            },
            onCancel = {
                editorState = editorState.withClosedNestedScreen()
            },
        )
        return
    }

    if (editorState.activeNestedScreen == ProfileEditorNestedScreen.Apps) {
        AppRulesEditorScreen(
            appMode = editorState.appMode,
            selectedPackageNames = editorState.selectedPackageNames,
            appMessage = editorState.appMessage,
            ownPackageName = context.packageName,
            onAppModeChange = {
                editorState = editorState.copy(
                    appMode = it,
                    appMessage = null,
                )
            },
            onSelectedPackageNamesChange = {
                editorState = editorState.copy(
                    selectedPackageNames = it,
                    appMessage = null,
                )
            },
            onApply = {
                if (parseAppsForSave() != null) {
                    editorState = editorState.copy(
                        activeNestedScreen = null,
                        message = null,
                    )
                }
            },
            onCancel = {
                editorState = editorState.withClosedNestedScreen()
            },
        )
        return
    }

    if (editorState.activeNestedScreen == ProfileEditorNestedScreen.TestUrls) {
        TestUrlsEditorScreen(
            testUrlsText = editorState.testUrlsText,
            testUrlsMessage = editorState.testUrlsMessage,
            onTestUrlsTextChange = {
                editorState = editorState.copy(
                    testUrlsText = it,
                    testUrlsMessage = null,
                )
            },
            onApply = {
                if (parseTestUrlsForSave() != null) {
                    editorState = editorState.copy(
                        activeNestedScreen = null,
                        message = null,
                    )
                }
            },
            onCancel = {
                editorState = editorState.withClosedNestedScreen()
            },
        )
        return
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .statusBarsPadding()
            .navigationBarsPadding()
            .padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text(
            text = if (profileId == null) "Add Profile" else "Edit Profile",
            style = MaterialTheme.typography.headlineSmall,
            fontWeight = FontWeight.SemiBold,
        )
        OutlinedTextField(
            value = editorState.name,
            onValueChange = { editorState = editorState.copy(name = it) },
            modifier = Modifier.fillMaxWidth(),
            singleLine = true,
            label = { Text("Profile name") },
        )
        OutlinedTextField(
            value = editorState.toml,
            onValueChange = {
                editorState = editorState.copy(
                    toml = it,
                    validation = null,
                    message = null,
                )
            },
            modifier = Modifier
                .fillMaxWidth()
                .weight(1f),
            label = { Text("SLT client TOML") },
            textStyle = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
        )
        editorState.validation?.summary?.let { summary ->
            Text(
                text = "Server ${summary.serverHost}:${summary.serverPort}  MTU ${summary.tunMtu}  IPv4 ${summary.assignedIpv4}",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Text(
                text = routeSummary(editorState.routeText),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            OutlinedButton(
                onClick = {
                    editorState = editorState.copy(activeNestedScreen = ProfileEditorNestedScreen.Routes)
                },
            ) {
                Text("Edit Routes")
            }
            editorState.routeMessage?.let {
                Text(
                    text = it,
                    style = MaterialTheme.typography.bodySmall,
                    color = if (it.contains("required") || it.contains("Line ") || it.contains("cannot")) {
                        MaterialTheme.colorScheme.error
                    } else {
                        MaterialTheme.colorScheme.onSurfaceVariant
                    },
                )
            }
        }
        Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Text(
                text = dnsSummary(editorState.dnsMode, editorState.dnsText),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            OutlinedButton(
                onClick = {
                    editorState = editorState.copy(activeNestedScreen = ProfileEditorNestedScreen.Dns)
                },
            ) {
                Text("Edit DNS")
            }
            editorState.dnsMessage?.let {
                Text(
                    text = it,
                    style = MaterialTheme.typography.bodySmall,
                    color = if (messageIsError(it)) {
                        MaterialTheme.colorScheme.error
                    } else {
                        MaterialTheme.colorScheme.onSurfaceVariant
                    },
                )
            }
        }
        Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Text(
                text = appsSummary(
                    editorState.appMode,
                    editorState.selectedPackageNames.filterNot { it == context.packageName },
                ),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            OutlinedButton(
                onClick = {
                    editorState = editorState.copy(activeNestedScreen = ProfileEditorNestedScreen.Apps)
                },
            ) {
                Text("Edit Apps")
            }
            editorState.appMessage?.let {
                Text(
                    text = it,
                    style = MaterialTheme.typography.bodySmall,
                    color = if (messageIsError(it)) {
                        MaterialTheme.colorScheme.error
                    } else {
                        MaterialTheme.colorScheme.onSurfaceVariant
                    },
                )
            }
        }
        Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Text(
                text = testUrlsSummary(editorState.testUrlsText),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            OutlinedButton(
                onClick = {
                    editorState = editorState.copy(activeNestedScreen = ProfileEditorNestedScreen.TestUrls)
                },
            ) {
                Text("Edit Test URLs")
            }
            editorState.testUrlsMessage?.let {
                Text(
                    text = it,
                    style = MaterialTheme.typography.bodySmall,
                    color = if (messageIsError(it)) {
                        MaterialTheme.colorScheme.error
                    } else {
                        MaterialTheme.colorScheme.onSurfaceVariant
                    },
                )
            }
        }
        editorState.message?.let {
            Text(
                text = it,
                style = MaterialTheme.typography.bodyMedium,
                color = if (editorState.validation?.isValid == false || messageIsError(it)) {
                    MaterialTheme.colorScheme.error
                } else {
                    MaterialTheme.colorScheme.primary
                },
            )
        }
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            OutlinedButton(onClick = { validate() }) {
                Text("Validate")
            }
            Button(
                onClick = {
                    val trimmedName = editorState.name.trim()
                    if (trimmedName.isEmpty()) {
                        editorState = editorState.copy(message = "Profile name is required")
                        return@Button
                    }
                    val result = validate()
                    if (!result.isValid) {
                        return@Button
                    }
                    val routes = parseRoutesForSave() ?: return@Button
                    val dns = parseDnsForSave(routes) ?: return@Button
                    val appRules = parseAppsForSave() ?: return@Button
                    val testUrls = parseTestUrlsForSave() ?: return@Button
                    scope.launch {
                        val metadata = (editorState.sourceMetadata ?: ProfileMetadata(name = trimmedName))
                            .copy(
                                name = trimmedName,
                                routes = routes,
                                dns = dns,
                                testUrls = testUrls,
                                appRules = appRules,
                            )
                        profileRepository.saveProfile(
                            id = profileId,
                            name = trimmedName,
                            clientToml = editorState.toml,
                            metadata = metadata,
                        )
                        onSaved()
                    }
                },
            ) {
                Text("Save")
            }
            OutlinedButton(onClick = { context.copySensitiveText("SLT config", editorState.toml) }) {
                Text("Copy")
            }
            TextButton(onClick = onCancel) {
                Text("Cancel")
            }
        }
    }
}

private fun routeSummary(routeText: String): String =
    try {
        val routes = parseVpnRouteRules(routeText)
        val included = routes.count { !it.excluded }
        val excluded = routes.count { it.excluded }
        "Routes: $included include, $excluded exclude"
    } catch (_: IllegalArgumentException) {
        "Routes need attention"
    }

private fun dnsSummary(mode: DnsMode, dnsText: String): String =
    try {
        val dns = parseDnsSettings(mode, dnsText)
        when (dns.mode) {
            DnsMode.System -> "DNS: system"
            DnsMode.Custom -> "DNS: ${dns.servers.size} custom server${if (dns.servers.size == 1) "" else "s"}"
        }
    } catch (_: IllegalArgumentException) {
        "DNS needs attention"
    }

private fun appsSummary(mode: AppVpnMode, packageNames: List<String>): String =
    when (mode) {
        AppVpnMode.All -> "Apps: all"
        AppVpnMode.Allowlist -> "Apps: ${packageNames.size} allowed"
        AppVpnMode.Blocklist -> "Apps: ${packageNames.size} blocked"
    }

private fun testUrlsSummary(testUrlsText: String): String =
    try {
        val testUrls = parseTestUrls(testUrlsText)
        "Tests: ${testUrls.size} URL${if (testUrls.size == 1) "" else "s"}"
    } catch (_: IllegalArgumentException) {
        "Tests need attention"
    }

private fun appRulesSummary(rules: AppVpnRules): String =
    when (rules.mode) {
        AppVpnMode.All -> "All apps ready"
        AppVpnMode.Allowlist -> "${rules.packageNames.size} allowed app${if (rules.packageNames.size == 1) "" else "s"} ready"
        AppVpnMode.Blocklist -> "${rules.packageNames.size} blocked app${if (rules.packageNames.size == 1) "" else "s"} ready"
    }
