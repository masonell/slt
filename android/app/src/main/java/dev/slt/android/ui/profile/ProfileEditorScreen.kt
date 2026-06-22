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
import dev.slt.android.SltProfile
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
    var loadedProfile by remember(profileId) { mutableStateOf<SltProfile?>(null) }
    var name by remember(profileId) { mutableStateOf("") }
    var toml by remember(profileId) { mutableStateOf("") }
    var routeText by remember(profileId) { mutableStateOf("") }
    var dnsMode by remember(profileId) { mutableStateOf(DnsMode.System) }
    var dnsText by remember(profileId) { mutableStateOf("") }
    var appMode by remember(profileId) { mutableStateOf(AppVpnMode.All) }
    var appPackageNames by remember(profileId) { mutableStateOf(emptyList<String>()) }
    var testUrlsText by remember(profileId) { mutableStateOf("") }
    var validation by remember(profileId) { mutableStateOf<ConfigValidationResult?>(null) }
    var message by remember(profileId) { mutableStateOf<String?>(null) }
    var routeMessage by remember(profileId) { mutableStateOf<String?>(null) }
    var dnsMessage by remember(profileId) { mutableStateOf<String?>(null) }
    var appMessage by remember(profileId) { mutableStateOf<String?>(null) }
    var testUrlsMessage by remember(profileId) { mutableStateOf<String?>(null) }
    var editingRoutes by remember(profileId) { mutableStateOf(false) }
    var editingDns by remember(profileId) { mutableStateOf(false) }
    var editingApps by remember(profileId) { mutableStateOf(false) }
    var editingTestUrls by remember(profileId) { mutableStateOf(false) }

    LaunchedEffect(profileId) {
        val profile = profileId?.let { profileRepository.loadProfile(it) }
        loadedProfile = profile
        name = profile?.metadata?.name.orEmpty()
        toml = profile?.clientToml.orEmpty()
        routeText = exportVpnRouteRules(profile?.metadata?.routes.orEmpty())
        dnsMode = profile?.metadata?.dns?.mode ?: DnsMode.System
        dnsText = exportDnsServers(profile?.metadata?.dns?.servers.orEmpty())
        appMode = profile?.metadata?.appRules?.mode ?: AppVpnMode.All
        appPackageNames = profile?.metadata?.appRules?.packageNames.orEmpty()
        testUrlsText = exportTestUrls(profile?.metadata?.testUrls.orEmpty())
        validation = null
        message = null
        routeMessage = null
        dnsMessage = null
        appMessage = null
        testUrlsMessage = null
        editingRoutes = false
        editingDns = false
        editingApps = false
        editingTestUrls = false
    }

    BackHandler(enabled = editingRoutes || editingDns || editingApps || editingTestUrls) {
        editingRoutes = false
        editingDns = false
        editingApps = false
        editingTestUrls = false
    }

    fun validate(): ConfigValidationResult {
        val result = SltNative.validateClientConfig(toml)
        validation = result
        message = if (result.isValid) "Config is valid" else result.error
        return result
    }

    fun parseRoutesForSave(): List<VpnRouteRule>? =
        try {
            val routes = parseVpnRouteRules(routeText)
            if (routes.isEmpty()) {
                routeMessage = "At least one VPN route is required"
                message = routeMessage
                null
            } else {
                routeText = exportVpnRouteRules(routes)
                routeMessage = "${routes.size} route${if (routes.size == 1) "" else "s"} ready"
                routes
            }
        } catch (error: IllegalArgumentException) {
            routeMessage = error.message ?: "Invalid routes"
            message = routeMessage
            null
        }

    fun parseDnsForSave(routes: List<VpnRouteRule>?): DnsSettings? =
        try {
            val dns = parseDnsSettings(dnsMode, dnsText)
            dnsText = exportDnsServers(dns.servers)
            val warnings = routes?.let { dnsExcludedRouteWarnings(it, dns) }.orEmpty()
            dnsMessage = warnings.firstOrNull()
                ?: when (dns.mode) {
                    DnsMode.System -> "System DNS ready"
                    DnsMode.Custom -> "${dns.servers.size} DNS server${if (dns.servers.size == 1) "" else "s"} ready"
                }
            dns
        } catch (error: IllegalArgumentException) {
            dnsMessage = error.message ?: "Invalid DNS settings"
            message = dnsMessage
            null
        }

    fun parseAppsForSave(): AppVpnRules? =
        try {
            val appRules = normalizeAppVpnRules(appMode, appPackageNames, context.packageName)
            appMode = appRules.mode
            appPackageNames = appRules.packageNames
            appMessage = appRulesSummary(appRules)
            appRules
        } catch (error: IllegalArgumentException) {
            appMessage = error.message ?: "Invalid app rules"
            message = appMessage
            null
        }

    fun parseTestUrlsForSave(): List<String>? =
        try {
            val testUrls = parseTestUrls(testUrlsText)
            testUrlsText = exportTestUrls(testUrls)
            testUrlsMessage = if (testUrls.isEmpty()) {
                "No test URLs configured"
            } else {
                "${testUrls.size} test URL${if (testUrls.size == 1) "" else "s"} ready"
            }
            testUrls
        } catch (error: IllegalArgumentException) {
            testUrlsMessage = error.message ?: "Invalid test URLs"
            message = testUrlsMessage
            null
        }

    if (editingRoutes) {
        RouteEditorScreen(
            routeText = routeText,
            routeMessage = routeMessage,
            onRouteTextChange = {
                routeText = it
                routeMessage = null
            },
            onApply = {
                val routes = parseRoutesForSave()
                if (routes != null) {
                    editingRoutes = false
                    message = null
                }
            },
            onCopy = {
                try {
                    val routes = parseVpnRouteRules(routeText)
                    val normalizedRoutes = exportVpnRouteRules(routes)
                    routeText = normalizedRoutes
                    context.copySensitiveText("SLT routes", normalizedRoutes)
                    routeMessage = "Routes copied"
                } catch (error: IllegalArgumentException) {
                    routeMessage = error.message ?: "Invalid routes"
                }
            },
            onCancel = {
                editingRoutes = false
            },
        )
        return
    }

    if (editingDns) {
        DnsEditorScreen(
            dnsMode = dnsMode,
            dnsText = dnsText,
            dnsMessage = dnsMessage,
            onDnsModeChange = {
                dnsMode = it
                dnsMessage = null
            },
            onDnsTextChange = {
                dnsText = it
                dnsMessage = null
            },
            onApply = {
                val routes = try {
                    parseVpnRouteRules(routeText)
                } catch (_: IllegalArgumentException) {
                    null
                }
                if (parseDnsForSave(routes) != null) {
                    editingDns = false
                    message = null
                }
            },
            onCancel = {
                editingDns = false
            },
        )
        return
    }

    if (editingApps) {
        AppRulesEditorScreen(
            appMode = appMode,
            selectedPackageNames = appPackageNames,
            appMessage = appMessage,
            ownPackageName = context.packageName,
            onAppModeChange = {
                appMode = it
                appMessage = null
            },
            onSelectedPackageNamesChange = {
                appPackageNames = it
                appMessage = null
            },
            onApply = {
                if (parseAppsForSave() != null) {
                    editingApps = false
                    message = null
                }
            },
            onCancel = {
                editingApps = false
            },
        )
        return
    }

    if (editingTestUrls) {
        TestUrlsEditorScreen(
            testUrlsText = testUrlsText,
            testUrlsMessage = testUrlsMessage,
            onTestUrlsTextChange = {
                testUrlsText = it
                testUrlsMessage = null
            },
            onApply = {
                if (parseTestUrlsForSave() != null) {
                    editingTestUrls = false
                    message = null
                }
            },
            onCancel = {
                editingTestUrls = false
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
            value = name,
            onValueChange = { name = it },
            modifier = Modifier.fillMaxWidth(),
            singleLine = true,
            label = { Text("Profile name") },
        )
        OutlinedTextField(
            value = toml,
            onValueChange = {
                toml = it
                validation = null
                message = null
            },
            modifier = Modifier
                .fillMaxWidth()
                .weight(1f),
            label = { Text("SLT client TOML") },
            textStyle = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
        )
        validation?.summary?.let { summary ->
            Text(
                text = "Server ${summary.serverHost}:${summary.serverPort}  MTU ${summary.tunMtu}  IPv4 ${summary.assignedIpv4}",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Text(
                text = routeSummary(routeText),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            OutlinedButton(onClick = { editingRoutes = true }) {
                Text("Edit Routes")
            }
            routeMessage?.let {
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
                text = dnsSummary(dnsMode, dnsText),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            OutlinedButton(onClick = { editingDns = true }) {
                Text("Edit DNS")
            }
            dnsMessage?.let {
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
                text = appsSummary(appMode, appPackageNames.filterNot { it == context.packageName }),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            OutlinedButton(onClick = { editingApps = true }) {
                Text("Edit Apps")
            }
            appMessage?.let {
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
                text = testUrlsSummary(testUrlsText),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            OutlinedButton(onClick = { editingTestUrls = true }) {
                Text("Edit Test URLs")
            }
            testUrlsMessage?.let {
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
        message?.let {
            Text(
                text = it,
                style = MaterialTheme.typography.bodyMedium,
                color = if (validation?.isValid == false || messageIsError(it)) {
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
                    val trimmedName = name.trim()
                    if (trimmedName.isEmpty()) {
                        message = "Profile name is required"
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
                        val metadata = (loadedProfile?.metadata ?: ProfileMetadata(name = trimmedName))
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
                            clientToml = toml,
                            metadata = metadata,
                        )
                        onSaved()
                    }
                },
            ) {
                Text("Save")
            }
            OutlinedButton(onClick = { context.copySensitiveText("SLT config", toml) }) {
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

