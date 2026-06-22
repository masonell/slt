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
import dev.slt.android.profile.store.ProfileRepository
import dev.slt.android.SltNative
import dev.slt.android.profile.AppVpnMode
import dev.slt.android.profile.DnsMode
import dev.slt.android.profile.rules.exportVpnRouteRules
import dev.slt.android.profile.rules.parseDnsSettings
import dev.slt.android.profile.rules.parseTestUrls
import dev.slt.android.profile.rules.parseVpnRouteRules
import dev.slt.android.ui.UiMessage
import dev.slt.android.ui.copySensitiveText
import dev.slt.android.ui.uiMessageColor
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
                when (val result = parseProfileEditorRoutesForSave(editorState)) {
                    is ProfileEditorActionResult.Success -> editorState = result.state.copy(
                        activeNestedScreen = null,
                        message = null,
                    )
                    is ProfileEditorActionResult.Failure -> editorState = result.state
                }
            },
            onCopy = {
                try {
                    val routes = parseVpnRouteRules(editorState.routeText)
                    val normalizedRoutes = exportVpnRouteRules(routes)
                    context.copySensitiveText("SLT routes", normalizedRoutes)
                    editorState = editorState.copy(
                        routeText = normalizedRoutes,
                        routeMessage = UiMessage.info("Routes copied"),
                    )
                } catch (error: IllegalArgumentException) {
                    editorState = editorState.copy(
                        routeMessage = UiMessage.error(error.message ?: "Invalid routes"),
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
                when (val result = parseProfileEditorDnsForSave(editorState, routes)) {
                    is ProfileEditorActionResult.Success -> editorState = result.state.copy(
                        activeNestedScreen = null,
                        message = null,
                    )
                    is ProfileEditorActionResult.Failure -> editorState = result.state
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
                when (val result = normalizeProfileEditorAppsForSave(editorState, context.packageName)) {
                    is ProfileEditorActionResult.Success -> editorState = result.state.copy(
                        activeNestedScreen = null,
                        message = null,
                    )
                    is ProfileEditorActionResult.Failure -> editorState = result.state
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
                when (val result = parseProfileEditorTestUrlsForSave(editorState)) {
                    is ProfileEditorActionResult.Success -> editorState = result.state.copy(
                        activeNestedScreen = null,
                        message = null,
                    )
                    is ProfileEditorActionResult.Failure -> editorState = result.state
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
                    text = it.text,
                    style = MaterialTheme.typography.bodySmall,
                    color = uiMessageColor(it, infoColor = MaterialTheme.colorScheme.onSurfaceVariant),
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
                    text = it.text,
                    style = MaterialTheme.typography.bodySmall,
                    color = uiMessageColor(it, infoColor = MaterialTheme.colorScheme.onSurfaceVariant),
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
                    text = it.text,
                    style = MaterialTheme.typography.bodySmall,
                    color = uiMessageColor(it, infoColor = MaterialTheme.colorScheme.onSurfaceVariant),
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
                    text = it.text,
                    style = MaterialTheme.typography.bodySmall,
                    color = uiMessageColor(it, infoColor = MaterialTheme.colorScheme.onSurfaceVariant),
                )
            }
        }
        editorState.message?.let {
            Text(
                text = it.text,
                style = MaterialTheme.typography.bodyMedium,
                color = uiMessageColor(it),
            )
        }
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            OutlinedButton(
                onClick = {
                    editorState = validateProfileEditorToml(
                        editorState,
                        SltNative::validateClientConfig,
                    ).state
                },
            ) {
                Text("Validate")
            }
            Button(
                onClick = {
                    when (
                        val result = prepareProfileEditorSave(
                            state = editorState,
                            ownPackageName = context.packageName,
                            validateClientConfig = SltNative::validateClientConfig,
                        )
                    ) {
                        is ProfileEditorSaveResult.Blocked -> editorState = result.state
                        is ProfileEditorSaveResult.Ready -> {
                            editorState = result.state
                            scope.launch {
                                profileRepository.saveProfile(
                                    id = profileId,
                                    name = result.name,
                                    clientToml = result.clientToml,
                                    metadata = result.metadata,
                                )
                                onSaved()
                            }
                        }
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
