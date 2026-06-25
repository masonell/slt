package dev.slt.android.ui.profile

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.KeyboardArrowRight
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Snackbar
import androidx.compose.material3.SnackbarDuration
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
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
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import dev.slt.android.SltNative
import dev.slt.android.profile.AppVpnMode
import dev.slt.android.profile.DnsMode
import dev.slt.android.profile.rules.parseDnsSettings
import dev.slt.android.profile.rules.parseTestUrls
import dev.slt.android.profile.rules.parseVpnRouteRules
import dev.slt.android.profile.store.ProfileRepository
import dev.slt.android.ui.copySensitiveText
import kotlinx.coroutines.launch

@OptIn(ExperimentalMaterial3Api::class)
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
        val base = profileEditorStateFrom(profile)
        // Validate an existing config up front so the Client config card can show
        // the server summary immediately; new (empty) profiles stay "Not set".
        editorState = if (base.toml.isNotBlank()) {
            base.copy(validation = SltNative.validateClientConfig(base.toml))
        } else {
            base
        }
    }

    BackHandler(enabled = editorState.isEditingNestedScreen) {
        editorState = editorState.withClosedNestedScreen()
    }

    if (editorState.activeNestedScreen == ProfileEditorNestedScreen.Toml) {
        TomlEditorScreen(
            initialToml = editorState.toml,
            validate = SltNative::validateClientConfig,
            onApply = { toml, validation ->
                editorState = editorState.copy(
                    toml = toml,
                    validation = validation,
                    activeNestedScreen = null,
                    message = null,
                )
            },
            onCancel = { editorState = editorState.withClosedNestedScreen() },
            onCopy = { context.copySensitiveText("SLT config", it) },
        )
        return
    }

    if (editorState.activeNestedScreen == ProfileEditorNestedScreen.Routes) {
        RouteEditorScreen(
            initialText = editorState.routeText,
            onApply = { committed ->
                editorState = editorState.copy(
                    routeText = committed,
                    activeNestedScreen = null,
                    message = null,
                )
            },
            onCopy = { context.copySensitiveText("SLT routes", it) },
            onCancel = {
                editorState = editorState.withClosedNestedScreen()
            },
        )
        return
    }

    if (editorState.activeNestedScreen == ProfileEditorNestedScreen.Dns) {
        DnsEditorScreen(
            initialMode = editorState.dnsMode,
            initialText = editorState.dnsText,
            onApply = { mode, text ->
                editorState = editorState.copy(
                    dnsMode = mode,
                    dnsText = text,
                    activeNestedScreen = null,
                    message = null,
                )
            },
            onCancel = {
                editorState = editorState.withClosedNestedScreen()
            },
        )
        return
    }

    if (editorState.activeNestedScreen == ProfileEditorNestedScreen.Apps) {
        AppRulesEditorScreen(
            initialMode = editorState.appMode,
            initialPackages = editorState.selectedPackageNames,
            ownPackageName = context.packageName,
            onApply = { mode, packages ->
                editorState = editorState.copy(
                    appMode = mode,
                    selectedPackageNames = packages,
                    activeNestedScreen = null,
                    message = null,
                )
            },
            onCancel = {
                editorState = editorState.withClosedNestedScreen()
            },
        )
        return
    }

    if (editorState.activeNestedScreen == ProfileEditorNestedScreen.TestUrls) {
        TestUrlsEditorScreen(
            initialText = editorState.testUrlsText,
            onApply = { committed ->
                editorState = editorState.copy(
                    testUrlsText = committed,
                    activeNestedScreen = null,
                    message = null,
                )
            },
            onCancel = {
                editorState = editorState.withClosedNestedScreen()
            },
        )
        return
    }

    val snackbarHostState = remember { SnackbarHostState() }
    LaunchedEffect(editorState.message) {
        editorState.message?.let {
            snackbarHostState.showSnackbar(
                message = it.text,
                actionLabel = "Dismiss",
                duration = SnackbarDuration.Short,
            )
            editorState = editorState.copy(message = null)
        }
    }

    Scaffold(
        containerColor = MaterialTheme.colorScheme.background,
        topBar = {
            TopAppBar(
                title = { Text(if (profileId == null) "Add Profile" else "Edit Profile") },
                navigationIcon = {
                    IconButton(onClick = onCancel) {
                        Icon(
                            imageVector = Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = "Cancel",
                        )
                    }
                },
                actions = {
                    TextButton(onClick = {
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
                    }) {
                        Text("Save")
                    }
                },
            )
        },
        snackbarHost = {
            SnackbarHost(snackbarHostState) { snackbarData ->
                Snackbar(
                    snackbarData = snackbarData,
                    containerColor = MaterialTheme.colorScheme.surfaceContainerHigh,
                    contentColor = MaterialTheme.colorScheme.onSurface,
                    actionColor = MaterialTheme.colorScheme.primary,
                )
            }
        },
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .verticalScroll(rememberScrollState())
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            OutlinedTextField(
                value = editorState.name,
                onValueChange = { editorState = editorState.copy(name = it) },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
                label = { Text("Profile name") },
            )
            EditorSectionCard(
                title = "Client config",
                summary = tomlCardSummary(editorState),
                onClick = {
                    editorState = editorState.copy(activeNestedScreen = ProfileEditorNestedScreen.Toml)
                },
            )
            EditorSectionCard(
                title = "Routes",
                summary = routeSummary(editorState.routeText),
                onClick = {
                    editorState = editorState.copy(activeNestedScreen = ProfileEditorNestedScreen.Routes)
                },
            )
            EditorSectionCard(
                title = "DNS",
                summary = dnsSummary(editorState.dnsMode, editorState.dnsText),
                onClick = {
                    editorState = editorState.copy(activeNestedScreen = ProfileEditorNestedScreen.Dns)
                },
            )
            EditorSectionCard(
                title = "Apps",
                summary = appsSummary(
                    editorState.appMode,
                    editorState.selectedPackageNames.filterNot { it == context.packageName },
                ),
                onClick = {
                    editorState = editorState.copy(activeNestedScreen = ProfileEditorNestedScreen.Apps)
                },
            )
            EditorSectionCard(
                title = "Test URLs",
                summary = testUrlsSummary(editorState.testUrlsText),
                onClick = {
                    editorState = editorState.copy(activeNestedScreen = ProfileEditorNestedScreen.TestUrls)
                },
            )
        }
    }
}

@Composable
private fun EditorSectionCard(
    title: String,
    summary: String,
    onClick: () -> Unit,
) {
    Surface(
        onClick = onClick,
        shape = RoundedCornerShape(16.dp),
        color = MaterialTheme.colorScheme.surface,
        contentColor = MaterialTheme.colorScheme.onSurface,
        modifier = Modifier.fillMaxWidth(),
    ) {
        Row(
            modifier = Modifier.padding(16.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(
                modifier = Modifier.weight(1f),
                verticalArrangement = Arrangement.spacedBy(2.dp),
            ) {
                Text(
                    text = title,
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Medium,
                )
                Text(
                    text = summary,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Icon(
                imageVector = Icons.AutoMirrored.Filled.KeyboardArrowRight,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

private fun tomlCardSummary(state: ProfileEditorState): String {
    val validation = state.validation
    return when {
        state.toml.isBlank() -> "Not set"
        validation?.summary != null ->
            "Server ${validation.summary.serverHost}:${validation.summary.serverPort}"
        else -> "Not validated"
    }
}

private fun routeSummary(routeText: String): String =
    try {
        val routes = parseVpnRouteRules(routeText)
        val included = routes.count { !it.excluded }
        val excluded = routes.count { it.excluded }
        "$included include · $excluded exclude"
    } catch (_: IllegalArgumentException) {
        "Needs attention"
    }

private fun dnsSummary(mode: DnsMode, dnsText: String): String =
    try {
        val dns = parseDnsSettings(mode, dnsText)
        when (dns.mode) {
            DnsMode.System -> "System"
            DnsMode.Custom -> "${dns.servers.size} custom server${if (dns.servers.size == 1) "" else "s"}"
        }
    } catch (_: IllegalArgumentException) {
        "Needs attention"
    }

private fun appsSummary(mode: AppVpnMode, packageNames: List<String>): String =
    when (mode) {
        AppVpnMode.All -> "All apps"
        AppVpnMode.Allowlist -> "${packageNames.size} allowed"
        AppVpnMode.Blocklist -> "${packageNames.size} blocked"
    }

private fun testUrlsSummary(testUrlsText: String): String =
    try {
        val testUrls = parseTestUrls(testUrlsText)
        "${testUrls.size} URL${if (testUrls.size == 1) "" else "s"}"
    } catch (_: IllegalArgumentException) {
        "Needs attention"
    }
