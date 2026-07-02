package dev.slt.android.ui.profile

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
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import dev.slt.android.ConfigValidationResult
import dev.slt.android.profile.AppVpnMode
import dev.slt.android.profile.DnsMode
import dev.slt.android.profile.rules.parseDnsSettings
import dev.slt.android.profile.rules.parseTestUrls
import dev.slt.android.profile.rules.parseVpnRouteRules

/**
 * The editor hub: renders the profile name field, the section cards that open
 * nested editors, the save action, and the editor-wide snackbar. It owns no
 * validation or persistence; [onSave] is invoked as a plain click and the
 * orchestration in [ProfileEditorScreen] decides what to do with it.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun ProfileEditorHub(
    state: ProfileEditorState,
    profileId: String?,
    ownPackageName: String,
    onNameChange: (String) -> Unit,
    onOpenScreen: (ProfileEditorNestedScreen) -> Unit,
    onSave: () -> Unit,
    onCancel: () -> Unit,
    onMessageShown: () -> Unit,
) {
    val snackbarHostState = remember { SnackbarHostState() }
    LaunchedEffect(state.message) {
        state.message?.let {
            snackbarHostState.showSnackbar(
                message = it.text,
                actionLabel = "Dismiss",
                duration = SnackbarDuration.Short,
            )
            onMessageShown()
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
                    TextButton(onClick = onSave) {
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
                value = state.name,
                onValueChange = onNameChange,
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
                label = { Text("Profile name") },
            )
            EditorSectionCard(
                title = "Client config",
                summary = tomlCardSummary(state),
                onClick = { onOpenScreen(ProfileEditorNestedScreen.Toml) },
            )
            EditorSectionCard(
                title = "Routes",
                summary = routeSummary(state.routeText),
                onClick = { onOpenScreen(ProfileEditorNestedScreen.Routes) },
            )
            EditorSectionCard(
                title = "DNS",
                summary = dnsSummary(state.dnsMode, state.dnsText),
                onClick = { onOpenScreen(ProfileEditorNestedScreen.Dns) },
            )
            EditorSectionCard(
                title = "Apps",
                summary = appsSummary(
                    state.appMode,
                    state.selectedPackageNames.filterNot { it == ownPackageName },
                ),
                onClick = { onOpenScreen(ProfileEditorNestedScreen.Apps) },
            )
            EditorSectionCard(
                title = "Test URLs",
                summary = testUrlsSummary(state.testUrlsText),
                onClick = { onOpenScreen(ProfileEditorNestedScreen.TestUrls) },
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
        validation is ConfigValidationResult.Valid ->
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
