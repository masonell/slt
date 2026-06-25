package dev.slt.android.ui.profile

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Checkbox
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.PrimaryTabRow
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Tab
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import dev.slt.android.profile.AppVpnMode
import dev.slt.android.profile.AppVpnRules
import dev.slt.android.profile.rules.missingAppPackages
import dev.slt.android.ui.UiMessage
import dev.slt.android.ui.uiMessageColor
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Per-app VPN rules editor. Edits a local buffer (mode + selected package
 * names); Apply commits it back, back discards. All mode hides the app list;
 * Allowlist/Blocklist shows a searchable, checkable list of installed apps with
 * bulk Add all / Remove all.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun AppRulesEditorScreen(
    initialMode: AppVpnMode,
    initialPackages: List<String>,
    ownPackageName: String,
    onApply: (AppVpnMode, List<String>) -> Unit,
    onCancel: () -> Unit,
) {
    val context = LocalContext.current
    var bufferMode by remember { mutableStateOf(initialMode) }
    var bufferPackages by remember { mutableStateOf(initialPackages) }
    var installedApps by remember { mutableStateOf<List<InstalledApp>?>(null) }
    var loadMessage by remember { mutableStateOf<UiMessage?>(null) }
    var search by remember { mutableStateOf("") }

    LaunchedEffect(Unit) {
        try {
            installedApps = withContext(Dispatchers.Default) {
                loadInstalledApps(context)
            }
        } catch (error: RuntimeException) {
            loadMessage = UiMessage.error(error.message ?: "Could not load installed apps")
            installedApps = emptyList()
        }
    }

    val effectiveSelected = effectiveSelectedPackages(
        appMode = bufferMode,
        selectedPackageNames = bufferPackages,
        ownPackageName = ownPackageName,
    )
    val selectedSet = effectiveSelected.toSet()
    val installedNames = installedApps.orEmpty().map { it.packageName }.toSet() + ownPackageName
    val missingPackages = missingAppPackages(
        rules = AppVpnRules(mode = bufferMode, packageNames = effectiveSelected),
        installedPackages = installedNames,
    )
    val visibleApps = visibleInstalledAppsForEditor(
        installedApps = installedApps.orEmpty(),
        search = search,
        selectedPackageNames = selectedSet,
        ownPackageName = ownPackageName,
    )

    fun togglePackage(packageName: String, selected: Boolean) {
        bufferPackages = setPackageSelected(
            appMode = bufferMode,
            selectedPackageNames = bufferPackages,
            ownPackageName = ownPackageName,
            packageName = packageName,
            selected = selected,
        )
    }

    fun changeMode(newMode: AppVpnMode) {
        bufferMode = newMode
        bufferPackages = selectedPackagesForMode(newMode, bufferPackages, ownPackageName)
    }

    Scaffold(
        containerColor = MaterialTheme.colorScheme.background,
        topBar = {
            TopAppBar(
                title = { Text("Apps") },
                navigationIcon = {
                    IconButton(onClick = onCancel) {
                        Icon(
                            imageVector = Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = "Cancel",
                        )
                    }
                },
                actions = {
                    TextButton(onClick = { onApply(bufferMode, bufferPackages) }) {
                        Text("Apply")
                    }
                },
            )
        },
    ) { padding ->
        Column(modifier = Modifier.fillMaxSize().padding(padding)) {
            PrimaryTabRow(selectedTabIndex = bufferMode.ordinal) {
                AppVpnMode.entries.forEach { mode ->
                    Tab(
                        selected = bufferMode == mode,
                        onClick = { changeMode(mode) },
                        text = { Text(mode.label()) },
                    )
                }
            }
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .weight(1f)
                    .padding(horizontal = 16.dp)
                    .padding(top = 12.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                if (bufferMode == AppVpnMode.All) {
                    Text(
                        text = "All apps use the VPN.",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                } else {
                    OutlinedTextField(
                        value = search,
                        onValueChange = { search = it },
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true,
                        label = { Text("Search apps") },
                    )
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        TextButton(
                            onClick = {
                                bufferPackages = addAllInstalledPackages(
                                    appMode = bufferMode,
                                    selectedPackageNames = bufferPackages,
                                    ownPackageName = ownPackageName,
                                    installedApps = installedApps.orEmpty(),
                                )
                            },
                            enabled = installedApps != null,
                        ) {
                            Text("Add all")
                        }
                        TextButton(
                            onClick = {
                                bufferPackages = removeAllSelectedPackages(
                                    appMode = bufferMode,
                                    ownPackageName = ownPackageName,
                                )
                            },
                        ) {
                            Text("Remove all")
                        }
                    }
                    if (missingPackages.isNotEmpty()) {
                        Text(
                            text = "Missing: ${missingPackages.joinToString()}",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.error,
                        )
                    }
                    loadMessage?.let {
                        Text(
                            text = it.text,
                            style = MaterialTheme.typography.bodyMedium,
                            color = uiMessageColor(it),
                        )
                    }
                    LazyColumn(
                        modifier = Modifier
                            .weight(1f)
                            .fillMaxWidth(),
                        verticalArrangement = Arrangement.spacedBy(6.dp),
                    ) {
                        when {
                            installedApps == null -> item {
                                Text(
                                    text = "Loading apps",
                                    style = MaterialTheme.typography.bodyMedium,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                )
                            }
                            visibleApps.isEmpty() -> item {
                                Text(
                                    text = "No apps found",
                                    style = MaterialTheme.typography.bodyMedium,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                )
                            }
                            else -> items(visibleApps, key = { it.packageName }) { app ->
                                AppRow(
                                    app = app,
                                    checked = app.packageName in selectedSet,
                                    enabled = app.packageName != ownPackageName,
                                    onCheckedChange = { togglePackage(app.packageName, it) },
                                )
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun AppRow(
    app: InstalledApp,
    checked: Boolean,
    enabled: Boolean,
    onCheckedChange: (Boolean) -> Unit,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(enabled = enabled) { onCheckedChange(!checked) },
        horizontalArrangement = Arrangement.spacedBy(12.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Checkbox(
            checked = checked,
            onCheckedChange = if (enabled) onCheckedChange else null,
            enabled = enabled,
        )
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = app.label,
                style = MaterialTheme.typography.bodyLarge,
            )
            Text(
                text = app.packageName,
                style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

private fun AppVpnMode.label(): String =
    when (this) {
        AppVpnMode.All -> "All"
        AppVpnMode.Allowlist -> "Allowlist"
        AppVpnMode.Blocklist -> "Blocklist"
    }
