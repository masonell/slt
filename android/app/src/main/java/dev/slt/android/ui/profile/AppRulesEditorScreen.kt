package dev.slt.android.ui.profile

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.HorizontalDivider
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
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import dev.slt.android.ui.profile.rules.missingAppPackages
import dev.slt.android.ui.UiMessage
import dev.slt.android.ui.uiMessageColor
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

@Composable
internal fun AppRulesEditorScreen(
    appMode: AppVpnMode,
    selectedPackageNames: List<String>,
    appMessage: UiMessage?,
    ownPackageName: String,
    onAppModeChange: (AppVpnMode) -> Unit,
    onSelectedPackageNamesChange: (List<String>) -> Unit,
    onApply: () -> Unit,
    onCancel: () -> Unit,
) {
    val context = LocalContext.current
    var installedApps by remember { mutableStateOf<List<InstalledApp>?>(null) }
    var loadMessage by remember { mutableStateOf<UiMessage?>(null) }
    var search by remember { mutableStateOf("") }

    LaunchedEffect(Unit) {
        try {
            installedApps = withContext(Dispatchers.Default) {
                loadInstalledLaunchableApps(context)
            }
        } catch (error: RuntimeException) {
            loadMessage = UiMessage.error(error.message ?: "Could not load installed apps")
            installedApps = emptyList()
        }
    }

    val effectiveSelectedPackages = effectiveSelectedPackages(
        appMode = appMode,
        selectedPackageNames = selectedPackageNames,
        ownPackageName = ownPackageName,
    )
    val selectedPackageSet = effectiveSelectedPackages.toSet()
    val installedPackageNames = installedApps.orEmpty().map { it.packageName }.toSet() + ownPackageName
    val missingPackages = missingAppPackages(
        rules = AppVpnRules(mode = appMode, packageNames = effectiveSelectedPackages),
        installedPackages = installedPackageNames,
    )
    val visibleApps = visibleInstalledAppsForEditor(
        installedApps = installedApps.orEmpty(),
        search = search,
        selectedPackageNames = selectedPackageSet,
        ownPackageName = ownPackageName,
    )
    val currentMessage = loadMessage ?: appMessage

    fun setAppPackageSelected(packageName: String, selected: Boolean) {
        onSelectedPackageNamesChange(
            setPackageSelected(
                appMode = appMode,
                selectedPackageNames = selectedPackageNames,
                ownPackageName = ownPackageName,
                packageName = packageName,
                selected = selected,
            ),
        )
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
            text = "Apps",
            style = MaterialTheme.typography.headlineSmall,
            fontWeight = FontWeight.SemiBold,
        )
        AppVpnModeSelector(
            appMode = appMode,
            onAppModeChange = {
                onAppModeChange(it)
                onSelectedPackageNamesChange(selectedPackagesForMode(it, selectedPackageNames, ownPackageName))
            },
        )
        if (appMode != AppVpnMode.All) {
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
                verticalAlignment = Alignment.CenterVertically,
            ) {
                OutlinedButton(
                    onClick = {
                        onSelectedPackageNamesChange(
                            addAllInstalledPackages(
                                appMode = appMode,
                                selectedPackageNames = selectedPackageNames,
                                ownPackageName = ownPackageName,
                                installedApps = installedApps.orEmpty(),
                            ),
                        )
                    },
                    enabled = installedApps != null,
                ) {
                    Text("Add all")
                }
                OutlinedButton(
                    onClick = {
                        onSelectedPackageNamesChange(
                            removeAllSelectedPackages(
                                appMode = appMode,
                                ownPackageName = ownPackageName,
                            ),
                        )
                    },
                ) {
                    Text("Remove all")
                }
            }
        }
        if (missingPackages.isNotEmpty()) {
            Text(
                text = "Missing saved packages: ${missingPackages.joinToString(", ")}",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.error,
            )
        }
        currentMessage?.let {
            Text(
                text = it.text,
                style = MaterialTheme.typography.bodyMedium,
                color = uiMessageColor(it),
            )
        }
        if (appMode == AppVpnMode.All) {
            Spacer(modifier = Modifier.weight(1f))
        } else {
            LazyColumn(
                modifier = Modifier
                    .fillMaxWidth()
                    .weight(1f),
                verticalArrangement = Arrangement.spacedBy(6.dp),
            ) {
                if (installedApps == null) {
                    item {
                        Text(
                            text = "Loading apps",
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                } else if (visibleApps.isEmpty()) {
                    item {
                        Text(
                            text = "No apps found",
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                } else {
                    items(visibleApps, key = { it.packageName }) { app ->
                        AppListItem(
                            app = app,
                            checked = app.packageName in selectedPackageSet,
                            enabled = app.packageName != ownPackageName,
                            onCheckedChange = { selected -> setAppPackageSelected(app.packageName, selected) },
                        )
                    }
                }
            }
        }
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Button(onClick = onApply) {
                Text("Apply")
            }
            TextButton(onClick = onCancel) {
                Text("Cancel")
            }
        }
    }
}

@Composable
private fun AppVpnModeSelector(
    appMode: AppVpnMode,
    onAppModeChange: (AppVpnMode) -> Unit,
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        AppVpnMode.entries.forEach { mode ->
            if (appMode == mode) {
                Button(
                    onClick = { onAppModeChange(mode) },
                    modifier = Modifier.weight(1f),
                ) {
                    Text(mode.label())
                }
            } else {
                OutlinedButton(
                    onClick = { onAppModeChange(mode) },
                    modifier = Modifier.weight(1f),
                ) {
                    Text(mode.label())
                }
            }
        }
    }
}

@Composable
private fun AppListItem(
    app: InstalledApp,
    checked: Boolean,
    enabled: Boolean,
    onCheckedChange: (Boolean) -> Unit,
) {
    Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
        HorizontalDivider()
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
}

private fun AppVpnMode.label(): String =
    when (this) {
        AppVpnMode.All -> "All"
        AppVpnMode.Allowlist -> "Allowlist"
        AppVpnMode.Blocklist -> "Blocklist"
    }
