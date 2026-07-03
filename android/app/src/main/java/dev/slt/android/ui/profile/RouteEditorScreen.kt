package dev.slt.android.ui.profile

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Close
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.PrimaryTabRow
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Snackbar
import androidx.compose.material3.SnackbarDuration
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Tab
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
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import dev.slt.android.profile.VpnRouteRule
import dev.slt.android.profile.rules.exportVpnRouteRules
import dev.slt.android.profile.rules.parseVpnRouteRules
import dev.slt.android.ui.UiMessage
import kotlinx.coroutines.launch

/**
 * VPN route editor. Edits a local buffer (newline-separated CIDRs with optional
 * `!` exclude prefix) in List or Text mode; Apply commits it back (only if it
 * parses), back discards. Copy exports the normalized buffer to the clipboard.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun RouteEditorScreen(
    initialText: String,
    onApply: (String) -> Unit,
    onCopy: (String) -> Unit,
    onCancel: () -> Unit,
) {
    val context = LocalContext.current
    val coroutineScope = rememberCoroutineScope()
    var buffer by remember { mutableStateOf(initialText) }
    var editorMode by remember { mutableStateOf(RouteEditorMode.List) }
    var newRouteCidr by remember { mutableStateOf("") }
    var newRouteExcluded by remember { mutableStateOf(false) }
    var message by remember { mutableStateOf<UiMessage?>(null) }
    val snackbarHostState = remember { SnackbarHostState() }
    val importLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocument(),
    ) { uri ->
        uri ?: return@rememberLauncherForActivityResult
        coroutineScope.launch {
            runCatching { context.readImportedText(uri) }
                .onSuccess { importedText ->
                    runCatching { exportVpnRouteRules(parseVpnRouteRules(importedText)) }
                        .onSuccess { normalized ->
                            buffer = normalized
                            editorMode = RouteEditorMode.List
                            message = UiMessage.info("Routes imported")
                        }
                        .onFailure { error ->
                            buffer = importedText
                            editorMode = RouteEditorMode.Text
                            message = UiMessage.error(error.message ?: "Invalid routes")
                        }
                }
                .onFailure { error ->
                    message = UiMessage.error(error.message ?: "Could not import routes")
                }
        }
    }
    LaunchedEffect(message) {
        message?.let {
            snackbarHostState.showSnackbar(
                message = it.text,
                actionLabel = "Dismiss",
                duration = SnackbarDuration.Short,
            )
            message = null
        }
    }

    val currentRoutes = displayedVpnRoutes(buffer)

    fun addRoute() {
        val result = addVpnRouteFromForm(
            routeText = buffer,
            cidrText = newRouteCidr,
            excluded = newRouteExcluded,
        )
        if (result.changed) {
            buffer = result.text
            newRouteCidr = ""
        }
        message = result.message
    }

    fun copyRoutes() {
        try {
            val normalized = exportVpnRouteRules(parseVpnRouteRules(buffer))
            onCopy(normalized)
            buffer = normalized
            message = UiMessage.info("Routes copied")
        } catch (error: IllegalArgumentException) {
            message = UiMessage.error(error.message ?: "Invalid routes")
        }
    }

    Scaffold(
        containerColor = MaterialTheme.colorScheme.background,
        topBar = {
            TopAppBar(
                title = { Text("Routes") },
                navigationIcon = {
                    IconButton(onClick = onCancel) {
                        Icon(
                            imageVector = Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = "Cancel",
                        )
                    }
                },
                actions = {
                    TextButton(onClick = { importLauncher.launch(importTextMimeTypes) }) {
                        Text("Import")
                    }
                    TextButton(onClick = { copyRoutes() }) {
                        Text("Copy")
                    }
                    TextButton(onClick = {
                        val parsed = runCatching { parseVpnRouteRules(buffer) }
                        if (parsed.isSuccess) {
                            onApply(buffer)
                        } else {
                            message = UiMessage.error(
                                parsed.exceptionOrNull()?.message ?: "Invalid routes",
                            )
                        }
                    }) {
                        Text("Apply")
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
        Column(modifier = Modifier.fillMaxSize().padding(padding)) {
            PrimaryTabRow(selectedTabIndex = editorMode.ordinal) {
                RouteEditorMode.entries.forEach { mode ->
                    Tab(
                        selected = editorMode == mode,
                        onClick = { editorMode = mode },
                        text = { Text(mode.label) },
                    )
                }
            }
            when (editorMode) {
                RouteEditorMode.List -> Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .weight(1f)
                        .padding(horizontal = 16.dp)
                        .padding(top = 12.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    LazyColumn(
                        modifier = Modifier.weight(1f).fillMaxWidth(),
                        verticalArrangement = Arrangement.spacedBy(6.dp),
                    ) {
                        when {
                            currentRoutes == null -> item {
                                Text(
                                    text = "Fix route text in Text mode before using the list view.",
                                    style = MaterialTheme.typography.bodyMedium,
                                    color = MaterialTheme.colorScheme.error,
                                )
                            }
                            currentRoutes.isEmpty() -> item {
                                Text(
                                    text = "No routes",
                                    style = MaterialTheme.typography.bodyMedium,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                )
                            }
                            else -> itemsIndexed(currentRoutes) { index, route ->
                                RouteRow(route) { buffer = removeVpnRouteAt(buffer, index).text }
                            }
                        }
                    }
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        FilterChip(
                            selected = !newRouteExcluded,
                            onClick = { newRouteExcluded = false },
                            label = { Text("Include") },
                            modifier = Modifier.weight(1f),
                        )
                        FilterChip(
                            selected = newRouteExcluded,
                            onClick = { newRouteExcluded = true },
                            label = { Text("Exclude") },
                            modifier = Modifier.weight(1f),
                        )
                    }
                    OutlinedTextField(
                        value = newRouteCidr,
                        onValueChange = {
                            newRouteCidr = it
                            message = null
                        },
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true,
                        label = { Text("CIDR") },
                        trailingIcon = {
                            IconButton(onClick = { addRoute() }) {
                                Icon(
                                    imageVector = Icons.Filled.Add,
                                    contentDescription = "Add",
                                )
                            }
                        },
                        textStyle = MaterialTheme.typography.bodyMedium.copy(fontFamily = FontFamily.Monospace),
                    )
                }

                RouteEditorMode.Text -> OutlinedTextField(
                    value = buffer,
                    onValueChange = {
                        buffer = it
                        message = null
                    },
                    modifier = Modifier
                        .fillMaxWidth()
                        .weight(1f)
                        .padding(horizontal = 16.dp)
                        .padding(top = 12.dp),
                    label = { Text("VPN routes") },
                    textStyle = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
                )
            }
        }
    }
}

@Composable
private fun RouteRow(route: VpnRouteRule, onRemove: () -> Unit) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(12.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(
            text = if (route.excluded) "Exclude" else "Include",
            modifier = Modifier.weight(0.4f),
            style = MaterialTheme.typography.labelLarge,
            color = if (route.excluded) {
                MaterialTheme.colorScheme.error
            } else {
                MaterialTheme.colorScheme.primary
            },
        )
        Text(
            text = route.cidr,
            modifier = Modifier.weight(1f),
            style = MaterialTheme.typography.bodyMedium.copy(fontFamily = FontFamily.Monospace),
        )
        IconButton(onClick = onRemove) {
            Icon(
                imageVector = Icons.Filled.Close,
                contentDescription = "Remove",
            )
        }
    }
}

private enum class RouteEditorMode(val label: String) {
    List("List"),
    Text("Text"),
}
