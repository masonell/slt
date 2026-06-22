package dev.slt.android.ui.profile

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.PrimaryTabRow
import androidx.compose.material3.Tab
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import dev.slt.android.VpnRouteRule
import dev.slt.android.exportVpnRouteRules
import dev.slt.android.parseVpnRouteRules
import dev.slt.android.ui.UiMessage
import dev.slt.android.ui.uiMessageColor

@Composable
internal fun RouteEditorScreen(
    routeText: String,
    routeMessage: UiMessage?,
    onRouteTextChange: (String) -> Unit,
    onApply: () -> Unit,
    onCopy: () -> Unit,
    onCancel: () -> Unit,
) {
    var editorMode by remember { mutableStateOf(RouteEditorMode.List) }
    var newRouteCidr by remember { mutableStateOf("") }
    var newRouteExcluded by remember { mutableStateOf(false) }
    var listMessage by remember { mutableStateOf<UiMessage?>(null) }
    val currentMessage = listMessage ?: routeMessage

    fun currentRoutesOrNull(): List<VpnRouteRule>? =
        try {
            parseVpnRouteRules(routeText)
        } catch (error: IllegalArgumentException) {
            listMessage = UiMessage.error(error.message ?: "Invalid routes")
            null
        }

    fun currentRoutesForDisplay(): List<VpnRouteRule>? =
        try {
            parseVpnRouteRules(routeText)
        } catch (_: IllegalArgumentException) {
            null
        }

    fun replaceRoutes(routes: List<VpnRouteRule>) {
        onRouteTextChange(exportVpnRouteRules(routes))
        listMessage = null
    }

    fun addRouteFromListForm() {
        val cidr = newRouteCidr.trim()
        if (cidr.isEmpty()) {
            listMessage = UiMessage.error("Route CIDR is required")
            return
        }
        val prefix = if (newRouteExcluded) "!" else ""
        val existingRoutes = currentRoutesOrNull() ?: return
        val newRoutes = try {
            parseVpnRouteRules("$prefix$cidr")
        } catch (error: IllegalArgumentException) {
            listMessage = UiMessage.error(error.message ?: "Invalid route")
            return
        }
        val existingText = exportVpnRouteRules(existingRoutes)
        val candidateText = listOf(existingText, "$prefix$cidr")
            .filter { it.isNotBlank() }
            .joinToString("\n")
        try {
            val routes = parseVpnRouteRules(candidateText)
            if (routes == existingRoutes) {
                listMessage = if (newRoutes.any { route -> existingRoutes.contains(route) }) {
                    UiMessage.info("Route already exists")
                } else {
                    UiMessage.info(
                        "Route is already covered by an existing ${if (newRouteExcluded) "exclude" else "include"} route",
                    )
                }
                return
            }
            replaceRoutes(routes)
            newRouteCidr = ""
            listMessage = UiMessage.info("Route added")
        } catch (error: IllegalArgumentException) {
            listMessage = UiMessage.error(error.message ?: "Invalid route")
        }
    }

    fun removeRoute(index: Int) {
        val routes = currentRoutesOrNull() ?: return
        replaceRoutes(routes.filterIndexed { routeIndex, _ -> routeIndex != index })
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
            text = "Routes",
            style = MaterialTheme.typography.headlineSmall,
            fontWeight = FontWeight.SemiBold,
        )
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
            RouteEditorMode.List -> RouteListEditor(
                routes = currentRoutesForDisplay(),
                newRouteCidr = newRouteCidr,
                newRouteExcluded = newRouteExcluded,
                onNewRouteCidrChange = {
                    newRouteCidr = it
                    listMessage = null
                },
                onNewRouteExcludedChange = {
                    newRouteExcluded = it
                    listMessage = null
                },
                onAdd = ::addRouteFromListForm,
                onRemove = ::removeRoute,
                modifier = Modifier
                    .fillMaxWidth()
                    .weight(1f),
            )

            RouteEditorMode.Text -> OutlinedTextField(
                value = routeText,
                onValueChange = {
                    onRouteTextChange(it)
                    listMessage = null
                },
                modifier = Modifier
                    .fillMaxWidth()
                    .weight(1f),
                label = { Text("VPN routes") },
                textStyle = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
            )
        }
        currentMessage?.let {
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
            Button(onClick = onApply) {
                Text("Apply")
            }
            OutlinedButton(onClick = onCopy) {
                Text("Copy")
            }
            TextButton(onClick = onCancel) {
                Text("Cancel")
            }
        }
    }
}

@Composable
private fun RouteListEditor(
    routes: List<VpnRouteRule>?,
    newRouteCidr: String,
    newRouteExcluded: Boolean,
    onNewRouteCidrChange: (String) -> Unit,
    onNewRouteExcludedChange: (Boolean) -> Unit,
    onAdd: () -> Unit,
    onRemove: (Int) -> Unit,
    modifier: Modifier = Modifier,
) {
    Column(
        modifier = modifier.verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        if (routes == null) {
            Text(
                text = "Fix route text before using the list view.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.error,
            )
        } else if (routes.isEmpty()) {
            Text(
                text = "No routes",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        } else {
            routes.forEachIndexed { index, route ->
                RouteListItem(
                    route = route,
                    onRemove = { onRemove(index) },
                )
            }
        }

        HorizontalDivider()
        OutlinedTextField(
            value = newRouteCidr,
            onValueChange = onNewRouteCidrChange,
            modifier = Modifier.fillMaxWidth(),
            singleLine = true,
            label = { Text("CIDR") },
            textStyle = MaterialTheme.typography.bodyMedium.copy(fontFamily = FontFamily.Monospace),
        )
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            if (newRouteExcluded) {
                OutlinedButton(
                    onClick = { onNewRouteExcludedChange(false) },
                    modifier = Modifier.weight(1f),
                ) {
                    Text("Include")
                }
                Button(
                    onClick = { onNewRouteExcludedChange(true) },
                    modifier = Modifier.weight(1f),
                ) {
                    Text("Exclude")
                }
            } else {
                Button(
                    onClick = { onNewRouteExcludedChange(false) },
                    modifier = Modifier.weight(1f),
                ) {
                    Text("Include")
                }
                OutlinedButton(
                    onClick = { onNewRouteExcludedChange(true) },
                    modifier = Modifier.weight(1f),
                ) {
                    Text("Exclude")
                }
            }
            Button(onClick = onAdd) {
                Text("Add")
            }
        }
    }
}

@Composable
private fun RouteListItem(
    route: VpnRouteRule,
    onRemove: () -> Unit,
) {
    Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
        HorizontalDivider()
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(12.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = if (route.excluded) "Exclude" else "Include",
                    style = MaterialTheme.typography.labelLarge,
                    color = if (route.excluded) {
                        MaterialTheme.colorScheme.error
                    } else {
                        MaterialTheme.colorScheme.primary
                    },
                )
                Text(
                    text = route.cidr,
                    style = MaterialTheme.typography.bodyMedium.copy(fontFamily = FontFamily.Monospace),
                )
            }
            TextButton(onClick = onRemove) {
                Text("Remove")
            }
        }
    }
}

private enum class RouteEditorMode(val label: String) {
    List("List"),
    Text("Text"),
}
