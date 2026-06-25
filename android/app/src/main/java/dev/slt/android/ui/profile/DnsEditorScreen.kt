package dev.slt.android.ui.profile

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
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import dev.slt.android.profile.DnsMode
import dev.slt.android.profile.rules.parseDnsSettings
import dev.slt.android.ui.UiMessage

/**
 * DNS editor. Edits a local buffer (mode + newline-separated server IPs);
 * Apply commits it back (only if it parses), back discards. Custom mode shows a
 * list of servers with per-server add/remove; System mode uses the Android
 * system DNS.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun DnsEditorScreen(
    initialMode: DnsMode,
    initialText: String,
    onApply: (DnsMode, String) -> Unit,
    onCancel: () -> Unit,
) {
    var bufferMode by remember { mutableStateOf(initialMode) }
    var bufferText by remember { mutableStateOf(initialText) }
    var newServer by remember { mutableStateOf("") }
    var message by remember { mutableStateOf<UiMessage?>(null) }
    val snackbarHostState = remember { SnackbarHostState() }
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

    val currentServers = displayedDnsServers(bufferText)

    fun addServer() {
        val result = addDnsServerFromForm(currentServers, newServer)
        if (result.changed) {
            bufferText = result.text
            newServer = ""
        }
        message = result.message
    }

    Scaffold(
        containerColor = MaterialTheme.colorScheme.background,
        topBar = {
            TopAppBar(
                title = { Text("DNS") },
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
                        val parsed = runCatching { parseDnsSettings(bufferMode, bufferText) }
                        if (parsed.isSuccess) {
                            onApply(bufferMode, bufferText)
                        } else {
                            message = UiMessage.error(
                                parsed.exceptionOrNull()?.message ?: "Invalid DNS settings",
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
            PrimaryTabRow(selectedTabIndex = bufferMode.ordinal) {
                Tab(
                    selected = bufferMode == DnsMode.System,
                    onClick = { bufferMode = DnsMode.System },
                    text = { Text("System") },
                )
                Tab(
                    selected = bufferMode == DnsMode.Custom,
                    onClick = { bufferMode = DnsMode.Custom },
                    text = { Text("Custom") },
                )
            }
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .weight(1f)
                    .padding(horizontal = 16.dp)
                    .padding(top = 12.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                if (bufferMode == DnsMode.System) {
                    Text(
                        text = "System DNS uses the Android system's DNS servers.",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                } else {
                    LazyColumn(
                        modifier = Modifier
                            .weight(1f)
                            .fillMaxWidth(),
                        verticalArrangement = Arrangement.spacedBy(6.dp),
                    ) {
                        if (currentServers.isEmpty()) {
                            item {
                                Text(
                                    text = "No DNS servers",
                                    style = MaterialTheme.typography.bodyMedium,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                )
                            }
                        } else {
                            itemsIndexed(currentServers) { index, server ->
                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    horizontalArrangement = Arrangement.spacedBy(12.dp),
                                    verticalAlignment = Alignment.CenterVertically,
                                ) {
                                    Text(
                                        text = server,
                                        modifier = Modifier.weight(1f),
                                        style = MaterialTheme.typography.bodyMedium.copy(
                                            fontFamily = FontFamily.Monospace,
                                        ),
                                    )
                                    IconButton(onClick = {
                                        bufferText = removeDnsServerAt(currentServers, index).text
                                    }) {
                                        Icon(
                                            imageVector = Icons.Filled.Close,
                                            contentDescription = "Remove",
                                        )
                                    }
                                }
                            }
                        }
                    }
                    OutlinedTextField(
                        value = newServer,
                        onValueChange = {
                            newServer = it
                            message = null
                        },
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true,
                        label = { Text("Server IP") },
                        trailingIcon = {
                            IconButton(onClick = { addServer() }) {
                                Icon(
                                    imageVector = Icons.Filled.Add,
                                    contentDescription = "Add",
                                )
                            }
                        },
                        textStyle = MaterialTheme.typography.bodyMedium.copy(fontFamily = FontFamily.Monospace),
                    )
                }
            }
        }
    }
}
