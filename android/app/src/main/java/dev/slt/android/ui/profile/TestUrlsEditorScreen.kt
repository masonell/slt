package dev.slt.android.ui.profile

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.ArrowDropDown
import androidx.compose.material.icons.filled.Close
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
import dev.slt.android.profile.rules.parseTestUrls
import dev.slt.android.ui.UiMessage

/**
 * Test-URL editor. Edits a local buffer of newline-separated URLs; Apply commits
 * it back (only if it parses), back discards. Adding uses a tappable scheme
 * prefix (HTTPS default / HTTP) inside the field plus the host/path, so the
 * scheme is picked, not typed.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun TestUrlsEditorScreen(
    initialText: String,
    onApply: (String) -> Unit,
    onCancel: () -> Unit,
) {
    var buffer by remember { mutableStateOf(initialText) }
    var newUrl by remember { mutableStateOf("") }
    var scheme by remember { mutableStateOf("https://") }
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

    val currentUrls = displayedTestUrls(buffer)

    fun add() {
        val result = addTestUrlFromForm(currentUrls, scheme + newUrl.trim())
        if (result.changed) {
            buffer = result.text
            newUrl = ""
        }
        message = result.message
    }

    Scaffold(
        containerColor = MaterialTheme.colorScheme.background,
        topBar = {
            TopAppBar(
                title = { Text("Test URLs") },
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
                        val parsed = runCatching { parseTestUrls(buffer) }
                        if (parsed.isSuccess) {
                            onApply(buffer)
                        } else {
                            message = UiMessage.error(
                                parsed.exceptionOrNull()?.message ?: "Invalid test URLs",
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
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            LazyColumn(
                modifier = Modifier
                    .weight(1f)
                    .fillMaxWidth(),
                verticalArrangement = Arrangement.spacedBy(6.dp),
            ) {
                if (currentUrls.isEmpty()) {
                    item {
                        Text(
                            text = "No test URLs yet",
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                } else {
                    items(currentUrls, key = { it }) { url ->
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.spacedBy(12.dp),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            Text(
                                text = url,
                                modifier = Modifier.weight(1f),
                                style = MaterialTheme.typography.bodyMedium.copy(
                                    fontFamily = FontFamily.Monospace,
                                ),
                            )
                            IconButton(onClick = {
                                buffer = removeTestUrlAt(currentUrls, currentUrls.indexOf(url)).text
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
                value = newUrl,
                onValueChange = {
                    newUrl = it
                    message = null
                },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
                label = { Text("URL") },
                prefix = {
                    Box(
                        modifier = Modifier.clickable {
                            scheme = if (scheme == "https://") "http://" else "https://"
                        },
                    ) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Text(
                                text = scheme,
                                color = MaterialTheme.colorScheme.primary,
                                style = MaterialTheme.typography.bodyMedium,
                            )
                            Icon(
                                imageVector = Icons.Filled.ArrowDropDown,
                                contentDescription = "Change scheme",
                                tint = MaterialTheme.colorScheme.primary,
                                modifier = Modifier.size(18.dp),
                            )
                        }
                    }
                },
                trailingIcon = {
                    IconButton(onClick = { add() }) {
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
