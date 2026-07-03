package dev.slt.android.ui.profile

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
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
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import dev.slt.android.ConfigValidationResult
import kotlinx.coroutines.launch

/**
 * Raw SLT client TOML editor. Edits a local buffer; the Apply action validates
 * it and commits only if valid (otherwise the error is shown as a Snackbar), so
 * the committed TOML is always valid. Cancel discards the buffer.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun TomlEditorScreen(
    initialToml: String,
    validate: (String) -> ConfigValidationResult,
    onApply: (String, ConfigValidationResult) -> Unit,
    onCancel: () -> Unit,
    onCopy: (String) -> Unit,
) {
    val context = LocalContext.current
    val coroutineScope = rememberCoroutineScope()
    var buffer by remember { mutableStateOf(initialToml) }
    var message by remember { mutableStateOf<String?>(null) }
    val snackbarHostState = remember { SnackbarHostState() }
    val importLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocument(),
    ) { uri ->
        uri ?: return@rememberLauncherForActivityResult
        coroutineScope.launch {
            runCatching { context.readImportedText(uri) }
                .onSuccess {
                    buffer = it
                    message = "Config imported"
                }
                .onFailure { importError ->
                    message = importError.message ?: "Could not import config"
                }
        }
    }
    LaunchedEffect(message) {
        message?.let {
            snackbarHostState.showSnackbar(
                message = it,
                actionLabel = "Dismiss",
                duration = SnackbarDuration.Short,
            )
            message = null
        }
    }

    Scaffold(
        containerColor = MaterialTheme.colorScheme.background,
        topBar = {
            TopAppBar(
                title = { Text("Client config") },
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
                    TextButton(onClick = { onCopy(buffer) }) {
                        Text("Copy")
                    }
                    TextButton(onClick = {
                        val result = validate(buffer)
                        when (result) {
                            is ConfigValidationResult.Valid -> onApply(buffer, result)
                            is ConfigValidationResult.Invalid -> message = result.message
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
        OutlinedTextField(
            value = buffer,
            onValueChange = { buffer = it },
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(16.dp),
            label = { Text("TOML") },
            textStyle = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
        )
    }
}
