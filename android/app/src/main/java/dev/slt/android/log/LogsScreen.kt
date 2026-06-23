package dev.slt.android.log

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import java.io.File
import java.text.SimpleDateFormat
import java.util.Locale

/**
 * In-app log viewer. Shows a file selector for the kept log files (newest first,
 * the live one marked) and tails the selected file, rendering lines in a
 * scrolling, monospace list with a Clear action.
 */
@Composable
internal fun LogsScreen(
    logStore: LogStore,
    onClose: () -> Unit,
) {
    val tailer = remember { LogTailer() }
    val lines = remember { mutableStateListOf<String>() }
    // Newest first; index 0 is the live (active) file.
    var availableFiles by remember { mutableStateOf(logStore.files().reversed()) }
    var selectedName by remember { mutableStateOf(logStore.activeFile()?.name) }
    var loaded by remember { mutableStateOf(false) }
    val listState = rememberLazyListState()

    val target: File? = availableFiles.firstOrNull { it.name == selectedName }

    LaunchedEffect(selectedName) {
        tailer.reset()
        lines.clear()
        loaded = false
        while (isActive) {
            val all = logStore.files()
            availableFiles = all.reversed()
            val file = all.firstOrNull { it.name == selectedName }
            if (file == null) {
                loaded = true
            } else {
                when (val result = tailer.poll(logStore, file)) {
                    PollResult.Nothing -> Unit
                    is PollResult.Updated -> {
                        // Capture whether the viewer is at the bottom BEFORE mutating
                        // lines: layoutInfo still reflects the old end here, so checking
                        // now (rather than after addAll) keeps tail-follow working when a
                        // poll brings many lines at once or loads an existing file.
                        val lastVisible = listState.layoutInfo.visibleItemsInfo.lastOrNull()?.index ?: -1
                        val shouldFollow = result.clearFirst ||
                            lines.isEmpty() ||
                            lastVisible >= lines.lastIndex - 1
                        loaded = true
                        if (result.clearFirst) lines.clear()
                        if (result.lines.isNotEmpty()) {
                            lines.addAll(result.lines)
                            while (lines.size > MAX_LINES) lines.removeAt(0)
                        }
                        if (shouldFollow && lines.isNotEmpty()) {
                            // Jump instantly to a freshly loaded file; smooth-follow appends.
                            if (result.clearFirst) listState.scrollToItem(lines.lastIndex)
                            else listState.animateScrollToItem(lines.lastIndex)
                        }
                    }
                }
            }
            delay(POLL_MS)
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .statusBarsPadding()
            .navigationBarsPadding()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Text(
                text = "Logs",
                style = MaterialTheme.typography.titleLarge,
                modifier = Modifier.weight(1f),
            )
            OutlinedButton(onClick = {
                logStore.clear()
                selectedName = logStore.activeFile()?.name
                tailer.reset()
                lines.clear()
            }) {
                Text("Clear")
            }
            OutlinedButton(onClick = onClose) {
                Text("Close")
            }
        }
        if (availableFiles.size > 1) {
            LazyRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                itemsIndexed(availableFiles) { index, file ->
                    FilterChip(
                        selected = file.name == selectedName,
                        onClick = { selectedName = file.name },
                        label = {
                            val name = logDisplayName(file.name)
                            Text(if (index == 0) "$name (live)" else name)
                        },
                    )
                }
            }
        }
        when {
            !loaded -> Text(
                text = "Loading…",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            target == null -> Text(
                text = "No log file yet.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            lines.isEmpty() -> Text(
                text = "No log lines.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            else -> LazyColumn(
                state = listState,
                modifier = Modifier.fillMaxSize(),
            ) {
                items(lines) { line ->
                    Text(
                        text = line,
                        style = MaterialTheme.typography.bodySmall,
                        fontFamily = FontFamily.Monospace,
                    )
                }
            }
        }
    }
}

private const val MAX_LINES = 2_000
private const val POLL_MS = 500L

/**
 * Render a log file name (`slt-YYYYMMdd-HHmmss-SSS-<pid>.log`) as a readable
 * timestamp. Falls back to the raw name if it does not match the expected shape.
 */
private fun logDisplayName(fileName: String): String {
    val core = fileName.removePrefix("slt-").removeSuffix(".log")
    val parts = core.split("-")
    if (parts.size < 3) return fileName
    val parsed = runCatching {
        SimpleDateFormat("yyyyMMdd-HHmmss", Locale.US).parse("${parts[0]}-${parts[1]}")
    }.getOrNull() ?: return fileName
    return SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(parsed) + ".${parts[2]}"
}
