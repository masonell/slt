package dev.slt.android.log

import android.content.ClipData
import android.content.ClipboardManager
import android.widget.Toast
import androidx.compose.foundation.background
import androidx.compose.foundation.gestures.Orientation
import androidx.compose.foundation.gestures.draggable
import androidx.compose.foundation.gestures.rememberDraggableState
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyListState
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.KeyboardArrowDown
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.derivedStateOf
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.IntOffset
import androidx.compose.ui.unit.dp
import java.io.File
import java.text.SimpleDateFormat
import java.util.Locale
import java.util.TimeZone
import kotlin.math.roundToInt
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

/**
 * In-app log viewer. Shows a file selector for the kept log files (newest first,
 * the live one labeled "Live") and tails the selected file, rendering lines in a
 * scrolling, monospace list with a Copy action (whole file to clipboard), Clear,
 * and a draggable scrollbar.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun LogsScreen(
    logStore: LogStore,
    onBack: () -> Unit,
) {
    val context = LocalContext.current
    val tailer = remember { LogTailer() }
    val lines = remember { mutableStateListOf<String>() }
    // Newest first; index 0 is the live (active) file.
    var availableFiles by remember { mutableStateOf(logStore.files().reversed()) }
    var selectedName by remember { mutableStateOf(logStore.activeFile()?.name) }
    var loaded by remember { mutableStateOf(false) }
    val listState = rememberLazyListState()
    val scope = rememberCoroutineScope()
    val atBottom by remember {
        derivedStateOf {
            val info = listState.layoutInfo
            val total = info.totalItemsCount
            val lastVisible = info.visibleItemsInfo.lastOrNull()?.index ?: -1
            total == 0 || lastVisible >= total - 2
        }
    }

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

    Scaffold(
        containerColor = MaterialTheme.colorScheme.background,
        floatingActionButton = {
            if (!atBottom) {
                FloatingActionButton(
                    onClick = {
                        if (lines.isNotEmpty()) {
                            scope.launch { listState.animateScrollToItem(lines.lastIndex) }
                        }
                    },
                ) {
                    Icon(
                        imageVector = Icons.Filled.KeyboardArrowDown,
                        contentDescription = "Jump to latest",
                    )
                }
            }
        },
        topBar = {
            TopAppBar(
                title = { Text("Logs") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            imageVector = Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = "Back",
                        )
                    }
                },
                actions = {
                    TextButton(
                        onClick = {
                            val clipboard = context.getSystemService(ClipboardManager::class.java)
                            clipboard?.setPrimaryClip(
                                ClipData.newPlainText("SLT log", lines.joinToString("\n")),
                            )
                            Toast.makeText(context, "Copied", Toast.LENGTH_SHORT).show()
                        },
                    ) {
                        Text("Copy")
                    }
                    TextButton(onClick = {
                        logStore.clear()
                        selectedName = logStore.activeFile()?.name
                        tailer.reset()
                        lines.clear()
                    }) {
                        Text("Clear")
                    }
                },
            )
        },
    ) { innerPadding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            if (availableFiles.size > 1) {
                LazyRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    itemsIndexed(availableFiles) { index, file ->
                        FilterChip(
                            selected = file.name == selectedName,
                            onClick = { selectedName = file.name },
                            label = {
                                Text(if (index == 0) "Live" else logDisplayName(file.name))
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
                else -> Row(modifier = Modifier.fillMaxSize()) {
                    LazyColumn(
                        state = listState,
                        modifier = Modifier.weight(1f),
                    ) {
                        items(lines) { line ->
                            Text(
                                text = line,
                                style = MaterialTheme.typography.bodySmall,
                                fontFamily = FontFamily.Monospace,
                            )
                        }
                    }
                    LogScrollbar(
                        listState = listState,
                        modifier = Modifier.padding(start = 8.dp),
                    )
                }
            }
        }
    }
}

/**
 * Thin draggable scrollbar for the log list. The thumb size reflects the visible
 * fraction of the document and dragging it scrolls the list proportionally.
 */
@Composable
private fun LogScrollbar(
    listState: LazyListState,
    modifier: Modifier = Modifier,
) {
    val dragState = rememberDraggableState { delta ->
        val info = listState.layoutInfo
        val total = info.totalItemsCount
        val visibleCount = info.visibleItemsInfo.size
        if (total > visibleCount && visibleCount > 0) {
            listState.dispatchRawDelta(delta * (total - visibleCount).toFloat() / visibleCount)
        }
    }

    BoxWithConstraints(
        modifier = modifier
            .fillMaxHeight()
            .width(4.dp)
            .draggable(dragState, Orientation.Vertical),
    ) {
        val metrics by remember {
            derivedStateOf {
                val info = listState.layoutInfo
                val total = info.totalItemsCount
                val visible = info.visibleItemsInfo
                val thumbFraction = if (total > 0) {
                    (visible.size.toFloat() / total).coerceIn(0.05f, 1f)
                } else {
                    0f
                }
                val topFraction = if (total > visible.size && visible.isNotEmpty()) {
                    (visible.first().index.toFloat() / (total - visible.size)).coerceIn(0f, 1f)
                } else {
                    0f
                }
                ScrollbarMetrics(thumbFraction, topFraction)
            }
        }
        val trackPx = constraints.maxHeight.toFloat()
        val thumbPx = trackPx * metrics.thumbFraction
        val offsetPx = metrics.topFraction * (trackPx - thumbPx)
        Box(
            Modifier
                .fillMaxHeight(metrics.thumbFraction)
                .width(4.dp)
                .offset { IntOffset(0, offsetPx.roundToInt()) }
                .clip(RoundedCornerShape(2.dp))
                .background(MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.4f)),
        )
    }
}

private data class ScrollbarMetrics(
    val thumbFraction: Float,
    val topFraction: Float,
)

private const val POLL_MS = 500L

/**
 * Render a log file name (`slt-YYYYMMdd-HHmmss-SSSZ-<pid>.log`, UTC) as a
 * readable UTC timestamp. Falls back to the raw name if it does not match the
 * expected shape.
 */
private fun logDisplayName(fileName: String): String {
    val core = fileName.removePrefix("slt-").removeSuffix(".log")
    val parts = core.split("-")
    if (parts.size < 3) return fileName
    val utc = TimeZone.getTimeZone("UTC")
    val parsed = runCatching {
        SimpleDateFormat("yyyyMMdd-HHmmss", Locale.US).apply { timeZone = utc }
            .parse("${parts[0]}-${parts[1]}")
    }.getOrNull() ?: return fileName
    return SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).apply { timeZone = utc }
        .format(parsed) + ".${parts[2]}"
}
