package dev.slt.android.ui.profile

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
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
import dev.slt.android.exportTestUrls
import dev.slt.android.parseTestUrls
import dev.slt.android.ui.UiMessage
import dev.slt.android.ui.uiMessageColor

@Composable
internal fun TestUrlsEditorScreen(
    testUrlsText: String,
    testUrlsMessage: UiMessage?,
    onTestUrlsTextChange: (String) -> Unit,
    onApply: () -> Unit,
    onCancel: () -> Unit,
) {
    var newTestUrl by remember { mutableStateOf("") }
    var listMessage by remember { mutableStateOf<UiMessage?>(null) }
    val currentUrls = try {
        parseTestUrls(testUrlsText)
    } catch (_: IllegalArgumentException) {
        emptyList()
    }
    val currentMessage = listMessage ?: testUrlsMessage

    fun replaceTestUrls(urls: List<String>) {
        onTestUrlsTextChange(exportTestUrls(urls))
        listMessage = null
    }

    fun addTestUrl() {
        val candidate = newTestUrl.trim()
        if (candidate.isEmpty()) {
            listMessage = UiMessage.error("Test URL is required")
            return
        }

        try {
            val nextUrls = parseTestUrls(
                (currentUrls + candidate).joinToString("\n"),
            )
            if (nextUrls == currentUrls) {
                listMessage = UiMessage.info("Test URL already exists")
                return
            }
            replaceTestUrls(nextUrls)
            newTestUrl = ""
            listMessage = UiMessage.info("Test URL added")
        } catch (error: IllegalArgumentException) {
            listMessage = UiMessage.error(error.message ?: "Invalid test URL")
        }
    }

    fun removeTestUrl(index: Int) {
        replaceTestUrls(currentUrls.filterIndexed { urlIndex, _ -> urlIndex != index })
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
            text = "Test URLs",
            style = MaterialTheme.typography.headlineSmall,
            fontWeight = FontWeight.SemiBold,
        )
        LazyColumn(
            modifier = Modifier
                .fillMaxWidth()
                .weight(1f),
            verticalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            if (currentUrls.isEmpty()) {
                item {
                    Text(
                        text = "No test URLs",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            } else {
                items(currentUrls, key = { it }) { url ->
                    TestUrlListItem(
                        url = url,
                        onRemove = { removeTestUrl(currentUrls.indexOf(url)) },
                    )
                }
            }
        }
        HorizontalDivider()
        OutlinedTextField(
            value = newTestUrl,
            onValueChange = {
                newTestUrl = it
                listMessage = null
            },
            modifier = Modifier.fillMaxWidth(),
            singleLine = true,
            label = { Text("URL") },
            textStyle = MaterialTheme.typography.bodyMedium.copy(fontFamily = FontFamily.Monospace),
        )
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
            OutlinedButton(onClick = ::addTestUrl) {
                Text("Add")
            }
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
private fun TestUrlListItem(
    url: String,
    onRemove: () -> Unit,
) {
    Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
        HorizontalDivider()
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(12.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(
                text = url,
                modifier = Modifier.weight(1f),
                style = MaterialTheme.typography.bodyMedium.copy(fontFamily = FontFamily.Monospace),
            )
            TextButton(onClick = onRemove) {
                Text("Remove")
            }
        }
    }
}
