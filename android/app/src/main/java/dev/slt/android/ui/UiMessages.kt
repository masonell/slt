package dev.slt.android.ui

import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.os.PersistableBundle
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

internal data class UiMessage(
    val text: String,
    val severity: UiMessageSeverity,
) {
    companion object {
        fun info(text: String): UiMessage =
            UiMessage(text = text, severity = UiMessageSeverity.Info)

        fun warning(text: String): UiMessage =
            UiMessage(text = text, severity = UiMessageSeverity.Warning)

        fun error(text: String): UiMessage =
            UiMessage(text = text, severity = UiMessageSeverity.Error)
    }
}

internal enum class UiMessageSeverity {
    Info,
    Warning,
    Error,
}

internal data class SensitiveClipboardText(
    val label: String,
    val text: String,
    val booleanExtras: Map<String, Boolean>,
)

internal fun sensitiveClipboardText(label: String, text: String): SensitiveClipboardText =
    SensitiveClipboardText(
        label = label,
        text = text,
        booleanExtras = mapOf(ClipDescription.EXTRA_IS_SENSITIVE to true),
    )

internal fun Context.copySensitiveText(label: String, text: String) {
    val clipboardManager = getSystemService(ClipboardManager::class.java)
    val clipboardText = sensitiveClipboardText(label, text)
    val clip = ClipData.newPlainText(clipboardText.label, clipboardText.text)
    clip.description.extras = PersistableBundle().apply {
        clipboardText.booleanExtras.forEach { (key, value) ->
            putBoolean(key, value)
        }
    }
    clipboardManager.setPrimaryClip(clip)
}

@Composable
internal fun uiMessageColor(
    message: UiMessage,
    infoColor: Color = MaterialTheme.colorScheme.primary,
): Color =
    when (message.severity) {
        UiMessageSeverity.Info -> infoColor
        UiMessageSeverity.Warning -> MaterialTheme.colorScheme.tertiary
        UiMessageSeverity.Error -> MaterialTheme.colorScheme.error
    }
