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

internal fun Context.copySensitiveText(label: String, text: String) {
    val clipboardManager = getSystemService(ClipboardManager::class.java)
    val clip = ClipData.newPlainText(label, text)
    clip.description.extras = PersistableBundle().apply {
        putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true)
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
