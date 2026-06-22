package dev.slt.android.ui

import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.os.PersistableBundle

internal fun Context.copySensitiveText(label: String, text: String) {
    val clipboardManager = getSystemService(ClipboardManager::class.java)
    val clip = ClipData.newPlainText(label, text)
    clip.description.extras = PersistableBundle().apply {
        putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true)
    }
    clipboardManager.setPrimaryClip(clip)
}

internal fun messageIsError(message: String): Boolean =
    message.contains("Line ") ||
        message.contains("cannot") ||
        message.contains("required") ||
        message.contains("Invalid") ||
        message.contains("not valid") ||
        message.contains("must be") ||
        message.contains("must not")
