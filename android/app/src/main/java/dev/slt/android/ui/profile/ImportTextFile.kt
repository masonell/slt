package dev.slt.android.ui.profile

import android.content.Context
import android.net.Uri
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

internal val importTextMimeTypes = arrayOf(
    "text/*",
    "application/octet-stream",
    "application/toml",
    "application/x-toml",
)

internal suspend fun Context.readImportedText(uri: Uri): String =
    withContext(Dispatchers.IO) {
        val inputStream = contentResolver.openInputStream(uri)
            ?: error("Could not open selected file")
        inputStream.bufferedReader(Charsets.UTF_8).use { it.readText() }
    }
