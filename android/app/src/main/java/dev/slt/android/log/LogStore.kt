package dev.slt.android.log

import android.content.Context
import android.os.Process
import java.io.File
import java.io.IOException
import java.io.RandomAccessFile
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone

/**
 * Owns the Rust log directory: file naming, the active-file lookup, the keep-N
 * sweep, clearing, and offset-based tailing of a chosen file.
 *
 * Rust appends formatted tracing lines to a single file per process (the path
 * Kotlin hands it via [dev.slt.android.SltNative.initLogSink]); this class never
 * writes — it only manages the directory and reads bytes back for the UI.
 */
class LogStore(context: Context) {
    private val appContext = context.applicationContext
    private val dir = File(appContext.filesDir, DIR_NAME)

    /** Build a fresh per-process log file path (`slt-<utc-ts>Z-<pid>.log`). */
    fun newFilePath(): String {
        if (!dir.exists()) dir.mkdirs()
        val stamp = SimpleDateFormat("yyyyMMdd-HHmmss-SSS", Locale.US).apply {
            timeZone = TimeZone.getTimeZone("UTC")
        }.format(Date())
        val path = File(dir, "$PREFIX${stamp}Z-${Process.myPid()}$SUFFIX").absolutePath
        // Remember the file Rust will write to so sweep/clear never touch it,
        // even if a wall-clock jump makes its name sort older than leftovers.
        activePath = path
        return path
    }

    /** All log files, sorted by name (lexicographic order == chronological). */
    fun files(): List<File> =
        dir.listFiles { file -> file.isFile && file.name.startsWith(PREFIX) && file.name.endsWith(SUFFIX) }
            ?.sortedBy { it.name }
            ?: emptyList()

    /**
     * The active file: the path Kotlin handed to Rust, if known and present;
     * otherwise the newest by name. Preferring the known path keeps sweep/clear
     * from deleting the file Rust is writing under a wall-clock jump.
     */
    fun activeFile(): File? {
        activePath?.let { path -> if (File(path).isFile) return File(path) }
        return files().maxByOrNull { it.name }
    }

    /**
     * Keep the active file plus the newest [KEEP_INACTIVE] non-empty inactive
     * files. Empty inactive files (e.g. from a quick launch/close cycle that
     * wrote nothing) are removed, and the active file is never deleted (it may
     * be open and being written by Rust).
     */
    fun sweep() {
        val active = activeFile() ?: return
        val keep = (files() - active)
            .filter { it.length() > 0 }
            .sortedByDescending { it.name }
            .take(KEEP_INACTIVE)
            .toMutableSet()
            .apply { add(active) }
        files().forEach { file -> if (file !in keep) file.delete() }
    }

    /**
     * Delete inactive files and truncate the active one in place. The active file
     * cannot be deleted (Rust holds it open and writes by path); truncating is
     * safe because Rust appends with `O_APPEND`, so writes regrow from 0.
     */
    fun clear() {
        val active = activeFile()
        files().forEach { file -> if (file != active) file.delete() }
        active?.let { RandomAccessFile(it, "rw").use { raf -> raf.setLength(0) } }
    }

    /**
     * Read bytes appended to [file] since [offset], capped at [MAX_READ_CHUNK] per
     * call (larger growth is picked up on later polls). Returns the new bytes and
     * the offset to use next time. If the file shrank (truncated/cleared), resets
     * to 0. Any read failure degrades to an empty read + reset rather than
     * throwing, so a transiently-vanished file can't kill the poll loop.
     */
    fun readSince(file: File, offset: Long): Pair<ByteArray, Long> {
        return try {
            val length = file.length()
            if (length < offset) return ByteArray(0) to 0L
            if (length == offset) return ByteArray(0) to offset
            val toRead = minOf(length - offset, MAX_READ_CHUNK.toLong()).toInt()
            val bytes = ByteArray(toRead)
            RandomAccessFile(file, "r").use { raf ->
                raf.seek(offset)
                raf.readFully(bytes)
            }
            bytes to (offset + toRead)
        } catch (_: IOException) {
            ByteArray(0) to 0L
        }
    }

    private companion object {
        const val DIR_NAME = "logs"
        const val PREFIX = "slt-"
        const val SUFFIX = ".log"
        const val KEEP_INACTIVE = 5
        const val MAX_READ_CHUNK = 512 * 1024

        /** Absolute path of the file the current process handed to Rust. */
        @Volatile
        var activePath: String? = null
    }
}
