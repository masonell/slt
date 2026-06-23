package dev.slt.android.log

import java.io.File

/** Result of a single [LogTailer.poll]. */
sealed interface PollResult {
    /** Nothing changed since the last poll. */
    data object Nothing : PollResult

    /**
     * The tailed file state. [clearFirst] is true when the file changed (first
     * read or a different file selected) and the UI should clear its view before
     * adding [lines]. [lines] may be empty when the file exists but has no
     * complete lines yet — the UI treats that as "confirmed empty".
     */
    data class Updated(
        val clearFirst: Boolean,
        val lines: List<String>,
    ) : PollResult
}

/**
 * Incremental tailer for a chosen log file. Tracks a byte offset and buffers a
 * trailing partial line across polls. Only complete lines (terminated by `\n`)
 * are decoded as UTF-8, so a multibyte character split across two reads is never
 * mangled — `\n` is ASCII and is never part of a multibyte sequence.
 *
 * For the active (live) file this streams new lines as they are written; for an
 * older file it loads the frozen content once and then reports nothing.
 */
class LogTailer {
    private var offset = 0L
    private var pending = ByteArray(0)
    private var activeName: String? = null

    /** Reset state (after a clear or when switching files). */
    fun reset() {
        offset = 0L
        pending = ByteArray(0)
        activeName = null
    }

    /** Poll [file] for new completed lines. */
    fun poll(store: LogStore, file: File): PollResult {
        val switched = file.name != activeName
        if (switched) {
            activeName = file.name
            offset = 0L
            pending = ByteArray(0)
        }

        val (bytes, newOffset) = store.readSince(file, offset)
        offset = newOffset
        if (bytes.isEmpty() && !switched) return PollResult.Nothing

        val combined = pending + bytes
        val lastNewline = combined.indexOfLast { it == NEWLINE }
        val lines = if (lastNewline >= 0) {
            val complete = combined.copyOfRange(0, lastNewline + 1)
            pending = combined.copyOfRange(lastNewline + 1, combined.size)
            // `complete` ends with '\n', so split yields a trailing "" we drop.
            String(complete, Charsets.UTF_8).split(NEWLINE_CHAR).dropLast(1)
        } else {
            pending = combined
            emptyList()
        }
        return PollResult.Updated(switched, lines)
    }

    private companion object {
        const val NEWLINE: Byte = '\n'.code.toByte()
        const val NEWLINE_CHAR = '\n'
    }
}
