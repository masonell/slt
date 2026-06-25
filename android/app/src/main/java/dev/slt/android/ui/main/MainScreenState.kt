package dev.slt.android.ui.main

import dev.slt.android.connection.ConnectionTestEntry

internal data class ConnectionTestUiState(
    val inProgress: Boolean = false,
    val entries: List<ConnectionTestEntry> = emptyList(),
)

/** Replace the entry for [entry]'s URL, or append it if unseen. */
internal fun ConnectionTestUiState.withEntry(entry: ConnectionTestEntry): ConnectionTestUiState {
    val index = entries.indexOfFirst { it.url == entry.url }
    val updated = if (index >= 0) {
        entries.toMutableList().apply { this[index] = entry }
    } else {
        entries + entry
    }
    return copy(entries = updated)
}
