package dev.slt.android.ui.main

import dev.slt.android.connection.ConnectionTestResult

internal data class ConnectionTestUiState(
    val inProgress: Boolean = false,
    val results: List<ConnectionTestResult>? = null,
)
