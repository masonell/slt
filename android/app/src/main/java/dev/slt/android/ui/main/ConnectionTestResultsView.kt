package dev.slt.android.ui.main

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import dev.slt.android.connection.ConnectionTestEntry
import dev.slt.android.connection.ConnectionTestOutcome
import dev.slt.android.connection.ConnectionTestPhase
import dev.slt.android.connection.ExpectedNetworkPath

/**
 * Live connection-test results, hosted in the results bottom sheet. Each URL row
 * shows its current phase ("Resolving…" / "Checking…") and, once done, the
 * resolved addresses, expected path, and outcome.
 */
@Composable
internal fun ConnectionTestResultsView(
    entries: List<ConnectionTestEntry>,
    inProgress: Boolean,
    modifier: Modifier = Modifier,
) {
    Column(
        modifier = modifier.fillMaxWidth(),
        verticalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        Text(
            text = "Connection tests",
            style = MaterialTheme.typography.titleMedium,
            fontWeight = FontWeight.SemiBold,
        )
        if (entries.isEmpty()) {
            Text(
                text = if (inProgress) "Starting…" else "No results",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        } else {
            entries.forEach { entry -> ConnectionTestEntryRow(entry) }
        }
    }
}

@Composable
private fun ConnectionTestEntryRow(entry: ConnectionTestEntry) {
    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Text(
            text = entry.url,
            style = MaterialTheme.typography.bodyMedium,
            fontWeight = FontWeight.SemiBold,
        )
        when (entry.phase) {
            ConnectionTestPhase.Resolving -> PhaseText("Resolving…")
            ConnectionTestPhase.Checking -> PhaseText("Checking…")
            ConnectionTestPhase.Done -> ConnectionTestDoneDetail(entry)
        }
    }
}

@Composable
private fun PhaseText(text: String) {
    Text(
        text = text,
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )
}

@Composable
private fun ConnectionTestDoneDetail(entry: ConnectionTestEntry) {
    val success = entry.outcome is ConnectionTestOutcome.Success
    Text(
        text = "Resolved: ${entry.resolvedAddresses.ifEmpty { listOf("none") }.joinToString()}",
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )
    Text(
        text = "Expected: ${entry.expectedPath.label()}",
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )
    Text(
        text = entry.outcome?.label() ?: "—",
        style = MaterialTheme.typography.bodySmall,
        color = if (success) {
            MaterialTheme.colorScheme.primary
        } else {
            MaterialTheme.colorScheme.error
        },
    )
}

private fun ExpectedNetworkPath.label(): String =
    when (this) {
        ExpectedNetworkPath.Vpn -> "VPN"
        ExpectedNetworkPath.Direct -> "direct"
        ExpectedNetworkPath.Mixed -> "mixed"
    }

private fun ConnectionTestOutcome.label(): String =
    when (this) {
        is ConnectionTestOutcome.Success -> "GET succeeded: HTTP $statusCode"
        is ConnectionTestOutcome.Failure -> message
    }
