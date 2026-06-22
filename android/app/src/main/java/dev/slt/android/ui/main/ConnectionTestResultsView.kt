package dev.slt.android.ui.main

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import dev.slt.android.connection.ConnectionTestOutcome
import dev.slt.android.connection.ConnectionTestResult
import dev.slt.android.connection.ExpectedNetworkPath

@Composable
internal fun ConnectionTestResultsView(results: List<ConnectionTestResult>) {
    Column(
        modifier = Modifier.fillMaxWidth(),
        verticalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        HorizontalDivider()
        Text(
            text = "Connection tests",
            style = MaterialTheme.typography.titleMedium,
            fontWeight = FontWeight.SemiBold,
        )
        results.forEach { result ->
            ConnectionTestResultRow(result)
        }
    }
}

@Composable
private fun ConnectionTestResultRow(result: ConnectionTestResult) {
    val success = result.outcome is ConnectionTestOutcome.Success
    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Text(
            text = result.url,
            style = MaterialTheme.typography.bodyMedium,
            fontWeight = FontWeight.SemiBold,
        )
        Text(
            text = "Resolved: ${result.resolvedAddresses.ifEmpty { listOf("none") }.joinToString()}",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Text(
            text = "Expected: ${result.expectedPath.label()}",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Text(
            text = result.outcome.label(),
            style = MaterialTheme.typography.bodySmall,
            color = if (success) {
                MaterialTheme.colorScheme.primary
            } else {
                MaterialTheme.colorScheme.error
            },
        )
    }
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
