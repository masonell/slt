package dev.slt.android.ui.profile

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import dev.slt.android.ui.UiMessage
import dev.slt.android.ui.uiMessageColor

@Composable
internal fun DnsEditorScreen(
    dnsMode: DnsMode,
    dnsText: String,
    dnsMessage: UiMessage?,
    onDnsModeChange: (DnsMode) -> Unit,
    onDnsTextChange: (String) -> Unit,
    onApply: () -> Unit,
    onCancel: () -> Unit,
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .statusBarsPadding()
            .navigationBarsPadding()
            .padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text(
            text = "DNS",
            style = MaterialTheme.typography.headlineSmall,
            fontWeight = FontWeight.SemiBold,
        )
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            if (dnsMode == DnsMode.System) {
                Button(
                    onClick = { onDnsModeChange(DnsMode.System) },
                    modifier = Modifier.weight(1f),
                ) {
                    Text("System")
                }
                OutlinedButton(
                    onClick = { onDnsModeChange(DnsMode.Custom) },
                    modifier = Modifier.weight(1f),
                ) {
                    Text("Custom")
                }
            } else {
                OutlinedButton(
                    onClick = { onDnsModeChange(DnsMode.System) },
                    modifier = Modifier.weight(1f),
                ) {
                    Text("System")
                }
                Button(
                    onClick = { onDnsModeChange(DnsMode.Custom) },
                    modifier = Modifier.weight(1f),
                ) {
                    Text("Custom")
                }
            }
        }
        if (dnsMode == DnsMode.Custom) {
            OutlinedTextField(
                value = dnsText,
                onValueChange = onDnsTextChange,
                modifier = Modifier
                    .fillMaxWidth()
                    .weight(1f),
                label = { Text("DNS servers") },
                textStyle = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
            )
        } else {
            Spacer(modifier = Modifier.weight(1f))
        }
        dnsMessage?.let {
            Text(
                text = it.text,
                style = MaterialTheme.typography.bodyMedium,
                color = uiMessageColor(it),
            )
        }
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Button(onClick = onApply) {
                Text("Apply")
            }
            TextButton(onClick = onCancel) {
                Text("Cancel")
            }
        }
    }
}
