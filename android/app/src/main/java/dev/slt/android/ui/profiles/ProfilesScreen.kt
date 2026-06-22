package dev.slt.android.ui.profiles

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import dev.slt.android.ui.profile.ProfileStoreState
import dev.slt.android.ui.UiMessage
import dev.slt.android.ui.uiMessageColor

@Composable
internal fun ProfilesScreen(
    profileState: ProfileStoreState?,
    message: UiMessage?,
    onAdd: () -> Unit,
    onEdit: (String) -> Unit,
    onSelect: (String) -> Unit,
    onDuplicate: (String) -> Unit,
    onDelete: (String) -> Unit,
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .statusBarsPadding()
            .navigationBarsPadding()
            .padding(24.dp)
            .verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Text(
            text = "Profiles",
            style = MaterialTheme.typography.headlineSmall,
            fontWeight = FontWeight.SemiBold,
        )
        Button(onClick = onAdd) {
            Text("Add Profile")
        }
        message?.let {
            Text(
                text = it.text,
                style = MaterialTheme.typography.bodyMedium,
                color = uiMessageColor(it),
            )
        }

        val profiles = profileState?.profiles.orEmpty()
        if (profiles.isEmpty()) {
            Text(
                text = "No profiles",
                style = MaterialTheme.typography.bodyLarge,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }

        profiles.forEach { profile ->
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                HorizontalDivider()
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = profile.name,
                            style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.Medium,
                        )
                        Text(
                            text = if (profile.isActive) "Active" else "Inactive",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                    if (!profile.isActive) {
                        TextButton(onClick = { onSelect(profile.id) }) {
                            Text("Use")
                        }
                    }
                }
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedButton(onClick = { onEdit(profile.id) }) {
                        Text("Edit")
                    }
                    OutlinedButton(onClick = { onDuplicate(profile.id) }) {
                        Text("Duplicate")
                    }
                    OutlinedButton(onClick = { onDelete(profile.id) }) {
                        Text("Delete")
                    }
                }
            }
        }
    }
}
