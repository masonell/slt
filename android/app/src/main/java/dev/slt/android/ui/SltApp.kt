package dev.slt.android.ui

import android.content.Context
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import dev.slt.android.ProfileRepository
import dev.slt.android.ProfileStoreState
import dev.slt.android.SltVpnStatusBus
import dev.slt.android.VpnStatus
import dev.slt.android.ui.main.MainScreen
import dev.slt.android.ui.profile.ProfileEditorScreen
import dev.slt.android.ui.profiles.ProfilesScreen
import kotlinx.coroutines.launch

@Composable
internal fun SltApp(
    profileRepository: ProfileRepository,
    onStart: () -> Unit,
    onStop: () -> Unit,
) {
    val vpnState by SltVpnStatusBus.state.collectAsState()
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var screen by remember { mutableStateOf<AppScreen>(AppScreen.Main) }
    var profileState by remember { mutableStateOf<ProfileStoreState?>(null) }
    var message by remember { mutableStateOf<String?>(null) }

    LaunchedEffect(Unit) {
        profileState = profileRepository.loadState()
    }

    BackHandler(enabled = screen != AppScreen.Main) {
        screen = when (screen) {
            AppScreen.Main -> AppScreen.Main
            AppScreen.Profiles -> AppScreen.Main
            is AppScreen.EditProfile -> AppScreen.Profiles
        }
        message = null
    }

    MaterialTheme {
        Surface(
            modifier = Modifier.fillMaxSize(),
            color = MaterialTheme.colorScheme.background,
        ) {
            when (val currentScreen = screen) {
                AppScreen.Main -> MainScreen(
                    vpnState = vpnState,
                    profileState = profileState,
                    message = message,
                    canStop = context.canStopVpn(vpnState.status),
                    onStart = onStart,
                    onStop = onStop,
                    onOpenProfiles = {
                        message = null
                        screen = AppScreen.Profiles
                    },
                )

                AppScreen.Profiles -> ProfilesScreen(
                    profileState = profileState,
                    message = message,
                    onAdd = {
                        message = null
                        screen = AppScreen.EditProfile(null)
                    },
                    onEdit = { id ->
                        message = null
                        screen = AppScreen.EditProfile(id)
                    },
                    onSelect = { id ->
                        scope.launch {
                            profileRepository.setActiveProfileId(id)
                            profileState = profileRepository.loadState()
                            message = "Active profile changed"
                        }
                    },
                    onDuplicate = { id ->
                        scope.launch {
                            val profile = profileRepository.duplicateProfile(id)
                            profileState = profileRepository.loadState()
                            message = profile?.let { "Duplicated ${it.metadata.name}" }
                                ?: "Profile not found"
                        }
                    },
                    onDelete = { id ->
                        scope.launch {
                            profileRepository.deleteProfile(id)
                            profileState = profileRepository.loadState()
                            message = "Profile deleted"
                        }
                    },
                )

                is AppScreen.EditProfile -> ProfileEditorScreen(
                    profileRepository = profileRepository,
                    profileId = currentScreen.profileId,
                    onSaved = {
                        scope.launch {
                            profileState = profileRepository.loadState()
                            message = "Profile saved"
                            screen = AppScreen.Profiles
                        }
                    },
                    onCancel = {
                        message = null
                        screen = AppScreen.Profiles
                    },
                )
            }
        }
    }
}

private sealed interface AppScreen {
    data object Main : AppScreen

    data object Profiles : AppScreen

    data class EditProfile(val profileId: String?) : AppScreen
}

private fun Context.canStopVpn(status: VpnStatus): Boolean =
    status == VpnStatus.Starting || status == VpnStatus.Running

