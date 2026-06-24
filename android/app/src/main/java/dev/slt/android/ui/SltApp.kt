package dev.slt.android.ui

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
import dev.slt.android.log.LogStore
import dev.slt.android.log.LogsScreen
import dev.slt.android.profile.ProfileStoreState
import dev.slt.android.profile.store.ProfileRepository
import dev.slt.android.ui.main.MainScreenRoute
import dev.slt.android.ui.profile.ProfileEditorScreen
import dev.slt.android.ui.profiles.ProfilesScreen
import dev.slt.android.ui.theme.SltTheme
import dev.slt.android.vpn.SltVpnStatusBus
import kotlinx.coroutines.launch

@Composable
internal fun SltApp(
    profileRepository: ProfileRepository,
    onStart: () -> Unit,
    onStop: () -> Unit,
) {
    val vpnState by SltVpnStatusBus.state.collectAsState()
    val scope = rememberCoroutineScope()
    val context = LocalContext.current
    val logStore = remember { LogStore(context) }
    var screen by remember { mutableStateOf<AppScreen>(AppScreen.Main) }
    var profileState by remember { mutableStateOf<ProfileStoreState?>(null) }
    var message by remember { mutableStateOf<UiMessage?>(null) }

    LaunchedEffect(Unit) {
        profileState = profileRepository.loadState()
    }

    BackHandler(enabled = screen != AppScreen.Main) {
        screen = when (screen) {
            AppScreen.Main -> AppScreen.Main
            AppScreen.Profiles -> AppScreen.Main
            is AppScreen.EditProfile -> AppScreen.Profiles
            AppScreen.Logs -> AppScreen.Main
        }
        message = null
    }

    SltTheme {
        Surface(
            modifier = Modifier.fillMaxSize(),
            color = MaterialTheme.colorScheme.background,
        ) {
            when (val currentScreen = screen) {
                AppScreen.Main -> MainScreenRoute(
                    vpnState = vpnState,
                    profileState = profileState,
                    message = message,
                    onMessageChange = { message = it },
                    onSelectProfile = { id ->
                        scope.launch {
                            profileRepository.setActiveProfileId(id)
                            profileState = profileRepository.loadState()
                            message = UiMessage.info("Active profile changed")
                        }
                    },
                    onStart = onStart,
                    onStop = onStop,
                    onOpenProfiles = {
                        screen = AppScreen.Profiles
                    },
                    onOpenLogs = {
                        screen = AppScreen.Logs
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
                            message = UiMessage.info("Active profile changed")
                        }
                    },
                    onDuplicate = { id ->
                        scope.launch {
                            val profile = profileRepository.duplicateProfile(id)
                            profileState = profileRepository.loadState()
                            message = profile?.let { UiMessage.info("Duplicated ${it.metadata.name}") }
                                ?: UiMessage.error("Profile not found")
                        }
                    },
                    onDelete = { id ->
                        scope.launch {
                            profileRepository.deleteProfile(id)
                            profileState = profileRepository.loadState()
                            message = UiMessage.info("Profile deleted")
                        }
                    },
                )

                is AppScreen.EditProfile -> ProfileEditorScreen(
                    profileRepository = profileRepository,
                    profileId = currentScreen.profileId,
                    onSaved = {
                        scope.launch {
                            profileState = profileRepository.loadState()
                            message = UiMessage.info("Profile saved")
                            screen = AppScreen.Profiles
                        }
                    },
                    onCancel = {
                        message = null
                        screen = AppScreen.Profiles
                    },
                )

                AppScreen.Logs -> LogsScreen(
                    logStore = logStore,
                    onClose = {
                        message = null
                        screen = AppScreen.Main
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

    data object Logs : AppScreen
}
