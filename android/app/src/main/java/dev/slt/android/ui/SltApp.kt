package dev.slt.android.ui

import android.util.Log
import androidx.activity.compose.BackHandler
import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.imePadding
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
import dev.slt.android.profile.store.ProfileStore
import dev.slt.android.ui.main.MainScreenRoute
import dev.slt.android.ui.profile.ProfileController
import dev.slt.android.ui.profile.ProfileEditorScreen
import dev.slt.android.ui.profiles.ProfilesScreen
import dev.slt.android.ui.theme.SltTheme
import dev.slt.android.vpn.SltVpnStatusBus
import kotlinx.coroutines.launch

@Composable
internal fun SltApp(
    profileStore: ProfileStore,
    onStart: () -> Unit,
    onStop: () -> Unit,
) {
    val vpnState by SltVpnStatusBus.state.collectAsState()
    val scope = rememberCoroutineScope()
    val context = LocalContext.current
    val logStore = remember { LogStore(context) }
    val profileController = remember(profileStore) {
        ProfileController(
            profileStore = profileStore,
            reportError = { message, error -> Log.e(TAG, message.text, error) },
        )
    }
    val profileUiState by profileController.state.collectAsState()
    val profileState = profileUiState.profileState
    var screen by remember { mutableStateOf<AppScreen>(AppScreen.Main) }

    LaunchedEffect(profileController) {
        profileController.loadProfiles()
    }

    BackHandler(enabled = screen != AppScreen.Main) {
        screen = when (screen) {
            AppScreen.Main -> AppScreen.Main
            AppScreen.Profiles -> AppScreen.Main
            AppScreen.EditProfile -> if (profileController.closeEditor()) {
                AppScreen.Profiles
            } else {
                AppScreen.EditProfile
            }
            AppScreen.Logs -> AppScreen.Main
        }
        profileController.setMessage(null)
    }

    SltTheme {
        Surface(
            modifier = Modifier.fillMaxSize().imePadding(),
            color = MaterialTheme.colorScheme.background,
        ) {
            AnimatedContent(
                targetState = screen,
                transitionSpec = { fadeIn(tween(220)) togetherWith fadeOut(tween(220)) },
                label = "screen",
            ) { currentScreen ->
                when (currentScreen) {
                    AppScreen.Main -> MainScreenRoute(
                        vpnState = vpnState,
                        profileState = profileState,
                        message = profileUiState.message,
                        onMessageChange = profileController::setMessage,
                        onSelectProfile = { id ->
                            scope.launch { profileController.selectProfile(id) }
                        },
                        onStart = onStart,
                        onStop = onStop,
                        onOpenProfiles = {
                            profileController.setMessage(null)
                            screen = AppScreen.Profiles
                        },
                        onOpenLogs = {
                            profileController.setMessage(null)
                            screen = AppScreen.Logs
                        },
                    )

                    AppScreen.Profiles -> ProfilesScreen(
                        profilesState = profileUiState.profiles,
                        message = profileUiState.message,
                        onBack = {
                            profileController.setMessage(null)
                            screen = AppScreen.Main
                        },
                        onDismissMessage = { profileController.setMessage(null) },
                        onAdd = {
                            if (profileController.beginNewEditor()) {
                                screen = AppScreen.EditProfile
                            }
                        },
                        onRetry = {
                            scope.launch { profileController.loadProfiles() }
                        },
                        onEdit = { id ->
                            if (profileController.beginExistingEditor(id)) {
                                screen = AppScreen.EditProfile
                            }
                        },
                        onSelect = { id ->
                            scope.launch { profileController.selectProfile(id) }
                        },
                        onDuplicate = { id ->
                            scope.launch { profileController.duplicateProfile(id) }
                        },
                        onDelete = { id ->
                            scope.launch { profileController.deleteProfile(id) }
                        },
                    )

                    AppScreen.EditProfile -> {
                        val editor = profileUiState.editor
                        if (editor != null) {
                            ProfileEditorScreen(
                                controller = profileController,
                                state = editor,
                                onClose = {
                                    if (profileController.closeEditor()) {
                                        screen = AppScreen.Profiles
                                    }
                                },
                            )
                        }
                    }

                    AppScreen.Logs -> LogsScreen(
                        logStore = logStore,
                        onBack = {
                            profileController.setMessage(null)
                            screen = AppScreen.Main
                        },
                    )
                }
            }
        }
    }
}

private sealed interface AppScreen {
    data object Main : AppScreen

    data object Profiles : AppScreen

    data object EditProfile : AppScreen

    data object Logs : AppScreen
}

private const val TAG = "SltApp"
