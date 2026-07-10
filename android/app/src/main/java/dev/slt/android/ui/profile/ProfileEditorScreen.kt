package dev.slt.android.ui.profile

import androidx.activity.compose.BackHandler
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.platform.LocalContext
import dev.slt.android.ConfigValidationResult
import dev.slt.android.SltNative
import dev.slt.android.profile.AppVpnMode
import dev.slt.android.profile.DnsMode
import dev.slt.android.ui.copySensitiveText
import kotlinx.coroutines.launch

@Composable
internal fun ProfileEditorScreen(
    controller: ProfileController,
    state: ProfileEditorUiState,
    onClose: () -> Unit,
) {
    when (state) {
        is ProfileEditorUiState.Loading -> {
            LaunchedEffect(state.requestId) {
                controller.loadEditor(
                    requestId = state.requestId,
                    validateClientConfig = SltNative::validateClientConfig,
                )
            }
            ProfileEditorStatusScreen(
                title = "Edit Profile",
                message = "Loading profile",
                onBack = onClose,
            )
        }
        is ProfileEditorUiState.LoadFailed -> ProfileEditorStatusScreen(
            title = "Edit Profile",
            message = state.message.text,
            onBack = onClose,
            onRetry = controller::retryEditorLoad,
        )
        is ProfileEditorUiState.Editing -> ProfileEditorContent(
            controller = controller,
            state = state,
            onClose = onClose,
        )
    }
}

@Composable
private fun ProfileEditorContent(
    controller: ProfileController,
    state: ProfileEditorUiState.Editing,
    onClose: () -> Unit,
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val form = state.form

    BackHandler(enabled = state.saving || form.isEditingNestedScreen) {
        if (!state.saving) {
            controller.updateEditor(ProfileEditorState::withClosedNestedScreen)
        }
    }

    val closeNested: () -> Unit = {
        controller.updateEditor(ProfileEditorState::withClosedNestedScreen)
    }

    when (form.activeNestedScreen) {
        null -> ProfileEditorHub(
            state = form,
            profileId = state.profileId,
            ownPackageName = context.packageName,
            saveEnabled = !state.saving,
            cancelEnabled = !state.saving,
            onNameChange = { name -> controller.updateEditor { it.copy(name = name) } },
            onOpenScreen = { screen ->
                controller.updateEditor { it.copy(activeNestedScreen = screen) }
            },
            onSave = {
                if (!state.saving) {
                    when (
                        val result = prepareProfileEditorSave(
                            state = form,
                            ownPackageName = context.packageName,
                            validateClientConfig = SltNative::validateClientConfig,
                        )
                    ) {
                        is ProfileEditorSaveResult.Blocked -> {
                            controller.updateEditor { result.state }
                        }
                        is ProfileEditorSaveResult.Ready -> {
                            controller.updateEditor { result.state }
                            scope.launch {
                                if (controller.saveEditor(result) == ProfileEditorSaveOutcome.Saved) {
                                    onClose()
                                }
                            }
                        }
                    }
                }
            },
            onCancel = onClose,
            onMessageShown = { controller.updateEditor { it.copy(message = null) } },
        )

        ProfileEditorNestedScreen.Toml -> TomlEditorScreen(
            initialToml = form.toml,
            validate = SltNative::validateClientConfig,
            onApply = { toml, validation ->
                controller.updateEditor { it.commitToml(toml, validation) }
            },
            onCancel = closeNested,
            onCopy = { context.copySensitiveText("SLT config", it) },
        )

        ProfileEditorNestedScreen.Routes -> RouteEditorScreen(
            initialText = form.routeText,
            onApply = { committed -> controller.updateEditor { it.commitRoutes(committed) } },
            onCopy = { context.copySensitiveText("SLT routes", it) },
            onCancel = closeNested,
        )

        ProfileEditorNestedScreen.Dns -> DnsEditorScreen(
            initialMode = form.dnsMode,
            initialText = form.dnsText,
            onApply = { mode, text -> controller.updateEditor { it.commitDns(mode, text) } },
            onCancel = closeNested,
        )

        ProfileEditorNestedScreen.Apps -> AppRulesEditorScreen(
            initialMode = form.appMode,
            initialPackages = form.selectedPackageNames,
            ownPackageName = context.packageName,
            onApply = { mode, packages ->
                controller.updateEditor { it.commitApps(mode, packages) }
            },
            onCancel = closeNested,
        )

        ProfileEditorNestedScreen.TestUrls -> TestUrlsEditorScreen(
            initialText = form.testUrlsText,
            onApply = { committed -> controller.updateEditor { it.commitTestUrls(committed) } },
            onCancel = closeNested,
        )
    }
}

private fun ProfileEditorState.commitToml(
    toml: String,
    validation: ConfigValidationResult,
): ProfileEditorState = copy(toml = toml, validation = validation).withClosedNestedScreen()

private fun ProfileEditorState.commitRoutes(routeText: String): ProfileEditorState =
    copy(routeText = routeText).withClosedNestedScreen()

private fun ProfileEditorState.commitDns(mode: DnsMode, dnsText: String): ProfileEditorState =
    copy(dnsMode = mode, dnsText = dnsText).withClosedNestedScreen()

private fun ProfileEditorState.commitApps(
    mode: AppVpnMode,
    packageNames: List<String>,
): ProfileEditorState = copy(appMode = mode, selectedPackageNames = packageNames).withClosedNestedScreen()

private fun ProfileEditorState.commitTestUrls(testUrlsText: String): ProfileEditorState =
    copy(testUrlsText = testUrlsText).withClosedNestedScreen()
