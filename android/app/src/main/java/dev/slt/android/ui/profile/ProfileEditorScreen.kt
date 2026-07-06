package dev.slt.android.ui.profile

import androidx.activity.compose.BackHandler
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.platform.LocalContext
import dev.slt.android.ConfigValidationResult
import dev.slt.android.SltNative
import dev.slt.android.profile.AppVpnMode
import dev.slt.android.profile.DnsMode
import dev.slt.android.profile.store.ProfileRepository
import dev.slt.android.ui.copySensitiveText
import kotlinx.coroutines.launch

@Composable
internal fun ProfileEditorScreen(
    profileRepository: ProfileRepository,
    profileId: String?,
    onSaved: () -> Unit,
    onCancel: () -> Unit,
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var editorState by remember(profileId) { mutableStateOf(ProfileEditorState()) }

    LaunchedEffect(profileId) {
        val profile = profileId?.let { profileRepository.loadProfile(it) }
        val base = profileEditorStateFrom(profile)
        // Validate an existing config up front so the Client config card can show
        // the server summary immediately; new (empty) profiles stay "Not set".
        editorState = if (base.toml.isNotBlank()) {
            base.copy(validation = SltNative.validateClientConfig(base.toml))
        } else {
            base
        }
    }

    BackHandler(enabled = editorState.isEditingNestedScreen) {
        editorState = editorState.withClosedNestedScreen()
    }

    val closeNested: () -> Unit = { editorState = editorState.withClosedNestedScreen() }

    when (editorState.activeNestedScreen) {
        null -> ProfileEditorHub(
            state = editorState,
            profileId = profileId,
            ownPackageName = context.packageName,
            onNameChange = { editorState = editorState.copy(name = it) },
            onOpenScreen = { editorState = editorState.copy(activeNestedScreen = it) },
            onSave = {
                when (
                    val result = prepareProfileEditorSave(
                        state = editorState,
                        ownPackageName = context.packageName,
                        validateClientConfig = SltNative::validateClientConfig,
                    )
                ) {
                    is ProfileEditorSaveResult.Blocked -> editorState = result.state
                    is ProfileEditorSaveResult.Ready -> {
                        editorState = result.state
                        scope.launch {
                            profileRepository.saveProfile(
                                id = profileId,
                                name = result.name,
                                clientToml = result.clientToml,
                                metadata = result.metadata,
                            )
                            onSaved()
                        }
                    }
                }
            },
            onCancel = onCancel,
            onMessageShown = { editorState = editorState.copy(message = null) },
        )

        ProfileEditorNestedScreen.Toml -> TomlEditorScreen(
            initialToml = editorState.toml,
            validate = SltNative::validateClientConfig,
            onApply = { toml, validation -> editorState = editorState.commitToml(toml, validation) },
            onCancel = closeNested,
            onCopy = { context.copySensitiveText("SLT config", it) },
        )

        ProfileEditorNestedScreen.Routes -> RouteEditorScreen(
            initialText = editorState.routeText,
            onApply = { committed -> editorState = editorState.commitRoutes(committed) },
            onCopy = { context.copySensitiveText("SLT routes", it) },
            onCancel = closeNested,
        )

        ProfileEditorNestedScreen.Dns -> DnsEditorScreen(
            initialMode = editorState.dnsMode,
            initialText = editorState.dnsText,
            onApply = { mode, text -> editorState = editorState.commitDns(mode, text) },
            onCancel = closeNested,
        )

        ProfileEditorNestedScreen.Apps -> AppRulesEditorScreen(
            initialMode = editorState.appMode,
            initialPackages = editorState.selectedPackageNames,
            ownPackageName = context.packageName,
            onApply = { mode, packages -> editorState = editorState.commitApps(mode, packages) },
            onCancel = closeNested,
        )

        ProfileEditorNestedScreen.TestUrls -> TestUrlsEditorScreen(
            initialText = editorState.testUrlsText,
            onApply = { committed -> editorState = editorState.commitTestUrls(committed) },
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
