package dev.slt.android.ui.profile

import dev.slt.android.ConfigValidationResult
import dev.slt.android.profile.ProfileStoreState
import dev.slt.android.profile.store.ProfileStore
import dev.slt.android.ui.ProfileStoreActionResult
import dev.slt.android.ui.ProfileStoreActions
import dev.slt.android.ui.UiMessage
import java.util.UUID
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

internal enum class ProfileEditorSaveOutcome {
    Saved,
    KeepEditing,
}

internal class ProfileController(
    profileStore: ProfileStore,
    private val reportError: (UiMessage, Exception) -> Unit = { _, _ -> },
    private val newProfileId: () -> String = { UUID.randomUUID().toString() },
) {
    private val actions = ProfileStoreActions(profileStore)
    private val storeMutex = Mutex()
    private val mutableState = MutableStateFlow(ProfileManagementUiState())
    private var nextEditorRequestId = 0L

    val state: StateFlow<ProfileManagementUiState> = mutableState.asStateFlow()

    suspend fun loadProfiles() {
        storeMutex.withLock {
            mutableState.update {
                it.copy(
                    profiles = ProfilesUiState.Loading,
                    message = null,
                )
            }
            applyProfilesResult(actions.loadState())
        }
    }

    suspend fun selectProfile(id: String) {
        runReadyProfileAction { actions.selectProfile(id) }
    }

    suspend fun duplicateProfile(id: String) {
        runReadyProfileAction { actions.duplicateProfile(id) }
    }

    suspend fun deleteProfile(id: String) {
        runReadyProfileAction { actions.deleteProfile(id) }
    }

    fun beginNewEditor(): Boolean {
        if (mutableState.value.profiles !is ProfilesUiState.Ready) {
            return false
        }
        mutableState.update {
            it.copy(
                editor = ProfileEditorUiState.Editing(
                    profileId = null,
                    saveProfileId = newProfileId(),
                    form = ProfileEditorState(),
                ),
                message = null,
            )
        }
        return true
    }

    fun beginExistingEditor(profileId: String): Boolean {
        if (mutableState.value.profiles !is ProfilesUiState.Ready) {
            return false
        }
        mutableState.update {
            it.copy(
                editor = newEditorLoadingState(profileId),
                message = null,
            )
        }
        return true
    }

    fun retryEditorLoad() {
        val failed = mutableState.value.editor as? ProfileEditorUiState.LoadFailed ?: return
        mutableState.update {
            it.copy(editor = newEditorLoadingState(failed.profileId))
        }
    }

    suspend fun loadEditor(
        requestId: Long,
        validateClientConfig: (String) -> ConfigValidationResult,
    ) {
        val loading = mutableState.value.editor as? ProfileEditorUiState.Loading ?: return
        if (loading.requestId != requestId) {
            return
        }

        val result = storeMutex.withLock { actions.loadProfile(loading.profileId) }
        if (!isCurrentEditorRequest(loading)) {
            return
        }

        when (result) {
            is ProfileStoreActionResult.Success -> {
                val profile = result.value
                if (profile == null) {
                    reconcileMissingEditorProfile(loading)
                    return
                }

                val base = profileEditorStateFrom(profile)
                val form = if (base.toml.isNotBlank()) {
                    base.copy(validation = validateClientConfig(base.toml))
                } else {
                    base
                }
                mutableState.update {
                    if (it.editor.hasRequestId(loading.requestId)) {
                        it.copy(
                            editor = ProfileEditorUiState.Editing(
                                profileId = loading.profileId,
                                saveProfileId = loading.profileId,
                                form = form,
                            ),
                        )
                    } else {
                        it
                    }
                }
            }
            is ProfileStoreActionResult.Failure -> {
                report(result)
                mutableState.update {
                    if (it.editor.hasRequestId(loading.requestId)) {
                        it.copy(
                            editor = ProfileEditorUiState.LoadFailed(
                                profileId = loading.profileId,
                                message = result.message,
                            ),
                        )
                    } else {
                        it
                    }
                }
            }
            is ProfileStoreActionResult.StateUnavailable -> {
                report(result)
                mutableState.update {
                    if (it.editor.hasRequestId(loading.requestId)) {
                        it.copy(
                            profiles = ProfilesUiState.Unavailable(result.message),
                            editor = ProfileEditorUiState.LoadFailed(
                                profileId = loading.profileId,
                                message = result.message,
                            ),
                            message = result.message,
                        )
                    } else {
                        it
                    }
                }
            }
        }
    }

    fun updateEditor(transform: (ProfileEditorState) -> ProfileEditorState) {
        mutableState.update {
            val editing = it.editor as? ProfileEditorUiState.Editing ?: return@update it
            if (editing.saving) {
                it
            } else {
                it.copy(editor = editing.copy(form = transform(editing.form)))
            }
        }
    }

    suspend fun saveEditor(ready: ProfileEditorSaveResult.Ready): ProfileEditorSaveOutcome {
        val editing = mutableState.value.editor as? ProfileEditorUiState.Editing
            ?: return ProfileEditorSaveOutcome.KeepEditing
        if (editing.saving) {
            return ProfileEditorSaveOutcome.KeepEditing
        }
        mutableState.update {
            val current = it.editor as? ProfileEditorUiState.Editing ?: return@update it
            it.copy(editor = current.copy(form = ready.state, saving = true))
        }

        return try {
            val result = storeMutex.withLock {
                actions.saveProfile(
                    id = editing.saveProfileId,
                    name = ready.name,
                    clientToml = ready.clientToml,
                    metadata = ready.metadata,
                )
            }
            when (result) {
                is ProfileStoreActionResult.Success -> {
                    mutableState.update {
                        it.copy(
                            profiles = ProfilesUiState.Ready(result.value),
                            message = result.message,
                        )
                    }
                    ProfileEditorSaveOutcome.Saved
                }
                is ProfileStoreActionResult.Failure -> {
                    report(result)
                    mutableState.update {
                        val current = it.editor as? ProfileEditorUiState.Editing ?: return@update it
                        it.copy(
                            editor = current.copy(
                                form = current.form.copy(message = result.message),
                                saving = false,
                            ),
                        )
                    }
                    ProfileEditorSaveOutcome.KeepEditing
                }
                is ProfileStoreActionResult.StateUnavailable -> {
                    report(result)
                    mutableState.update {
                        val current = it.editor as? ProfileEditorUiState.Editing
                            ?: return@update it.copy(
                                profiles = ProfilesUiState.Unavailable(result.message),
                                message = result.message,
                            )
                        it.copy(
                            profiles = ProfilesUiState.Unavailable(result.message),
                            editor = current.copy(
                                form = current.form.copy(message = result.message),
                                saving = false,
                            ),
                            message = result.message,
                        )
                    }
                    ProfileEditorSaveOutcome.KeepEditing
                }
            }
        } finally {
            mutableState.update {
                val current = it.editor as? ProfileEditorUiState.Editing ?: return@update it
                if (current.saving) {
                    it.copy(editor = current.copy(saving = false))
                } else {
                    it
                }
            }
        }
    }

    fun closeEditor(): Boolean {
        val editing = mutableState.value.editor as? ProfileEditorUiState.Editing
        if (editing?.saving == true) {
            return false
        }
        mutableState.update { it.copy(editor = null) }
        return true
    }

    fun setMessage(message: UiMessage?) {
        mutableState.update { it.copy(message = message) }
    }

    private suspend fun runReadyProfileAction(
        operation: suspend () -> ProfileStoreActionResult<ProfileStoreState>,
    ) {
        storeMutex.withLock {
            if (mutableState.value.profiles !is ProfilesUiState.Ready) {
                return@withLock
            }
            applyProfilesResult(operation())
        }
    }

    private fun applyProfilesResult(result: ProfileStoreActionResult<ProfileStoreState>) {
        when (result) {
            is ProfileStoreActionResult.Success -> mutableState.update {
                it.copy(
                    profiles = ProfilesUiState.Ready(result.value),
                    message = result.message,
                )
            }
            is ProfileStoreActionResult.Failure -> {
                report(result)
                mutableState.update {
                    val profiles = if (it.profiles is ProfilesUiState.Ready) {
                        it.profiles
                    } else {
                        ProfilesUiState.Unavailable(result.message)
                    }
                    it.copy(profiles = profiles, message = result.message)
                }
            }
            is ProfileStoreActionResult.StateUnavailable -> {
                report(result)
                mutableState.update {
                    it.copy(
                        profiles = ProfilesUiState.Unavailable(result.message),
                        message = result.message,
                    )
                }
            }
        }
    }

    private suspend fun reconcileMissingEditorProfile(
        loading: ProfileEditorUiState.Loading,
    ) {
        val missingMessage = UiMessage.error("Profile could not be loaded")
        mutableState.update {
            if (it.editor.hasRequestId(loading.requestId)) {
                it.copy(
                    profiles = ProfilesUiState.Unavailable(missingMessage),
                    message = missingMessage,
                )
            } else {
                it
            }
        }
        if (!isCurrentEditorRequest(loading)) {
            return
        }

        val result = storeMutex.withLock { actions.loadState() }
        if (!isCurrentEditorRequest(loading)) {
            return
        }

        when (result) {
            is ProfileStoreActionResult.Success -> finishMissingEditorLoad(
                loading = loading,
                profiles = ProfilesUiState.Ready(result.value),
                message = missingMessage,
            )
            is ProfileStoreActionResult.Failure -> {
                report(result)
                finishMissingEditorLoad(
                    loading = loading,
                    profiles = ProfilesUiState.Unavailable(result.message),
                    message = result.message,
                )
            }
            is ProfileStoreActionResult.StateUnavailable -> {
                report(result)
                finishMissingEditorLoad(
                    loading = loading,
                    profiles = ProfilesUiState.Unavailable(result.message),
                    message = result.message,
                )
            }
        }
    }

    private fun finishMissingEditorLoad(
        loading: ProfileEditorUiState.Loading,
        profiles: ProfilesUiState,
        message: UiMessage,
    ) {
        mutableState.update {
            if (it.editor.hasRequestId(loading.requestId)) {
                it.copy(
                    profiles = profiles,
                    editor = ProfileEditorUiState.LoadFailed(
                        profileId = loading.profileId,
                        message = message,
                    ),
                    message = message,
                )
            } else {
                it
            }
        }
    }

    private fun newEditorLoadingState(profileId: String): ProfileEditorUiState.Loading =
        ProfileEditorUiState.Loading(
            profileId = profileId,
            requestId = ++nextEditorRequestId,
        )

    private fun isCurrentEditorRequest(expected: ProfileEditorUiState.Loading): Boolean {
        return mutableState.value.editor.hasRequestId(expected.requestId)
    }

    private fun report(result: ProfileStoreActionResult.Failure) {
        result.cause?.let { reportError(result.message, it) }
    }

    private fun report(result: ProfileStoreActionResult.StateUnavailable) {
        reportError(result.message, result.cause)
    }
}

private fun ProfileEditorUiState?.hasRequestId(requestId: Long): Boolean =
    (this as? ProfileEditorUiState.Loading)?.requestId == requestId
