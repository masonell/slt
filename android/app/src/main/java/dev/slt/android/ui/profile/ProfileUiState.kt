package dev.slt.android.ui.profile

import dev.slt.android.profile.ProfileStoreState
import dev.slt.android.ui.UiMessage

internal sealed interface ProfilesUiState {
    data object Loading : ProfilesUiState

    data class Ready(val value: ProfileStoreState) : ProfilesUiState

    data class Unavailable(val message: UiMessage) : ProfilesUiState
}

internal sealed interface ProfileEditorUiState {
    val profileId: String?

    data class Loading(
        override val profileId: String,
        val requestId: Long,
    ) : ProfileEditorUiState

    data class Editing(
        override val profileId: String?,
        val saveProfileId: String,
        val form: ProfileEditorState,
        val saving: Boolean = false,
    ) : ProfileEditorUiState

    data class LoadFailed(
        override val profileId: String,
        val message: UiMessage,
    ) : ProfileEditorUiState
}

internal data class ProfileManagementUiState(
    val profiles: ProfilesUiState = ProfilesUiState.Loading,
    val editor: ProfileEditorUiState? = null,
    val message: UiMessage? = null,
) {
    val profileState: ProfileStoreState?
        get() = (profiles as? ProfilesUiState.Ready)?.value
}
