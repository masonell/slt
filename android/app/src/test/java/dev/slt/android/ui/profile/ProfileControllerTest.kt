package dev.slt.android.ui.profile

import dev.slt.android.ConfigValidationResult
import dev.slt.android.profile.ProfileListItem
import dev.slt.android.profile.ProfileMetadata
import dev.slt.android.profile.ProfileStoreState
import dev.slt.android.profile.SltProfile
import dev.slt.android.profile.store.ProfileStore
import dev.slt.android.ui.UiMessageSeverity
import java.io.IOException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ProfileControllerTest {
    @Test
    fun existingProfileLoadTransitionsFromLoadingToEditing() = runBlocking {
        val store = FakeProfileStore(states = listOf(STALE_STATE))
        val controller = ProfileController(store)
        controller.loadProfiles()
        assertTrue(controller.beginExistingEditor(PROFILE_ID))
        val loading = controller.state.value.editor as ProfileEditorUiState.Loading

        controller.loadEditor(loading.requestId) {
            ConfigValidationResult.Invalid("invalid for test")
        }

        val editing = controller.state.value.editor as ProfileEditorUiState.Editing
        assertEquals(PROFILE_ID, editing.profileId)
        assertEquals(PROFILE_ID, editing.saveProfileId)
        assertEquals("Work", editing.form.name)
        assertFalse(editing.saving)
    }

    @Test
    fun existingProfileLoadFailureBlocksEditingAndSaving() = runBlocking {
        val store = FakeProfileStore(
            states = listOf(STALE_STATE),
            loadProfileFailure = IOException("read failed"),
        )
        val controller = ProfileController(store)
        controller.loadProfiles()
        assertTrue(controller.beginExistingEditor(PROFILE_ID))
        val loading = controller.state.value.editor as ProfileEditorUiState.Loading

        controller.loadEditor(loading.requestId) {
            error("validation must not run when profile loading fails")
        }

        val failed = controller.state.value.editor
        assertTrue(failed is ProfileEditorUiState.LoadFailed)
        controller.updateEditor { it.copy(name = "unsafe overwrite") }
        assertEquals(failed, controller.state.value.editor)
        assertEquals(ProfileEditorSaveOutcome.KeepEditing, controller.saveEditor(SAVE_READY))
        assertEquals(0, store.saveCount)
    }

    @Test
    fun missingExistingProfileEntersLoadFailureAndRefreshesList() = runBlocking {
        val store = FakeProfileStore(
            states = listOf(STALE_STATE, EMPTY_STATE),
            profileResult = null,
        )
        val controller = ProfileController(store)
        controller.loadProfiles()
        assertTrue(controller.beginExistingEditor(PROFILE_ID))
        val loading = controller.state.value.editor as ProfileEditorUiState.Loading

        controller.loadEditor(loading.requestId) {
            error("validation must not run for a missing profile")
        }

        assertTrue(controller.state.value.editor is ProfileEditorUiState.LoadFailed)
        val profiles = controller.state.value.profiles as ProfilesUiState.Ready
        assertEquals(emptyList<ProfileListItem>(), profiles.value.profiles)
        assertEquals(2, store.loadStateCount)
    }

    @Test
    fun missingExistingProfileRemainsLoadingUntilRefreshCompletes() = runBlocking {
        val refreshStarted = CompletableDeferred<Unit>()
        val continueRefresh = CompletableDeferred<Unit>()
        val store = FakeProfileStore(
            states = listOf(STALE_STATE, EMPTY_STATE),
            profileResult = null,
            beforeLoadState = { loadIndex ->
                if (loadIndex == 1) {
                    refreshStarted.complete(Unit)
                    continueRefresh.await()
                }
            },
        )
        val controller = ProfileController(store)
        controller.loadProfiles()
        assertTrue(controller.beginExistingEditor(PROFILE_ID))
        val loading = controller.state.value.editor as ProfileEditorUiState.Loading

        val loadJob = launch {
            controller.loadEditor(loading.requestId) {
                error("validation must not run for a missing profile")
            }
        }
        refreshStarted.await()

        assertTrue(controller.state.value.editor is ProfileEditorUiState.Loading)
        assertTrue(controller.state.value.profiles is ProfilesUiState.Unavailable)

        continueRefresh.complete(Unit)
        loadJob.join()

        assertTrue(controller.state.value.editor is ProfileEditorUiState.LoadFailed)
        val profiles = controller.state.value.profiles as ProfilesUiState.Ready
        assertEquals(emptyList<ProfileListItem>(), profiles.value.profiles)
    }

    @Test
    fun missingDuplicateSourceRefreshesControllerState() = runBlocking {
        val store = FakeProfileStore(
            states = listOf(STALE_STATE, EMPTY_STATE),
            duplicateResult = null,
        )
        val controller = ProfileController(store)
        controller.loadProfiles()

        controller.duplicateProfile(PROFILE_ID)

        val profiles = controller.state.value.profiles as ProfilesUiState.Ready
        assertEquals(emptyList<ProfileListItem>(), profiles.value.profiles)
        assertEquals("Profile not found", controller.state.value.message?.text)
        assertEquals(UiMessageSeverity.Error, controller.state.value.message?.severity)
        assertEquals(2, store.loadStateCount)
    }

    @Test
    fun newEditorUsesStableCallerGeneratedProfileId() = runBlocking {
        val store = FakeProfileStore(states = listOf(EMPTY_STATE))
        val controller = ProfileController(
            profileStore = store,
            newProfileId = { GENERATED_PROFILE_ID },
        )
        controller.loadProfiles()

        assertTrue(controller.beginNewEditor())
        val editing = controller.state.value.editor as ProfileEditorUiState.Editing
        assertEquals(GENERATED_PROFILE_ID, editing.saveProfileId)

        assertEquals(ProfileEditorSaveOutcome.Saved, controller.saveEditor(SAVE_READY))
        assertEquals(GENERATED_PROFILE_ID, store.savedProfileId)
    }

    @Test
    fun unknownSaveOutcomeKeepsDraftAndRetriesWithStableId() = runBlocking {
        val ready = SAVE_READY.copy(
            state = SAVE_READY.state.copy(
                toml = CLIENT_TOML,
                routeText = "0.0.0.0/0",
                dnsText = "1.1.1.1",
                selectedPackageNames = listOf("com.example.app"),
                testUrlsText = "https://example.com",
            ),
        )
        val store = FakeProfileStore(
            states = listOf(EMPTY_STATE),
            saveFailure = IOException("save failed before write"),
        )
        val controller = ProfileController(
            profileStore = store,
            newProfileId = { GENERATED_PROFILE_ID },
        )
        controller.loadProfiles()
        assertTrue(controller.beginNewEditor())

        assertEquals(
            ProfileEditorSaveOutcome.KeepEditing,
            controller.saveEditor(ready),
        )

        val retained = controller.state.value.editor as ProfileEditorUiState.Editing
        assertEquals(GENERATED_PROFILE_ID, retained.saveProfileId)
        assertEquals(ready.state, retained.form.copy(message = null))
        assertEquals(
            "Could not confirm whether the profile was saved. Your edits were kept; retry saving",
            retained.form.message?.text,
        )
        assertFalse(retained.saving)
        assertTrue(controller.state.value.profiles is ProfilesUiState.Unavailable)
        assertEquals(listOf(GENERATED_PROFILE_ID), store.requestedSaveProfileIds)

        store.clearSaveFailure()
        assertEquals(ProfileEditorSaveOutcome.Saved, controller.saveEditor(ready))
        assertEquals(
            listOf(GENERATED_PROFILE_ID, GENERATED_PROFILE_ID),
            store.requestedSaveProfileIds,
        )
    }

    private class FakeProfileStore(
        private val states: List<ProfileStoreState>,
        private val profileResult: SltProfile? = PROFILE,
        private val loadProfileFailure: Exception? = null,
        private val duplicateResult: SltProfile? = PROFILE,
        private val beforeLoadState: suspend (Int) -> Unit = {},
        private var saveFailure: Exception? = null,
    ) : ProfileStore {
        var loadStateCount = 0
            private set
        var saveCount = 0
            private set
        var savedProfileId: String? = null
            private set
        val requestedSaveProfileIds = mutableListOf<String?>()

        init {
            require(states.isNotEmpty())
        }

        override suspend fun loadState(): ProfileStoreState {
            beforeLoadState(loadStateCount)
            val state = states[loadStateCount.coerceAtMost(states.lastIndex)]
            loadStateCount += 1
            return state
        }

        override suspend fun loadProfile(id: String): SltProfile? {
            loadProfileFailure?.let { throw it }
            return profileResult?.takeIf { it.id == id }
        }

        override suspend fun saveProfile(
            id: String?,
            name: String,
            clientToml: String,
            metadata: ProfileMetadata?,
        ): SltProfile {
            saveCount += 1
            savedProfileId = id
            requestedSaveProfileIds += id
            saveFailure?.let { throw it }
            return SltProfile(
                id = requireNotNull(id),
                clientToml = clientToml,
                metadata = requireNotNull(metadata).copy(name = name),
            )
        }

        override suspend fun duplicateProfile(id: String): SltProfile? = duplicateResult

        override suspend fun deleteProfile(id: String) = Unit

        override suspend fun setActiveProfileId(id: String?) = Unit

        fun clearSaveFailure() {
            saveFailure = null
        }
    }

    private companion object {
        const val PROFILE_ID = "work"
        const val GENERATED_PROFILE_ID = "generated-profile-id"
        const val CLIENT_TOML = "server_host = \"example.com\""

        val PROFILE = SltProfile(
            id = PROFILE_ID,
            clientToml = CLIENT_TOML,
            metadata = ProfileMetadata(name = "Work"),
        )
        val STALE_STATE = ProfileStoreState(
            profiles = listOf(ProfileListItem(PROFILE_ID, "Work", isActive = true)),
            activeProfile = PROFILE,
        )
        val EMPTY_STATE = ProfileStoreState(
            profiles = emptyList(),
            activeProfile = null,
        )
        val SAVE_READY = ProfileEditorSaveResult.Ready(
            state = ProfileEditorState(name = "New"),
            name = "New",
            clientToml = CLIENT_TOML,
            metadata = ProfileMetadata(name = "New"),
        )
    }
}
