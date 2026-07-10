package dev.slt.android.ui

import dev.slt.android.profile.ProfileMetadata
import dev.slt.android.profile.ProfileStoreState
import dev.slt.android.profile.SltProfile
import dev.slt.android.profile.store.ProfileStore
import java.io.IOException
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

class ProfileStoreActionsTest {
    @Test
    fun initialLoadFailureReturnsUiError() = runBlocking {
        val error = IOException("load failed")
        val actions = ProfileStoreActions(FakeProfileStore(FailingOperation.LoadState, error))

        val result = actions.loadState()

        assertFailure("Could not load profiles", error, result)
    }

    @Test
    fun editorLoadFailureReturnsUiError() = runBlocking {
        val error = IOException("profile load failed")
        val actions = ProfileStoreActions(FakeProfileStore(FailingOperation.LoadProfile, error))

        val result = actions.loadProfile(PROFILE_ID)

        assertFailure("Could not load profile", error, result)
    }

    @Test
    fun selectFailureReturnsUiError() = runBlocking {
        val error = IOException("select failed")
        val actions = ProfileStoreActions(FakeProfileStore(FailingOperation.SetActive, error))

        val result = actions.selectProfile(PROFILE_ID)

        assertFailure("Could not change active profile", error, result)
    }

    @Test
    fun duplicateExceptionAfterMutationMakesStateUnavailable() = runBlocking {
        val error = IOException("duplicate failed")
        val store = FakeProfileStore(
            failingOperation = FailingOperation.Duplicate,
            failure = error,
            failureTiming = FailureTiming.AfterMutation,
        )
        val actions = ProfileStoreActions(store)

        val result = actions.duplicateProfile(PROFILE_ID)

        assertStateUnavailable(
            "Could not confirm whether the profile was duplicated. Reload profiles before retrying",
            error,
            result,
        )
        assertEquals(1, store.duplicateCount)
    }

    @Test
    fun missingDuplicateSourceRefreshesProfileState() = runBlocking {
        val store = FakeProfileStore()
        val actions = ProfileStoreActions(store)

        val result = actions.duplicateProfile("missing")

        assertTrue(result is ProfileStoreActionResult.Success)
        result as ProfileStoreActionResult.Success
        assertEquals(PROFILE_STATE, result.value)
        assertEquals("Profile not found", result.message?.text)
        assertEquals(UiMessageSeverity.Error, result.message?.severity)
        assertEquals(1, store.duplicateCount)
        assertEquals(1, store.loadStateCount)
    }

    @Test
    fun missingDuplicateSourceWithRefreshFailureMakesStateUnavailable() = runBlocking {
        val error = IOException("refresh failed")
        val actions = ProfileStoreActions(
            FakeProfileStore(FailingOperation.LoadState, error),
        )

        val result = actions.duplicateProfile("missing")

        assertStateUnavailable(
            "Profile was not found, and profiles could not be refreshed",
            error,
            result,
        )
    }

    @Test
    fun deleteExceptionAfterMutationMakesStateUnavailable() = runBlocking {
        val error = IOException("delete failed")
        val store = FakeProfileStore(
            failingOperation = FailingOperation.Delete,
            failure = error,
            failureTiming = FailureTiming.AfterMutation,
        )
        val actions = ProfileStoreActions(store)

        val result = actions.deleteProfile(PROFILE_ID)

        assertStateUnavailable(
            "Could not confirm whether the profile was deleted. Reload profiles before retrying",
            error,
            result,
        )
        assertEquals(1, store.deleteCount)
    }

    @Test
    fun saveExceptionAfterMutationMakesStateUnavailable() = runBlocking {
        val error = IOException("save failed")
        val store = FakeProfileStore(
            failingOperation = FailingOperation.Save,
            failure = error,
            failureTiming = FailureTiming.AfterMutation,
        )
        val actions = ProfileStoreActions(store)

        val result = actions.saveProfile(
            id = PROFILE_ID,
            name = PROFILE_NAME,
            clientToml = CLIENT_TOML,
            metadata = PROFILE.metadata,
        )

        assertStateUnavailable(
            "Could not confirm whether the profile was saved. Your edits were kept; retry saving",
            error,
            result,
        )
        assertEquals(1, store.saveCount)
    }

    @Test
    fun selectRefreshFailureReportsCommittedMutationAndUnavailableState() = runBlocking {
        val error = IOException("refresh failed")
        val store = FakeProfileStore(FailingOperation.LoadState, error)
        val actions = ProfileStoreActions(store)

        val result = actions.selectProfile(PROFILE_ID)

        assertStateUnavailable(
            "Active profile changed, but profiles could not be refreshed",
            error,
            result,
        )
        assertEquals(1, store.setActiveCount)
    }

    @Test
    fun duplicateRefreshFailureReportsCommittedMutationAndUnavailableState() = runBlocking {
        val error = IOException("refresh failed")
        val store = FakeProfileStore(FailingOperation.LoadState, error)
        val actions = ProfileStoreActions(store)

        val result = actions.duplicateProfile(PROFILE_ID)

        assertStateUnavailable(
            "Profile duplicated, but profiles could not be refreshed",
            error,
            result,
        )
        assertEquals(1, store.duplicateCount)
    }

    @Test
    fun deleteRefreshFailureReportsCommittedMutationAndUnavailableState() = runBlocking {
        val error = IOException("refresh failed")
        val store = FakeProfileStore(FailingOperation.LoadState, error)
        val actions = ProfileStoreActions(store)

        val result = actions.deleteProfile(PROFILE_ID)

        assertStateUnavailable(
            "Profile deleted, but profiles could not be refreshed",
            error,
            result,
        )
        assertEquals(1, store.deleteCount)
    }

    @Test
    fun saveRefreshFailureReportsCommittedMutationAndUnavailableState() = runBlocking {
        val error = IOException("refresh failed")
        val store = FakeProfileStore(FailingOperation.LoadState, error)
        val actions = ProfileStoreActions(store)

        val result = actions.saveProfile(
            id = PROFILE_ID,
            name = PROFILE_NAME,
            clientToml = CLIENT_TOML,
            metadata = PROFILE.metadata,
        )

        assertStateUnavailable(
            "Profile saved, but profiles could not be refreshed",
            error,
            result,
        )
        assertEquals(1, store.saveCount)
    }

    @Test
    fun reloadAfterUnknownSaveOutcomeDoesNotRepeatSave() = runBlocking {
        val store = FakeProfileStore(
            failingOperation = FailingOperation.Save,
            failureTiming = FailureTiming.AfterMutation,
        )
        val actions = ProfileStoreActions(store)

        val saveResult = actions.saveProfile(
            id = null,
            name = PROFILE_NAME,
            clientToml = CLIENT_TOML,
            metadata = PROFILE.metadata,
        )
        assertTrue(saveResult is ProfileStoreActionResult.StateUnavailable)
        assertEquals(1, store.saveCount)

        store.clearFailure()
        val reloadResult = actions.loadState()

        assertTrue(reloadResult is ProfileStoreActionResult.Success)
        assertEquals(1, store.saveCount)
    }

    @Test
    fun cancellationIsNotConvertedToUiError() = runBlocking {
        val cancellation = CancellationException("cancelled")
        val actions = ProfileStoreActions(
            FakeProfileStore(FailingOperation.Delete, cancellation),
        )

        val thrown = try {
            actions.deleteProfile(PROFILE_ID)
            null
        } catch (error: CancellationException) {
            error
        }

        assertSame(cancellation, thrown)
    }

    private fun assertFailure(
        expectedMessage: String,
        expectedCause: Exception,
        result: ProfileStoreActionResult<*>,
    ) {
        assertTrue(result is ProfileStoreActionResult.Failure)
        result as ProfileStoreActionResult.Failure
        assertEquals(expectedMessage, result.message.text)
        assertEquals(UiMessageSeverity.Error, result.message.severity)
        assertSame(expectedCause, result.cause)
    }

    private fun assertStateUnavailable(
        expectedMessage: String,
        expectedCause: Exception,
        result: ProfileStoreActionResult<*>,
    ) {
        assertTrue(result is ProfileStoreActionResult.StateUnavailable)
        result as ProfileStoreActionResult.StateUnavailable
        assertEquals(expectedMessage, result.message.text)
        assertEquals(UiMessageSeverity.Error, result.message.severity)
        assertSame(expectedCause, result.cause)
    }

    private enum class FailingOperation {
        LoadState,
        LoadProfile,
        Save,
        Duplicate,
        Delete,
        SetActive,
    }

    private enum class FailureTiming {
        BeforeMutation,
        AfterMutation,
    }

    private class FakeProfileStore(
        private var failingOperation: FailingOperation? = null,
        private val failure: Exception = IOException("store failed"),
        private val failureTiming: FailureTiming = FailureTiming.BeforeMutation,
    ) : ProfileStore {
        var saveCount = 0
            private set
        var loadStateCount = 0
            private set
        var duplicateCount = 0
            private set
        var deleteCount = 0
            private set
        var setActiveCount = 0
            private set

        override suspend fun loadState(): ProfileStoreState {
            failIf(FailingOperation.LoadState)
            loadStateCount += 1
            return PROFILE_STATE
        }

        override suspend fun loadProfile(id: String): SltProfile? {
            failIf(FailingOperation.LoadProfile)
            return PROFILE.takeIf { it.id == id }
        }

        override suspend fun saveProfile(
            id: String?,
            name: String,
            clientToml: String,
            metadata: ProfileMetadata?,
        ): SltProfile {
            failIf(FailingOperation.Save, FailureTiming.BeforeMutation)
            saveCount += 1
            val profile = SltProfile(
                id = id ?: PROFILE_ID,
                clientToml = clientToml,
                metadata = requireNotNull(metadata).copy(name = name),
            )
            failIf(FailingOperation.Save, FailureTiming.AfterMutation)
            return profile
        }

        override suspend fun duplicateProfile(id: String): SltProfile? {
            failIf(FailingOperation.Duplicate, FailureTiming.BeforeMutation)
            duplicateCount += 1
            val profile = PROFILE.takeIf { it.id == id }
            failIf(FailingOperation.Duplicate, FailureTiming.AfterMutation)
            return profile
        }

        override suspend fun deleteProfile(id: String) {
            failIf(FailingOperation.Delete, FailureTiming.BeforeMutation)
            deleteCount += 1
            failIf(FailingOperation.Delete, FailureTiming.AfterMutation)
        }

        override suspend fun setActiveProfileId(id: String?) {
            failIf(FailingOperation.SetActive, FailureTiming.BeforeMutation)
            setActiveCount += 1
            failIf(FailingOperation.SetActive, FailureTiming.AfterMutation)
        }

        fun clearFailure() {
            failingOperation = null
        }

        private fun failIf(
            operation: FailingOperation,
            timing: FailureTiming = FailureTiming.BeforeMutation,
        ) {
            if (failingOperation == operation && failureTiming == timing) {
                throw failure
            }
        }
    }

    private companion object {
        const val PROFILE_ID = "work"
        const val PROFILE_NAME = "Work"
        const val CLIENT_TOML = "server_host = \"example.com\""

        val PROFILE = SltProfile(
            id = PROFILE_ID,
            clientToml = CLIENT_TOML,
            metadata = ProfileMetadata(name = PROFILE_NAME),
        )
        val PROFILE_STATE = ProfileStoreState(
            profiles = emptyList(),
            activeProfile = PROFILE,
        )
    }
}
