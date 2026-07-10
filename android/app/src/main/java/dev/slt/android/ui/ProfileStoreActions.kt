package dev.slt.android.ui

import dev.slt.android.profile.ProfileMetadata
import dev.slt.android.profile.ProfileStoreState
import dev.slt.android.profile.SltProfile
import dev.slt.android.profile.store.ProfileStore
import kotlinx.coroutines.CancellationException

internal sealed interface ProfileStoreActionResult<out T> {
    data class Success<T>(
        val value: T,
        val message: UiMessage? = null,
    ) : ProfileStoreActionResult<T>

    data class Failure(
        val message: UiMessage,
        val cause: Exception? = null,
    ) : ProfileStoreActionResult<Nothing>

    data class StateUnavailable(
        val message: UiMessage,
        val cause: Exception,
    ) : ProfileStoreActionResult<Nothing>
}

internal class ProfileStoreActions(
    private val profileStore: ProfileStore,
) {
    suspend fun loadState(): ProfileStoreActionResult<ProfileStoreState> =
        perform("Could not load profiles") {
            profileStore.loadState()
        }

    suspend fun loadProfile(id: String): ProfileStoreActionResult<SltProfile?> =
        perform("Could not load profile") {
            profileStore.loadProfile(id)
        }

    suspend fun selectProfile(id: String): ProfileStoreActionResult<ProfileStoreState> =
        atomicMutationAndRefresh(
            mutationFailureMessage = "Could not change active profile",
            refreshFailureMessage = "Active profile changed, but profiles could not be refreshed",
            successMessage = UiMessage.info("Active profile changed"),
        ) {
            profileStore.setActiveProfileId(id)
        }

    suspend fun duplicateProfile(id: String): ProfileStoreActionResult<ProfileStoreState> {
        return when (val mutation = attempt { profileStore.duplicateProfile(id) }) {
            is StoreOperationResult.Success -> {
                val profile = mutation.value
                    ?: return refreshAfterMissingProfile()
                refreshAfterMutation(
                    successMessage = UiMessage.info("Duplicated ${profile.metadata.name}"),
                    refreshFailureMessage = "Profile duplicated, but profiles could not be refreshed",
                )
            }
            is StoreOperationResult.Failure -> ProfileStoreActionResult.StateUnavailable(
                message = UiMessage.error(
                    "Could not confirm whether the profile was duplicated. Reload profiles before retrying",
                ),
                cause = mutation.cause,
            )
        }
    }

    private suspend fun refreshAfterMissingProfile(): ProfileStoreActionResult<ProfileStoreState> =
        when (val refresh = attempt { profileStore.loadState() }) {
            is StoreOperationResult.Success -> ProfileStoreActionResult.Success(
                value = refresh.value,
                message = UiMessage.error("Profile not found"),
            )
            is StoreOperationResult.Failure -> ProfileStoreActionResult.StateUnavailable(
                message = UiMessage.error(
                    "Profile was not found, and profiles could not be refreshed",
                ),
                cause = refresh.cause,
            )
        }

    suspend fun deleteProfile(id: String): ProfileStoreActionResult<ProfileStoreState> =
        ambiguousMutationAndRefresh(
            unknownOutcomeMessage =
                "Could not confirm whether the profile was deleted. Reload profiles before retrying",
            refreshFailureMessage = "Profile deleted, but profiles could not be refreshed",
            successMessage = UiMessage.info("Profile deleted"),
        ) {
            profileStore.deleteProfile(id)
        }

    suspend fun saveProfile(
        id: String?,
        name: String,
        clientToml: String,
        metadata: ProfileMetadata,
    ): ProfileStoreActionResult<ProfileStoreState> =
        ambiguousMutationAndRefresh(
            unknownOutcomeMessage =
                "Could not confirm whether the profile was saved. Your edits were kept; retry saving",
            refreshFailureMessage = "Profile saved, but profiles could not be refreshed",
            successMessage = UiMessage.info("Profile saved"),
        ) {
            profileStore.saveProfile(
                id = id,
                name = name,
                clientToml = clientToml,
                metadata = metadata,
            )
        }

    private suspend fun <T> perform(
        failureMessage: String,
        operation: suspend () -> T,
    ): ProfileStoreActionResult<T> =
        when (val result = attempt(operation)) {
            is StoreOperationResult.Success -> ProfileStoreActionResult.Success(result.value)
            is StoreOperationResult.Failure -> ProfileStoreActionResult.Failure(
                message = UiMessage.error(failureMessage),
                cause = result.cause,
            )
        }

    private suspend fun <T> atomicMutationAndRefresh(
        mutationFailureMessage: String,
        refreshFailureMessage: String,
        successMessage: UiMessage,
        mutation: suspend () -> T,
    ): ProfileStoreActionResult<ProfileStoreState> =
        when (val mutationResult = attempt(mutation)) {
            is StoreOperationResult.Success -> refreshAfterMutation(
                successMessage = successMessage,
                refreshFailureMessage = refreshFailureMessage,
            )
            is StoreOperationResult.Failure -> ProfileStoreActionResult.Failure(
                message = UiMessage.error(mutationFailureMessage),
                cause = mutationResult.cause,
            )
        }

    private suspend fun <T> ambiguousMutationAndRefresh(
        unknownOutcomeMessage: String,
        refreshFailureMessage: String,
        successMessage: UiMessage,
        mutation: suspend () -> T,
    ): ProfileStoreActionResult<ProfileStoreState> =
        when (val mutationResult = attempt(mutation)) {
            is StoreOperationResult.Success -> refreshAfterMutation(
                successMessage = successMessage,
                refreshFailureMessage = refreshFailureMessage,
            )
            is StoreOperationResult.Failure -> ProfileStoreActionResult.StateUnavailable(
                message = UiMessage.error(unknownOutcomeMessage),
                cause = mutationResult.cause,
            )
        }

    private suspend fun refreshAfterMutation(
        successMessage: UiMessage,
        refreshFailureMessage: String,
    ): ProfileStoreActionResult<ProfileStoreState> =
        when (val refresh = attempt { profileStore.loadState() }) {
            is StoreOperationResult.Success -> ProfileStoreActionResult.Success(
                value = refresh.value,
                message = successMessage,
            )
            is StoreOperationResult.Failure ->
                ProfileStoreActionResult.StateUnavailable(
                    message = UiMessage.error(refreshFailureMessage),
                    cause = refresh.cause,
                )
        }

    private suspend fun <T> attempt(
        operation: suspend () -> T,
    ): StoreOperationResult<T> =
        try {
            StoreOperationResult.Success(operation())
        } catch (cancel: CancellationException) {
            throw cancel
        } catch (error: Exception) {
            StoreOperationResult.Failure(error)
        }
}

private sealed interface StoreOperationResult<out T> {
    data class Success<T>(val value: T) : StoreOperationResult<T>

    data class Failure(val cause: Exception) : StoreOperationResult<Nothing>
}
