package dev.slt.android.profile.store

import dev.slt.android.profile.ProfileMetadata
import dev.slt.android.profile.ProfileStoreState
import dev.slt.android.profile.SltProfile

internal interface ProfileStore {
    suspend fun loadState(): ProfileStoreState

    suspend fun loadProfile(id: String): SltProfile?

    suspend fun saveProfile(
        id: String?,
        name: String,
        clientToml: String,
        metadata: ProfileMetadata?,
    ): SltProfile

    suspend fun duplicateProfile(id: String): SltProfile?

    suspend fun deleteProfile(id: String)

    suspend fun setActiveProfileId(id: String?)
}
