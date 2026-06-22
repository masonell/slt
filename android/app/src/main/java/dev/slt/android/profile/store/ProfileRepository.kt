package dev.slt.android.profile.store

import android.content.Context
import android.util.Log
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import dev.slt.android.profile.ProfileListItem
import dev.slt.android.profile.ProfileMetadata
import dev.slt.android.profile.ProfileStoreState
import dev.slt.android.profile.SltProfile
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.File
import java.util.UUID
import kotlin.text.get

private val Context.profileDataStore by preferencesDataStore(name = "profiles")

class ProfileRepository(context: Context) {
    private val appContext = context.applicationContext
    private val profilesDir = File(appContext.filesDir, "profiles")

    suspend fun loadState(): ProfileStoreState =
        withContext(Dispatchers.IO) {
            val activeProfileId = activeProfileId()
            val profiles = listProfiles(activeProfileId)
            val activeProfile = activeProfileId?.let { loadProfileInternal(it) }
            ProfileStoreState(
                profiles = profiles,
                activeProfile = activeProfile,
            )
        }

    suspend fun loadProfile(id: String): SltProfile? =
        withContext(Dispatchers.IO) {
            loadProfileInternal(id)
        }

    suspend fun saveProfile(
        id: String?,
        name: String,
        clientToml: String,
        metadata: ProfileMetadata?,
    ): SltProfile =
        withContext(Dispatchers.IO) {
            val profileId = id ?: UUID.randomUUID().toString()
            val profileMetadata = (metadata ?: ProfileMetadata(name = name)).copy(name = name)
            val dir = profileDir(profileId)
            if (!dir.exists() && !dir.mkdirs()) {
                error("could not create profile directory: $dir")
            }

            clientTomlFile(dir).writeText(clientToml)
            metadataFile(dir).writeText(profileMetadata.toProfileJson().toString(2))

            val profile = SltProfile(profileId, clientToml, profileMetadata)
            if (activeProfileId() == null) {
                setActiveProfileId(profileId)
            }
            profile
        }

    suspend fun duplicateProfile(id: String): SltProfile? =
        withContext(Dispatchers.IO) {
            val source = loadProfileInternal(id) ?: return@withContext null
            val copyName = "${source.metadata.name} Copy"
            saveProfile(
                id = null,
                name = copyName,
                clientToml = source.clientToml,
                metadata = source.metadata.copy(name = copyName),
            )
        }

    suspend fun deleteProfile(id: String) =
        withContext(Dispatchers.IO) {
            profileDir(id).deleteRecursively()
            if (activeProfileId() == id) {
                setActiveProfileId(null)
            }
        }

    suspend fun setActiveProfileId(id: String?) {
        appContext.profileDataStore.edit { preferences ->
            if (id == null) {
                preferences.remove(ACTIVE_PROFILE_ID)
            } else {
                preferences[ACTIVE_PROFILE_ID] = id
            }
        }
    }

    private suspend fun activeProfileId(): String? =
        appContext.profileDataStore.data.first()[ACTIVE_PROFILE_ID]

    private fun listProfiles(activeProfileId: String?): List<ProfileListItem> {
        val profileDirs = profilesDir.listFiles { file -> file.isDirectory }.orEmpty()
        return profileDirs
            .mapNotNull { dir ->
                when (val result = loadProfileResult(dir.name)) {
                    is ProfileLoadResult.Loaded -> ProfileListItem(
                        id = result.profile.id,
                        name = result.profile.metadata.name,
                        isActive = result.profile.id == activeProfileId,
                    )

                    ProfileLoadResult.Missing -> null
                    is ProfileLoadResult.Corrupt -> {
                        logCorruptProfile(result)
                        null
                    }
                }
            }
            .sortedWith(compareBy<ProfileListItem> { !it.isActive }.thenBy { it.name.lowercase() })
    }

    private fun loadProfileInternal(id: String): SltProfile? =
        when (val result = loadProfileResult(id)) {
            is ProfileLoadResult.Loaded -> result.profile
            ProfileLoadResult.Missing -> null
            is ProfileLoadResult.Corrupt -> {
                logCorruptProfile(result)
                null
            }
        }

    private fun loadProfileResult(id: String): ProfileLoadResult {
        return try {
            val dir = profileDir(id)
            val clientToml = clientTomlFile(dir)
            val metadata = metadataFile(dir)
            if (!clientToml.isFile || !metadata.isFile) {
                return ProfileLoadResult.Missing
            }

            ProfileLoadResult.Loaded(
                SltProfile(
                    id = id,
                    clientToml = clientToml.readText(),
                    metadata = profileMetadataFromJson(JSONObject(metadata.readText())),
                ),
            )
        } catch (exception: Exception) {
            ProfileLoadResult.Corrupt(
                id = id,
                reason = exception.message ?: exception::class.java.simpleName,
                cause = exception,
            )
        }
    }

    private fun logCorruptProfile(result: ProfileLoadResult.Corrupt) {
        Log.w(TAG, "Ignoring corrupt profile ${result.id}: ${result.reason}", result.cause)
    }

    private fun profileDir(id: String): File {
        require(!id.contains('/') && !id.contains('\\')) { "invalid profile id" }
        return File(profilesDir, id)
    }

    private fun clientTomlFile(dir: File): File = File(dir, "client.toml")

    private fun metadataFile(dir: File): File = File(dir, "metadata.json")

    private sealed interface ProfileLoadResult {
        data class Loaded(val profile: SltProfile) : ProfileLoadResult

        data object Missing : ProfileLoadResult

        data class Corrupt(
            val id: String,
            val reason: String,
            val cause: Exception,
        ) : ProfileLoadResult
    }

    private companion object {
        const val TAG = "ProfileRepository"
        val ACTIVE_PROFILE_ID = stringPreferencesKey("activeProfileId")
    }
}
