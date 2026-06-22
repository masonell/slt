package dev.slt.android

import android.content.Context
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.util.UUID

private val Context.profileDataStore by preferencesDataStore(name = "profiles")

data class ProfileStoreState(
    val profiles: List<ProfileListItem>,
    val activeProfile: SltProfile?,
)

data class ProfileListItem(
    val id: String,
    val name: String,
    val isActive: Boolean,
)

data class SltProfile(
    val id: String,
    val clientToml: String,
    val metadata: ProfileMetadata,
)

data class ProfileMetadata(
    val name: String,
    val routes: List<VpnRouteRule> = emptyList(),
    val dns: DnsSettings = DnsSettings(),
    val testUrls: List<String> = emptyList(),
    val appRules: AppVpnRules = AppVpnRules(),
) {
    companion object
}

data class VpnRouteRule(
    val cidr: String,
    val excluded: Boolean,
)

data class DnsSettings(
    val mode: DnsMode = DnsMode.System,
    val servers: List<String> = emptyList(),
)

enum class DnsMode(val wireName: String) {
    System("system"),
    Custom("custom"),
}

data class AppVpnRules(
    val mode: AppVpnMode = AppVpnMode.All,
    val packageNames: List<String> = emptyList(),
)

enum class AppVpnMode(val wireName: String) {
    All("all"),
    Allowlist("allowlist"),
    Blocklist("blocklist"),
}

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
            metadataFile(dir).writeText(profileMetadata.toJson().toString(2))

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
                val profile = loadProfileInternal(dir.name) ?: return@mapNotNull null
                ProfileListItem(
                    id = profile.id,
                    name = profile.metadata.name,
                    isActive = profile.id == activeProfileId,
                )
            }
            .sortedWith(compareBy<ProfileListItem> { !it.isActive }.thenBy { it.name.lowercase() })
    }

    private fun loadProfileInternal(id: String): SltProfile? {
        return try {
            val dir = profileDir(id)
            val clientToml = clientTomlFile(dir)
            val metadata = metadataFile(dir)
            if (!clientToml.isFile || !metadata.isFile) {
                return null
            }

            SltProfile(
                id = id,
                clientToml = clientToml.readText(),
                metadata = ProfileMetadata.fromJson(JSONObject(metadata.readText())),
            )
        } catch (_: Exception) {
            null
        }
    }

    private fun profileDir(id: String): File {
        require(!id.contains('/') && !id.contains('\\')) { "invalid profile id" }
        return File(profilesDir, id)
    }

    private fun clientTomlFile(dir: File): File = File(dir, "client.toml")

    private fun metadataFile(dir: File): File = File(dir, "metadata.json")

    private companion object {
        val ACTIVE_PROFILE_ID = stringPreferencesKey("activeProfileId")
    }
}

private fun ProfileMetadata.toJson(): JSONObject =
    JSONObject()
        .put("version", 1)
        .put("name", name)
        .put(
            "routes",
            JSONArray().also { routesJson ->
                routes.forEach { route ->
                    routesJson.put(
                        JSONObject()
                            .put("cidr", route.cidr)
                            .put("excluded", route.excluded),
                    )
                }
            },
        )
        .put(
            "dns",
            JSONObject()
                .put("mode", dns.mode.wireName)
                .put("servers", JSONArray(dns.servers)),
        )
        .put("testUrls", JSONArray(testUrls))
        .put(
            "appRules",
            JSONObject()
                .put("mode", appRules.mode.wireName)
                .put("packageNames", JSONArray(appRules.packageNames)),
        )

private fun ProfileMetadata.Companion.fromJson(json: JSONObject): ProfileMetadata =
    ProfileMetadata(
        name = json.getString("name"),
        routes = json.optJSONArray("routes").toVpnRouteRules(),
        dns = json.optJSONObject("dns").toDnsSettings(),
        testUrls = json.optJSONArray("testUrls").toStringList(),
        appRules = json.optJSONObject("appRules").toAppVpnRules(),
    )

private fun JSONArray?.toVpnRouteRules(): List<VpnRouteRule> {
    if (this == null) {
        return emptyList()
    }
    return buildList {
        for (index in 0 until length()) {
            val route = getJSONObject(index)
            add(
                VpnRouteRule(
                    cidr = route.getString("cidr"),
                    excluded = route.optBoolean("excluded", false),
                ),
            )
        }
    }
}

private fun JSONObject?.toDnsSettings(): DnsSettings {
    if (this == null) {
        return DnsSettings()
    }
    return DnsSettings(
        mode = dnsModeFromWireName(optString("mode", DnsMode.System.wireName)),
        servers = optJSONArray("servers").toStringList(),
    )
}

private fun JSONObject?.toAppVpnRules(): AppVpnRules {
    if (this == null) {
        return AppVpnRules()
    }
    return AppVpnRules(
        mode = appVpnModeFromWireName(optString("mode", AppVpnMode.All.wireName)),
        packageNames = optJSONArray("packageNames").toStringList(),
    )
}

private fun JSONArray?.toStringList(): List<String> {
    if (this == null) {
        return emptyList()
    }
    return buildList {
        for (index in 0 until length()) {
            add(getString(index))
        }
    }
}

private fun dnsModeFromWireName(wireName: String): DnsMode =
    DnsMode.entries.firstOrNull { it.wireName == wireName } ?: DnsMode.System

private fun appVpnModeFromWireName(wireName: String): AppVpnMode =
    AppVpnMode.entries.firstOrNull { it.wireName == wireName } ?: AppVpnMode.All
