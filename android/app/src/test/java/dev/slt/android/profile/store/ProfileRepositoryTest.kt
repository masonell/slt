package dev.slt.android.profile.store

import dev.slt.android.profile.AppVpnMode
import dev.slt.android.profile.AppVpnRules
import dev.slt.android.profile.DnsMode
import dev.slt.android.profile.DnsSettings
import dev.slt.android.profile.ProfileListItem
import dev.slt.android.profile.ProfileMetadata
import dev.slt.android.profile.VpnRouteRule
import java.io.File
import java.nio.file.Files
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Test

class ProfileRepositoryTest {
    @Test
    fun saveProfilePersistsSerializedMetadataAndActiveProfile() = runBlocking {
        withTempProfiles { profilesDir ->
            val activeProfileStore = MemoryActiveProfileStore()
            val repository = ProfileRepository(profilesDir, activeProfileStore)
            val metadata = ProfileMetadata(
                name = "ignored",
                routes = listOf(VpnRouteRule(cidr = "0.0.0.0/0", excluded = false)),
                dns = DnsSettings(DnsMode.Custom, listOf("1.1.1.1")),
                testUrls = listOf("https://example.com/check"),
                appRules = AppVpnRules(
                    mode = AppVpnMode.Blocklist,
                    packageNames = listOf("com.example.app"),
                ),
            )

            val saved = repository.saveProfile(
                id = "work",
                name = "Work",
                clientToml = "client = true",
                metadata = metadata,
            )

            assertEquals("work", activeProfileStore.activeProfileId())
            assertEquals("Work", saved.metadata.name)
            assertEquals(saved, repository.loadProfile("work"))
            assertEquals(
                listOf(ProfileListItem(id = "work", name = "Work", isActive = true)),
                repository.loadState().profiles,
            )
            assertEquals(saved, repository.loadState().activeProfile)
        }
    }

    @Test
    fun concurrentSavesToSameProfileLeaveConsistentFiles() = runBlocking {
        withTempProfiles { profilesDir ->
            val repository = ProfileRepository(profilesDir, MemoryActiveProfileStore())

            (0 until 40)
                .map { index ->
                    async(Dispatchers.Default) {
                        repository.saveProfile(
                            id = "shared",
                            name = "Profile $index",
                            clientToml = "client-index=$index",
                            metadata = ProfileMetadata(
                                name = "ignored",
                                testUrls = listOf("https://example.com/$index"),
                            ),
                        )
                    }
                }
                .awaitAll()

            val loaded = checkNotNull(repository.loadProfile("shared"))
            val savedIndex = loaded.metadata.name.removePrefix("Profile ").toInt()
            assertEquals("client-index=$savedIndex", loaded.clientToml)
            assertEquals(listOf("https://example.com/$savedIndex"), loaded.metadata.testUrls)
        }
    }

    private suspend fun withTempProfiles(block: suspend (File) -> Unit) {
        val root = Files.createTempDirectory("slt-profile-repository-test").toFile()
        try {
            block(File(root, "profiles"))
        } finally {
            root.deleteRecursively()
        }
    }

    private class MemoryActiveProfileStore : ActiveProfileStore {
        private val lock = Any()
        private var activeProfileId: String? = null

        override suspend fun activeProfileId(): String? =
            synchronized(lock) { activeProfileId }

        override suspend fun setActiveProfileId(id: String?) {
            synchronized(lock) {
                activeProfileId = id
            }
        }
    }
}
