package dev.slt.android.profile.store

import dev.slt.android.profile.AppVpnMode
import dev.slt.android.profile.AppVpnRules
import dev.slt.android.profile.DnsMode
import dev.slt.android.profile.DnsSettings
import dev.slt.android.profile.ProfileMetadata
import dev.slt.android.profile.VpnRouteRule
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Test

class ProfileJsonTest {
    @Test
    fun metadataRoundTripsAllSerializedFields() {
        val metadata = ProfileMetadata(
            name = "Work",
            routes = listOf(
                VpnRouteRule(cidr = "0.0.0.0/0", excluded = false),
                VpnRouteRule(cidr = "10.0.0.0/8", excluded = true),
            ),
            dns = DnsSettings(
                mode = DnsMode.Custom,
                servers = listOf("1.1.1.1", "8.8.8.8"),
            ),
            testUrls = listOf("https://example.com/check"),
            appRules = AppVpnRules(
                mode = AppVpnMode.Allowlist,
                packageNames = listOf("com.example.app"),
            ),
        )

        assertEquals(metadata, profileMetadataFromJson(metadata.toProfileJson()))
    }

    @Test
    fun missingOptionalMetadataFieldsUseDefaults() {
        val metadata = profileMetadataFromJson(JSONObject().put("name", "Bare"))

        assertEquals(ProfileMetadata(name = "Bare"), metadata)
    }
}
