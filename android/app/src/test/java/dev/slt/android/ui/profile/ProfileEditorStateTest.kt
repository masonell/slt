package dev.slt.android.ui.profile

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ProfileEditorStateTest {
    @Test
    fun loadsEditableFieldsFromProfile() {
        val metadata = ProfileMetadata(
            name = "Work",
            routes = listOf(
                VpnRouteRule(cidr = "10.0.0.0/8", excluded = false),
                VpnRouteRule(cidr = "192.168.0.0/16", excluded = true),
            ),
            dns = DnsSettings(
                mode = DnsMode.Custom,
                servers = listOf("1.1.1.1", "2606:4700:4700::1111"),
            ),
            testUrls = listOf("https://example.com/health"),
            appRules = AppVpnRules(
                mode = AppVpnMode.Allowlist,
                packageNames = listOf("com.example.app"),
            ),
        )
        val profile = SltProfile(
            id = "profile-id",
            clientToml = "server_host = \"example.com\"",
            metadata = metadata,
        )

        val state = profileEditorStateFrom(profile)

        assertEquals(metadata, state.sourceMetadata)
        assertEquals("Work", state.name)
        assertEquals("server_host = \"example.com\"", state.toml)
        assertEquals("10.0.0.0/8\n!192.168.0.0/16", state.routeText)
        assertEquals(DnsMode.Custom, state.dnsMode)
        assertEquals("1.1.1.1\n2606:4700:4700::1111", state.dnsText)
        assertEquals(AppVpnMode.Allowlist, state.appMode)
        assertEquals(listOf("com.example.app"), state.selectedPackageNames)
        assertEquals("https://example.com/health", state.testUrlsText)
        assertNull(state.validation)
        assertNull(state.message)
        assertNull(state.activeNestedScreen)
        assertFalse(state.isEditingNestedScreen)
    }

    @Test
    fun createsBlankStateForNewProfile() {
        val state = profileEditorStateFrom(null)

        assertNull(state.sourceMetadata)
        assertEquals("", state.name)
        assertEquals("", state.toml)
        assertEquals("", state.routeText)
        assertEquals(DnsMode.System, state.dnsMode)
        assertEquals("", state.dnsText)
        assertEquals(AppVpnMode.All, state.appMode)
        assertEquals(emptyList<String>(), state.selectedPackageNames)
        assertEquals("", state.testUrlsText)
        assertNull(state.validation)
        assertNull(state.message)
        assertNull(state.activeNestedScreen)
    }

    @Test
    fun closesNestedEditorScreen() {
        val state = ProfileEditorState(activeNestedScreen = ProfileEditorNestedScreen.Dns)

        val closed = state.withClosedNestedScreen()

        assertTrue(state.isEditingNestedScreen)
        assertNull(closed.activeNestedScreen)
        assertFalse(closed.isEditingNestedScreen)
    }
}
