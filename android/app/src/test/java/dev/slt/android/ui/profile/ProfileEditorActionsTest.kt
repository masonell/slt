package dev.slt.android.ui.profile

import dev.slt.android.ClientConfigSummary
import dev.slt.android.ConfigValidationResult
import dev.slt.android.ui.UiMessageSeverity
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ProfileEditorActionsTest {
    @Test
    fun validatesTomlAndUpdatesStateMessage() {
        val validation = validValidation()
        val result = validateProfileEditorToml(
            state = ProfileEditorState(toml = "client toml"),
            validateClientConfig = { toml ->
                assertEquals("client toml", toml)
                validation
            },
        )

        assertEquals(validation, result.validation)
        assertEquals(validation, result.state.validation)
        assertEquals("Config is valid", result.state.message?.text)
        assertEquals(UiMessageSeverity.Info, result.state.message?.severity)
    }

    @Test
    fun prepareSaveBuildsMetadataAndNormalizesEditorFields() {
        val result = prepareProfileEditorSave(
            state = ProfileEditorState(
                name = " Work ",
                toml = "client toml",
                routeText = """
                10.0.1.1/8
                0.0.0.0/0
                """.trimIndent(),
                dnsMode = DnsMode.Custom,
                dnsText = "1.1.1.1, 1.1.1.1",
                appMode = AppVpnMode.Allowlist,
                selectedPackageNames = listOf(
                    " com.example.app ",
                    "com.example.app",
                    "dev.slt.android",
                ),
                testUrlsText = """
                HTTPS://Example.COM:443/check
                https://example.com/check
                """.trimIndent(),
            ),
            ownPackageName = "dev.slt.android",
            validateClientConfig = { validValidation() },
        )

        assertTrue(result is ProfileEditorSaveResult.Ready)
        val ready = result as ProfileEditorSaveResult.Ready
        assertEquals("Work", ready.name)
        assertEquals("client toml", ready.clientToml)
        assertEquals(
            listOf(VpnRouteRule(cidr = "0.0.0.0/0", excluded = false)),
            ready.metadata.routes,
        )
        assertEquals(
            DnsSettings(
                mode = DnsMode.Custom,
                servers = listOf("1.1.1.1"),
            ),
            ready.metadata.dns,
        )
        assertEquals(
            AppVpnRules(
                mode = AppVpnMode.Allowlist,
                packageNames = listOf("com.example.app"),
            ),
            ready.metadata.appRules,
        )
        assertEquals(listOf("https://example.com/check"), ready.metadata.testUrls)
        assertEquals("0.0.0.0/0", ready.state.routeText)
        assertEquals("1 route ready", ready.state.routeMessage?.text)
        assertEquals(UiMessageSeverity.Info, ready.state.routeMessage?.severity)
        assertEquals("1.1.1.1", ready.state.dnsText)
        assertEquals("1 DNS server ready", ready.state.dnsMessage?.text)
        assertEquals(UiMessageSeverity.Info, ready.state.dnsMessage?.severity)
        assertEquals(listOf("com.example.app"), ready.state.selectedPackageNames)
        assertEquals("1 allowed app ready", ready.state.appMessage?.text)
        assertEquals(UiMessageSeverity.Info, ready.state.appMessage?.severity)
        assertEquals("https://example.com/check", ready.state.testUrlsText)
        assertEquals("1 test URL ready", ready.state.testUrlsMessage?.text)
        assertEquals(UiMessageSeverity.Info, ready.state.testUrlsMessage?.severity)
    }

    @Test
    fun prepareSaveBlocksEmptyProfileNameBeforeValidation() {
        var validated = false

        val result = prepareProfileEditorSave(
            state = ProfileEditorState(name = " "),
            ownPackageName = "dev.slt.android",
            validateClientConfig = {
                validated = true
                validValidation()
            },
        )

        assertTrue(result is ProfileEditorSaveResult.Blocked)
        assertEquals("Profile name is required", result.state.message?.text)
        assertEquals(UiMessageSeverity.Error, result.state.message?.severity)
        assertEquals(false, validated)
    }

    @Test
    fun prepareSaveBlocksInvalidTomlBeforeParsingMetadata() {
        val result = prepareProfileEditorSave(
            state = ProfileEditorState(
                name = "Work",
                toml = "bad toml",
                routeText = "not a route",
            ),
            ownPackageName = "dev.slt.android",
            validateClientConfig = {
                ConfigValidationResult(
                    summary = null,
                    error = "Invalid config",
                )
            },
        )

        assertTrue(result is ProfileEditorSaveResult.Blocked)
        assertEquals("Invalid config", result.state.message?.text)
        assertEquals(UiMessageSeverity.Error, result.state.message?.severity)
        assertEquals("not a route", result.state.routeText)
        assertNull(result.state.routeMessage)
    }

    @Test
    fun routeParsingFailureReturnsUpdatedState() {
        val result = parseProfileEditorRoutesForSave(
            ProfileEditorState(routeText = ""),
        )

        assertTrue(result is ProfileEditorActionResult.Failure)
        assertEquals("At least one VPN route is required", result.state.routeMessage?.text)
        assertEquals(UiMessageSeverity.Error, result.state.routeMessage?.severity)
        assertEquals("At least one VPN route is required", result.state.message?.text)
        assertEquals(UiMessageSeverity.Error, result.state.message?.severity)
    }

    @Test
    fun dnsExcludedRouteProducesWarningMessage() {
        val result = parseProfileEditorDnsForSave(
            state = ProfileEditorState(
                dnsMode = DnsMode.Custom,
                dnsText = "8.8.8.8",
            ),
            routes = listOf(VpnRouteRule(cidr = "8.8.8.0/24", excluded = true)),
        )

        assertTrue(result is ProfileEditorActionResult.Success)
        assertEquals(
            "DNS server 8.8.8.8 is excluded by 8.8.8.0/24; a DNS route will still be added",
            result.state.dnsMessage?.text,
        )
        assertEquals(UiMessageSeverity.Warning, result.state.dnsMessage?.severity)
    }

    private fun validValidation(): ConfigValidationResult =
        ConfigValidationResult(
            summary = ClientConfigSummary(
                assignedIpv4 = "10.0.0.2",
                tunMtu = 1400,
                serverHost = "vpn.example.com",
                serverPort = 443,
                clientId = "client-id",
            ),
            error = null,
        )
}
