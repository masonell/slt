package dev.slt.android.ui.main

import dev.slt.android.connection.ConnectionTestOutcome
import dev.slt.android.connection.ConnectionTestResult
import dev.slt.android.connection.ExpectedNetworkPath
import dev.slt.android.profile.ProfileMetadata
import dev.slt.android.profile.SltProfile
import dev.slt.android.ui.UiMessageSeverity
import dev.slt.android.vpn.VpnStatus
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class MainScreenActionsTest {
    @Test
    fun prepareConnectionTestStartBlocksMissingProfile() {
        val result = prepareConnectionTestStart(
            state = ConnectionTestUiState(results = existingResults()),
            vpnStatus = VpnStatus.Running,
            activeProfile = null,
        )

        assertTrue(result is ConnectionTestStartResult.Blocked)
        assertEquals("No active profile", result.message.text)
        assertEquals(UiMessageSeverity.Error, result.message.severity)
        assertEquals(null, result.state.results)
    }

    @Test
    fun prepareConnectionTestStartBlocksWhenVpnIsNotRunning() {
        val result = prepareConnectionTestStart(
            state = ConnectionTestUiState(results = existingResults()),
            vpnStatus = VpnStatus.Stopped,
            activeProfile = profile(testUrls = listOf("https://example.com/check")),
        )

        assertTrue(result is ConnectionTestStartResult.Blocked)
        assertEquals("Connect the VPN before running tests", result.message.text)
        assertEquals(UiMessageSeverity.Warning, result.message.severity)
        assertEquals(null, result.state.results)
    }

    @Test
    fun prepareConnectionTestStartBlocksMissingUrls() {
        val result = prepareConnectionTestStart(
            state = ConnectionTestUiState(results = existingResults()),
            vpnStatus = VpnStatus.Running,
            activeProfile = profile(testUrls = emptyList()),
        )

        assertTrue(result is ConnectionTestStartResult.Blocked)
        assertEquals("Active profile has no test URLs", result.message.text)
        assertEquals(UiMessageSeverity.Warning, result.message.severity)
        assertEquals(null, result.state.results)
    }

    @Test
    fun prepareConnectionTestStartReturnsReadyState() {
        val profile = profile(testUrls = listOf("https://example.com/check"))
        val result = prepareConnectionTestStart(
            state = ConnectionTestUiState(results = existingResults()),
            vpnStatus = VpnStatus.Running,
            activeProfile = profile,
        )

        assertTrue(result is ConnectionTestStartResult.Ready)
        val ready = result as ConnectionTestStartResult.Ready
        assertEquals(profile, ready.profile)
        assertEquals("Running connection tests", ready.message.text)
        assertEquals(UiMessageSeverity.Info, ready.message.severity)
        assertTrue(ready.state.inProgress)
        assertEquals(null, ready.state.results)
    }

    @Test
    fun completeConnectionTestSuccessStoresResults() {
        val results = existingResults()
        val result = completeConnectionTestSuccess(results)

        assertFalse(result.state.inProgress)
        assertEquals(results, result.state.results)
        assertEquals("Connection tests finished", result.message.text)
        assertEquals(UiMessageSeverity.Info, result.message.severity)
    }

    @Test
    fun completeConnectionTestFailureClearsState() {
        val result = completeConnectionTestFailure(IllegalStateException("failed"))

        assertFalse(result.state.inProgress)
        assertEquals(null, result.state.results)
        assertEquals("failed", result.message.text)
        assertEquals(UiMessageSeverity.Error, result.message.severity)
    }

    private fun profile(testUrls: List<String>): SltProfile =
        SltProfile(
            id = "profile-id",
            clientToml = "",
            metadata = ProfileMetadata(
                name = "Work",
                testUrls = testUrls,
            ),
        )

    private fun existingResults(): List<ConnectionTestResult> =
        listOf(
            ConnectionTestResult(
                url = "https://example.com/check",
                resolvedAddresses = listOf("203.0.113.1"),
                expectedPath = ExpectedNetworkPath.Direct,
                outcome = ConnectionTestOutcome.Success(204),
            ),
        )
}
