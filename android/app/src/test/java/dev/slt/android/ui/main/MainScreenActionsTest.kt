package dev.slt.android.ui.main

import dev.slt.android.connection.ConnectionTestEntry
import dev.slt.android.connection.ConnectionTestOutcome
import dev.slt.android.connection.ConnectionTestPhase
import dev.slt.android.connection.ExpectedNetworkPath
import dev.slt.android.profile.ProfileMetadata
import dev.slt.android.profile.SltProfile
import dev.slt.android.ui.UiMessageSeverity
import dev.slt.android.vpn.VpnStatus
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class MainScreenActionsTest {
    @Test
    fun prepareConnectionTestStartBlocksMissingProfile() {
        val result = prepareConnectionTestStart(
            state = ConnectionTestUiState(entries = existingEntries()),
            vpnStatus = VpnStatus.Running,
            activeProfile = null,
        )

        assertTrue(result is ConnectionTestStartResult.Blocked)
        val blocked = result as ConnectionTestStartResult.Blocked
        assertEquals("No active profile", blocked.message.text)
        assertEquals(UiMessageSeverity.Error, blocked.message.severity)
        assertTrue(blocked.state.entries.isEmpty())
    }

    @Test
    fun prepareConnectionTestStartBlocksWhenVpnIsNotRunning() {
        val result = prepareConnectionTestStart(
            state = ConnectionTestUiState(entries = existingEntries()),
            vpnStatus = VpnStatus.Stopped,
            activeProfile = profile(testUrls = listOf("https://example.com/check")),
        )

        assertTrue(result is ConnectionTestStartResult.Blocked)
        val blocked = result as ConnectionTestStartResult.Blocked
        assertEquals("Connect the VPN before running tests", blocked.message.text)
        assertEquals(UiMessageSeverity.Warning, blocked.message.severity)
        assertTrue(blocked.state.entries.isEmpty())
    }

    @Test
    fun prepareConnectionTestStartBlocksMissingUrls() {
        val result = prepareConnectionTestStart(
            state = ConnectionTestUiState(entries = existingEntries()),
            vpnStatus = VpnStatus.Running,
            activeProfile = profile(testUrls = emptyList()),
        )

        assertTrue(result is ConnectionTestStartResult.Blocked)
        val blocked = result as ConnectionTestStartResult.Blocked
        assertEquals("Active profile has no test URLs", blocked.message.text)
        assertEquals(UiMessageSeverity.Warning, blocked.message.severity)
        assertTrue(blocked.state.entries.isEmpty())
    }

    @Test
    fun prepareConnectionTestStartReturnsReadyState() {
        val profile = profile(
            testUrls = listOf("https://example.com/check", "https://example.org/check"),
        )
        val result = prepareConnectionTestStart(
            state = ConnectionTestUiState(entries = existingEntries()),
            vpnStatus = VpnStatus.Running,
            activeProfile = profile,
        )

        assertTrue(result is ConnectionTestStartResult.Ready)
        val ready = result as ConnectionTestStartResult.Ready
        assertEquals(profile, ready.profile)
        assertTrue(ready.state.inProgress)
        assertEquals(profile.metadata.testUrls, ready.state.entries.map { it.url })
        assertTrue(ready.state.entries.all { it.phase == ConnectionTestPhase.Resolving })
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

    private fun existingEntries(): List<ConnectionTestEntry> =
        listOf(
            ConnectionTestEntry(
                url = "https://example.com/check",
                phase = ConnectionTestPhase.Done,
                resolvedAddresses = listOf("203.0.113.1"),
                expectedPath = ExpectedNetworkPath.Direct,
                outcome = ConnectionTestOutcome.Success(204),
            ),
        )
}
