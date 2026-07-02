package dev.slt.android.vpn

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class NativeSessionSupervisorPolicyTest {
    @Test
    fun retryable_terminal_error_restarts_before_authentication() {
        assertTrue(
            shouldRestartTerminalNativeError(
                retryable = true,
                authenticatedSinceStart = false,
            ),
        )
    }

    @Test
    fun non_retryable_terminal_error_restarts_after_authentication() {
        assertTrue(
            shouldRestartTerminalNativeError(
                retryable = false,
                authenticatedSinceStart = true,
            ),
        )
    }

    @Test
    fun non_retryable_terminal_error_stays_fatal_before_authentication() {
        assertFalse(
            shouldRestartTerminalNativeError(
                retryable = false,
                authenticatedSinceStart = false,
            ),
        )
    }
}
