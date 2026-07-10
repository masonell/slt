package dev.slt.android.vpn

import org.junit.Assert.assertEquals
import org.junit.Test

class NativeSessionSupervisorPolicyTest {
    @Test
    fun retryable_terminal_error_restarts_with_tunnel_retained_before_authentication() {
        assertEquals(
            NativeTerminalAction.RestartKeepingTunnel,
            nativeTerminalAction(
                retryable = true,
                failClosedArmed = false,
            ),
        )
    }

    @Test
    fun post_auth_non_retryable_error_restarts_with_fail_closed_tunnel_retained() {
        assertEquals(
            NativeTerminalAction.RestartKeepingTunnel,
            nativeTerminalAction(
                retryable = false,
                failClosedArmed = true,
            ),
        )
    }

    @Test
    fun post_auth_retryable_error_restarts_with_fail_closed_tunnel_retained() {
        assertEquals(
            NativeTerminalAction.RestartKeepingTunnel,
            nativeTerminalAction(
                retryable = true,
                failClosedArmed = true,
            ),
        )
    }

    @Test
    fun pre_auth_non_retryable_terminal_error_tears_down_tunnel() {
        assertEquals(
            NativeTerminalAction.TearDownTunnel,
            nativeTerminalAction(
                retryable = false,
                failClosedArmed = false,
            ),
        )
    }
}
