package dev.slt.android

import org.junit.Assert.assertEquals
import org.junit.Test

class VpnStartPermissionFlowTest {
    @Test
    fun missingNotificationPermissionRequestsPermission() {
        assertEquals(
            VpnStartAction.RequestNotificationPermission,
            vpnStartActionForNotificationPermission(hasPermission = false),
        )
    }

    @Test
    fun grantedNotificationPermissionPreparesVpn() {
        assertEquals(
            VpnStartAction.PrepareVpn,
            vpnStartActionForNotificationPermission(hasPermission = true),
        )
    }

    @Test
    fun deniedNotificationPermissionStillPreparesVpn() {
        assertEquals(
            VpnStartAction.PrepareVpn,
            vpnStartActionAfterNotificationPermissionResult(PermissionGrant.Denied),
        )
    }
}
