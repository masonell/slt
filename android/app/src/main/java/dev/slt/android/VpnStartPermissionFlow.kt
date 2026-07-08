package dev.slt.android

internal enum class PermissionGrant {
    Granted,
    Denied,
}

internal enum class VpnStartAction {
    RequestNotificationPermission,
    PrepareVpn,
}

internal fun permissionGrant(granted: Boolean): PermissionGrant =
    if (granted) PermissionGrant.Granted else PermissionGrant.Denied

internal fun vpnStartActionForNotificationPermission(hasPermission: Boolean): VpnStartAction =
    if (hasPermission) VpnStartAction.PrepareVpn else VpnStartAction.RequestNotificationPermission

internal fun vpnStartActionAfterNotificationPermissionResult(grant: PermissionGrant): VpnStartAction =
    when (grant) {
        PermissionGrant.Granted,
        PermissionGrant.Denied -> VpnStartAction.PrepareVpn
    }
