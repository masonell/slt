package dev.slt.android

import android.Manifest
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.content.ContextCompat
import dev.slt.android.ui.SltApp
import dev.slt.android.profile.store.ProfileRepository
import dev.slt.android.vpn.SltVpnService
import dev.slt.android.vpn.SltVpnStatusBus

class MainActivity : ComponentActivity() {
    private lateinit var profileRepository: ProfileRepository

    private val vpnPermissionLauncher =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
            if (result.resultCode == RESULT_OK) {
                startVpnService()
            } else {
                SltVpnStatusBus.markPermissionRequired("VPN permission denied")
            }
        }

    private val notificationPermissionLauncher =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
            // Notification permission is optional for VPN startup: Android shows the
            // active tunnel through the system VPN indicator, and users can enable
            // app notifications later from system settings. The notification adds
            // drawer status and a Stop action, so denial still proceeds into VPN
            // preparation.
            handleVpnStartAction(
                vpnStartActionAfterNotificationPermissionResult(permissionGrant(granted)),
            )
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        profileRepository = ProfileRepository(applicationContext)

        setContent {
            SltApp(
                profileRepository = profileRepository,
                onStart = ::requestStart,
                onStop = ::stopVpnService,
            )
        }
    }

    private fun requestStart() {
        val hasNotificationPermission =
            checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED

        handleVpnStartAction(vpnStartActionForNotificationPermission(hasNotificationPermission))
    }

    private fun handleVpnStartAction(action: VpnStartAction) {
        when (action) {
            VpnStartAction.RequestNotificationPermission ->
                notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
            VpnStartAction.PrepareVpn -> prepareVpnAndStart()
        }
    }

    private fun prepareVpnAndStart() {
        val permissionIntent = VpnService.prepare(this)
        if (permissionIntent != null) {
            SltVpnStatusBus.markPermissionRequired(null)
            vpnPermissionLauncher.launch(permissionIntent)
            return
        }

        startVpnService()
    }

    private fun startVpnService() {
        val intent = SltVpnService.startIntent(this)
        ContextCompat.startForegroundService(this, intent)
    }

    private fun stopVpnService() {
        startService(SltVpnService.stopIntent(this))
    }
}
