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
        registerForActivityResult(ActivityResultContracts.RequestPermission()) {
            prepareVpnAndStart()
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
        if (
            checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
            return
        }

        prepareVpnAndStart()
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
