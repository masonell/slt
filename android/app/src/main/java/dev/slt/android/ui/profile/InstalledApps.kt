package dev.slt.android.ui.profile

import android.content.Context
import android.content.pm.PackageManager

internal data class InstalledApp(
    val label: String,
    val packageName: String,
)

internal fun loadInstalledApps(context: Context): List<InstalledApp> {
    val packageManager = context.packageManager
    return packageManager.getInstalledApplications(PackageManager.ApplicationInfoFlags.of(0L))
        .map { applicationInfo ->
            val label = applicationInfo.loadLabel(packageManager).toString()
            InstalledApp(
                label = label.ifBlank { applicationInfo.packageName },
                packageName = applicationInfo.packageName,
            )
        }
        .distinctBy { it.packageName }
        .sortedWith(compareBy<InstalledApp> { it.label.lowercase() }.thenBy { it.packageName })
}
