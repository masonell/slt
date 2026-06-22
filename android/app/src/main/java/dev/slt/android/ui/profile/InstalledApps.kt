package dev.slt.android.ui.profile

import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager

internal data class InstalledApp(
    val label: String,
    val packageName: String,
)

internal fun loadInstalledLaunchableApps(context: Context): List<InstalledApp> {
    val packageManager = context.packageManager
    val launcherIntent = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
    return packageManager.queryIntentActivities(launcherIntent, PackageManager.ResolveInfoFlags.of(0L))
        .map { resolveInfo ->
            InstalledApp(
                label = resolveInfo.loadLabel(packageManager).toString(),
                packageName = resolveInfo.activityInfo.packageName,
            )
        }
        .distinctBy { it.packageName }
        .sortedWith(compareBy<InstalledApp> { it.label.lowercase() }.thenBy { it.packageName })
}
