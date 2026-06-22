package dev.slt.android

import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager

data class InstalledApp(
    val label: String,
    val packageName: String,
)

fun loadInstalledLaunchableApps(context: Context): List<InstalledApp> {
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

fun normalizeAppVpnRules(
    mode: AppVpnMode,
    packageNames: List<String>,
    ownPackageName: String,
): AppVpnRules {
    if (mode == AppVpnMode.All) {
        return AppVpnRules()
    }

    val normalizedPackages = packageNames
        .mapIndexed { index, packageName -> normalizePackageName(packageName, index + 1) }
        .distinct()
        .filterNot { it == ownPackageName }

    return when (mode) {
        AppVpnMode.All -> AppVpnRules()
        AppVpnMode.Allowlist -> AppVpnRules(
            mode = AppVpnMode.Allowlist,
            packageNames = normalizedPackages,
        )
        AppVpnMode.Blocklist -> AppVpnRules(
            mode = AppVpnMode.Blocklist,
            packageNames = normalizedPackages,
        )
    }
}

fun missingAppPackages(rules: AppVpnRules, installedPackages: Set<String>): List<String> =
    rules.packageNames
        .filterNot { it in installedPackages }
        .sorted()

private fun normalizePackageName(packageName: String, ordinal: Int): String {
    val trimmed = packageName.trim()
    require(trimmed.isNotEmpty()) { "App package $ordinal is empty" }
    require(trimmed.length <= 255) { "App package $trimmed is too long" }

    val segments = trimmed.split('.')
    require(segments.size >= 2) { "App package $trimmed must contain at least one dot" }
    segments.forEach { segment ->
        require(segment.isNotEmpty()) { "App package $trimmed contains an empty segment" }
        require(segment.first().isLetter()) { "App package $trimmed segment must start with a letter" }
        require(segment.all { it.isLetterOrDigit() || it == '_' }) {
            "App package $trimmed contains invalid characters"
        }
    }
    return trimmed
}
