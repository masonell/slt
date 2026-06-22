package dev.slt.android.profile.rules

import dev.slt.android.profile.AppVpnMode
import dev.slt.android.profile.AppVpnRules

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
