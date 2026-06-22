package dev.slt.android.ui.profile

import dev.slt.android.ui.UiMessage
import dev.slt.android.ui.profile.rules.exportTestUrls
import dev.slt.android.ui.profile.rules.exportVpnRouteRules
import dev.slt.android.ui.profile.rules.parseTestUrls
import dev.slt.android.ui.profile.rules.parseVpnRouteRules

internal data class EditorTextOperationResult(
    val text: String,
    val message: UiMessage?,
    val changed: Boolean,
)

internal fun displayedVpnRoutes(routeText: String): List<VpnRouteRule>? =
    try {
        parseVpnRouteRules(routeText)
    } catch (_: IllegalArgumentException) {
        null
    }

internal fun addVpnRouteFromForm(
    routeText: String,
    cidrText: String,
    excluded: Boolean,
): EditorTextOperationResult {
    val cidr = cidrText.trim()
    if (cidr.isEmpty()) {
        return EditorTextOperationResult(
            text = routeText,
            message = UiMessage.error("Route CIDR is required"),
            changed = false,
        )
    }

    val prefix = if (excluded) "!" else ""
    val existingRoutes = try {
        parseVpnRouteRules(routeText)
    } catch (error: IllegalArgumentException) {
        return EditorTextOperationResult(
            text = routeText,
            message = UiMessage.error(error.message ?: "Invalid routes"),
            changed = false,
        )
    }
    val newRoutes = try {
        parseVpnRouteRules("$prefix$cidr")
    } catch (error: IllegalArgumentException) {
        return EditorTextOperationResult(
            text = routeText,
            message = UiMessage.error(error.message ?: "Invalid route"),
            changed = false,
        )
    }

    val candidateText = listOf(exportVpnRouteRules(existingRoutes), "$prefix$cidr")
        .filter { it.isNotBlank() }
        .joinToString("\n")
    val routes = try {
        parseVpnRouteRules(candidateText)
    } catch (error: IllegalArgumentException) {
        return EditorTextOperationResult(
            text = routeText,
            message = UiMessage.error(error.message ?: "Invalid route"),
            changed = false,
        )
    }

    if (routes == existingRoutes) {
        val message = if (newRoutes.any { route -> existingRoutes.contains(route) }) {
            UiMessage.info("Route already exists")
        } else {
            UiMessage.info(
                "Route is already covered by an existing ${if (excluded) "exclude" else "include"} route",
            )
        }
        return EditorTextOperationResult(
            text = routeText,
            message = message,
            changed = false,
        )
    }

    return EditorTextOperationResult(
        text = exportVpnRouteRules(routes),
        message = UiMessage.info("Route added"),
        changed = true,
    )
}

internal fun removeVpnRouteAt(routeText: String, index: Int): EditorTextOperationResult {
    val routes = try {
        parseVpnRouteRules(routeText)
    } catch (error: IllegalArgumentException) {
        return EditorTextOperationResult(
            text = routeText,
            message = UiMessage.error(error.message ?: "Invalid routes"),
            changed = false,
        )
    }

    return EditorTextOperationResult(
        text = exportVpnRouteRules(routes.filterIndexed { routeIndex, _ -> routeIndex != index }),
        message = null,
        changed = true,
    )
}

internal fun displayedTestUrls(testUrlsText: String): List<String> =
    try {
        parseTestUrls(testUrlsText)
    } catch (_: IllegalArgumentException) {
        emptyList()
    }

internal fun addTestUrlFromForm(
    currentUrls: List<String>,
    urlText: String,
): EditorTextOperationResult {
    val candidate = urlText.trim()
    if (candidate.isEmpty()) {
        return EditorTextOperationResult(
            text = exportTestUrls(currentUrls),
            message = UiMessage.error("Test URL is required"),
            changed = false,
        )
    }

    return try {
        val nextUrls = parseTestUrls((currentUrls + candidate).joinToString("\n"))
        if (nextUrls == currentUrls) {
            EditorTextOperationResult(
                text = exportTestUrls(currentUrls),
                message = UiMessage.info("Test URL already exists"),
                changed = false,
            )
        } else {
            EditorTextOperationResult(
                text = exportTestUrls(nextUrls),
                message = UiMessage.info("Test URL added"),
                changed = true,
            )
        }
    } catch (error: IllegalArgumentException) {
        EditorTextOperationResult(
            text = exportTestUrls(currentUrls),
            message = UiMessage.error(error.message ?: "Invalid test URL"),
            changed = false,
        )
    }
}

internal fun removeTestUrlAt(currentUrls: List<String>, index: Int): EditorTextOperationResult =
    EditorTextOperationResult(
        text = exportTestUrls(currentUrls.filterIndexed { urlIndex, _ -> urlIndex != index }),
        message = null,
        changed = true,
    )

internal fun effectiveSelectedPackages(
    appMode: AppVpnMode,
    selectedPackageNames: List<String>,
    ownPackageName: String,
): List<String> =
    when (appMode) {
        AppVpnMode.All -> emptyList()
        AppVpnMode.Allowlist,
        AppVpnMode.Blocklist,
        -> selectedPackageNames.filterNot { it == ownPackageName }.distinct()
    }

internal fun selectedPackagesForMode(
    appMode: AppVpnMode,
    selectedPackageNames: List<String>,
    ownPackageName: String,
): List<String> =
    effectiveSelectedPackages(appMode, selectedPackageNames, ownPackageName)

internal fun setPackageSelected(
    appMode: AppVpnMode,
    selectedPackageNames: List<String>,
    ownPackageName: String,
    packageName: String,
    selected: Boolean,
): List<String> {
    if (appMode == AppVpnMode.All || packageName == ownPackageName) {
        return effectiveSelectedPackages(appMode, selectedPackageNames, ownPackageName)
    }

    val effectivePackages = effectiveSelectedPackages(appMode, selectedPackageNames, ownPackageName)
    val nextPackages = if (selected) {
        effectivePackages + packageName
    } else {
        effectivePackages.filterNot { it == packageName }
    }
    return effectiveSelectedPackages(appMode, nextPackages, ownPackageName)
}

internal fun addAllInstalledPackages(
    appMode: AppVpnMode,
    selectedPackageNames: List<String>,
    ownPackageName: String,
    installedApps: List<InstalledApp>,
): List<String> =
    effectiveSelectedPackages(
        appMode = appMode,
        selectedPackageNames = selectedPackageNames + installedApps.map { it.packageName },
        ownPackageName = ownPackageName,
    )

internal fun removeAllSelectedPackages(
    appMode: AppVpnMode,
    ownPackageName: String,
): List<String> =
    effectiveSelectedPackages(
        appMode = appMode,
        selectedPackageNames = emptyList(),
        ownPackageName = ownPackageName,
    )

internal fun visibleInstalledAppsForEditor(
    installedApps: List<InstalledApp>,
    search: String,
    selectedPackageNames: Set<String>,
    ownPackageName: String,
): List<InstalledApp> =
    installedApps
        .filterNot { app -> app.packageName == ownPackageName }
        .filter { app ->
            search.isBlank() ||
                app.label.contains(search, ignoreCase = true) ||
                app.packageName.contains(search, ignoreCase = true)
        }
        .sortedWith(
            compareByDescending<InstalledApp> { it.packageName in selectedPackageNames }
                .thenBy { it.label.lowercase() }
                .thenBy { it.packageName },
        )
