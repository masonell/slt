package dev.slt.android.ui.profile

import dev.slt.android.profile.AppVpnMode
import dev.slt.android.profile.VpnRouteRule
import dev.slt.android.ui.UiMessageSeverity
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class EditorListOperationsTest {
    @Test
    fun routeAddNormalizesAndExportsText() {
        val result = addVpnRouteFromForm(
            routeText = "!192.168.1.1/16",
            cidrText = "10.0.1.1/16",
            excluded = false,
        )

        assertTrue(result.changed)
        assertEquals(
            """
            10.0.0.0/16
            !192.168.0.0/16
            """.trimIndent(),
            result.text,
        )
        assertEquals("Route added", result.message?.text)
        assertEquals(UiMessageSeverity.Info, result.message?.severity)
    }

    @Test
    fun routeAddReportsDuplicateWithoutChangingText() {
        val result = addVpnRouteFromForm(
            routeText = "10.0.0.0/8",
            cidrText = "10.0.0.0/8",
            excluded = false,
        )

        assertFalse(result.changed)
        assertEquals("10.0.0.0/8", result.text)
        assertEquals("Route already exists", result.message?.text)
        assertEquals(UiMessageSeverity.Info, result.message?.severity)
    }

    @Test
    fun routeAddReportsCoveredRouteWithoutChangingText() {
        val result = addVpnRouteFromForm(
            routeText = "10.0.0.0/8",
            cidrText = "10.10.0.0/16",
            excluded = false,
        )

        assertFalse(result.changed)
        assertEquals("10.0.0.0/8", result.text)
        assertEquals("Route is already covered by an existing include route", result.message?.text)
        assertEquals(UiMessageSeverity.Info, result.message?.severity)
    }

    @Test
    fun routeRemoveExportsRemainingRoutes() {
        val result = removeVpnRouteAt(
            routeText = """
            0.0.0.0/0
            !10.0.0.0/8
            """.trimIndent(),
            index = 0,
        )

        assertTrue(result.changed)
        assertEquals("!10.0.0.0/8", result.text)
        assertNull(result.message)
    }

    @Test
    fun displayedRoutesReturnsNullWhenTextIsInvalid() {
        assertNull(displayedVpnRoutes("not-a-route"))
    }

    @Test
    fun testUrlAddNormalizesAndExportsText() {
        val result = addTestUrlFromForm(
            currentUrls = listOf("https://example.com/check"),
            urlText = "HTTP://Example.NET:80/status",
        )

        assertTrue(result.changed)
        assertEquals(
            """
            https://example.com/check
            http://example.net/status
            """.trimIndent(),
            result.text,
        )
        assertEquals("Test URL added", result.message?.text)
        assertEquals(UiMessageSeverity.Info, result.message?.severity)
    }

    @Test
    fun testUrlAddReportsDuplicateWithoutChangingText() {
        val result = addTestUrlFromForm(
            currentUrls = listOf("https://example.com/check"),
            urlText = "HTTPS://Example.COM:443/check",
        )

        assertFalse(result.changed)
        assertEquals("https://example.com/check", result.text)
        assertEquals("Test URL already exists", result.message?.text)
        assertEquals(UiMessageSeverity.Info, result.message?.severity)
    }

    @Test
    fun testUrlRemoveExportsRemainingUrls() {
        val result = removeTestUrlAt(
            currentUrls = listOf(
                "https://example.com/check",
                "https://example.net/status",
            ),
            index = 0,
        )

        assertTrue(result.changed)
        assertEquals("https://example.net/status", result.text)
        assertNull(result.message)
    }

    @Test
    fun appSelectionCalculatesEffectivePackages() {
        assertEquals(
            listOf("com.example.one", "com.example.two"),
            effectiveSelectedPackages(
                appMode = AppVpnMode.Allowlist,
                selectedPackageNames = listOf(
                    "com.example.one",
                    "dev.slt.android",
                    "com.example.one",
                    "com.example.two",
                ),
                ownPackageName = "dev.slt.android",
            ),
        )
        assertEquals(
            emptyList<String>(),
            effectiveSelectedPackages(
                appMode = AppVpnMode.All,
                selectedPackageNames = listOf("com.example.one"),
                ownPackageName = "dev.slt.android",
            ),
        )
    }

    @Test
    fun appSelectionSelectsAndDeselectsPackages() {
        val selected = setPackageSelected(
            appMode = AppVpnMode.Blocklist,
            selectedPackageNames = listOf("com.example.one"),
            ownPackageName = "dev.slt.android",
            packageName = "com.example.two",
            selected = true,
        )

        assertEquals(listOf("com.example.one", "com.example.two"), selected)
        assertEquals(
            listOf("com.example.two"),
            setPackageSelected(
                appMode = AppVpnMode.Blocklist,
                selectedPackageNames = selected,
                ownPackageName = "dev.slt.android",
                packageName = "com.example.one",
                selected = false,
            ),
        )
    }

    @Test
    fun appSelectionIgnoresOwnPackage() {
        assertEquals(
            listOf("com.example.one"),
            setPackageSelected(
                appMode = AppVpnMode.Allowlist,
                selectedPackageNames = listOf("com.example.one"),
                ownPackageName = "dev.slt.android",
                packageName = "dev.slt.android",
                selected = true,
            ),
        )
    }

    @Test
    fun appSelectionAddAllFiltersOwnPackage() {
        val selected = addAllInstalledPackages(
            appMode = AppVpnMode.Allowlist,
            selectedPackageNames = listOf("com.example.one"),
            ownPackageName = "dev.slt.android",
            installedApps = listOf(
                InstalledApp(label = "SLT", packageName = "dev.slt.android"),
                InstalledApp(label = "Two", packageName = "com.example.two"),
            ),
        )

        assertEquals(listOf("com.example.one", "com.example.two"), selected)
    }

    @Test
    fun appSelectionVisibleAppsFiltersOwnPackageAndSortsSelectedFirst() {
        val visibleApps = visibleInstalledAppsForEditor(
            installedApps = listOf(
                InstalledApp(label = "Alpha", packageName = "com.example.alpha"),
                InstalledApp(label = "SLT", packageName = "dev.slt.android"),
                InstalledApp(label = "Beta", packageName = "com.example.beta"),
            ),
            search = "",
            selectedPackageNames = setOf("com.example.beta"),
            ownPackageName = "dev.slt.android",
        )

        assertEquals(
            listOf(
                InstalledApp(label = "Beta", packageName = "com.example.beta"),
                InstalledApp(label = "Alpha", packageName = "com.example.alpha"),
            ),
            visibleApps,
        )
    }

    @Test
    fun displayedTestUrlsReturnsEmptyListWhenTextIsInvalid() {
        assertEquals(emptyList<String>(), displayedTestUrls("ftp://example.com/check"))
    }

    @Test
    fun displayedRoutesParsesCanonicalRoutes() {
        assertEquals(
            listOf(VpnRouteRule(cidr = "10.0.0.0/8", excluded = false)),
            displayedVpnRoutes("10.1.2.3/8"),
        )
    }
}
