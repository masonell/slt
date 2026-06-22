package dev.slt.android.ui.profile.rules

import dev.slt.android.ui.profile.AppVpnMode
import dev.slt.android.ui.profile.AppVpnRules
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class AppVpnRulesRulesTest {
    @Test
    fun allModeClearsPackageNames() {
        assertEquals(
            AppVpnRules(),
            normalizeAppVpnRules(
                mode = AppVpnMode.All,
                packageNames = listOf("com.example.app"),
                ownPackageName = "dev.slt.android",
            ),
        )
    }

    @Test
    fun allowlistDeduplicatesAndRemovesOwnPackage() {
        assertEquals(
            AppVpnRules(
                mode = AppVpnMode.Allowlist,
                packageNames = listOf("com.example.app"),
            ),
            normalizeAppVpnRules(
                mode = AppVpnMode.Allowlist,
                packageNames = listOf(" com.example.app ", "com.example.app", "dev.slt.android"),
                ownPackageName = "dev.slt.android",
            ),
        )
    }

    @Test
    fun blocklistRemovesOwnPackage() {
        assertEquals(
            AppVpnRules(
                mode = AppVpnMode.Blocklist,
                packageNames = listOf("com.example.app"),
            ),
            normalizeAppVpnRules(
                mode = AppVpnMode.Blocklist,
                packageNames = listOf("dev.slt.android", "com.example.app"),
                ownPackageName = "dev.slt.android",
            ),
        )
    }

    @Test
    fun rejectsMalformedPackageNames() {
        val error = assertThrows(IllegalArgumentException::class.java) {
            normalizeAppVpnRules(
                mode = AppVpnMode.Allowlist,
                packageNames = listOf("example"),
                ownPackageName = "dev.slt.android",
            )
        }

        assertEquals("App package example must contain at least one dot", error.message)
    }

    @Test
    fun reportsMissingPackages() {
        val missing = missingAppPackages(
            rules = AppVpnRules(
                mode = AppVpnMode.Allowlist,
                packageNames = listOf("com.example.missing", "com.example.installed"),
            ),
            installedPackages = setOf("com.example.installed"),
        )

        assertEquals(listOf("com.example.missing"), missing)
    }
}
