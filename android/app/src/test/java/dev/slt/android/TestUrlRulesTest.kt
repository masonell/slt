package dev.slt.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class TestUrlRulesTest {
    @Test
    fun parsesNormalizesAndDeduplicatesTestUrls() {
        val urls = parseTestUrls(
            """
            HTTPS://Example.COM:443/check
            https://example.com/check
            http://Example.COM:80/status?probe=1
            """.trimIndent(),
        )

        assertEquals(
            listOf(
                "https://example.com/check",
                "http://example.com/status?probe=1",
            ),
            urls,
        )
    }

    @Test
    fun allowsEmptyTestUrlList() {
        assertEquals(emptyList<String>(), parseTestUrls(""))
    }

    @Test
    fun rejectsUrlsWithoutHttpScheme() {
        val error = assertThrows(IllegalArgumentException::class.java) {
            parseTestUrls("ftp://example.com/check")
        }

        assertEquals("Line 1: test URL must use http or https", error.message)
    }

    @Test
    fun rejectsUrlsWithoutHost() {
        val error = assertThrows(IllegalArgumentException::class.java) {
            parseTestUrls("https:///check")
        }

        assertEquals("Line 1: test URL must include a host", error.message)
    }

    @Test
    fun rejectsUrlsWithCredentials() {
        val error = assertThrows(IllegalArgumentException::class.java) {
            parseTestUrls("https://user:pass@example.com/check")
        }

        assertEquals("Line 1: test URL must not include credentials", error.message)
    }

    @Test
    fun exportsTestUrls() {
        assertEquals(
            """
            https://example.com/check
            http://example.net/status
            """.trimIndent(),
            exportTestUrls(
                listOf(
                    "https://example.com/check",
                    "http://example.net/status",
                ),
            ),
        )
    }
}
