package dev.slt.android.vpn

import android.content.SharedPreferences
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test

class DnsResolutionCacheTest {
    @Test
    fun returnsValidCacheHit() {
        val prefs = FakeSharedPreferences()
        val cache = DnsResolutionCache(prefs, LOG_TAG, nowMs = { 1_000L })

        cache.save("server.example", listOf("192.0.2.1", "2001:db8::1"))

        assertEquals(listOf("192.0.2.1", "2001:db8::1"), cache.load("server.example"))
    }

    @Test
    fun removesExpiredEntries() {
        var now = 1_000L
        val prefs = FakeSharedPreferences()
        val cache = DnsResolutionCache(
            prefs = prefs,
            logTag = LOG_TAG,
            maxAgeMs = 100L,
            nowMs = { now },
        )
        cache.save("server.example", listOf("192.0.2.1"))

        now = 1_101L

        assertEquals(emptyList<String>(), cache.load("server.example"))
        assertFalse(prefs.contains("addresses:server.example"))
        assertFalse(prefs.contains("timestamp:server.example"))
    }

    @Test
    fun removesMalformedJsonEntries() {
        val prefs = FakeSharedPreferences()
        prefs.edit()
            .putString("addresses:server.example", "{not-json")
            .putLong("timestamp:server.example", 1_000L)
            .apply()
        val cache = DnsResolutionCache(prefs, LOG_TAG, nowMs = { 1_000L })

        assertEquals(emptyList<String>(), cache.load("server.example"))
        assertFalse(prefs.contains("addresses:server.example"))
        assertFalse(prefs.contains("timestamp:server.example"))
    }

    @Test
    fun filtersBlankAddresses() {
        val prefs = FakeSharedPreferences()
        val cache = DnsResolutionCache(prefs, LOG_TAG, nowMs = { 1_000L })

        cache.save("server.example", listOf("", "192.0.2.1", "   "))

        assertEquals(listOf("192.0.2.1"), cache.load("server.example"))
    }

    @Test
    fun normalizesHostnameKeys() {
        val prefs = FakeSharedPreferences()
        val cache = DnsResolutionCache(prefs, LOG_TAG, nowMs = { 1_000L })

        cache.save("Server.Example", listOf("192.0.2.1"))

        assertEquals(listOf("192.0.2.1"), cache.load(" server.example "))
    }

    private class FakeSharedPreferences : SharedPreferences {
        private val values = mutableMapOf<String, Any?>()

        override fun getAll(): MutableMap<String, *> = values.toMutableMap()

        override fun getString(key: String, defValue: String?): String? =
            values[key] as? String ?: defValue

        override fun getStringSet(key: String, defValues: MutableSet<String>?): MutableSet<String>? =
            @Suppress("UNCHECKED_CAST")
            (values[key] as? Set<String>)?.toMutableSet() ?: defValues

        override fun getInt(key: String, defValue: Int): Int =
            values[key] as? Int ?: defValue

        override fun getLong(key: String, defValue: Long): Long =
            values[key] as? Long ?: defValue

        override fun getFloat(key: String, defValue: Float): Float =
            values[key] as? Float ?: defValue

        override fun getBoolean(key: String, defValue: Boolean): Boolean =
            values[key] as? Boolean ?: defValue

        override fun contains(key: String): Boolean = values.containsKey(key)

        override fun edit(): SharedPreferences.Editor = FakeEditor()

        override fun registerOnSharedPreferenceChangeListener(
            listener: SharedPreferences.OnSharedPreferenceChangeListener?,
        ) = Unit

        override fun unregisterOnSharedPreferenceChangeListener(
            listener: SharedPreferences.OnSharedPreferenceChangeListener?,
        ) = Unit

        private inner class FakeEditor : SharedPreferences.Editor {
            private val staged = mutableMapOf<String, Any?>()
            private val removals = mutableSetOf<String>()
            private var clear = false

            override fun putString(key: String, value: String?): SharedPreferences.Editor =
                apply { staged[key] = value }

            override fun putStringSet(
                key: String,
                values: MutableSet<String>?,
            ): SharedPreferences.Editor =
                apply { staged[key] = values?.toSet() }

            override fun putInt(key: String, value: Int): SharedPreferences.Editor =
                apply { staged[key] = value }

            override fun putLong(key: String, value: Long): SharedPreferences.Editor =
                apply { staged[key] = value }

            override fun putFloat(key: String, value: Float): SharedPreferences.Editor =
                apply { staged[key] = value }

            override fun putBoolean(key: String, value: Boolean): SharedPreferences.Editor =
                apply { staged[key] = value }

            override fun remove(key: String): SharedPreferences.Editor =
                apply { removals += key }

            override fun clear(): SharedPreferences.Editor =
                apply { clear = true }

            override fun commit(): Boolean {
                applyChanges()
                return true
            }

            override fun apply() {
                applyChanges()
            }

            private fun applyChanges() {
                if (clear) {
                    values.clear()
                }
                removals.forEach(values::remove)
                staged.forEach { (key, value) ->
                    if (value == null) {
                        values.remove(key)
                    } else {
                        values[key] = value
                    }
                }
            }
        }
    }

    private companion object {
        const val LOG_TAG = "DnsResolutionCacheTest"
    }
}
