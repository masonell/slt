package dev.slt.android.vpn

import android.content.SharedPreferences
import android.util.Log
import androidx.core.content.edit
import org.json.JSONArray
import org.json.JSONException

internal interface DnsAddressCache {
    fun save(hostname: String, addresses: List<String>)

    fun load(hostname: String): List<String>
}

internal class DnsResolutionCache(
    private val prefs: SharedPreferences,
    private val logTag: String,
    private val maxAgeMs: Long = DEFAULT_MAX_AGE_MS,
    private val nowMs: () -> Long = { System.currentTimeMillis() },
) : DnsAddressCache {
    override fun save(hostname: String, addresses: List<String>) {
        val filtered = addresses.filter { it.isNotBlank() }
        if (filtered.isEmpty()) {
            return
        }

        prefs.edit {
            putString(addressesKey(hostname), JSONArray(filtered).toString())
            putLong(timestampKey(hostname), nowMs())
        }
    }

    override fun load(hostname: String): List<String> {
        val timestamp = prefs.getLong(timestampKey(hostname), 0L)
        if (timestamp == 0L || nowMs() - timestamp > maxAgeMs) {
            remove(hostname)
            return emptyList()
        }

        val raw = prefs.getString(addressesKey(hostname), null)
            ?: return emptyList()
        return try {
            val payload = JSONArray(raw)
            buildList {
                for (index in 0 until payload.length()) {
                    val address = payload.optString(index)
                    if (address.isNotBlank()) {
                        add(address)
                    }
                }
            }
        } catch (error: JSONException) {
            logWarning("Dropping malformed DNS cache entry for $hostname", error)
            remove(hostname)
            emptyList()
        }
    }

    private fun remove(hostname: String) {
        prefs.edit {
            remove(addressesKey(hostname))
            remove(timestampKey(hostname))
        }
    }

    private fun addressesKey(hostname: String): String =
        "addresses:${hostname.normalizedCacheHostname()}"

    private fun timestampKey(hostname: String): String =
        "timestamp:${hostname.normalizedCacheHostname()}"

    private fun String.normalizedCacheHostname(): String = trim().lowercase()

    private fun logWarning(message: String, error: Throwable) {
        runCatching {
            Log.w(logTag, message, error)
        }
    }

    companion object {
        const val PREFS_NAME = "slt_dns_cache"
        const val DEFAULT_MAX_AGE_MS = 24L * 60L * 60L * 1000L
    }
}
