package dev.slt.android

import org.json.JSONObject

object SltNative {
    init {
        System.loadLibrary("slt_client")
    }

    fun load() = Unit

    fun start(
        configToml: String,
        tunFd: Int,
        mtu: Int,
        callback: NativeCallback,
    ): Long = nativeStart(configToml, tunFd, mtu, callback)

    fun stop(handle: Long) {
        if (handle != 0L) {
            nativeStop(handle)
        }
    }

    fun validateClientConfig(configToml: String): ConfigValidationResult =
        try {
            val json = JSONObject(nativeValidateClientConfig(configToml))
            ConfigValidationResult(
                summary = ClientConfigSummary(
                    assignedIpv4 = json.getString("assignedIpv4"),
                    tunMtu = json.getInt("tunMtu"),
                    serverHost = json.getString("serverHost"),
                    serverPort = json.getInt("serverPort"),
                    clientId = json.getString("clientId"),
                ),
                error = null,
            )
        } catch (error: RuntimeException) {
            ConfigValidationResult(summary = null, error = error.message ?: "Invalid config")
        }

    interface NativeCallback {
        fun onStatus(status: String, detail: String?)

        fun onLog(level: String, message: String)

        fun protectSocket(fd: Int): Boolean
    }

    @JvmStatic
    private external fun nativeStart(
        configToml: String,
        tunFd: Int,
        mtu: Int,
        callback: NativeCallback,
    ): Long

    @JvmStatic
    private external fun nativeValidateClientConfig(configToml: String): String

    @JvmStatic
    private external fun nativeStop(handle: Long)
}

data class ConfigValidationResult(
    val summary: ClientConfigSummary?,
    val error: String?,
) {
    val isValid: Boolean
        get() = summary != null
}

data class ClientConfigSummary(
    val assignedIpv4: String,
    val tunMtu: Int,
    val serverHost: String,
    val serverPort: Int,
    val clientId: String,
)
