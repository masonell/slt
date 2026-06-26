package dev.slt.android

import dev.slt.android.uniffi.ClientConfigSummary
import dev.slt.android.uniffi.validateClientConfig as validateClientConfigUniFfi

object SltNative {
    init {
        System.loadLibrary("slt_client")
    }

    fun load() = Unit

    fun initLogSink(filePath: String): Boolean = nativeInitLogSink(filePath)

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
            ConfigValidationResult(
                summary = validateClientConfigUniFfi(configToml),
                error = null,
            )
        } catch (error: Exception) {
            ConfigValidationResult(summary = null, error = error.message ?: "Invalid config")
        }

    interface NativeCallback {
        fun onStatus(status: String, detail: String?)

        fun protectSocket(fd: Int): Boolean

        fun resolveHost(hostname: String): Array<String>
    }

    @JvmStatic
    private external fun nativeStart(
        configToml: String,
        tunFd: Int,
        mtu: Int,
        callback: NativeCallback,
    ): Long

    @JvmStatic
    private external fun nativeInitLogSink(filePath: String): Boolean

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
