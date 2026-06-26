package dev.slt.android

import dev.slt.android.uniffi.ClientConfigSummary
import dev.slt.android.uniffi.SltInteropException
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
            ConfigValidationResult.Valid(validateClientConfigUniFfi(configToml))
        } catch (error: SltInteropException.InvalidConfig) {
            ConfigValidationResult.Invalid(error.detail.ifBlank { "Invalid config" })
        } catch (error: Exception) {
            ConfigValidationResult.Invalid(error.message ?: "Invalid config")
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

sealed class ConfigValidationResult {
    data class Valid(val summary: ClientConfigSummary) : ConfigValidationResult()

    data class Invalid(val message: String) : ConfigValidationResult()
}
