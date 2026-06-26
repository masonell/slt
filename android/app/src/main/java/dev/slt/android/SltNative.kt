package dev.slt.android

import dev.slt.android.uniffi.ClientConfigSummary
import dev.slt.android.uniffi.NativeSession
import dev.slt.android.uniffi.NativeSessionCallback
import dev.slt.android.uniffi.PlatformServices
import dev.slt.android.uniffi.SltInteropException
import dev.slt.android.uniffi.initLogSink as initLogSinkUniFfi
import dev.slt.android.uniffi.startSession as startSessionUniFfi
import dev.slt.android.uniffi.validateClientConfig as validateClientConfigUniFfi

object SltNative {
    init {
        System.loadLibrary("slt_client")
    }

    fun load() = Unit

    fun initLogSink(filePath: String): Boolean = initLogSinkUniFfi(filePath)

    fun start(
        configToml: String,
        tunFd: Int,
        mtu: Int,
        platformServices: PlatformServices,
        callback: NativeSessionCallback,
    ): NativeSession = startSessionUniFfi(configToml, tunFd, mtu, platformServices, callback)

    fun stop(session: NativeSession?) {
        session?.stop()
        session?.destroy()
    }

    fun validateClientConfig(configToml: String): ConfigValidationResult =
        try {
            ConfigValidationResult.Valid(validateClientConfigUniFfi(configToml))
        } catch (error: SltInteropException.InvalidConfig) {
            ConfigValidationResult.Invalid(error.detail.ifBlank { "Invalid config" })
        } catch (error: Exception) {
            ConfigValidationResult.Invalid(error.message ?: "Invalid config")
        }
}

sealed class ConfigValidationResult {
    data class Valid(val summary: ClientConfigSummary) : ConfigValidationResult()

    data class Invalid(val message: String) : ConfigValidationResult()
}
