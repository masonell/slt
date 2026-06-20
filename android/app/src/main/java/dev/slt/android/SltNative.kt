package dev.slt.android

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

    interface NativeCallback {
        fun onStatus(status: String, detail: String?)

        fun onLog(level: String, message: String)
    }

    @JvmStatic
    private external fun nativeStart(
        configToml: String,
        tunFd: Int,
        mtu: Int,
        callback: NativeCallback,
    ): Long

    @JvmStatic
    private external fun nativeStop(handle: Long)
}
