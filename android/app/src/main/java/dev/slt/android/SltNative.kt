package dev.slt.android

object SltNative {
    init {
        System.loadLibrary("slt_client")
    }

    fun load() = Unit
}
