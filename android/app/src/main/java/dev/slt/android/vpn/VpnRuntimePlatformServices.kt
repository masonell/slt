package dev.slt.android.vpn

import android.net.Network
import android.os.ParcelFileDescriptor
import android.util.Log
import dev.slt.android.uniffi.PlatformServices
import dev.slt.android.uniffi.SocketKind
import dev.slt.android.uniffi.SocketProtectionResult

internal fun <N> bindProtectedSocket(
    protected: Boolean,
    currentUnderlyingNetworks: () -> List<N>,
    bindSocket: (N) -> SocketProtectionResult,
    onBound: (N) -> Unit = {},
): SocketProtectionResult {
    if (!protected) {
        return SocketProtectionResult.PROTECT_REJECTED
    }

    val networks = currentUnderlyingNetworks()
    if (networks.isEmpty()) {
        return SocketProtectionResult.NO_UNDERLYING_NETWORK
    }

    for (network in networks) {
        when (val result = bindSocket(network)) {
            SocketProtectionResult.PROTECTED -> {
                onBound(network)
                return result
            }
            SocketProtectionResult.BIND_FAILED -> Unit
            else -> return result
        }
    }

    return SocketProtectionResult.BIND_FAILED
}

internal class VpnRuntimePlatformServices(
    private val protect: (Int) -> Boolean,
    private val currentUnderlyingNetworks: () -> List<Network>,
    private val onSocketBound: (SocketKind, Network) -> Unit,
    private val dnsResolver: UnderlyingNetworkDnsResolver,
    private val logTag: String,
) {
    fun build(): PlatformServices =
        object : PlatformServices {
            override fun protectSocket(fd: Int, kind: SocketKind): SocketProtectionResult =
                protectAndBindSocket(fd, kind)

            override fun resolveHost(hostname: String): List<String> =
                dnsResolver.resolveHost(hostname)
        }

    private fun protectAndBindSocket(
        fd: Int,
        kind: SocketKind,
    ): SocketProtectionResult {
        val protected = try {
            protect(fd)
        } catch (error: Exception) {
            Log.w(logTag, "Failed to protect SLT socket: fd=$fd kind=$kind", error)
            return SocketProtectionResult.PLATFORM_FAILURE
        }

        val result = try {
            bindProtectedSocket(
                protected = protected,
                currentUnderlyingNetworks = currentUnderlyingNetworks,
                bindSocket = { network -> bindSocket(fd, kind, network) },
                onBound = { network ->
                    try {
                        onSocketBound(kind, network)
                    } catch (error: Exception) {
                        Log.w(
                            logTag,
                            "Failed to record bound SLT socket: fd=$fd kind=$kind network=$network",
                            error,
                        )
                    }
                },
            )
        } catch (error: Exception) {
            Log.w(logTag, "Failed to use underlying networks: fd=$fd kind=$kind", error)
            return SocketProtectionResult.PLATFORM_FAILURE
        }

        when (result) {
            SocketProtectionResult.PROTECTED -> Unit
            SocketProtectionResult.PROTECT_REJECTED ->
                Log.w(logTag, "Android refused to protect SLT socket: fd=$fd kind=$kind")
            SocketProtectionResult.NO_UNDERLYING_NETWORK ->
                Log.w(
                    logTag,
                    "No underlying network available for SLT socket binding: fd=$fd kind=$kind",
                )
            SocketProtectionResult.BIND_FAILED ->
                Log.w(logTag, "All underlying network bindings failed: fd=$fd kind=$kind")
            SocketProtectionResult.PLATFORM_FAILURE -> Unit
        }
        return result
    }

    private fun bindSocket(fd: Int, kind: SocketKind, network: Network): SocketProtectionResult {
        // Invariant: this fd is borrowed from Rust. fromFd() duplicates it, so
        // closing this wrapper must only close the duplicate; Rust owns and
        // closes the original fd.
        val duplicate = try {
            ParcelFileDescriptor.fromFd(fd)
        } catch (error: Exception) {
            Log.w(logTag, "Failed to duplicate SLT socket: fd=$fd kind=$kind", error)
            return SocketProtectionResult.PLATFORM_FAILURE
        }
        return try {
            duplicate.use { dup ->
                network.bindSocket(dup.fileDescriptor)
            }
            SocketProtectionResult.PROTECTED
        } catch (error: Exception) {
            Log.w(logTag, "Failed to bind SLT socket: fd=$fd kind=$kind network=$network", error)
            SocketProtectionResult.BIND_FAILED
        }
    }
}
