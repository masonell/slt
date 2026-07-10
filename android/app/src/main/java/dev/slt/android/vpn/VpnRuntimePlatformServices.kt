package dev.slt.android.vpn

import android.net.Network
import android.os.ParcelFileDescriptor
import android.util.Log
import dev.slt.android.uniffi.PlatformServices
import dev.slt.android.uniffi.SocketKind
import dev.slt.android.uniffi.SocketProtectionResult

internal sealed interface SocketBindingSelection<out N> {
    data class Ready<N>(val network: N) : SocketBindingSelection<N>

    data class Failure(val result: SocketProtectionResult) : SocketBindingSelection<Nothing>
}

internal fun <N> selectSocketBinding(
    protected: Boolean,
    currentUnderlyingNetwork: () -> N?,
): SocketBindingSelection<N> {
    if (!protected) {
        return SocketBindingSelection.Failure(SocketProtectionResult.PROTECT_REJECTED)
    }
    val network = currentUnderlyingNetwork()
        ?: return SocketBindingSelection.Failure(SocketProtectionResult.NO_UNDERLYING_NETWORK)
    return SocketBindingSelection.Ready(network)
}

internal class VpnRuntimePlatformServices(
    private val protect: (Int) -> Boolean,
    private val currentUnderlyingNetworks: () -> List<Network>,
    private val publishUnderlyingNetwork: (Network?) -> Unit,
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

    private fun protectAndBindSocket(fd: Int, kind: SocketKind): SocketProtectionResult {
        val protected = try {
            protect(fd)
        } catch (error: Exception) {
            Log.w(logTag, "Failed to protect SLT socket: fd=$fd kind=$kind", error)
            return SocketProtectionResult.PLATFORM_FAILURE
        }

        val selection = try {
            selectSocketBinding(protected, ::currentUnderlyingNetwork)
        } catch (error: Exception) {
            Log.w(logTag, "Failed to select an underlying network: fd=$fd kind=$kind", error)
            return SocketProtectionResult.PLATFORM_FAILURE
        }

        return when (selection) {
            is SocketBindingSelection.Failure -> {
                when (selection.result) {
                    SocketProtectionResult.PROTECT_REJECTED ->
                        Log.w(logTag, "Android refused to protect SLT socket: fd=$fd kind=$kind")
                    SocketProtectionResult.NO_UNDERLYING_NETWORK ->
                        Log.w(
                            logTag,
                            "No underlying network available for SLT socket binding: fd=$fd kind=$kind",
                        )
                    else ->
                        Log.w(logTag, "Unexpected socket binding selection: ${selection.result}")
                }
                selection.result
            }
            is SocketBindingSelection.Ready -> bindSocket(fd, kind, selection.network)
        }
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

    private fun currentUnderlyingNetwork(): Network? {
        val network = currentUnderlyingNetworks().firstOrNull()
        publishUnderlyingNetwork(network)
        return network
    }
}
