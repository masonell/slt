package dev.slt.android.vpn

import android.net.Network
import android.os.ParcelFileDescriptor
import android.util.Log
import dev.slt.android.uniffi.PlatformServices
import dev.slt.android.uniffi.SocketKind

internal class VpnRuntimePlatformServices(
    private val protect: (Int) -> Boolean,
    private val currentUnderlyingNetworks: () -> List<Network>,
    private val publishUnderlyingNetwork: (Network?) -> Unit,
    private val dnsResolver: UnderlyingNetworkDnsResolver,
    private val logTag: String,
) {
    fun build(): PlatformServices =
        object : PlatformServices {
            override fun protectSocket(fd: Int, kind: SocketKind): Boolean =
                try {
                    protectAndBindSocket(fd, kind)
                } catch (error: RuntimeException) {
                    Log.w(logTag, "Failed to protect SLT socket: fd=$fd kind=$kind", error)
                    false
                } catch (error: Exception) {
                    Log.w(logTag, "Failed to bind SLT socket: fd=$fd kind=$kind", error)
                    false
                }

            override fun resolveHost(hostname: String): List<String> =
                dnsResolver.resolveHost(hostname)
        }

    private fun protectAndBindSocket(fd: Int, kind: SocketKind): Boolean {
        val protected = protect(fd)
        if (!protected) {
            Log.w(logTag, "Android refused to protect SLT socket: fd=$fd kind=$kind")
            return false
        }

        val network = currentUnderlyingNetwork()
        if (network == null) {
            Log.w(logTag, "No underlying network available for SLT socket binding: fd=$fd kind=$kind")
            return false
        }

        ParcelFileDescriptor.fromFd(fd).use { dup ->
            network.bindSocket(dup.fileDescriptor)
        }
        return true
    }

    private fun currentUnderlyingNetwork(): Network? {
        val network = currentUnderlyingNetworks().firstOrNull()
        publishUnderlyingNetwork(network)
        return network
    }
}
