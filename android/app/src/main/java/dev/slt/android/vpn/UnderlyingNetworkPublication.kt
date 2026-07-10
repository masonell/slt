package dev.slt.android.vpn

/**
 * Keeps selection state changes and Android publication in one order across
 * the main-looper network watcher and the blocking DNS worker.
 */
internal class UnderlyingNetworkPublicationSequencer {
    private val lock = Any()

    fun <T> sequence(action: () -> T): T = synchronized(lock, action)
}

internal fun <N : Any> configureInitialUnderlyingNetwork(
    network: N?,
    configure: (List<N>) -> Unit,
) {
    if (network != null) {
        configure(listOf(network))
    }
}

/** Use the selected startup path until sockets bind, then publish only bound paths. */
internal fun <K, N : Any> liveUnderlyingNetworks(
    selectedNetwork: N?,
    boundNetworks: Map<K, N>,
): List<N> {
    val actualNetworks = boundNetworks.values.distinct()
    if (actualNetworks.isEmpty()) {
        return listOfNotNull(selectedNetwork)
    }

    val selectedActualNetwork = selectedNetwork?.takeIf(actualNetworks::contains)
    return listOfNotNull(selectedActualNetwork) +
        actualNetworks.filterNot { network -> network == selectedActualNetwork }
}

internal fun <N : Any> publishLiveUnderlyingNetworks(
    networks: List<N>,
    publish: (List<N>) -> Boolean,
): Boolean = publish(networks)
