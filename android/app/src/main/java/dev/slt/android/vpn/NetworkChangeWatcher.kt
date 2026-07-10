package dev.slt.android.vpn

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.Handler
import android.os.Looper
import android.util.Log

/**
 * One selected underlying-network event observed by [NetworkChangeWatcher].
 *
 * Generic over the network key so the transition logic in
 * [applyUnderlyingNetworkEvent] is unit-testable without the Android framework.
 */
internal sealed interface UnderlyingNetworkEvent<out K> {
    /** Android selected a new best matching underlying network. */
    data class Selected<K>(val network: K) : UnderlyingNetworkEvent<K>

    /** A selected underlying network is no longer available. */
    data class Lost<K>(val network: K) : UnderlyingNetworkEvent<K>

    /** The initial callback burst after registration has settled. */
    data object PrimingComplete : UnderlyingNetworkEvent<Nothing>
}

/**
 * Transition state for underlying-network watching.
 *
 * [current] is Android's selected best non-VPN network. [reconnectBaseline] is
 * the selection that the native runtime most recently used as its reconnect
 * baseline. [primed] becomes `true` after the initial best-network callback has
 * settled.
 */
internal data class UnderlyingNetworkState<K>(
    val current: K?,
    val reconnectBaseline: K?,
    val primed: Boolean,
)

/**
 * Result of applying one event: the updated state and whether a reconnect should
 * be scheduled. [publishImmediately] is limited to initial selection changes,
 * before the native runtime starts. Settled runtime changes are published by the
 * reconnect callback.
 */
internal data class UnderlyingNetworkTransition<K>(
    val state: UnderlyingNetworkState<K>,
    val networkChanged: Boolean,
    val publishImmediately: Boolean,
    val reconnect: Boolean,
)

private data class NetworkChangeAction(
    val underlyingNetwork: Network?,
    val publishImmediately: Boolean,
    val debounceAction: ReconnectDebounceAction?,
)

private sealed interface ReconnectDebounceAction {
    val generation: Long

    data class Schedule(override val generation: Long) : ReconnectDebounceAction

    data class Cancel(override val generation: Long) : ReconnectDebounceAction
}

private data class ReconnectAction(val underlyingNetwork: Network?)

/**
 * Pure transition decision for underlying-network watching.
 *
 * Rules:
 * - Events before [UnderlyingNetworkEvent.PrimingComplete] never reconnect. This
 *   absorbs the initial best-network callback after registration.
 * - `Selected(n)` updates the current path. A selection that differs from the
 *   reconnect baseline schedules a reconnect; returning to the baseline cancels
 *   pending reconnect work.
 * - `Lost(n)` clears the current path only when `n` is still selected. Android's
 *   best-matching callback reports a replacement through `Selected` when one is
 *   available.
 */
internal fun <K> applyUnderlyingNetworkEvent(
    event: UnderlyingNetworkEvent<K>,
    state: UnderlyingNetworkState<K>,
): UnderlyingNetworkTransition<K> {
    val current = when (event) {
        is UnderlyingNetworkEvent.Selected -> event.network
        is UnderlyingNetworkEvent.Lost ->
            if (event.network == state.current) null else state.current
        UnderlyingNetworkEvent.PrimingComplete -> state.current
    }

    if (!state.primed) {
        return UnderlyingNetworkTransition(
            state = state.copy(
                current = current,
                reconnectBaseline = current,
                primed = event is UnderlyingNetworkEvent.PrimingComplete,
            ),
            networkChanged = current != state.current,
            publishImmediately = current != state.current,
            reconnect = false,
        )
    }

    if (event is UnderlyingNetworkEvent.PrimingComplete || current == state.current) {
        return UnderlyingNetworkTransition(
            state = state,
            networkChanged = false,
            publishImmediately = false,
            reconnect = false,
        )
    }

    return UnderlyingNetworkTransition(
        state = state.copy(current = current),
        networkChanged = true,
        publishImmediately = false,
        reconnect = current != state.reconnectBaseline,
    )
}

/**
 * Watches Android's best underlying (non-VPN) network and signals the caller to
 * reconnect the VPN when the selected underlying path changes.
 *
 * The [NetworkRequest] requires `NET_CAPABILITY_INTERNET` +
 * `NET_CAPABILITY_NOT_VPN`, so the VPN's own network (which satisfies `INTERNET`
 * but never carries `NOT_VPN`) is never matched. The best-matching callback does
 * not promote backup networks merely because they become available. The initial
 * selection is published before [onInitialSelectionReady], allowing the caller
 * to bind the native runtime's first sockets correctly. Later selections remain
 * private until a single settled change fires [onReconnect].
 *
 * Network changes are infrequent, so running the decision on the main looper is
 * fine. [onReconnect] is invoked on the main looper; the caller is expected to do
 * any blocking work (such as stopping the native client) on its own background
 * scope.
 *
 * The transition rules live in [applyUnderlyingNetworkEvent], which is pure and
 * unit-tested independently of the Android framework.
 *
 * @param onInitialUnderlyingNetworkChanged invoked when the selected network
 * changes during the initial priming window.
 * @param onInitialSelectionReady invoked after the initial selection has settled,
 * or immediately when watching is unavailable.
 * @param onReconnect invoked on the main looper with the current underlying
 * network when a settled underlying-network change is observed.
 */
internal class NetworkChangeWatcher(
    context: Context,
    private val initialNetwork: Network?,
    private val onInitialUnderlyingNetworkChanged: (Network?) -> Unit,
    private val onInitialSelectionReady: (Network?) -> Unit,
    private val onReconnect: (Network?) -> Unit,
) {
    private val connectivityManager = context.getSystemService(ConnectivityManager::class.java)
    private val handler = Handler(Looper.getMainLooper())
    private val primingCompleteRunnable = Runnable {
        handleEvent(UnderlyingNetworkEvent.PrimingComplete)
        val selectedNetwork = synchronized(lock) { state.current }
        onInitialSelectionReady(selectedNetwork)
    }
    private val lock = Any()

    private var registered = false
    private var pendingReconnectRunnable: Runnable? = null
    // Invalidates delayed reconnect work captured before stop/start or a newer event.
    private var reconnectGeneration = 0L
    private var state: UnderlyingNetworkState<Network> =
        UnderlyingNetworkState(
            current = initialNetwork,
            reconnectBaseline = initialNetwork,
            primed = false,
        )

    private val callback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) {
            handleEvent(UnderlyingNetworkEvent.Selected(network))
        }

        override fun onLost(network: Network) {
            handleEvent(UnderlyingNetworkEvent.Lost(network))
        }
    }

    /** Begin observing underlying networks. Safe to call once; idempotent. */
    fun start() {
        synchronized(lock) {
            if (registered) return
            state = UnderlyingNetworkState(
                current = initialNetwork,
                reconnectBaseline = initialNetwork,
                primed = false,
            )
            pendingReconnectRunnable = null
            reconnectGeneration += 1
            val manager = connectivityManager ?: run {
                Log.w(TAG, "No ConnectivityManager; auto-reconnect disabled")
                handler.post { onInitialSelectionReady(initialNetwork) }
                return
            }

            val request = NetworkRequest.Builder()
                .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                .build()

            try {
                manager.registerBestMatchingNetworkCallback(request, callback, handler)
                registered = true
                handler.removeCallbacks(primingCompleteRunnable)
                handler.postDelayed(primingCompleteRunnable, INITIAL_CALLBACK_SETTLE_MS)
            } catch (error: RuntimeException) {
                // Missing ACCESS_NETWORK_STATE or a revoked permission would
                // otherwise crash the service. Degrade to "no auto-reconnect".
                Log.w(TAG, "Failed to register network callback; auto-reconnect disabled", error)
                handler.post { onInitialSelectionReady(initialNetwork) }
            }
        }
    }

    /** Stop observing. Idempotent; safe to call even if never started. */
    fun stop() {
        synchronized(lock) {
            pendingReconnectRunnable?.let(handler::removeCallbacks)
            handler.removeCallbacks(primingCompleteRunnable)
            pendingReconnectRunnable = null
            reconnectGeneration += 1
            state = UnderlyingNetworkState(
                current = null,
                reconnectBaseline = null,
                primed = false,
            )
            if (!registered) return
            registered = false
            val manager = connectivityManager ?: return
            try {
                manager.unregisterNetworkCallback(callback)
            } catch (error: RuntimeException) {
                Log.w(TAG, "Failed to unregister network callback", error)
            }
        }
    }

    private fun handleEvent(event: UnderlyingNetworkEvent<Network>) {
        val action = synchronized(lock) {
            val result = applyUnderlyingNetworkEvent(event, state)
            state = result.state

            val debounceAction = if (result.networkChanged && result.state.primed) {
                reconnectGeneration += 1
                if (result.reconnect) {
                    ReconnectDebounceAction.Schedule(reconnectGeneration)
                } else {
                    ReconnectDebounceAction.Cancel(reconnectGeneration)
                }
            } else {
                null
            }

            NetworkChangeAction(
                underlyingNetwork = result.state.current,
                publishImmediately = result.publishImmediately,
                debounceAction = debounceAction,
            )
        }

        if (action.publishImmediately) {
            onInitialUnderlyingNetworkChanged(action.underlyingNetwork)
        }

        when (val debounceAction = action.debounceAction) {
            is ReconnectDebounceAction.Schedule -> scheduleReconnect(debounceAction.generation)
            is ReconnectDebounceAction.Cancel -> cancelReconnect(debounceAction.generation)
            null -> Unit
        }
    }

    private fun cancelReconnect(generation: Long) {
        val previousRunnable = synchronized(lock) {
            if (generation == reconnectGeneration) {
                val previous = pendingReconnectRunnable
                pendingReconnectRunnable = null
                previous
            } else {
                null
            }
        }
        previousRunnable?.let(handler::removeCallbacks)
    }

    private fun scheduleReconnect(generation: Long) {
        val runnable = Runnable { fireReconnect(generation) }
        var shouldSchedule = false
        val previousRunnable = synchronized(lock) {
            if (registered && generation == reconnectGeneration) {
                shouldSchedule = true
                val previous = pendingReconnectRunnable
                pendingReconnectRunnable = runnable
                previous
            } else {
                null
            }
        }

        if (!shouldSchedule) return
        previousRunnable?.let(handler::removeCallbacks)
        handler.postDelayed(runnable, RECONNECT_DEBOUNCE_MS)
    }

    private fun fireReconnect(generation: Long) {
        val action = synchronized(lock) {
            if (registered && generation == reconnectGeneration) {
                pendingReconnectRunnable = null
                if (state.current != state.reconnectBaseline) {
                    val underlyingNetwork = state.current
                    state = state.copy(reconnectBaseline = underlyingNetwork)
                    ReconnectAction(underlyingNetwork)
                } else {
                    null
                }
            } else {
                null
            }
        }

        action?.let { onReconnect(it.underlyingNetwork) }
    }

    companion object {
        private const val TAG = "NetworkChangeWatcher"

        /// Coalesce handover bursts before reconnecting (design: 1-3s window).
        private const val RECONNECT_DEBOUNCE_MS = 2000L

        /// Let the initial best-matching callback settle before reconnecting.
        private const val INITIAL_CALLBACK_SETTLE_MS = 1000L
    }
}
