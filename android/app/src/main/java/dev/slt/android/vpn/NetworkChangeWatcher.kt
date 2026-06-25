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
 * One underlying-network event observed by [NetworkChangeWatcher].
 *
 * Generic over the network key so the transition logic in
 * [applyUnderlyingNetworkEvent] is unit-testable without the Android framework.
 */
internal sealed interface UnderlyingNetworkEvent<out K> {
    /** A new underlying network became available. */
    data class Available<K>(val network: K) : UnderlyingNetworkEvent<K>

    /** A previously available underlying network was lost. */
    data class Lost<K>(val network: K) : UnderlyingNetworkEvent<K>

    /** The initial callback burst after registration has settled. */
    data object PrimingComplete : UnderlyingNetworkEvent<Nothing>
}

/**
 * Transition state for underlying-network watching.
 *
 * [current] is the active underlying network the VPN established over, usually
 * captured before the VPN network is created. [primed] becomes `true` after the
 * initial callback burst from `registerNetworkCallback` has settled.
 */
internal data class UnderlyingNetworkState<K>(
    val current: K?,
    val primed: Boolean,
)

/**
 * Result of applying one event: the updated state and whether a reconnect should
 * be scheduled. [networkChanged] is true whenever [UnderlyingNetworkState.current]
 * changed and should be published to DNS resolution.
 */
internal data class UnderlyingNetworkTransition<K>(
    val state: UnderlyingNetworkState<K>,
    val networkChanged: Boolean,
    val reconnect: Boolean,
)

/**
 * Pure transition decision for underlying-network watching.
 *
 * Rules:
 * - Events before [UnderlyingNetworkEvent.PrimingComplete] never reconnect. This
 *   absorbs the initial callback burst that fires right after registration, so a
 *   clean VPN start does not spuriously reconnect when Wi-Fi and cellular are
 *   both already available.
 * - `Available(n)` for a network different from the current one — a handoff, or a
 *   recovery after the active network was lost — triggers a reconnect and becomes
 *   the new baseline.
 * - `Lost(n)` of the current network triggers a reconnect and clears the baseline.
 * - `Lost(n)` of a non-current network does nothing: a non-active network dropping
 *   does not change the active path.
 */
internal fun <K> applyUnderlyingNetworkEvent(
    event: UnderlyingNetworkEvent<K>,
    state: UnderlyingNetworkState<K>,
): UnderlyingNetworkTransition<K> {
    if (!state.primed) {
        val current = when (event) {
            is UnderlyingNetworkEvent.Available -> state.current ?: event.network
            is UnderlyingNetworkEvent.Lost ->
                if (event.network == state.current) null else state.current
            UnderlyingNetworkEvent.PrimingComplete -> state.current
        }
        return UnderlyingNetworkTransition(
            state = state.copy(
                current = current,
                primed = event is UnderlyingNetworkEvent.PrimingComplete,
            ),
            networkChanged = current != state.current,
            reconnect = false,
        )
    }

    return when (event) {
        is UnderlyingNetworkEvent.Available ->
            if (event.network != state.current) {
                UnderlyingNetworkTransition(
                    state = state.copy(current = event.network),
                    networkChanged = true,
                    reconnect = true,
                )
            } else {
                UnderlyingNetworkTransition(
                    state = state,
                    networkChanged = false,
                    reconnect = false,
                )
            }

        is UnderlyingNetworkEvent.Lost ->
            if (event.network == state.current) {
                UnderlyingNetworkTransition(
                    state = state.copy(current = null),
                    networkChanged = true,
                    reconnect = true,
                )
            } else {
                UnderlyingNetworkTransition(
                    state = state,
                    networkChanged = false,
                    reconnect = false,
                )
            }

        UnderlyingNetworkEvent.PrimingComplete ->
            UnderlyingNetworkTransition(
                state = state,
                networkChanged = false,
                reconnect = false,
            )
    }
}

/**
 * Watches the phone's underlying (non-VPN) networks and signals the caller to
 * reconnect the VPN when the active underlying path changes.
 *
 * The [NetworkRequest] requires `NET_CAPABILITY_INTERNET` +
 * `NET_CAPABILITY_NOT_VPN`, so the VPN's own network (which satisfies `INTERNET`
 * but never carries `NOT_VPN`) is never matched. Transitions are debounced on the
 * main looper; after an initial settling window, a single settled change fires
 * [onReconnect].
 *
 * Network changes are infrequent, so running the decision on the main looper is
 * fine. [onReconnect] is invoked on the main looper; the caller is expected to do
 * any blocking work (such as stopping the native client) on its own background
 * scope.
 *
 * The transition rules live in [applyUnderlyingNetworkEvent], which is pure and
 * unit-tested independently of the Android framework.
 *
 * @param context used to obtain the [ConnectivityManager].
 * @param onUnderlyingNetworkChanged invoked when the current underlying network
 * changes, including during the initial priming window.
 * @param onReconnect invoked on the main looper with the current underlying
 * network when a settled underlying-network change is observed.
 */
internal class NetworkChangeWatcher(
    context: Context,
    private val initialNetwork: Network?,
    private val onUnderlyingNetworkChanged: (Network?) -> Unit,
    private val onReconnect: (Network?) -> Unit,
) {
    private val connectivityManager = context.getSystemService(ConnectivityManager::class.java)
    private val handler = Handler(Looper.getMainLooper())
    private val debounceRunnable = Runnable { onReconnect(pendingReconnectNetwork) }
    private val primingCompleteRunnable = Runnable {
        handleEvent(UnderlyingNetworkEvent.PrimingComplete)
    }
    private val lock = Any()

    private var registered = false
    private var pendingReconnectNetwork: Network? = null
    private var state: UnderlyingNetworkState<Network> =
        UnderlyingNetworkState(current = initialNetwork, primed = false)

    private val callback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) {
            handleEvent(UnderlyingNetworkEvent.Available(network))
        }

        override fun onLost(network: Network) {
            handleEvent(UnderlyingNetworkEvent.Lost(network))
        }
    }

    /** Begin observing underlying networks. Safe to call once; idempotent. */
    fun start() {
        synchronized(lock) {
            if (registered) return
            state = UnderlyingNetworkState(current = initialNetwork, primed = false)
            val manager = connectivityManager ?: run {
                Log.w(TAG, "No ConnectivityManager; auto-reconnect disabled")
                return
            }

            val request = NetworkRequest.Builder()
                .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                .build()

            try {
                manager.registerNetworkCallback(request, callback)
                registered = true
                handler.removeCallbacks(primingCompleteRunnable)
                handler.postDelayed(primingCompleteRunnable, INITIAL_CALLBACK_SETTLE_MS)
            } catch (error: RuntimeException) {
                // Missing ACCESS_NETWORK_STATE or a revoked permission would
                // otherwise crash the service. Degrade to "no auto-reconnect".
                Log.w(TAG, "Failed to register network callback; auto-reconnect disabled", error)
            }
        }
    }

    /** Stop observing. Idempotent; safe to call even if never started. */
    fun stop() {
        synchronized(lock) {
            handler.removeCallbacks(debounceRunnable)
            handler.removeCallbacks(primingCompleteRunnable)
            pendingReconnectNetwork = null
            state = UnderlyingNetworkState(current = null, primed = false)
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
        synchronized(lock) {
            val result = applyUnderlyingNetworkEvent(event, state)
            state = result.state

            if (result.networkChanged) {
                onUnderlyingNetworkChanged(result.state.current)
            }

            if (result.reconnect) {
                handler.removeCallbacks(debounceRunnable)
                pendingReconnectNetwork = result.state.current
                handler.postDelayed(debounceRunnable, RECONNECT_DEBOUNCE_MS)
            }
        }
    }

    companion object {
        private const val TAG = "NetworkChangeWatcher"

        /// Coalesce handover bursts before reconnecting (design: 1-3s window).
        private const val RECONNECT_DEBOUNCE_MS = 2000L

        /// Let registerNetworkCallback deliver its already-available networks
        /// before treating new availability as an underlying-network handoff.
        private const val INITIAL_CALLBACK_SETTLE_MS = 1000L
    }
}
