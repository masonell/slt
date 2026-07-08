package dev.slt.android.connection

import dev.slt.android.profile.SltProfile
import dev.slt.android.profile.VpnRouteRule
import dev.slt.android.profile.rules.vpnRouteActionForAddress
import java.io.IOException
import java.net.InetAddress
import java.net.URI
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.channelFlow
import kotlinx.coroutines.flow.flowOn
import kotlinx.coroutines.launch
import okhttp3.Dns
import okhttp3.OkHttpClient
import okhttp3.Request

internal class ConnectionTestRunner(
    private val resolver: HostResolver = JvmHostResolver,
    private val httpClient: TestHttpClient = OkHttpTestHttpClient,
) {
    /**
     * Run connection tests for all of the profile's URLs concurrently, emitting a
     * [ConnectionTestEntry] per URL as it moves through [ConnectionTestPhase].
     * Collecting the flow drives progress; cancelling the collector cancels the
     * run (blocking DNS/HTTP calls in flight finish on their own but their
     * results are dropped).
     */
    fun run(profile: SltProfile): Flow<ConnectionTestEntry> = channelFlow {
        coroutineScope {
            profile.metadata.testUrls.forEach { url ->
                launch {
                    runOne(url, profile.metadata.routes) { entry -> send(entry) }
                }
            }
        }
    }.flowOn(Dispatchers.IO)

    private suspend fun runOne(
        url: String,
        routes: List<VpnRouteRule>,
        emit: suspend (ConnectionTestEntry) -> Unit,
    ) {
        val host = URI(url).host
        if (host == null) {
            emit(
                ConnectionTestEntry(
                    url = url,
                    phase = ConnectionTestPhase.Done,
                    outcome = ConnectionTestOutcome.Failure("URL has no host"),
                ),
            )
            return
        }

        emit(ConnectionTestEntry(url = url, phase = ConnectionTestPhase.Resolving))
        val addresses = try {
            resolver.resolve(host)
        } catch (error: IOException) {
            emit(
                ConnectionTestEntry(
                    url = url,
                    phase = ConnectionTestPhase.Done,
                    outcome = ConnectionTestOutcome.Failure("DNS failed: ${error.readableMessage()}"),
                ),
            )
            return
        }
        val expectedPath = expectedPathForAddresses(routes, addresses)
        val numeric = addresses.map { it.numericHostAddress() }

        emit(
            ConnectionTestEntry(
                url = url,
                phase = ConnectionTestPhase.Checking,
                resolvedAddresses = numeric,
                expectedPath = expectedPath,
            ),
        )
        val outcome = try {
            httpClient.get(url, host, addresses)
        } catch (error: IOException) {
            ConnectionTestOutcome.Failure("GET failed: ${error.readableMessage()}")
        }
        emit(
            ConnectionTestEntry(
                url = url,
                phase = ConnectionTestPhase.Done,
                resolvedAddresses = numeric,
                expectedPath = expectedPath,
                outcome = outcome,
            ),
        )
    }
}

/** Live state of one URL's connection test. */
internal data class ConnectionTestEntry(
    val url: String,
    val phase: ConnectionTestPhase,
    val resolvedAddresses: List<String> = emptyList(),
    val expectedPath: ExpectedNetworkPath = ExpectedNetworkPath.Direct,
    val outcome: ConnectionTestOutcome? = null,
)

internal enum class ConnectionTestPhase {
    Resolving,
    Checking,
    Done,
}

internal enum class ExpectedNetworkPath {
    Vpn,
    Direct,
    Mixed,
}

internal sealed interface ConnectionTestOutcome {
    data class Success(val statusCode: Int) : ConnectionTestOutcome

    data class Failure(val message: String) : ConnectionTestOutcome
}

internal fun expectedPathForAddresses(
    routes: List<VpnRouteRule>,
    addresses: List<InetAddress>,
): ExpectedNetworkPath {
    val paths = addresses
        .map { address -> expectedPathForAddress(routes, address.numericHostAddress()) }
        .toSet()

    return when {
        paths.isEmpty() -> ExpectedNetworkPath.Direct
        paths.size == 1 -> paths.single()
        else -> ExpectedNetworkPath.Mixed
    }
}

internal fun expectedPathForAddress(
    routes: List<VpnRouteRule>,
    address: String,
): ExpectedNetworkPath {
    val route = vpnRouteActionForAddress(routes, address)
    return if (route != null && !route.excluded) {
        ExpectedNetworkPath.Vpn
    } else {
        ExpectedNetworkPath.Direct
    }
}

internal fun interface HostResolver {
    @Throws(IOException::class)
    fun resolve(host: String): List<InetAddress>
}

internal object JvmHostResolver : HostResolver {
    override fun resolve(host: String): List<InetAddress> =
        InetAddress.getAllByName(host).toList()
}

internal fun interface TestHttpClient {
    @Throws(IOException::class)
    fun get(url: String, host: String, addresses: List<InetAddress>): ConnectionTestOutcome
}

internal object OkHttpTestHttpClient : TestHttpClient {
    private val client = OkHttpClient.Builder()
        .connectTimeout(5, TimeUnit.SECONDS)
        .readTimeout(5, TimeUnit.SECONDS)
        .callTimeout(5, TimeUnit.SECONDS)
        .build()

    override fun get(url: String, host: String, addresses: List<InetAddress>): ConnectionTestOutcome =
        client.newBuilder()
            .dns(PinnedHostDns(host, addresses))
            .build()
            .newCall(Request.Builder().url(url).build())
            .execute()
            .use { response ->
                val code = response.code
                if (code in 200..399) {
                    ConnectionTestOutcome.Success(code)
                } else {
                    ConnectionTestOutcome.Failure("GET returned HTTP $code")
                }
            }
}

internal class PinnedHostDns(
    private val host: String,
    private val addresses: List<InetAddress>,
    private val fallback: Dns = Dns.SYSTEM,
) : Dns {
    override fun lookup(hostname: String): List<InetAddress> =
        if (hostname.equals(host, ignoreCase = true)) {
            addresses
        } else {
            fallback.lookup(hostname)
        }
}

private fun Throwable.readableMessage(): String =
    message ?: this::class.java.simpleName

private fun InetAddress.numericHostAddress(): String =
    hostAddress ?: error("resolved address has no numeric host address")
