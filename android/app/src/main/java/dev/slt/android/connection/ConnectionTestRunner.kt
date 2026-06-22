package dev.slt.android.connection

import dev.slt.android.profile.SltProfile
import dev.slt.android.profile.VpnRouteRule
import dev.slt.android.profile.rules.vpnRouteActionForAddress
import java.io.IOException
import java.net.HttpURLConnection
import java.net.InetAddress
import java.net.URI
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

internal class ConnectionTestRunner(
    private val resolver: HostResolver = JvmHostResolver,
    private val httpClient: TestHttpClient = UrlConnectionTestHttpClient,
) {
    suspend fun run(profile: SltProfile): List<ConnectionTestResult> =
        withContext(Dispatchers.IO) {
            profile.metadata.testUrls.map { url ->
                runOne(url = url, routes = profile.metadata.routes)
            }
        }

    private fun runOne(
        url: String,
        routes: List<VpnRouteRule>,
    ): ConnectionTestResult {
        val host = URI(url).host
            ?: return ConnectionTestResult(
                url = url,
                resolvedAddresses = emptyList(),
                expectedPath = ExpectedNetworkPath.Direct,
                outcome = ConnectionTestOutcome.Failure("URL has no host"),
            )

        val addresses = try {
            resolver.resolve(host)
        } catch (error: IOException) {
            return ConnectionTestResult(
                url = url,
                resolvedAddresses = emptyList(),
                expectedPath = ExpectedNetworkPath.Direct,
                outcome = ConnectionTestOutcome.Failure("DNS failed: ${error.readableMessage()}"),
            )
        }
        val expectedPath = expectedPathForAddresses(routes, addresses)

        val outcome = try {
            httpClient.get(url)
        } catch (error: IOException) {
            ConnectionTestOutcome.Failure("GET failed: ${error.readableMessage()}")
        }

        return ConnectionTestResult(
            url = url,
            resolvedAddresses = addresses.map { it.numericHostAddress() },
            expectedPath = expectedPath,
            outcome = outcome,
        )
    }
}

internal data class ConnectionTestResult(
    val url: String,
    val resolvedAddresses: List<String>,
    val expectedPath: ExpectedNetworkPath,
    val outcome: ConnectionTestOutcome,
)

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
    fun get(url: String): ConnectionTestOutcome
}

internal object UrlConnectionTestHttpClient : TestHttpClient {
    private const val CONNECT_TIMEOUT_MILLIS = 5_000
    private const val READ_TIMEOUT_MILLIS = 5_000

    override fun get(url: String): ConnectionTestOutcome {
        val connection = URI(url).toURL().openConnection() as HttpURLConnection
        return try {
            connection.requestMethod = "GET"
            connection.instanceFollowRedirects = true
            connection.connectTimeout = CONNECT_TIMEOUT_MILLIS
            connection.readTimeout = READ_TIMEOUT_MILLIS
            val statusCode = connection.responseCode
            val responseStream = if (statusCode in 200..399) {
                connection.inputStream
            } else {
                connection.errorStream
            }
            responseStream?.use { stream ->
                val buffer = ByteArray(256)
                stream.read(buffer)
            }
            if (statusCode in 200..399) {
                ConnectionTestOutcome.Success(statusCode)
            } else {
                ConnectionTestOutcome.Failure("GET returned HTTP $statusCode")
            }
        } finally {
            connection.disconnect()
        }
    }
}

private fun Throwable.readableMessage(): String =
    message ?: this::class.java.simpleName

private fun InetAddress.numericHostAddress(): String =
    hostAddress ?: error("resolved address has no numeric host address")
