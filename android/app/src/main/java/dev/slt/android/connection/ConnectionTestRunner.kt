package dev.slt.android.connection

import dev.slt.android.profile.DnsMode
import dev.slt.android.profile.DnsSettings
import dev.slt.android.profile.SltProfile
import dev.slt.android.profile.VpnRouteRule
import dev.slt.android.profile.rules.vpnRouteActionForAddress
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.IDN
import java.net.InetAddress
import java.net.URI
import java.net.UnknownHostException
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.channelFlow
import kotlinx.coroutines.flow.flowOn
import kotlinx.coroutines.launch
import kotlin.random.Random
import okhttp3.Dns
import okhttp3.OkHttpClient
import okhttp3.Request

internal class ConnectionTestRunner(
    private val dnsFactory: ConnectionTestDnsFactory = ProfileConnectionTestDnsFactory,
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
        val dns = dnsFactory.dnsFor(profile.metadata.dns)
        coroutineScope {
            profile.metadata.testUrls.forEach { url ->
                launch {
                    runOne(url, profile.metadata.routes, dns) { entry -> send(entry) }
                }
            }
        }
    }.flowOn(Dispatchers.IO)

    private suspend fun runOne(
        url: String,
        routes: List<VpnRouteRule>,
        dns: Dns,
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
            dns.lookup(host)
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
            httpClient.get(url, host, addresses, dns)
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

internal fun interface ConnectionTestDnsFactory {
    fun dnsFor(dns: DnsSettings): Dns
}

internal object ProfileConnectionTestDnsFactory : ConnectionTestDnsFactory {
    override fun dnsFor(dns: DnsSettings): Dns =
        when (dns.mode) {
            // System mode has no Android Network handle here, so the lookup uses OkHttp's platform DNS path.
            DnsMode.System -> Dns.SYSTEM
            DnsMode.Custom -> CustomServerDns(dns.servers)
        }
}

internal class CustomServerDns(
    servers: List<String>,
    private val timeoutMillis: Int = DNS_TIMEOUT_MILLIS,
) : Dns {
    private val serverAddresses = servers.mapNotNull(::parseIpv4Address)

    override fun lookup(hostname: String): List<InetAddress> {
        if (serverAddresses.isEmpty()) {
            throw UnknownHostException("No IPv4 DNS servers configured for connection test")
        }

        val asciiHostname = asciiDnsName(hostname)
        val failures = mutableListOf<String>()
        val addresses = DNS_QUERY_TYPES
            .flatMap { queryType -> lookupType(asciiHostname, queryType, failures) }
            .distinctBy { address -> address.hostAddress }

        if (addresses.isNotEmpty()) {
            return addresses
        }

        val detail = failures.ifEmpty { listOf("no A/AAAA records returned") }
            .joinToString("; ")
        throw UnknownHostException("Failed to resolve $hostname using profile DNS: $detail")
    }

    private fun lookupType(
        hostname: String,
        queryType: DnsQueryType,
        failures: MutableList<String>,
    ): List<InetAddress> {
        for (server in serverAddresses) {
            try {
                return queryServer(server, hostname, queryType)
            } catch (error: IOException) {
                failures += "${server.hostAddress}/${queryType.name}: ${error.readableMessage()}"
            }
        }
        return emptyList()
    }

    private fun queryServer(
        server: InetAddress,
        hostname: String,
        queryType: DnsQueryType,
    ): List<InetAddress> {
        val queryId = Random.nextInt(DNS_QUERY_ID_LIMIT)
        val query = buildDnsQuery(queryId, hostname, queryType)
        DatagramSocket().use { socket ->
            socket.soTimeout = timeoutMillis
            val request = DatagramPacket(query, query.size, server, DNS_PORT)
            socket.send(request)

            val buffer = ByteArray(DNS_MAX_UDP_PACKET_SIZE)
            val response = DatagramPacket(buffer, buffer.size)
            socket.receive(response)
            return parseDnsResponse(buffer.copyOf(response.length), queryId, queryType)
        }
    }
}

internal fun interface TestHttpClient {
    @Throws(IOException::class)
    fun get(url: String, host: String, addresses: List<InetAddress>, fallbackDns: Dns): ConnectionTestOutcome
}

internal object OkHttpTestHttpClient : TestHttpClient {
    private val client = OkHttpClient.Builder()
        .connectTimeout(5, TimeUnit.SECONDS)
        .readTimeout(5, TimeUnit.SECONDS)
        .callTimeout(5, TimeUnit.SECONDS)
        .build()

    override fun get(
        url: String,
        host: String,
        addresses: List<InetAddress>,
        fallbackDns: Dns,
    ): ConnectionTestOutcome =
        client.newBuilder()
            .dns(PinnedHostDns(host, addresses, fallbackDns))
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

private enum class DnsQueryType(
    val code: Int,
    val addressLength: Int,
) {
    A(code = 1, addressLength = 4),
    AAAA(code = 28, addressLength = 16),
}

private fun parseIpv4Address(address: String): InetAddress? {
    val parts = address.split(".")
    if (parts.size != 4) {
        return null
    }

    val bytes = parts.map { part ->
        if (part.isEmpty() || part.length > 3 || part.any { character -> !character.isDigit() }) {
            return null
        }
        val value = part.toInt()
        if (value !in 0..255) {
            return null
        }
        value.toByte()
    }
    return InetAddress.getByAddress(bytes.toByteArray())
}

private fun asciiDnsName(hostname: String): String {
    val trimmed = hostname.trimEnd('.')
    if (trimmed.isBlank()) {
        throw UnknownHostException("empty hostname")
    }

    return try {
        IDN.toASCII(trimmed, IDN.USE_STD3_ASCII_RULES)
    } catch (error: IllegalArgumentException) {
        throw UnknownHostException("Invalid DNS name: $hostname").apply { initCause(error) }
    }
}

private fun buildDnsQuery(
    queryId: Int,
    hostname: String,
    queryType: DnsQueryType,
): ByteArray {
    val encodedName = encodeDnsName(hostname)
    return ByteArray(DNS_HEADER_LENGTH + encodedName.size + DNS_QUESTION_TRAILER_LENGTH).also { query ->
        writeUnsignedShort(query, 0, queryId)
        writeUnsignedShort(query, 2, DNS_RECURSION_DESIRED_FLAG)
        writeUnsignedShort(query, 4, 1)
        encodedName.copyInto(query, DNS_HEADER_LENGTH)
        val questionOffset = DNS_HEADER_LENGTH + encodedName.size
        writeUnsignedShort(query, questionOffset, queryType.code)
        writeUnsignedShort(query, questionOffset + 2, DNS_CLASS_IN)
    }
}

private fun encodeDnsName(hostname: String): ByteArray {
    val output = ByteArrayOutputStream()
    hostname.split(".").forEach { label ->
        val labelBytes = label.encodeToByteArray()
        if (labelBytes.isEmpty() || labelBytes.size > DNS_MAX_LABEL_LENGTH) {
            throw UnknownHostException("Invalid DNS label in hostname: $hostname")
        }
        output.write(labelBytes.size)
        output.write(labelBytes)
    }
    output.write(0)

    val encoded = output.toByteArray()
    if (encoded.size > DNS_MAX_ENCODED_NAME_LENGTH) {
        throw UnknownHostException("DNS name is too long: $hostname")
    }
    return encoded
}

private fun parseDnsResponse(
    response: ByteArray,
    expectedQueryId: Int,
    queryType: DnsQueryType,
): List<InetAddress> {
    if (response.size < DNS_HEADER_LENGTH) {
        throw IOException("short DNS response")
    }

    val queryId = readUnsignedShort(response, 0)
    if (queryId != expectedQueryId) {
        throw IOException("mismatched DNS response id")
    }

    val flags = readUnsignedShort(response, 2)
    if (flags and DNS_RESPONSE_FLAG == 0) {
        throw IOException("DNS response flag is not set")
    }
    if (flags and DNS_TRUNCATED_FLAG != 0) {
        throw IOException("truncated DNS response")
    }

    val responseCode = flags and DNS_RESPONSE_CODE_MASK
    if (responseCode != 0) {
        throw UnknownHostException("DNS response code $responseCode")
    }

    val questionCount = readUnsignedShort(response, 4)
    val answerCount = readUnsignedShort(response, 6)
    var offset = DNS_HEADER_LENGTH
    repeat(questionCount) {
        offset = skipDnsName(response, offset)
        offset = checkedAdvance(offset, DNS_QUESTION_TRAILER_LENGTH, response.size)
    }

    val addresses = mutableListOf<InetAddress>()
    repeat(answerCount) {
        offset = skipDnsName(response, offset)
        if (offset + DNS_ANSWER_FIXED_LENGTH > response.size) {
            throw IOException("truncated DNS answer")
        }

        val answerType = readUnsignedShort(response, offset)
        val answerClass = readUnsignedShort(response, offset + 2)
        val dataLength = readUnsignedShort(response, offset + 8)
        offset += DNS_ANSWER_FIXED_LENGTH
        val dataEnd = checkedAdvance(offset, dataLength, response.size)
        if (
            answerClass == DNS_CLASS_IN &&
            answerType == queryType.code &&
            dataLength == queryType.addressLength
        ) {
            addresses += InetAddress.getByAddress(response.copyOfRange(offset, dataEnd))
        }
        offset = dataEnd
    }
    return addresses
}

private fun skipDnsName(message: ByteArray, startOffset: Int): Int {
    var offset = startOffset
    while (true) {
        if (offset >= message.size) {
            throw IOException("truncated DNS name")
        }

        val length = message[offset].toInt() and 0xff
        when (length and DNS_LABEL_POINTER_MASK) {
            DNS_LABEL_POINTER_MASK -> {
                if (offset + 1 >= message.size) {
                    throw IOException("truncated DNS name pointer")
                }
                val pointer = ((length and DNS_LABEL_POINTER_VALUE_MASK) shl 8) or
                    (message[offset + 1].toInt() and 0xff)
                if (pointer >= message.size) {
                    throw IOException("DNS name pointer is out of bounds")
                }
                return offset + 2
            }
            0 -> {
                offset += 1
                if (length == 0) {
                    return offset
                }
                offset = checkedAdvance(offset, length, message.size)
            }
            else -> throw IOException("unsupported DNS label encoding")
        }
    }
}

private fun checkedAdvance(offset: Int, length: Int, limit: Int): Int {
    val nextOffset = offset + length
    if (nextOffset > limit) {
        throw IOException("truncated DNS response")
    }
    return nextOffset
}

private fun readUnsignedShort(bytes: ByteArray, offset: Int): Int {
    if (offset + 2 > bytes.size) {
        throw IOException("truncated DNS response")
    }
    return ((bytes[offset].toInt() and 0xff) shl 8) or
        (bytes[offset + 1].toInt() and 0xff)
}

private fun writeUnsignedShort(bytes: ByteArray, offset: Int, value: Int) {
    bytes[offset] = (value ushr 8).toByte()
    bytes[offset + 1] = value.toByte()
}

private const val DNS_PORT = 53
private const val DNS_TIMEOUT_MILLIS = 5_000
private const val DNS_MAX_UDP_PACKET_SIZE = 512
private const val DNS_QUERY_ID_LIMIT = 0x1_0000
private const val DNS_HEADER_LENGTH = 12
private const val DNS_QUESTION_TRAILER_LENGTH = 4
private const val DNS_ANSWER_FIXED_LENGTH = 10
private const val DNS_CLASS_IN = 1
private const val DNS_RECURSION_DESIRED_FLAG = 0x0100
private const val DNS_RESPONSE_FLAG = 0x8000
private const val DNS_TRUNCATED_FLAG = 0x0200
private const val DNS_RESPONSE_CODE_MASK = 0x000f
private const val DNS_LABEL_POINTER_MASK = 0xc0
private const val DNS_LABEL_POINTER_VALUE_MASK = 0x3f
private const val DNS_MAX_LABEL_LENGTH = 63
private const val DNS_MAX_ENCODED_NAME_LENGTH = 255
private val DNS_QUERY_TYPES = listOf(DnsQueryType.A, DnsQueryType.AAAA)
