package dev.slt.android.profile.rules

import java.net.URI
import java.net.URISyntaxException

fun parseTestUrls(text: String): List<String> {
    val urls = linkedSetOf<String>()
    text.lineSequence().forEachIndexed { index, rawLine ->
        val lineNumber = index + 1
        val line = rawLine.trim()
        if (line.isEmpty()) {
            return@forEachIndexed
        }

        urls.add(normalizeTestUrl(line, lineNumber))
    }
    return urls.toList()
}

fun exportTestUrls(urls: List<String>): String =
    urls.joinToString("\n")

private fun normalizeTestUrl(url: String, lineNumber: Int): String {
    val uri = try {
        URI(url)
    } catch (_: URISyntaxException) {
        throw IllegalArgumentException("Line $lineNumber: test URL is not valid")
    }

    val scheme = uri.scheme?.lowercase()
    require(scheme == "http" || scheme == "https") {
        "Line $lineNumber: test URL must use http or https"
    }
    require(!uri.host.isNullOrBlank()) {
        "Line $lineNumber: test URL must include a host"
    }
    require(uri.rawUserInfo == null) {
        "Line $lineNumber: test URL must not include credentials"
    }

    val port = when {
        scheme == "http" && uri.port == 80 -> -1
        scheme == "https" && uri.port == 443 -> -1
        else -> uri.port
    }

    return URI(
        scheme,
        null,
        uri.host.lowercase(),
        port,
        uri.path?.ifEmpty { null },
        uri.query,
        uri.fragment,
    ).toASCIIString()
}
