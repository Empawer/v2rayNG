package com.v2ray.ang.core

import java.io.ByteArrayOutputStream
import java.net.IDN
import java.net.InetAddress
import java.nio.charset.Charset
import java.util.Locale
import java.util.concurrent.ThreadLocalRandom

/** Structure of a TLS ClientHello, every value is an offset into the packet. */
class DnsChainHelloInfo(
    val sessionId: Int,
    val csStart: Int,
    val cipherSuites: Int,
    val compression: Int,
    val extensions: Int,
    /** (type, start, end) of every extension. */
    val exts: List<Triple<Int, Int, Int>>,
    /** (offset, length) of the hostname, or null. */
    val sni: Pair<Int, Int>?,
)

/**
 * The byte level parts of the DNS chain proxy: DNS packets, the HTTP answer of a DoH server and the
 * cuts of a TLS ClientHello. It has no Android dependency, so JVM tests can cover it.
 */
object DnsChainWire {

    private val LATIN1: Charset = Charsets.ISO_8859_1
    private const val B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    private val CONTENT_LENGTH = Regex("content-length:\\s*(\\d+)")
    private val IPV4 = Regex("^(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\$")

    // ---------------------------------------------------------------- DNS

    /** @throws IllegalArgumentException when [domain] is not a valid name. */
    fun buildDnsQuery(domain: String, qtype: Int = 1): ByteArray {
        val out = ByteArrayOutputStream()
        // id = 0 (RFC 8484), flags = 0x0100, one question
        out.write(byteArrayOf(0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0))
        val name = domain.trimEnd('.')
        val labels: List<String> = if (name.isEmpty()) listOf("") else name.split(".")
        for (raw in labels) {
            val label = if (raw.all { it.code < 128 }) raw else IDN.toASCII(raw, IDN.ALLOW_UNASSIGNED)
            if (name.isNotEmpty() && (label.isEmpty() || label.length > 63)) {
                throw IllegalArgumentException("label empty or too long")
            }
            val bytes = label.toByteArray(Charsets.US_ASCII)
            out.write(bytes.size)
            out.write(bytes)
        }
        out.write(0)
        out.write(qtype shr 8)
        out.write(qtype and 0xFF)
        out.write(0)
        out.write(1)
        return out.toByteArray()
    }

    private fun u8(data: ByteArray, off: Int): Int = data[off].toInt() and 0xFF

    private fun skipName(data: ByteArray, start: Int): Int {
        var off = start
        while (true) {
            val length = u8(data, off)
            if (length == 0) return off + 1
            if ((length and 0xC0) == 0xC0) return off + 2
            off += length + 1
        }
    }

    /** (ip, ttl) of the first A or AAAA record, null when there is none. */
    fun parseDnsResponse(data: ByteArray, qtype: Int): Pair<String, Long>? {
        try {
            if (data.size < 12 || (u8(data, 3) and 0x0F) != 0) return null
            val qdcount = (u8(data, 4) shl 8) or u8(data, 5)
            val ancount = (u8(data, 6) shl 8) or u8(data, 7)
            var off = 12
            for (i in 0 until qdcount) {
                off = skipName(data, off) + 4
            }
            for (i in 0 until ancount) {
                off = skipName(data, off)
                if (off + 10 > data.size) return null
                val rtype = (u8(data, off) shl 8) or u8(data, off + 1)
                val ttl = (u8(data, off + 4).toLong() shl 24) or (u8(data, off + 5).toLong() shl 16) or
                    (u8(data, off + 6).toLong() shl 8) or u8(data, off + 7).toLong()
                val rdlen = (u8(data, off + 8) shl 8) or u8(data, off + 9)
                off += 10
                if (rtype == qtype) {
                    if (qtype == 1 && rdlen == 4 && off + 4 <= data.size) {
                        return "${u8(data, off)}.${u8(data, off + 1)}.${u8(data, off + 2)}.${u8(data, off + 3)}" to ttl
                    }
                    if (qtype == 28 && rdlen == 16 && off + 16 <= data.size) {
                        val raw = data.copyOfRange(off, off + 16)
                        return (InetAddress.getByAddress(raw).hostAddress ?: return null) to ttl
                    }
                }
                off += rdlen
            }
        } catch (_: IndexOutOfBoundsException) {
            // a truncated answer
        }
        return null
    }

    // ---------------------------------------------------------------- HTTP

    private fun indexOfCrlfCrlf(raw: ByteArray): Int {
        var i = 0
        while (i + 3 < raw.size) {
            if (raw[i] == 13.toByte() && raw[i + 1] == 10.toByte() && raw[i + 2] == 13.toByte() && raw[i + 3] == 10.toByte()) {
                return i
            }
            i++
        }
        return -1
    }

    /**
     * The body of the HTTP answer, null when it is not a 200 answer.
     * [onBadStatus] receives the status line of an answer that is not 200.
     */
    fun decodeHttpBody(raw: ByteArray, onBadStatus: (String) -> Unit): ByteArray? {
        val split = indexOfCrlfCrlf(raw)
        if (split < 0) return null
        val head = String(raw, 0, split, LATIN1)
        var body = raw.copyOfRange(split + 4, raw.size)
        val lines = head.split("\r\n")
        val status = lines[0].split(" ", limit = 3)
        if (status.size < 2 || status[1] != "200") {
            onBadStatus(lines[0])
            return null
        }

        val headers = HashMap<String, String>()
        for (line in lines.drop(1)) {
            val colon = line.indexOf(':')
            val key = if (colon < 0) line else line.substring(0, colon)
            val value = if (colon < 0) "" else line.substring(colon + 1)
            headers[key.trim().lowercase(Locale.ROOT)] = value.trim().lowercase(Locale.ROOT)
        }

        if ((headers["transfer-encoding"] ?: "").contains("chunked")) {
            val out = ByteArrayOutputStream()
            while (true) {
                var eol = -1
                var i = 0
                while (i + 1 < body.size) {
                    if (body[i] == 13.toByte() && body[i + 1] == 10.toByte()) {
                        eol = i
                        break
                    }
                    i++
                }
                val sizeLine: ByteArray
                if (eol < 0) {
                    sizeLine = body
                    body = ByteArray(0)
                } else {
                    sizeLine = body.copyOfRange(0, eol)
                    body = body.copyOfRange(eol + 2, body.size)
                }
                val sizeText = String(sizeLine, LATIN1).split(";")[0].trim().ifEmpty { "0" }
                val size = sizeText.toInt(16)
                if (size == 0) break
                val end = minOf(size, body.size)
                out.write(body, 0, end)
                body = if (size + 2 >= body.size) ByteArray(0) else body.copyOfRange(size + 2, body.size)
            }
            return out.toByteArray()
        }
        return body
    }

    /** True when the whole HTTP answer has arrived, so there is no need to wait for the connection to close. */
    fun httpComplete(raw: ByteArray): Boolean {
        val split = indexOfCrlfCrlf(raw)
        if (split < 0) return false
        val low = String(raw, 0, split, LATIN1).lowercase(Locale.ROOT)
        val bodyLength = raw.size - (split + 4)
        val match = CONTENT_LENGTH.find(low)
        if (match != null) {
            val wanted = match.groupValues[1].toLongOrNull() ?: return false
            return bodyLength >= wanted
        }
        if (low.contains("transfer-encoding: chunked")) {
            val tail = byteArrayOf(48, 13, 10, 13, 10) // 0 CR LF CR LF
            if (bodyLength < tail.size) return false
            for (i in tail.indices) {
                if (raw[raw.size - tail.size + i] != tail[i]) return false
            }
            return true
        }
        return false
    }

    /** URL-safe base64 without padding. */
    fun base64Url(data: ByteArray): String {
        val sb = StringBuilder()
        var i = 0
        while (i + 2 < data.size) {
            val b0 = u8(data, i)
            val b1 = u8(data, i + 1)
            val b2 = u8(data, i + 2)
            sb.append(B64[b0 shr 2])
            sb.append(B64[((b0 and 3) shl 4) or (b1 shr 4)])
            sb.append(B64[((b1 and 15) shl 2) or (b2 shr 6)])
            sb.append(B64[b2 and 63])
            i += 3
        }
        val rest = data.size - i
        if (rest == 1) {
            val b0 = u8(data, i)
            sb.append(B64[b0 shr 2])
            sb.append(B64[(b0 and 3) shl 4])
        } else if (rest == 2) {
            val b0 = u8(data, i)
            val b1 = u8(data, i + 1)
            sb.append(B64[b0 shr 2])
            sb.append(B64[((b0 and 3) shl 4) or (b1 shr 4)])
            sb.append(B64[(b1 and 15) shl 2])
        }
        return sb.toString()
    }

    /** What a DoH url holds. [port] is null when the url has none. */
    class DohUrl(val host: String, val port: Int?, val path: String)

    /** Reads a url the way Python's urlparse does. Null when the url has no host or a bad port. */
    fun parseDohUrl(url: String): DohUrl? {
        val schemeEnd = url.indexOf("://")
        if (schemeEnd < 0) return null
        val rest = url.substring(schemeEnd + 3)
        var netlocEnd = rest.length
        for (c in charArrayOf('/', '?', '#')) {
            val i = rest.indexOf(c)
            if (i in 0 until netlocEnd) netlocEnd = i
        }
        val netloc = rest.substring(0, netlocEnd)
        var pathPart = rest.substring(netlocEnd)
        for (c in charArrayOf('?', '#')) {
            val i = pathPart.indexOf(c)
            if (i >= 0) pathPart = pathPart.substring(0, i)
        }

        val hostInfo = netloc.substringAfterLast('@')
        val host: String
        var portText: String? = null
        if (hostInfo.contains('[')) {
            val open = hostInfo.indexOf('[')
            val close = hostInfo.indexOf(']')
            if (close < open) return null
            host = hostInfo.substring(open + 1, close)
            val after = hostInfo.substring(close + 1)
            if (after.startsWith(":")) portText = after.substring(1)
        } else {
            val colon = hostInfo.indexOf(':')
            if (colon < 0) {
                host = hostInfo
            } else {
                host = hostInfo.substring(0, colon)
                portText = hostInfo.substring(colon + 1)
            }
        }
        val lowerHost = host.lowercase(Locale.ROOT)
        if (lowerHost.isEmpty()) return null

        var port: Int? = null
        if (!portText.isNullOrEmpty()) {
            port = portText.toIntOrNull()
            if (port == null || port < 0 || port > 65535) return null
        }
        return DohUrl(lowerHost, port, pathPart.ifEmpty { "/dns-query" })
    }

    /** Python's ipaddress.ip_address: true for an IPv4 or IPv6 literal. */
    fun isIpLiteral(host: String): Boolean {
        if (host.isEmpty()) return false
        if (!host.contains(':')) {
            val m = IPV4.matchEntire(host) ?: return false
            return m.groupValues.drop(1).all { it.toInt() <= 255 }
        }
        if (!host.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' || it == ':' || it == '.' }) return false
        return try {
            // Only digits, colons and dots reach here, so no name lookup happens.
            InetAddress.getByName(host)
            true
        } catch (_: Exception) {
            false
        }
    }

    // ---------------------------------------------------------------- TLS ClientHello

    fun isTlsClientHello(data: ByteArray): Boolean =
        data.size >= 6 && data[0] == 0x16.toByte() && data[1] == 0x03.toByte() && data[5] == 0x01.toByte()

    /** Big endian number of the bytes data[from, to), with the bounds of a Python slice. */
    private fun beSlice(data: ByteArray, from: Int, to: Int): Int {
        var value = 0
        var i = from
        val end = minOf(to, data.size)
        while (i < end) {
            value = (value shl 8) or u8(data, i)
            i++
        }
        return value
    }

    /** (offset, length) of the hostname inside a TLS ClientHello, or null. */
    fun findSniSpan(data: ByteArray): Pair<Int, Int>? {
        try {
            var pos = 5 + 4 + 2 + 32
            pos += 1 + u8(data, pos)
            pos += 2 + beSlice(data, pos, pos + 2)
            pos += 1 + u8(data, pos)
            val extEnd = pos + 2 + beSlice(data, pos, pos + 2)
            pos += 2
            while (pos + 4 <= extEnd) {
                val etype = beSlice(data, pos, pos + 2)
                val elen = beSlice(data, pos + 2, pos + 4)
                if (etype == 0) {
                    val nameLen = beSlice(data, pos + 7, pos + 9)
                    if (nameLen > 0 && pos + 9 + nameLen <= data.size) {
                        return (pos + 9) to nameLen
                    }
                    return null
                }
                pos += 4 + elen
            }
        } catch (_: IndexOutOfBoundsException) {
            // a packet that is cut short
        }
        return null
    }

    /** Offsets of every structural part of a ClientHello, null when it is malformed. */
    fun parseClientHello(data: ByteArray): DnsChainHelloInfo? {
        try {
            if (!isTlsClientHello(data)) return null
            val n = data.size
            var pos = 43
            pos += 1 + u8(data, pos)
            val sessionId = pos
            val csLen = beSlice(data, pos, pos + 2)
            val csStart = pos + 2
            pos += 2 + csLen
            val cipherSuites = pos
            pos += 1 + u8(data, pos)
            val compression = pos
            val extTotal = beSlice(data, pos, pos + 2)
            pos += 2
            val extensions = pos
            val extEnd = minOf(pos + extTotal, n)
            val exts = ArrayList<Triple<Int, Int, Int>>()
            var sni: Pair<Int, Int>? = null
            while (pos + 4 <= extEnd) {
                val etype = beSlice(data, pos, pos + 2)
                val elen = beSlice(data, pos + 2, pos + 4)
                exts.add(Triple(etype, pos, minOf(pos + 4 + elen, n)))
                if (etype == 0 && sni == null) {
                    val nl = beSlice(data, pos + 7, pos + 9)
                    if (nl > 0 && pos + 9 + nl <= n) sni = (pos + 9) to nl
                }
                pos += 4 + elen
            }
            return DnsChainHelloInfo(sessionId, csStart, cipherSuites, compression, extensions, exts, sni)
        } catch (_: IndexOutOfBoundsException) {
            return null
        }
    }

    /** The sorted byte offsets where [points] cut the packet. */
    fun computeCuts(points: List<String>, info: DnsChainHelloInfo, data: ByteArray, sniPieces: Int): List<Int> {
        val n = data.size
        val cuts = HashSet<Int>()

        fun add(c: Int?) {
            if (c != null && c > 0 && c < n) cuts.add(c)
        }

        val exts = info.exts
        val sni = info.sni
        for (t in points) {
            when {
                t == "record_header" || t == "header" -> add(5)
                t == "handshake_header" -> add(9)
                t == "random" -> add(43)
                t == "session_id" -> add(info.sessionId)
                t == "cipher_suites" -> add(info.cipherSuites)
                t == "compression" -> add(info.compression)
                t == "extensions" -> add(info.extensions)
                t == "cipher_suites_mid" -> {
                    val length = info.cipherSuites - info.csStart
                    add(info.csStart + Math.floorDiv(length, 4) * 2)
                }
                t == "ext_each" -> for (e in exts) add(e.second)
                t == "ext_end" -> if (exts.isNotEmpty()) add(exts[exts.size - 1].third)
                t.startsWith("ext:") -> {
                    val name = t.substring(4)
                    val want: Long = DnsChainHello.EXT_BY_NAME[name]?.toLong()
                        ?: DnsChainHello.parseNumber(name)
                        ?: throw IllegalArgumentException("invalid literal for int(): '$name'")
                    for (e in exts) {
                        if (e.first.toLong() == want) {
                            add(e.second)
                            add(e.third)
                        }
                    }
                }
                t == "sni_edges" -> if (sni != null) {
                    add(sni.first)
                    add(sni.first + sni.second)
                }
                t == "sni" -> if (sni != null) {
                    val start = sni.first
                    val ln = sni.second
                    add(start)
                    add(start + ln)
                    val k = minOf(sniPieces, ln)
                    for (i in 1 until k) {
                        add(start + (ln * i) / k)
                    }
                }
                t == "sni_labels" -> if (sni != null) {
                    val start = sni.first
                    val ln = sni.second
                    // every dot of the hostname except a last character
                    for (i in 0 until ln - 1) {
                        if (data[start + i] == 0x2E.toByte()) add(start + i + 1)
                    }
                }
                t.startsWith("every:") -> {
                    val step = t.substring(6).trim().toInt()
                    var c = step
                    while (c < n) {
                        add(c)
                        c += step
                    }
                }
                t.startsWith("random:") -> {
                    val count = t.substring(7).trim().toInt()
                    for (i in 0 until count) {
                        add(ThreadLocalRandom.current().nextInt(1, n))
                    }
                }
                else -> {
                    val v = DnsChainHello.parseNumber(t)
                        ?: throw IllegalArgumentException("invalid literal for int(): '$t'")
                    val c = if (v < 0) n + v else v
                    if (c > 0 && c < n) add(c.toInt())
                }
            }
        }
        return cuts.sorted()
    }

    /**
     * Pieces a ClientHello is sent in. Null when the packet cannot be cut: it is not understood or
     * no cut point is left.
     */
    fun planHelloSplit(data: ByteArray, cfg: DnsChainHelloSplit): List<ByteArray>? {
        val info = parseClientHello(data) ?: return null
        val n = data.size
        val record = cfg.method == "record"

        var pts = ArrayList<Int>()
        var prev = 0
        for (c in computeCuts(cfg.points, info, data, cfg.sniPieces)) {
            if (record && c <= 5) continue // a record needs payload after its header
            if (c - prev >= cfg.minPiece && n - c >= 1) {
                pts.add(c)
                prev = c
            }
        }
        if (cfg.maxPieces > 0 && pts.size + 1 > cfg.maxPieces) {
            pts = ArrayList(pts.take(cfg.maxPieces - 1))
        }
        if (pts.isEmpty()) return null

        val pieces = ArrayList<ByteArray>()
        prev = 0
        val ends = ArrayList(pts)
        ends.add(n)
        for (c in ends) {
            if (record) {
                val lo = maxOf(prev, 5)
                val body = if (lo >= c) ByteArray(0) else data.copyOfRange(lo, c)
                val piece = ByteArray(5 + body.size)
                piece[0] = data[0]
                piece[1] = data[1]
                piece[2] = data[2]
                piece[3] = (body.size shr 8).toByte()
                piece[4] = (body.size and 0xFF).toByte()
                System.arraycopy(body, 0, piece, 5, body.size)
                pieces.add(piece)
            } else {
                pieces.add(data.copyOfRange(prev, c))
            }
            prev = c
        }
        return pieces
    }

    /** Pieces of a ClientHello cut inside the hostname. Null when no hostname was found. */
    fun planSniSplit(data: ByteArray, wantedPieces: Int): List<ByteArray>? {
        val span = findSniSpan(data) ?: return null
        val start = span.first
        val n = span.second
        val count = minOf(wantedPieces, n)
        val cuts = HashSet<Int>()
        for (i in 0 until count) cuts.add(start + (n * i) / count)
        cuts.add(start + n)
        val points = cuts.filter { it > 0 && it < data.size }.sorted()

        val pieces = ArrayList<ByteArray>()
        var prev = 0
        val ends = ArrayList(points)
        ends.add(data.size)
        for (c in ends) {
            if (c <= prev) continue
            pieces.add(data.copyOfRange(prev, c))
            prev = c
        }
        return pieces
    }
}
