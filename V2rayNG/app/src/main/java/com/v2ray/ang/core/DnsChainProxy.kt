package com.v2ray.ang.core

import java.io.BufferedInputStream
import java.io.ByteArrayOutputStream
import java.io.EOFException
import java.io.IOException
import java.io.InputStream
import java.io.InterruptedIOException
import java.io.OutputStream
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketException
import java.net.SocketTimeoutException
import java.net.UnknownHostException
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.security.cert.X509Certificate
import java.util.Collections
import java.util.Locale
import java.util.concurrent.Callable
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ExecutionException
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.Future
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.ThreadLocalRandom
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import javax.net.ssl.SSLException
import javax.net.ssl.SSLPeerUnverifiedException
import javax.net.ssl.SSLSession
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

/** Receives the log lines of the proxy. [level] is one of the levels of [DnsChainProxy]. */
fun interface DnsChainLog {
    fun write(level: Int, message: String)
}

/**
 * SOCKS5 / HTTP CONNECT proxy with SNI / Hello split and DNS over HTTPS.
 *
 * This is a port of main.py, the Python proxy, with the same behaviour: the same settings, the same
 * DoH race with cooldowns, the same caches, the same cuts of the ClientHello.
 *
 * It uses plain JVM sockets and nothing of Android, so it does not touch the VPN: it runs in the
 * chain process of the app, which keeps its sockets away from the tunnel (see [DnsChainNetwork]).
 */
class DnsChainProxy(
    private val cfg: DnsChainSettings,
    private val log: DnsChainLog,
    private val tuneSocket: (Socket) -> Unit = { defaultTune(it) },
) {

    companion object {
        const val DEBUG = 10
        const val INFO = 20
        const val WARNING = 30
        const val ERROR = 40

        /** Banner lines that are always shown, as a print in the Python proxy. */
        const val PRINT = 100

        private const val READ_SIZE = 16384
        private const val MAX_TLS_RECORD = 5 + 16384 + 2048
        private const val DNS_CACHE_MAX = 2048

        private const val SOCKS_OK = 0x00
        private const val SOCKS_GENERAL_FAILURE = 0x01
        private const val SOCKS_HOST_UNREACHABLE = 0x04
        private const val SOCKS_CONN_REFUSED = 0x05
        private const val SOCKS_CMD_UNSUPPORTED = 0x07

        // Linux values of the TCP keep alive options.
        private const val TCP_KEEPIDLE = 4
        private const val TCP_KEEPINTVL = 5
        private const val TCP_KEEPCNT = 6

        fun defaultTune(socket: Socket) {
            try {
                socket.tcpNoDelay = true
            } catch (_: Exception) {
            }
            try {
                socket.keepAlive = true
            } catch (_: Exception) {
            }
        }

        /** Like [defaultTune], and the keep alive timers of the Python proxy where the platform allows them. */
        fun androidTune(socket: Socket) {
            defaultTune(socket)
            val pfd = try {
                android.os.ParcelFileDescriptor.fromSocket(socket)
            } catch (_: Exception) {
                return
            }
            try {
                val opts = listOf(TCP_KEEPIDLE to 30, TCP_KEEPINTVL to 10, TCP_KEEPCNT to 3)
                for ((option, value) in opts) {
                    try {
                        android.system.Os.setsockoptInt(pfd.fileDescriptor, android.system.OsConstants.IPPROTO_TCP, option, value)
                    } catch (_: Exception) {
                    }
                }
            } finally {
                try {
                    pfd.close()
                } catch (_: Exception) {
                }
            }
        }
    }

    // ------------------------------------------------------------------ state

    private val pool: ExecutorService = Executors.newCachedThreadPool { r ->
        Thread(r, "dns-chain").also { it.isDaemon = true }
    }

    @Volatile
    private var stopped = false
    private var serverSocket: ServerSocket? = null
    private val active: MutableSet<Socket> = Collections.synchronizedSet(HashSet<Socket>())

    private val dnsCache = ConcurrentHashMap<String, Pair<String, Double>>()
    private val negCache = ConcurrentHashMap<String, Double>()
    private val dohIpCache = ConcurrentHashMap<String, Pair<String, Double>>()
    private val inflight = ConcurrentHashMap<String, CompletableFuture<String?>>()

    private class Health {
        var fails = 0
        var until = 0.0
    }

    private val health = HashMap<String, Health>()

    private fun mono(): Double = System.nanoTime() / 1e9

    private fun d(msg: String) = log.write(DEBUG, msg)
    private fun i(msg: String) = log.write(INFO, msg)
    private fun w(msg: String) = log.write(WARNING, msg)

    private fun why(e: Throwable?): String {
        if (e == null) return "error"
        val msg = e.message
        return if (!msg.isNullOrEmpty()) "${e.javaClass.simpleName}: $msg" else e.javaClass.simpleName
    }

    private fun closeQuietly(s: Socket?) {
        if (s == null) return
        try {
            s.close()
        } catch (_: Exception) {
        }
    }

    private fun closeBoth(a: Socket?, b: Socket?) {
        closeQuietly(a)
        closeQuietly(b)
    }

    // ------------------------------------------------------------------ server

    fun isRunning(): Boolean = !stopped && serverSocket?.isClosed == false

    /**
     * Binds the listening socket and starts serving. Returns when the proxy is ready.
     *
     * @throws IOException when the address cannot be used, for example because the port is taken.
     */
    @Throws(IOException::class)
    fun start() {
        val server = ServerSocket()
        try {
            server.reuseAddress = true
            server.bind(InetSocketAddress(InetAddress.getByName(cfg.listenIp), cfg.listenPort), 100)
        } catch (e: IOException) {
            closeQuietlyServer(server)
            throw e
        }
        serverSocket = server

        for (warning in cfg.warnings) {
            log.write(if (warning.startsWith("Section")) ERROR else WARNING, warning)
        }
        log.write(PRINT, "=".repeat(60))
        log.write(PRINT, "[*] Proxy listening on ${cfg.listenIp}:${cfg.listenPort}")
        if (cfg.dohServers.isNotEmpty()) {
            log.write(PRINT, "[*] DoH servers (queried in parallel, first answer wins): ${cfg.dohServers.size}")
            for (url in cfg.dohServers) log.write(PRINT, "    - $url")
        } else {
            log.write(PRINT, "[*] DoH: Disabled (system DNS)")
        }
        log.write(PRINT, "[*] Idle timeout: ${if (cfg.idleTimeout == 0) "disabled" else "${cfg.idleTimeout}s"}")
        val hello = cfg.helloSplit
        val sni = cfg.sniSplit
        if (hello != null) {
            val ms = if (hello.maxPieces == 0) "unlimited" else hello.maxPieces.toString()
            log.write(
                PRINT,
                "[*] Hello split: method=${hello.method} delay=${hello.delay}s jitter=${hello.jitter}s " +
                    "max_pieces=$ms\n    points=${hello.points.joinToString(",")}",
            )
            if (sni != null) {
                log.write(PRINT, "[*] SNI split: standby (used only if Hello split cannot parse a packet)")
            }
        } else if (sni != null) {
            log.write(PRINT, "[*] SNI split: pieces=${sni.pieces} delay=${sni.delay}s")
        } else {
            log.write(PRINT, "[*] SNI split / Hello split: disabled")
        }
        log.write(PRINT, "=".repeat(60))
        log.write(PRINT, "Waiting for client connections...")

        pool.execute { warmUpDoh() }
        val acceptor = Thread({ acceptLoop(server) }, "dns-chain-accept")
        acceptor.isDaemon = true
        acceptor.start()
    }

    private fun closeQuietlyServer(server: ServerSocket) {
        try {
            server.close()
        } catch (_: Exception) {
        }
    }

    /** Stops serving and closes every connection. */
    fun stop() {
        stopped = true
        serverSocket?.let { closeQuietlyServer(it) }
        val open = synchronized(active) { ArrayList(active) }
        for (s in open) closeQuietly(s)
        pool.shutdownNow()
    }

    private fun acceptLoop(server: ServerSocket) {
        while (!stopped) {
            val client = try {
                server.accept()
            } catch (e: IOException) {
                if (!stopped && !server.isClosed) {
                    w("accept failed: ${why(e)}")
                    continue
                }
                break
            }
            try {
                pool.execute { handleConnection(client) }
            } catch (e: Exception) {
                closeQuietly(client)
                if (stopped) break
            }
        }
    }

    // ------------------------------------------------------------------ DoH health

    private fun healthOf(url: String): Health = synchronized(health) { health.getOrPut(url) { Health() } }

    private fun markOk(url: String, rtt: Double) {
        val h = healthOf(url)
        val hadFails = synchronized(health) {
            val had = h.fails != 0
            h.fails = 0
            h.until = 0.0
            had
        }
        if (hadFails) i("DoH $url is back (${Math.round(rtt * 1000)} ms)")
    }

    private fun markFail(url: String, reason: String) {
        val h = healthOf(url)
        var fails = 0
        var cooldown = 0.0
        synchronized(health) {
            h.fails += 1
            fails = h.fails
            cooldown = minOf(
                cfg.dohCooldown * Math.pow(2.0, minOf(h.fails - 1, 10).toDouble()),
                DnsChainSettings.DOH_COOLDOWN_MAX,
            )
            h.until = mono() + cooldown
        }
        if (fails == 1) {
            w("DoH $url failed ($reason) - paused for ${Math.round(cooldown)}s")
        } else {
            d("DoH $url failed again ($reason) - paused for ${Math.round(cooldown)}s")
        }
    }

    private fun activeServers(): List<String> {
        val now = mono()
        val ready = cfg.dohServers.filter { url ->
            val h = healthOf(url)
            synchronized(health) { h.until } <= now
        }
        // If every server is paused, try all of them again.
        return ready.ifEmpty { cfg.dohServers.toList() }
    }

    // ------------------------------------------------------------------ one DoH request

    private class Attempt(val url: String) {
        @Volatile
        var socket: Socket? = null

        @Volatile
        var cancelled = false

        fun cancel() {
            cancelled = true
            try {
                socket?.close()
            } catch (_: Exception) {
            }
        }
    }

    private class Outcome(
        val url: String,
        val result: Pair<String, Long>?,
        val error: Throwable?,
        val rtt: Double,
        val ok: Boolean,
    )

    private class RaceResult(val answer: Pair<String, Long>?, val answered: Boolean)

    /** IP address of a DoH server. The result for a host name is cached for 10 minutes. */
    private fun dohConnectIp(host: String): String {
        if (DnsChainWire.isIpLiteral(host)) return host
        val cached = dohIpCache[host]
        if (cached != null && cached.second > mono()) return cached.first
        val all = InetAddress.getAllByName(host).sortedBy { it !is Inet4Address }
        val ip = all[0].hostAddress ?: throw UnknownHostException(host)
        dohIpCache[host] = ip to (mono() + 600)
        return ip
    }

    private fun dnsNameMatches(pattern: String, host: String): Boolean {
        val p = pattern.lowercase(Locale.ROOT).trimEnd('.')
        val h = host.lowercase(Locale.ROOT).trimEnd('.')
        if (p.startsWith("*.")) {
            val dot = h.indexOf('.')
            return dot > 0 && h.substring(dot + 1) == p.substring(2)
        }
        return p == h
    }

    /** The certificate must name the host: an IP address entry for an IP host, a DNS name entry otherwise. */
    private fun verifyHost(host: String, session: SSLSession) {
        val cert = session.peerCertificates.firstOrNull() as? X509Certificate
            ?: throw SSLPeerUnverifiedException("no certificate")
        val isIp = DnsChainWire.isIpLiteral(host)
        val names = (
            try {
                cert.subjectAlternativeNames
            } catch (_: Exception) {
                null
            }
            ) ?: throw SSLPeerUnverifiedException("certificate has no alternative names")
        for (entry in names) {
            val type = entry[0] as? Int ?: continue
            val value = entry[1] as? String ?: continue
            if (isIp && type == 7) {
                try {
                    if (InetAddress.getByName(value) == InetAddress.getByName(host)) return
                } catch (_: Exception) {
                }
            } else if (!isIp && type == 2) {
                if (dnsNameMatches(value, host)) return
            }
        }
        throw SSLPeerUnverifiedException("certificate does not match $host")
    }

    private fun dohQuery(attempt: Attempt, domain: String, qtype: Int): Pair<String, Long>? {
        val url = attempt.url
        val parsed = DnsChainWire.parseDohUrl(url) ?: throw IllegalArgumentException("invalid DoH url: $url")
        val host = parsed.host
        val explicitPort = parsed.port
        val port = explicitPort ?: 443
        val path = parsed.path
        val b64 = DnsChainWire.base64Url(DnsChainWire.buildDnsQuery(domain, qtype))

        var hostHeader = if (host.contains(':')) "[$host]" else host // an IPv6 address goes in brackets
        if (explicitPort != null && explicitPort != 0 && explicitPort != 443) hostHeader += ":$explicitPort"

        val connectIp = dohConnectIp(host)
        val soTimeout = Math.max(1, Math.round(cfg.dohTimeout * 1000).toInt())

        val plain = Socket()
        attempt.socket = plain
        var ssl: SSLSocket? = null
        try {
            if (attempt.cancelled) throw IOException("cancelled")
            plain.connect(InetSocketAddress(InetAddress.getByName(connectIp), port), soTimeout)
            plain.soTimeout = soTimeout
            val factory = SSLSocketFactory.getDefault() as SSLSocketFactory
            val secure = factory.createSocket(plain, host, port, true) as SSLSocket
            ssl = secure
            attempt.socket = secure
            secure.startHandshake()
            verifyHost(host, secure.session)

            val request = "GET $path?dns=$b64 HTTP/1.1\r\n" +
                "Host: $hostHeader\r\n" +
                "Accept: application/dns-message\r\n" +
                "Connection: close\r\n\r\n"
            val out = secure.outputStream
            out.write(request.toByteArray(Charsets.UTF_8))
            out.flush()

            val input = secure.inputStream
            val buf = ByteArray(4096)
            val collected = ByteArrayOutputStream()
            var response = ByteArray(0)
            while (response.size < 65536 && !DnsChainWire.httpComplete(response)) {
                val n = try {
                    input.read(buf)
                } catch (e: SSLException) {
                    // Some servers close without a close_notify, keep what has arrived.
                    if (response.isNotEmpty()) break
                    throw e
                } catch (e: SocketException) {
                    if (response.isNotEmpty()) break
                    throw e
                }
                if (n < 0) break
                collected.write(buf, 0, n)
                response = collected.toByteArray()
            }

            val body = DnsChainWire.decodeHttpBody(response) { line -> w("DoH server returned: $line") }
                ?: throw RuntimeException("invalid or non-200 HTTP response")
            return DnsChainWire.parseDnsResponse(body, qtype)
        } finally {
            closeQuietly(ssl)
            closeQuietly(plain)
        }
    }

    // ------------------------------------------------------------------ DoH race

    /**
     * Sends the request to every healthy server at the same time and returns the first answer,
     * the others are cancelled at once. The result is (answer or null, did at least one server answer).
     */
    private fun raceDoh(domain: String, qtype: Int): RaceResult {
        val servers = activeServers()
        val queue = LinkedBlockingQueue<Outcome>()
        val attempts = ArrayList<Attempt>()
        val futures = ArrayList<Future<*>>()
        for (url in servers) {
            val attempt = Attempt(url)
            attempts.add(attempt)
            futures.add(
                pool.submit(
                    Runnable {
                        val t0 = mono()
                        try {
                            val res = dohQuery(attempt, domain, qtype)
                            queue.put(Outcome(url, res, null, mono() - t0, true))
                        } catch (e: Throwable) {
                            queue.put(Outcome(url, null, e, 0.0, false))
                        }
                    },
                ),
            )
        }

        val pending = HashSet<String>(servers)
        val deadline = System.nanoTime() + Math.round(cfg.dohTimeout * 1e9)
        var timedOut = false
        try {
            while (pending.isNotEmpty()) {
                val remaining = deadline - System.nanoTime()
                if (remaining <= 0) {
                    timedOut = true
                    break
                }
                val outcome = queue.poll(remaining, TimeUnit.NANOSECONDS)
                if (outcome == null) {
                    timedOut = true
                    break
                }
                pending.remove(outcome.url)
                if (!outcome.ok) {
                    markFail(outcome.url, why(outcome.error))
                    continue
                }
                markOk(outcome.url, outcome.rtt)
                d("DoH winner for $domain: ${outcome.url} (${Math.round(outcome.rtt * 1000)} ms)")
                return RaceResult(outcome.result, true)
            }
            if (timedOut) {
                for (u in pending) markFail(u, "timeout")
            }
            w("No DoH server answered for $domain")
            return RaceResult(null, false)
        } finally {
            for (a in attempts) a.cancel()
            for (f in futures) f.cancel(true)
        }
    }

    private fun resolveDohUncached(domain: String): String? {
        try {
            DnsChainWire.buildDnsQuery(domain, 1) // an invalid name must not count against the servers
        } catch (_: IllegalArgumentException) {
            return null
        }
        for (qtype in intArrayOf(1, 28)) { // A, then AAAA
            val race = raceDoh(domain, qtype)
            val res = race.answer
            if (res != null) {
                val ip = res.first
                val ttl = res.second
                if (dnsCache.size >= DNS_CACHE_MAX) dnsCache.clear()
                dnsCache[domain] = ip to (mono() + minOf(maxOf(ttl, 30L), 3600L))
                return ip
            }
            if (!race.answered) return null // no server answered, do not waste time on AAAA
        }
        return null
    }

    private fun resolveWithDoh(domain: String): String? {
        if (cfg.dohServers.isEmpty()) return null
        val blockedUntil = negCache[domain]
        if (blockedUntil != null && blockedUntil > mono()) return null

        // Requests for one name at the same time share one race.
        val mine = CompletableFuture<String?>()
        val existing = inflight.putIfAbsent(domain, mine)
        val ip: String? = if (existing != null) {
            try {
                existing.get()
            } catch (_: ExecutionException) {
                null
            }
        } else {
            try {
                val result = resolveDohUncached(domain)
                mine.complete(result)
                result
            } catch (e: Throwable) {
                mine.completeExceptionally(e)
                throw e
            } finally {
                inflight.remove(domain)
            }
        }

        if (ip == null) {
            if (negCache.size >= DNS_CACHE_MAX) negCache.clear()
            negCache[domain] = mono() + DnsChainSettings.NEG_CACHE_TTL
        }
        return ip
    }

    /** Tests every server at the start, so a broken server is skipped from the first request. */
    private fun warmUpDoh() {
        if (cfg.dohServers.isEmpty()) return

        val tasks = cfg.dohServers.map { url -> pool.submit(Runnable { probe(url) }) }
        for (t in tasks) {
            try {
                t.get()
            } catch (_: Exception) {
            }
        }
        val good = cfg.dohServers.count { url ->
            val h = healthOf(url)
            synchronized(health) { h.fails } == 0
        }
        i("DoH ready: $good/${cfg.dohServers.size} servers responding")
    }

    private fun probe(url: String) {
        val t0 = mono()
        val attempt = Attempt(url)
        val job = pool.submit(Callable<Pair<String, Long>?> { dohQuery(attempt, cfg.testDomain, 1) })
        val res: Pair<String, Long>?
        try {
            res = job.get(Math.round(cfg.dohTimeout * 1e9), TimeUnit.NANOSECONDS)
        } catch (_: TimeoutException) {
            attempt.cancel()
            job.cancel(true)
            markFail(url, "TimeoutError")
            return
        } catch (e: ExecutionException) {
            markFail(url, why(e.cause ?: e))
            return
        } catch (e: Exception) {
            markFail(url, why(e))
            return
        }
        val rtt = mono() - t0
        markOk(url, rtt)
        val note = if (res == null) " [no A record for ${cfg.testDomain}]" else ""
        i("DoH OK      $url (${Math.round(rtt * 1000)} ms)$note")
    }

    private fun resolveHost(host: String): String {
        if (DnsChainWire.isIpLiteral(host)) return host

        val cached = dnsCache[host]
        if (cached != null && cached.second > mono()) return cached.first

        if (cfg.dohServers.isNotEmpty()) {
            val ip = resolveWithDoh(host)
            if (ip != null) {
                d("DoH resolved $host -> $ip")
                return ip
            }
        }

        val job = pool.submit(Callable<Array<InetAddress>> { InetAddress.getAllByName(host) })
        val all = try {
            job.get(Math.round(cfg.systemDnsTimeout * 1e9), TimeUnit.NANOSECONDS)
        } catch (_: TimeoutException) {
            job.cancel(true)
            throw SocketTimeoutException("system DNS timed out")
        } catch (e: ExecutionException) {
            throw (e.cause ?: e)
        }
        val sorted = all.sortedBy { it !is Inet4Address } // IPv4 first
        return sorted[0].hostAddress ?: throw UnknownHostException(host)
    }

    // ------------------------------------------------------------------ sending the ClientHello

    private fun sleepSeconds(seconds: Double) {
        if (seconds <= 0) return
        val nanos = Math.round(seconds * 1e9)
        try {
            Thread.sleep(nanos / 1_000_000L, (nanos % 1_000_000L).toInt())
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
            throw InterruptedIOException("interrupted")
        }
    }

    private fun sendPieces(out: OutputStream, pieces: List<ByteArray>, delayAfter: (Int) -> Double) {
        for ((index, piece) in pieces.withIndex()) {
            out.write(piece)
            out.flush()
            if (index == pieces.size - 1) break
            sleepSeconds(delayAfter(index))
        }
    }

    /** Sends the ClientHello cut inside the hostname. False if no hostname was found. */
    private fun sendSplitSni(out: OutputStream, data: ByteArray, cfgSni: DnsChainSniSplit): Boolean {
        val pieces = DnsChainWire.planSniSplit(data, cfgSni.pieces) ?: return false
        sendPieces(out, pieces) { cfgSni.delay }
        return true
    }

    /** Sends the ClientHello cut at the configured points. False means it does not apply. */
    private fun sendHelloSplit(out: OutputStream, data: ByteArray, h: DnsChainHelloSplit): Boolean {
        val pieces = DnsChainWire.planHelloSplit(data, h) ?: return false
        d("hello split: ${pieces.size} pieces (${h.method})")
        sendPieces(out, pieces) { index ->
            var delay = h.delay
            if (index == 0 && h.firstDelay != null) delay = h.firstDelay
            if (h.jitter > 0) delay += ThreadLocalRandom.current().nextDouble(0.0, h.jitter)
            delay
        }
        return true
    }

    // ------------------------------------------------------------------ streaming

    private fun timeoutMs(seconds: Double): Int {
        val ms = Math.round(seconds * 1000)
        return if (ms < 0) 0 else if (ms > Int.MAX_VALUE) Int.MAX_VALUE else ms.toInt()
    }

    private fun setReadTimeout(socket: Socket, ms: Int) {
        try {
            socket.soTimeout = ms
        } catch (_: Exception) {
        }
    }

    private fun idleMs(): Int = if (cfg.idleTimeout > 0) timeoutMs(cfg.idleTimeout.toDouble()) else 0

    /** Reads a chunk. Throws [SocketTimeoutException] after idle_timeout seconds of silence. */
    private fun readChunk(input: InputStream, socket: Socket): ByteArray {
        setReadTimeout(socket, idleMs())
        val buf = ByteArray(READ_SIZE)
        val n = input.read(buf)
        return if (n <= 0) ByteArray(0) else buf.copyOf(n)
    }

    /** The first data of the client. If it is a TLS ClientHello, the whole record is read. */
    private fun readFirstClientChunk(input: InputStream, socket: Socket): ByteArray {
        var data = readChunk(input, socket)
        if (data.size >= 5 && data[0] == 0x16.toByte() && data[1] == 0x03.toByte()) {
            val recordLength = ((data[3].toInt() and 0xFF) shl 8) or (data[4].toInt() and 0xFF)
            val need = minOf(5 + recordLength, MAX_TLS_RECORD)
            while (data.size < need) {
                setReadTimeout(socket, timeoutMs(cfg.handshakeTimeout))
                val buf = ByteArray(need - data.size)
                val n = input.read(buf)
                if (n <= 0) break
                data += buf.copyOf(n)
            }
        }
        return data
    }

    /** Copies one direction. True on a clean end of the stream, false on an error or a timeout. */
    private fun forwardStream(input: InputStream, out: OutputStream, inSocket: Socket, outSocket: Socket, isClient: Boolean): Boolean {
        var packetNum = 0
        var ok = true
        try {
            while (true) {
                val data: ByteArray = try {
                    if (isClient && packetNum == 0) readFirstClientChunk(input, inSocket) else readChunk(input, inSocket)
                } catch (_: SocketTimeoutException) {
                    i("Idle timeout — closing")
                    ok = false
                    break
                }
                if (data.isEmpty()) break

                if (isClient) {
                    packetNum += 1
                    if (packetNum == 1 && DnsChainWire.isTlsClientHello(data)) {
                        val hello = cfg.helloSplit
                        if (hello != null && sendHelloSplit(out, data, hello)) continue
                        val sni = cfg.sniSplit
                        if (sni != null && sendSplitSni(out, data, sni)) continue
                    }
                }

                out.write(data)
                out.flush()
            }
        } catch (e: IOException) {
            d("Forward stream error: ${why(e)}")
            ok = false
        } catch (e: Exception) {
            w("Forward unexpected error: ${why(e)}")
            ok = false
        } finally {
            if (ok) {
                // half-close: only tell that nothing more is sent
                try {
                    outSocket.shutdownOutput()
                } catch (_: Exception) {
                }
            }
        }
        return ok
    }

    // ------------------------------------------------------------------ proxy handshakes

    private class Request(val proto: String, val host: String, val port: Int)

    private fun socks5Reply(code: Int): ByteArray =
        byteArrayOf(0x05, code.toByte(), 0x00, 0x01, 0, 0, 0, 0, 0, 0)

    /** Reads exactly [n] bytes before the [deadline] (System.nanoTime). */
    private fun readExactly(socket: Socket, input: InputStream, n: Int, deadline: Long): ByteArray {
        val buf = ByteArray(n)
        var got = 0
        while (got < n) {
            val remainingMs = (deadline - System.nanoTime()) / 1_000_000L
            if (remainingMs <= 0) throw SocketTimeoutException("handshake timeout")
            socket.soTimeout = if (remainingMs > Int.MAX_VALUE) Int.MAX_VALUE else remainingMs.toInt()
            val r = input.read(buf, got, n - got)
            if (r < 0) throw EOFException()
            got += r
        }
        return buf
    }

    /** Reads until the end of the HTTP header, the separator included. A header over 64 KiB is refused. */
    private fun readUntilHeaderEnd(socket: Socket, input: InputStream, deadline: Long): ByteArray {
        val out = ByteArrayOutputStream()
        var matched = 0
        val sep = byteArrayOf(13, 10, 13, 10)
        while (true) {
            val b = readExactly(socket, input, 1, deadline)[0]
            out.write(b.toInt())
            if (out.size() > 65536) throw IllegalStateException("header too long")
            matched = if (b == sep[matched]) matched + 1 else if (b == sep[0]) 1 else 0
            if (matched == sep.size) return out.toByteArray()
        }
    }

    private fun decodeIgnoring(bytes: ByteArray): String {
        val decoder = Charsets.UTF_8.newDecoder()
            .onMalformedInput(CodingErrorAction.IGNORE)
            .onUnmappableCharacter(CodingErrorAction.IGNORE)
        return decoder.decode(ByteBuffer.wrap(bytes)).toString()
    }

    /**
     * Parses the first request of the client. Returns the protocol, host and port; no success reply
     * is sent here.
     */
    private fun readRequest(socket: Socket, input: InputStream, out: OutputStream): Request? {
        val deadline = System.nanoTime() + Math.round(cfg.handshakeTimeout * 1e9)
        val head = readExactly(socket, input, 1, deadline)[0].toInt() and 0xFF

        // ---- SOCKS5 ----
        if (head == 0x05) {
            val nmethods = readExactly(socket, input, 1, deadline)[0].toInt() and 0xFF
            val methods = readExactly(socket, input, nmethods, deadline)
            if (methods.none { it == 0.toByte() }) {
                out.write(byteArrayOf(0x05, 0xFF.toByte()))
                out.flush()
                return null
            }
            out.write(byteArrayOf(0x05, 0x00))
            out.flush()

            val request = readExactly(socket, input, 4, deadline)
            val ver = request[0].toInt() and 0xFF
            val cmd = request[1].toInt() and 0xFF
            val atyp = request[3].toInt() and 0xFF
            if (ver != 5) return null
            if (cmd != 1) {
                i("Unsupported SOCKS5 command: $cmd")
                out.write(socks5Reply(SOCKS_CMD_UNSUPPORTED))
                out.flush()
                return null
            }

            val host: String
            if (atyp == 1) {
                val raw = readExactly(socket, input, 4, deadline)
                host = raw.joinToString(".") { (it.toInt() and 0xFF).toString() }
            } else if (atyp == 3) {
                val len = readExactly(socket, input, 1, deadline)[0].toInt() and 0xFF
                host = decodeIgnoring(readExactly(socket, input, len, deadline))
            } else if (atyp == 4) {
                host = InetAddress.getByAddress(readExactly(socket, input, 16, deadline)).hostAddress ?: ""
            } else {
                i("Unsupported address type: $atyp")
                out.write(socks5Reply(0x08))
                out.flush()
                return null
            }

            val portBytes = readExactly(socket, input, 2, deadline)
            val port = ((portBytes[0].toInt() and 0xFF) shl 8) or (portBytes[1].toInt() and 0xFF)
            return Request("socks5", host, port)
        }

        // ---- HTTP CONNECT ----
        if (head == 'C'.code || head == 'c'.code) {
            val rest = readUntilHeaderEnd(socket, input, deadline)
            val all = ByteArray(1 + rest.size)
            all[0] = head.toByte()
            System.arraycopy(rest, 0, all, 1, rest.size)
            val firstLine = decodeIgnoring(all).split("\r\n")[0]
            val parts = firstLine.split(" ")
            if (parts.size < 2 || parts[0].uppercase(Locale.ROOT) != "CONNECT") return null

            val target = parts[1]
            val host: String
            val port: Int
            if (target.startsWith("[")) { // [IPv6]:port
                val end = target.indexOf(']')
                if (end == -1) return null
                host = target.substring(1, end)
                val portText = if (end + 2 <= target.length) target.substring(end + 2) else ""
                port = if (portText.isNotEmpty()) portText.trim().toInt() else 443
            } else if (target.contains(':')) {
                val colon = target.lastIndexOf(':')
                host = target.substring(0, colon)
                port = target.substring(colon + 1).trim().toInt()
            } else {
                host = target
                port = 443
            }
            return Request("http", host, port)
        }

        i("Unknown protocol (first byte: ${Integer.toHexString(head).padStart(2, '0')})")
        return null
    }

    private fun sendSuccess(proto: String, out: OutputStream) {
        if (proto == "socks5") {
            out.write(socks5Reply(SOCKS_OK))
        } else {
            out.write("HTTP/1.1 200 Connection Established\r\n\r\n".toByteArray(Charsets.ISO_8859_1))
        }
        out.flush()
    }

    private fun sendFailure(proto: String, out: OutputStream, e: Throwable) {
        try {
            if (proto == "socks5") {
                val refused = e is java.net.ConnectException &&
                    (e.message ?: "").lowercase(Locale.ROOT).contains("refused")
                val code = if (refused) {
                    SOCKS_CONN_REFUSED
                } else if (e is SocketTimeoutException || e is TimeoutException || e is UnknownHostException) {
                    SOCKS_HOST_UNREACHABLE
                } else {
                    SOCKS_GENERAL_FAILURE
                }
                out.write(socks5Reply(code))
            } else {
                out.write("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n".toByteArray(Charsets.ISO_8859_1))
            }
            out.flush()
        } catch (_: Exception) {
        }
    }

    // ------------------------------------------------------------------ connection handler

    private fun handleConnection(client: Socket) {
        val peer = client.remoteSocketAddress as? InetSocketAddress
        val clientName = if (peer != null) "${peer.address?.hostAddress}:${peer.port}" else "unknown"
        d("New connection from $clientName")

        val remote = Socket()
        active.add(client)
        active.add(remote)
        try {
            val input = BufferedInputStream(client.getInputStream(), READ_SIZE)
            val output = client.getOutputStream()

            val req: Request? = try {
                readRequest(client, input, output)
            } catch (_: EOFException) {
                d("Handshake failed/aborted by $clientName")
                return
            } catch (_: SocketTimeoutException) {
                d("Handshake failed/aborted by $clientName")
                return
            } catch (e: IllegalArgumentException) {
                i("Bad request from $clientName: ${why(e)}")
                return
            } catch (e: IllegalStateException) {
                i("Bad request from $clientName: ${why(e)}")
                return
            }
            if (req == null) return

            val proto = req.proto
            val targetHost = req.host
            val targetPort = req.port

            try {
                val resolvedIp = resolveHost(targetHost)
                i("[$proto] $clientName -> $targetHost ($resolvedIp):$targetPort")
                remote.connect(InetSocketAddress(InetAddress.getByName(resolvedIp), targetPort), timeoutMs(cfg.connectTimeout))
            } catch (e: Exception) {
                i("Connect to $targetHost:$targetPort failed: ${why(e)}")
                sendFailure(proto, output, e)
                return
            }

            // Only now do we tell the client that it is connected.
            sendSuccess(proto, output)

            tuneSocket(remote)
            tuneSocket(client)

            val remoteInput = remote.getInputStream()
            val remoteOutput = remote.getOutputStream()

            val down = pool.submit(
                Callable<Boolean> {
                    val ok = forwardStream(remoteInput, output, remote, client, false)
                    if (!ok) closeBoth(client, remote)
                    ok
                },
            )
            val upOk = forwardStream(input, remoteOutput, client, remote, true)
            // If one direction ended with an error, the other one is closed too.
            if (!upOk) closeBoth(client, remote)
            try {
                down.get()
            } catch (_: Exception) {
            }
        } catch (e: IOException) {
            d("Connection error with $clientName: ${why(e)}")
        } catch (e: Exception) {
            w("Unexpected error with $clientName: ${why(e)}")
        } finally {
            closeBoth(client, remote)
            active.remove(client)
            active.remove(remote)
        }
    }
}
