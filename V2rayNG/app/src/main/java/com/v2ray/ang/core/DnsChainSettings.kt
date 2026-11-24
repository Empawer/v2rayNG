package com.v2ray.ang.core

import java.util.Locale

/** Raised when the settings text cannot be read. The message is shown to the user as it is. */
class DnsChainConfigException(message: String) : Exception(message)

/** [sni split] section: the ClientHello is cut inside the hostname. Times are in seconds. */
data class DnsChainSniSplit(val pieces: Int, val delay: Double)

/** [hello split] section: the ClientHello is cut at many structural points. Times are in seconds. */
data class DnsChainHelloSplit(
    val points: List<String>,
    val sniPieces: Int,
    val method: String,
    val delay: Double,
    val jitter: Double,
    val firstDelay: Double?,
    val minPiece: Int,
    val maxPieces: Int,
)

/** Everything the DNS chain proxy reads from the settings text. */
data class DnsChainSettings(
    val listenIp: String,
    val listenPort: Int,
    val idleTimeout: Int,
    val connectTimeout: Double,
    val handshakeTimeout: Double,
    val dohTimeout: Double,
    val testDomain: String,
    val dohCooldown: Double,
    val systemDnsTimeout: Double,
    val logLevel: String,
    val dohServers: List<String>,
    val sniSplit: DnsChainSniSplit?,
    val helloSplit: DnsChainHelloSplit?,
    /** Problems that did not stop the proxy: an ignored DoH url, a skipped split section. */
    val warnings: List<String>,
) {
    companion object {
        const val DOH_COOLDOWN_MAX = 300.0
        const val NEG_CACHE_TTL = 20.0

        /**
         * Reads the settings text the way the Python proxy reads dns_chain.ini.
         *
         * @throws DnsChainConfigException when the text is not a readable ini file or a value of the
         * [proxy] section is not a number.
         */
        @Throws(DnsChainConfigException::class)
        fun parse(text: String): DnsChainSettings = DnsChainIniLoader.load(DnsChainIni.parse(text))

        /** The settings of [DnsChainDefaults.DEFAULT_INI]. */
        fun defaults(): DnsChainSettings = parse(DnsChainDefaults.DEFAULT_INI)
    }
}

/** A small reader with the rules of Python's configparser: sections, key = value or key: value, ; and # comment lines. */
class DnsChainIni private constructor(
    private val sections: LinkedHashMap<String, LinkedHashMap<String, String>>,
) {
    fun hasSection(name: String): Boolean = sections.containsKey(name)

    /** Options of a section in file order, keys are lower case. Empty when the section does not exist. */
    fun items(section: String): List<Pair<String, String>> =
        sections[section]?.entries?.map { it.key to it.value } ?: emptyList()

    fun get(section: String, key: String, fallback: String): String =
        sections[section]?.get(key.lowercase(Locale.ROOT)) ?: fallback

    fun has(section: String, key: String): Boolean =
        sections[section]?.containsKey(key.lowercase(Locale.ROOT)) == true

    companion object {
        private val SECTION = Regex("^\\[(.+)]")

        @Throws(DnsChainConfigException::class)
        fun parse(text: String): DnsChainIni {
            val sections = LinkedHashMap<String, LinkedHashMap<String, String>>()
            var current: LinkedHashMap<String, String>? = null
            var currentName: String? = null
            var optionName: String? = null
            var optionIndent = 0

            val lines = text.replace("\r\n", "\n").replace('\r', '\n').split('\n')
            for ((index, rawLine) in lines.withIndex()) {
                val number = index + 1
                val line = rawLine.trim()
                if (line.isEmpty()) {
                    optionName = null
                    continue
                }
                if (line.startsWith(";") || line.startsWith("#")) continue

                val indent = rawLine.length - rawLine.trimStart().length
                val section = current
                val name = optionName
                if (section != null && name != null && indent > optionIndent) {
                    // A value that goes on in the next lines.
                    section[name] = section[name] + "\n" + line
                    continue
                }

                val header = SECTION.find(line)
                if (header != null) {
                    val sectionName = header.groupValues[1]
                    if (sections.containsKey(sectionName)) {
                        throw DnsChainConfigException("Line $number: section [$sectionName] appears twice")
                    }
                    val created = LinkedHashMap<String, String>()
                    sections[sectionName] = created
                    current = created
                    currentName = sectionName
                    optionName = null
                    continue
                }

                if (section == null) {
                    throw DnsChainConfigException("Line $number: the file must start with a section header such as [proxy]")
                }

                val delimiter = line.indexOfFirst { it == '=' || it == ':' }
                if (delimiter < 0) {
                    throw DnsChainConfigException("Line $number: expected key = value, found: $line")
                }
                val key = line.substring(0, delimiter).trim().lowercase(Locale.ROOT)
                if (key.isEmpty()) {
                    throw DnsChainConfigException("Line $number: the key is empty")
                }
                if (section.containsKey(key)) {
                    throw DnsChainConfigException("Line $number: option $key appears twice in [$currentName]")
                }
                section[key] = line.substring(delimiter + 1).trim()
                optionName = key
                optionIndent = indent
            }
            return DnsChainIni(sections)
        }
    }
}

/** Presets and cut point checks of the hello split section. */
object DnsChainHello {
    val PRESETS: Map<String, String> = mapOf(
        "basic" to "sni",
        "standard" to "handshake_header,cipher_suites,extensions,sni,ext:alpn",
        "aggressive" to (
            "record_header,handshake_header,random,session_id,cipher_suites_mid," +
                "cipher_suites,compression,extensions,ext_each,sni,sni_labels"
            ),
        "paranoid" to (
            "record_header,handshake_header,random,session_id,cipher_suites_mid," +
                "cipher_suites,compression,extensions,ext_each,sni,sni_labels,random:5"
            ),
    )

    val EXT_BY_NAME: Map<String, Int> = mapOf(
        "sni" to 0, "status_request" to 5, "groups" to 10, "ec_formats" to 11, "sigalgs" to 13,
        "alpn" to 16, "sct" to 18, "padding" to 21, "ems" to 23, "compress_cert" to 27,
        "ticket" to 35, "psk" to 41, "versions" to 43, "psk_modes" to 45, "key_share" to 51,
        "reneg" to 65281, "ech" to 65037,
    )

    val SIMPLE_POINTS: Set<String> = setOf(
        "record_header", "header", "handshake_header", "random", "session_id",
        "cipher_suites", "cipher_suites_mid", "compression", "extensions",
        "ext_each", "ext_end", "sni_edges", "sni", "sni_labels",
    )

    /** Python's int(text, 0): decimal, 0x, 0o and 0b numbers, null when the text is none of them. */
    fun parseNumber(text: String): Long? {
        var s = text.trim().replace("_", "")
        var negative = false
        if (s.startsWith("+")) {
            s = s.substring(1)
        } else if (s.startsWith("-")) {
            negative = true
            s = s.substring(1)
        }
        if (s.isEmpty()) return null
        val lower = s.lowercase(Locale.ROOT)
        val value: Long? = when {
            lower.startsWith("0x") -> lower.substring(2).toLongOrNull(16)
            lower.startsWith("0o") -> lower.substring(2).toLongOrNull(8)
            lower.startsWith("0b") -> lower.substring(2).toLongOrNull(2)
            lower.all { it in '0'..'9' } -> {
                // A decimal number may not have leading zeros, except zero itself.
                if (lower.length > 1 && lower[0] == '0' && lower.any { it != '0' }) null else lower.toLongOrNull()
            }
            else -> null
        }
        if (value == null) return null
        return if (negative) -value else value
    }

    /** @throws IllegalArgumentException when [token] is not a known cut point. */
    fun validatePoint(token: String) {
        if (token in SIMPLE_POINTS) return
        if (token.startsWith("ext:")) {
            val name = token.substring(4)
            if (EXT_BY_NAME.containsKey(name)) return
            requireNotNull(parseNumber(name)) { "invalid literal for int(): '$name'" }
            return
        }
        if (token.startsWith("every:")) {
            val n = token.substring(6).trim().toIntOrNull()
                ?: throw IllegalArgumentException("invalid literal for int(): '${token.substring(6)}'")
            require(n >= 1) { "every:N needs N >= 1" }
            return
        }
        if (token.startsWith("random:")) {
            val n = token.substring(7).trim().toIntOrNull()
                ?: throw IllegalArgumentException("invalid literal for int(): '${token.substring(7)}'")
            require(n >= 0) { "random:K needs K >= 0" }
            return
        }
        requireNotNull(parseNumber(token)) { "invalid literal for int(): '$token'" }
    }
}

internal object DnsChainIniLoader {

    private val DOH_KEY = Regex("doh(?:_?(\\d+))?")
    private val SCHEME = Regex("^[a-z]+://", RegexOption.IGNORE_CASE)

    @Throws(DnsChainConfigException::class)
    fun load(ini: DnsChainIni): DnsChainSettings {
        val warnings = ArrayList<String>()
        val proxy = "proxy"

        fun int(key: String, fallback: Int): Int {
            if (!ini.has(proxy, key)) return fallback
            val raw = ini.get(proxy, key, "")
            return raw.trim().toIntOrNull()
                ?: throw DnsChainConfigException("[proxy] $key must be a whole number, found: $raw")
        }

        fun float(key: String, fallback: Double): Double {
            if (!ini.has(proxy, key)) return fallback
            val raw = ini.get(proxy, key, "")
            return raw.trim().toDoubleOrNull()
                ?: throw DnsChainConfigException("[proxy] $key must be a number, found: $raw")
        }

        val listenIp = ini.get(proxy, "listen_ip", "127.0.0.1")
        val listenPort = int("listen_port", 40443)
        if (listenPort !in 0..65535) {
            throw DnsChainConfigException("[proxy] listen_port must be between 0 and 65535, found: $listenPort")
        }
        val idleTimeout = int("idle_timeout", 300)
        val connectTimeout = float("connect_timeout", 10.0)
        val handshakeTimeout = float("handshake_timeout", 15.0)
        val dohTimeout = float("doh_timeout", 5.0)

        val rawDomain = ini.get(proxy, "domain", "").trim()
        // If the user wrote https:// or a path, keep only the domain.
        val testDomain = rawDomain
            .replace(SCHEME, "")
            .split("/")[0].split(":")[0].trimEnd('.')
            .ifEmpty { "example.com" }

        val dohCooldown = float("doh_cooldown", 30.0)
        val systemDnsTimeout = float("system_dns_timeout", 5.0)
        val logLevel = ini.get(proxy, "log_level", "INFO").trim().uppercase(Locale.ROOT)

        return DnsChainSettings(
            listenIp = listenIp,
            listenPort = listenPort,
            idleTimeout = idleTimeout,
            connectTimeout = connectTimeout,
            handshakeTimeout = handshakeTimeout,
            dohTimeout = dohTimeout,
            testDomain = testDomain,
            dohCooldown = dohCooldown,
            systemDnsTimeout = systemDnsTimeout,
            logLevel = logLevel,
            dohServers = loadDohServers(ini, warnings),
            sniSplit = loadSniSplit(ini, warnings),
            helloSplit = loadHelloSplit(ini, warnings),
            warnings = warnings,
        )
    }

    /** DOH_01, DOH_02, ... (any count) and the old DOH key, in the order of their numbers. Empty values are skipped. */
    private fun loadDohServers(ini: DnsChainIni, warnings: MutableList<String>): List<String> {
        val found = ArrayList<Pair<Int, String>>()
        for ((key, rawValue) in ini.items("proxy")) {
            val match = DOH_KEY.matchEntire(key.trim().lowercase(Locale.ROOT))
            val value = rawValue.trim()
            if (match == null || value.isEmpty()) continue
            if (!value.lowercase(Locale.ROOT).startsWith("https://")) {
                warnings.add("$key ignored: DoH URL must start with https://")
                continue
            }
            val number = match.groupValues[1].ifEmpty { "0" }.toIntOrNull() ?: Int.MAX_VALUE
            found.add(number to value)
        }
        // sortedBy is stable, as the sort of the Python code is.
        val servers = ArrayList<String>()
        for ((_, url) in found.sortedBy { it.first }) {
            if (url !in servers) servers.add(url)
        }
        return servers
    }

    private fun milliseconds(raw: String): Double {
        val cleaned = raw.lowercase(Locale.ROOT).replace("ms", "").trim()
        if (cleaned.isEmpty()) return 0.0
        val value = cleaned.toDoubleOrNull() ?: throw NumberFormatException("could not convert string to float: '$cleaned'")
        return maxOf(0.0, value / 1000.0)
    }

    private fun loadSniSplit(ini: DnsChainIni, warnings: MutableList<String>): DnsChainSniSplit? {
        val section = "sni split"
        if (!ini.hasSection(section)) return null
        if (ini.get(section, "Enable", "0").trim() != "1") return null
        return try {
            val piecesRaw = ini.get(section, "pieces", "3")
            val pieces = maxOf(
                2,
                if (ini.has(section, "pieces")) {
                    piecesRaw.trim().toIntOrNull()
                        ?: throw NumberFormatException("invalid literal for int(): '$piecesRaw'")
                } else {
                    3
                },
            )
            val delayRaw = ini.get(section, "delay", "0 ms").lowercase(Locale.ROOT).replace("ms", "").trim()
            val delayValue = delayRaw.toDoubleOrNull()
                ?: throw NumberFormatException("could not convert string to float: '$delayRaw'")
            DnsChainSniSplit(pieces, maxOf(0.0, delayValue / 1000.0))
        } catch (e: NumberFormatException) {
            warnings.add("Section [$section] skipped, invalid config: ${e.message}")
            null
        }
    }

    private fun loadHelloSplit(ini: DnsChainIni, warnings: MutableList<String>): DnsChainHelloSplit? {
        val section = "hello split"
        if (!ini.hasSection(section)) return null
        if (ini.get(section, "Enable", "0").trim() != "1") return null

        fun int(key: String, fallback: Int): Int {
            if (!ini.has(section, key)) return fallback
            val raw = ini.get(section, key, "")
            return raw.trim().toIntOrNull() ?: throw NumberFormatException("invalid literal for int(): '$raw'")
        }

        return try {
            val preset = ini.get(section, "preset", "standard").trim().lowercase(Locale.ROOT)
            var rawPoints = ini.get(section, "points", "").trim()
            if (rawPoints.isEmpty()) {
                rawPoints = DnsChainHello.PRESETS[preset] ?: throw IllegalArgumentException("unknown preset '$preset'")
            }
            val points = rawPoints.split(",").map { it.trim().lowercase(Locale.ROOT) }.filter { it.isNotEmpty() }
            require(points.isNotEmpty()) { "no cut points" }
            for (p in points) DnsChainHello.validatePoint(p)

            val method = ini.get(section, "method", "tcp").trim().lowercase(Locale.ROOT)
            require(method == "tcp" || method == "record") { "method must be tcp or record" }

            val firstRaw = ini.get(section, "first_delay", "").trim()
            DnsChainHelloSplit(
                points = points,
                sniPieces = maxOf(2, int("sni_pieces", 3)),
                method = method,
                delay = milliseconds(ini.get(section, "delay", "0 ms")),
                jitter = milliseconds(ini.get(section, "delay_jitter", "0 ms")),
                firstDelay = if (firstRaw.isNotEmpty()) milliseconds(firstRaw) else null,
                minPiece = maxOf(1, int("min_piece", 1)),
                maxPieces = maxOf(0, int("max_pieces", 0)),
            )
        } catch (e: IllegalArgumentException) {
            // NumberFormatException is an IllegalArgumentException too.
            warnings.add("Section [$section] skipped, invalid config: ${e.message}")
            null
        }
    }
}
