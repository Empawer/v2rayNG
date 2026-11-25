package com.v2ray.ang.core

import java.util.Locale

/** Raised when the settings text cannot be read. The message is shown to the user as it is. */
class DnsChainConfigException(message: String) : Exception(message)

/**
 * [fragment] section: the data sent by the client is cut into small TCP pieces, so DPI never sees a
 * full packet in one piece. Sizes are in bytes, times are in seconds.
 */
data class DnsChainFragment(
    /** Piece sizes in bytes, as inclusive (low, high) ranges; the list wraps around. */
    val lengths: List<Pair<Int, Int>>,
    /** Pause between pieces in seconds, as an inclusive (low, high) range. */
    val interval: Pair<Double, Double>,
    /** How many pieces are fragmented per connection, 0 = unlimited. */
    val maxSplit: Int,
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
    val fragment: DnsChainFragment?,
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

/**
 * "10" -> (10, 10); "10-20" -> (10, 20); "5-10 ms" -> (5, 10). The value of [what] names the
 * setting in error messages. This is the port of the _parse_range function of the Python proxy.
 *
 * @throws NumberFormatException when the text is not a number or a low-high range.
 */
internal object DnsChainRanges {
    private val RANGE = Regex("(\\d+(?:\\.\\d+)?)\\s*(?:ms)?\\s*(?:-\\s*(\\d+(?:\\.\\d+)?)\\s*(?:ms)?)?")

    fun parse(raw: String, what: String): Pair<Double, Double> {
        val match = RANGE.matchEntire(raw.trim().lowercase(Locale.ROOT))
            ?: throw NumberFormatException("invalid $what: '$raw'")
        val lo = match.groupValues[1].toDouble()
        val hi = if (match.groupValues[2].isEmpty()) lo else match.groupValues[2].toDouble()
        if (hi < lo) throw NumberFormatException("$what range must be written low-high: '$raw'")
        return lo to hi
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
            fragment = loadFragment(ini, warnings),
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

    /**
     * The [fragment] section. length is a comma separated list of numbers and ranges of bytes, an
     * item may not be a time; interval is one number or range of milliseconds. This is the port of
     * the load_fragment function of the Python proxy.
     */
    private fun loadFragment(ini: DnsChainIni, warnings: MutableList<String>): DnsChainFragment? {
        val section = "fragment"
        if (!ini.hasSection(section)) return null
        if (ini.get(section, "Enable", "0").trim() != "1") return null
        return try {
            // length: "10" | "10-20" | "20, 9, 1" | "20, 5-9, 1"
            val items = ini.get(section, "length", "").split(",").map { it.trim() }.filter { it.isNotEmpty() }
            if (items.isEmpty()) throw NumberFormatException("length is empty")
            val lengths = items.map { item ->
                if (item.lowercase(Locale.ROOT).contains("ms")) {
                    throw NumberFormatException("length is in bytes, not ms: '$item'")
                }
                val (lo, hi) = DnsChainRanges.parse(item, "length")
                if (lo != Math.floor(lo) || hi != Math.floor(hi) || lo < 1) {
                    throw NumberFormatException("length must be whole numbers >= 1: '$item'")
                }
                lo.toInt() to hi.toInt()
            }

            // interval: "0" | "5 ms" | "5-10 ms" (milliseconds -> seconds)
            val rawInterval = ini.get(section, "interval", "0").trim().ifEmpty { "0" }
            val (loMs, hiMs) = DnsChainRanges.parse(rawInterval, "interval")
            val interval = (loMs / 1000.0) to (hiMs / 1000.0)

            val maxSplitRaw = if (ini.has(section, "max_split")) ini.get(section, "max_split", "").trim() else "0"
            val maxSplit = maxSplitRaw.toIntOrNull()
                ?: throw NumberFormatException("invalid literal for int(): '$maxSplitRaw'")
            require(maxSplit >= 0) { "max_split must be 0 (unlimited) or a positive number" }

            DnsChainFragment(lengths, interval, maxSplit)
        } catch (e: IllegalArgumentException) {
            // NumberFormatException is an IllegalArgumentException too.
            warnings.add("Section [$section] skipped, invalid config: ${e.message}")
            null
        }
    }
}
