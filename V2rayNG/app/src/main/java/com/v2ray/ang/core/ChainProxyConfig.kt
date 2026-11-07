package com.v2ray.ang.core

import com.google.gson.JsonArray
import com.google.gson.JsonElement
import com.google.gson.JsonObject
import com.google.gson.JsonParser

/**
 * Pure decisions for the chain proxy, kept free of Android and native dependencies so they can be
 * covered by JVM tests.
 *
 * The chain config is a complete core JSON, chosen as a custom profile of the app, that runs on its own
 * core. Its inbound address and port belong to the user. The main profile config is then given one
 * extra first hop that points at that inbound, so the profile's own connections leave through the chain
 * config. Nothing here rewrites the chain config itself.
 */
object ChainProxyConfig {

    /** Tag of the hop added to the main config, it points at the chain config's inbound. */
    const val RELAY_TAG = "chain-relay"

    // Outbounds that do not open a proxy connection, or whose transport cannot be carried by a
    // SOCKS or HTTP hop, so they are left untouched.
    private val UNCHAINED_PROTOCOLS = setOf("freedom", "blackhole", "dns", "loopback", "wireguard", "hysteria", "hysteria2")
    private val UNCHAINED_NETWORKS = setOf("kcp", "quic")

    sealed interface Validation {
        data object Valid : Validation
        data object Empty : Validation
        data object NotJson : Validation
        data object NoInbound : Validation
        data object NoOutbound : Validation
    }

    /** Where the chain config accepts connections, read from its SOCKS or HTTP inbound. */
    data class RelayEndpoint(
        val protocol: String,
        val address: String,
        val port: Int,
        val user: String? = null,
        val pass: String? = null
    )

    /**
     * Checks that [content] is a JSON object with at least one inbound and one outbound.
     * An inbound is required because the main config connects to the chain config through it.
     */
    fun validate(content: String?): Validation {
        if (content.isNullOrBlank()) return Validation.Empty

        val root = parseObject(content) ?: return Validation.NotJson
        if (!root.hasNonEmptyArray("inbounds")) return Validation.NoInbound
        if (!root.hasNonEmptyArray("outbounds")) return Validation.NoOutbound
        return Validation.Valid
    }

    /**
     * The chain config runs only when the switch is on and the stored config is still runnable.
     * With the switch off the profile's own configs start and stop alone.
     */
    fun shouldStartRelay(enabled: Boolean, content: String?): Boolean {
        return enabled && validate(content) == Validation.Valid
    }

    /** The chain config must not be the profile the main core runs, both would listen on the same inbound. */
    fun isMainProfile(sourceGuid: String?, mainGuid: String?): Boolean {
        return !sourceGuid.isNullOrEmpty() && sourceGuid == mainGuid
    }

    /**
     * Finds the SOCKS or HTTP inbound of the chain config, SOCKS preferred. A wildcard or missing listen
     * address becomes the loopback address, since the main core runs on the same device.
     *
     * @return null when there is no SOCKS or HTTP inbound with a usable TCP port.
     */
    fun findRelayEndpoint(relayContent: String?): RelayEndpoint? {
        val root = relayContent?.let { parseObject(it) } ?: return null
        val inbounds = root.get("inbounds")?.takeIf { it.isJsonArray }?.asJsonArray ?: return null

        val candidates = inbounds.mapNotNull { element ->
            val inbound = element.takeIf { it.isJsonObject }?.asJsonObject ?: return@mapNotNull null
            val protocol = inbound.stringOrNull("protocol")?.lowercase()
            if (protocol != "socks" && protocol != "http") return@mapNotNull null
            val port = inbound.get("port")?.toPortOrNull() ?: return@mapNotNull null
            val address = inbound.stringOrNull("listen").toConnectAddress() ?: return@mapNotNull null
            val (user, pass) = inbound.get("settings")?.takeIf { it.isJsonObject }?.asJsonObject
                ?.credentials(protocol) ?: (null to null)
            RelayEndpoint(protocol, address, port, user, pass)
        }
        return candidates.firstOrNull { it.protocol == "socks" } ?: candidates.firstOrNull()
    }

    /**
     * Adds a first hop to [mainContent] that points at [endpoint] and makes every proxy outbound that
     * has no hop of its own dial through it. In a profile chain only the hop closest to the device has
     * none, so the whole chain leaves through the relay.
     *
     * @return the new config, or null when [mainContent] is not a config with outbounds or has no
     * outbound that can be carried by the hop.
     */
    fun applyRelayHop(mainContent: String, endpoint: RelayEndpoint): String? {
        val root = parseObject(mainContent) ?: return null
        val outbounds = root.get("outbounds")?.takeIf { it.isJsonArray }?.asJsonArray ?: return null

        val kept = JsonArray()
        var applied = 0
        for (element in outbounds) {
            val outbound = element.takeIf { it.isJsonObject }?.asJsonObject
            if (outbound == null) {
                kept.add(element)
                continue
            }
            // A hop left from an earlier pass is rebuilt below.
            if (outbound.stringOrNull("tag") == RELAY_TAG) continue
            if (outbound.canDialThroughRelay()) {
                outbound.dialThroughRelay()
                applied++
            }
            kept.add(outbound)
        }
        if (applied == 0) return null

        kept.add(buildRelayOutbound(endpoint))
        root.add("outbounds", kept)
        return root.toString()
    }

    private fun buildRelayOutbound(endpoint: RelayEndpoint): JsonObject {
        val settings = JsonObject().apply {
            addProperty("address", endpoint.address)
            addProperty("port", endpoint.port)
            if (!endpoint.user.isNullOrEmpty()) {
                addProperty("user", endpoint.user)
                addProperty("pass", endpoint.pass.orEmpty())
            }
        }
        return JsonObject().apply {
            addProperty("tag", RELAY_TAG)
            addProperty("protocol", endpoint.protocol)
            add("settings", settings)
        }
    }

    private fun JsonObject.canDialThroughRelay(): Boolean {
        val protocol = stringOrNull("protocol")?.lowercase() ?: return false
        if (protocol in UNCHAINED_PROTOCOLS) return false

        val stream = get("streamSettings")?.takeIf { it.isJsonObject }?.asJsonObject
        if (stream?.stringOrNull("network")?.lowercase() in UNCHAINED_NETWORKS) return false

        val existing = stream?.get("sockopt")?.takeIf { it.isJsonObject }?.asJsonObject?.stringOrNull("dialerProxy")
        return existing.isNullOrEmpty()
    }

    private fun JsonObject.dialThroughRelay() {
        val stream = get("streamSettings")?.takeIf { it.isJsonObject }?.asJsonObject
            ?: JsonObject().also { add("streamSettings", it) }
        val sockopt = stream.get("sockopt")?.takeIf { it.isJsonObject }?.asJsonObject
            ?: JsonObject().also { stream.add("sockopt", it) }
        sockopt.addProperty("dialerProxy", RELAY_TAG)
    }

    private fun JsonObject.credentials(protocol: String): Pair<String?, String?>? {
        // A SOCKS inbound only checks the account when auth is "password", an HTTP inbound when it has accounts.
        if (protocol == "socks" && stringOrNull("auth") != "password") return null
        val account = get("accounts")?.takeIf { it.isJsonArray }?.asJsonArray?.firstOrNull()
            ?.takeIf { it.isJsonObject }?.asJsonObject ?: return null
        val user = account.stringOrNull("user")?.takeIf { it.isNotEmpty() } ?: return null
        return user to account.stringOrNull("pass").orEmpty()
    }

    private fun String?.toConnectAddress(): String? {
        val listen = this?.trim().orEmpty()
        // A unix socket cannot be reached through a TCP hop.
        if (listen.startsWith("/") || listen.startsWith("@")) return null
        return when (listen.lowercase()) {
            "", "0.0.0.0", "::", "[::]", "localhost" -> "127.0.0.1"
            else -> listen
        }
    }

    private fun JsonElement.toPortOrNull(): Int? {
        if (!isJsonPrimitive) return null
        val port = if (asJsonPrimitive.isNumber) asInt else asString.trim().toIntOrNull()
        return port?.takeIf { it in 1..65535 }
    }

    private fun JsonObject.stringOrNull(name: String): String? {
        val element = get(name) ?: return null
        return if (element.isJsonPrimitive) element.asString else null
    }

    private fun parseObject(content: String): JsonObject? {
        val root = try {
            JsonParser.parseString(content)
        } catch (_: Exception) {
            return null
        }
        return root.takeIf { it.isJsonObject }?.asJsonObject
    }

    private fun JsonObject.hasNonEmptyArray(name: String): Boolean {
        val element = get(name)
        return element != null && element.isJsonArray && element.asJsonArray.size() > 0
    }
}
