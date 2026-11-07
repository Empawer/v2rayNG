package com.v2ray.ang.core

import com.google.gson.JsonObject
import com.google.gson.JsonParser

/**
 * Pure decisions for the chain proxy relay, kept free of Android and native dependencies so they can be
 * covered by JVM tests.
 *
 * The chain config is a complete core JSON, chosen as a custom profile of the app, that runs on a core of
 * its own. Its inbound address and port belong to the user, who connects to it with a proxy profile of
 * their own. Nothing here rewrites any config.
 */
object ChainProxyConfig {

    sealed interface Validation {
        data object Valid : Validation
        data object Empty : Validation
        data object NotJson : Validation
        data object NoInbound : Validation
        data object NoOutbound : Validation
    }

    /**
     * Checks that [content] is a JSON object with at least one inbound and one outbound.
     * An inbound is required because the user connects to the relay through it.
     */
    fun validate(content: String?): Validation {
        if (content.isNullOrBlank()) return Validation.Empty

        val root = parseObject(content) ?: return Validation.NotJson
        if (!root.hasNonEmptyArray("inbounds")) return Validation.NoInbound
        if (!root.hasNonEmptyArray("outbounds")) return Validation.NoOutbound
        return Validation.Valid
    }

    /**
     * The relay runs only when the switch is on and the stored config is still runnable.
     * With the switch off the profile's own configs start and stop alone.
     */
    fun shouldStartRelay(enabled: Boolean, content: String?): Boolean {
        return enabled && validate(content) == Validation.Valid
    }

    /** The relay must not be the profile the main core runs, both would listen on the same inbound. */
    fun isMainProfile(sourceGuid: String?, mainGuid: String?): Boolean {
        return !sourceGuid.isNullOrEmpty() && sourceGuid == mainGuid
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
