package com.v2ray.ang.core

import com.google.gson.JsonArray
import com.google.gson.JsonObject
import com.google.gson.JsonParser

/**
 * Pure decisions for the chain proxy relay core, kept free of Android and native dependencies so
 * they can be covered by JVM tests.
 *
 * The relay config is a complete core JSON chosen by the user. Its inbound address and port belong
 * to the user, so nothing here rewrites the content, it only decides whether it can be run.
 */
object ChainProxyConfig {

    /** Upper bound for a relay config file, a core JSON is far smaller than this. */
    const val MAX_CONFIG_BYTES = 2 * 1024 * 1024

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

        val root = try {
            JsonParser.parseString(content)
        } catch (_: Exception) {
            return Validation.NotJson
        }
        if (!root.isJsonObject) return Validation.NotJson

        val obj = root.asJsonObject
        if (!obj.hasNonEmptyArray("inbounds")) return Validation.NoInbound
        if (!obj.hasNonEmptyArray("outbounds")) return Validation.NoOutbound
        return Validation.Valid
    }

    /**
     * The relay runs only when the switch is on and a stored config is still runnable.
     * With the switch off the profile's own configs start and stop alone.
     */
    fun shouldStartRelay(enabled: Boolean, content: String?): Boolean {
        return enabled && validate(content) == Validation.Valid
    }

    /**
     * Picks the relay JSON. A source profile, when set, wins over the imported file content, so edits made
     * to that profile inside the app reach the relay on the next start. A set profile whose JSON is gone
     * yields null instead of falling back to a file the user no longer means.
     */
    fun selectContent(sourceGuid: String?, profileRaw: String?, fileContent: String?): String? {
        return if (sourceGuid.isNullOrEmpty()) fileContent else profileRaw
    }

    /** The relay must not be the profile the main core runs, both would listen on the same inbound. */
    fun isMainProfile(sourceGuid: String?, mainGuid: String?): Boolean {
        return !sourceGuid.isNullOrEmpty() && sourceGuid == mainGuid
    }

    private fun JsonObject.hasNonEmptyArray(name: String): Boolean {
        val element = get(name)
        return element != null && element.isJsonArray && (element as JsonArray).size() > 0
    }
}
