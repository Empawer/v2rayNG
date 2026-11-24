package com.v2ray.ang.core

import com.v2ray.ang.handler.MmkvManager

/**
 * Stored choice of the DNS chain: whether it is on and the text of its settings.
 *
 * The keys live here and not in AppConfig on purpose, so the DNS chain is a self contained addition.
 * The settings storage is shared between the processes, the chain process reads the text itself.
 */
object DnsChainStore {

    const val PREF_ENABLED = "pref_dns_chain_enabled"
    const val PREF_INI = "pref_dns_chain_ini"

    fun isEnabled(): Boolean = MmkvManager.decodeSettingsBool(PREF_ENABLED, false)

    fun setEnabled(enabled: Boolean): Boolean = MmkvManager.encodeSettings(PREF_ENABLED, enabled)

    /** The saved settings text, the default text when nothing was saved. */
    fun loadIni(): String {
        val saved = MmkvManager.decodeSettingsString(PREF_INI, "")
        return if (saved.isNullOrBlank()) DnsChainDefaults.DEFAULT_INI else saved
    }

    fun saveIni(text: String): Boolean = MmkvManager.encodeSettings(PREF_INI, text)

    /** Parses the saved text. */
    @Throws(DnsChainConfigException::class)
    fun loadSettings(): DnsChainSettings = DnsChainSettings.parse(loadIni())
}
