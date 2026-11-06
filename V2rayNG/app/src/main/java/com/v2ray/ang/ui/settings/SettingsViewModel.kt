package com.v2ray.ang.ui.settings

import android.app.Application
import android.content.Intent
import android.net.Uri
import android.provider.OpenableColumns
import android.provider.Settings
import com.v2ray.ang.AppConfig
import com.v2ray.ang.R
import com.v2ray.ang.core.ChainProxyConfig
import com.v2ray.ang.enums.EConfigType
import com.v2ray.ang.handler.MmkvManager
import com.v2ray.ang.handler.SettingsChangeManager
import com.v2ray.ang.root.RootManager
import com.v2ray.ang.ui.base.BaseViewModel
import com.v2ray.ang.util.LogUtil
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.withContext
import java.io.ByteArrayOutputStream

/** The stored relay config: [fromProfile] tells whether [guid] is an app profile or an imported file. */
data class ChainProxySelection(
    val name: String = "",
    val guid: String = "",
    val fromProfile: Boolean = false
)

/** A custom JSON profile that can be used as the relay config. */
data class ChainProxyProfileOption(val guid: String, val remarks: String)

class SettingsViewModel(application: Application) : BaseViewModel(application) {

    private val _systemVpnSettingsAvailable = MutableStateFlow(false)
    val systemVpnSettingsAvailable = _systemVpnSettingsAvailable.asStateFlow()

    private val _chainProxySelection = MutableStateFlow(
        MmkvManager.decodeSettingsString(AppConfig.PREF_CHAIN_PROXY_SOURCE_GUID, "").orEmpty().let { guid ->
            ChainProxySelection(
                name = MmkvManager.decodeSettingsString(AppConfig.PREF_CHAIN_PROXY_CONFIG_NAME, "").orEmpty(),
                guid = guid,
                fromProfile = guid.isNotEmpty()
            )
        }
    )

    /** The stored chain proxy relay config, an empty name means none is selected. */
    val chainProxySelection = _chainProxySelection.asStateFlow()

    private val _chainProxyProfiles = MutableStateFlow<List<ChainProxyProfileOption>>(emptyList())

    /** Custom JSON profiles in the app, without the profile the main core is set to run. */
    val chainProxyProfiles = _chainProxyProfiles.asStateFlow()

    suspend fun refreshChainProxyProfiles() {
        _chainProxyProfiles.value = withContext(Dispatchers.IO) {
            val mainGuid = MmkvManager.getSelectServer()
            MmkvManager.decodeAllServerList().distinct().mapNotNull { guid ->
                val profile = MmkvManager.decodeServerConfig(guid) ?: return@mapNotNull null
                if (profile.configType != EConfigType.CUSTOM || guid == mainGuid) return@mapNotNull null
                ChainProxyProfileOption(guid, profile.remarks.ifBlank { guid })
            }
        }
    }

    /**
     * Uses a custom JSON profile of the app as the relay config. Only the profile id is stored, so the
     * relay follows later edits of that profile. A running service is flagged for restart.
     */
    fun selectChainProxyProfile(option: ChainProxyProfileOption) {
        val raw = MmkvManager.decodeServerRaw(option.guid)
        if (ChainProxyConfig.validate(raw) != ChainProxyConfig.Validation.Valid) {
            toastError(R.string.toast_chain_proxy_config_invalid)
            return
        }
        val saved = MmkvManager.encodeSettings(AppConfig.PREF_CHAIN_PROXY_SOURCE_GUID, option.guid) &&
            MmkvManager.encodeSettings(AppConfig.PREF_CHAIN_PROXY_CONFIG_NAME, option.remarks) &&
            MmkvManager.encodeSettings(AppConfig.PREF_CHAIN_PROXY_CONFIG, "")
        if (!saved) {
            toastError(R.string.toast_chain_proxy_config_invalid)
            return
        }
        _chainProxySelection.value = ChainProxySelection(option.remarks, option.guid, fromProfile = true)
        SettingsChangeManager.makeRestartService()
        toastSuccess(R.string.toast_success)
    }

    suspend fun refreshSystemVpnSettingsAvailability() {
        _systemVpnSettingsAvailable.value = withContext(Dispatchers.IO) {
            // Android exposes the VPN page, not a direct link to the Always-on VPN switch.
            Intent(Settings.ACTION_VPN_SETTINGS).resolveActivity(getApplication<Application>().packageManager) != null
        }
    }

    /**
     * Checks for root access and requests it if necessary.
     * Updates [isLoading] during the process.
     */
    fun checkAndRequestRoot(onSuccess: () -> Unit) {
        launchLoading {
            val hasRoot = withContext(Dispatchers.IO) {
                RootManager.refresh()
            }
            if (hasRoot) {
                onSuccess()
            } else {
                toastError(R.string.toast_root_required)
            }
        }
    }

    /**
     * Validates if the given string is a valid observatory duration.
     * Shows error toast if invalid.
     * @return The trimmed value if valid, null otherwise.
     */
    fun validateObservatoryDuration(value: String): String? {
        val duration = value.trim()
        return if (AppConfig.OBSERVATORY_DURATION_PATTERN.matches(duration)) {
            duration
        } else {
            toastError(R.string.toast_invalid_observatory_duration)
            null
        }
    }

    /**
     * Validates if the given string is a valid observatory sampling value.
     * Shows error toast if invalid.
     * @return The value if valid, null otherwise.
     */
    fun validateObservatorySampling(value: String): String? {
        val sampling = value.trim().toIntOrNull()?.takeIf { it > 0 }
        return if (sampling != null) {
            sampling.toString()
        } else {
            toastError(R.string.toast_invalid_observatory_sampling)
            null
        }
    }

    /**
     * Reads the JSON file picked by the user, validates it and stores it as the chain proxy relay config.
     * The content is copied, so the relay keeps working when the source file moves or access to it is revoked.
     * A running service is flagged for restart so it picks up the new relay config.
     */
    fun importChainProxyConfig(uri: Uri) {
        launchLoading {
            val picked = withContext(Dispatchers.IO) { readChainProxyConfig(uri) }
            if (picked == null || ChainProxyConfig.validate(picked.first) != ChainProxyConfig.Validation.Valid) {
                toastError(R.string.toast_chain_proxy_config_invalid)
                return@launchLoading
            }

            val saved = MmkvManager.encodeSettings(AppConfig.PREF_CHAIN_PROXY_CONFIG, picked.first) &&
                MmkvManager.encodeSettings(AppConfig.PREF_CHAIN_PROXY_CONFIG_NAME, picked.second) &&
                MmkvManager.encodeSettings(AppConfig.PREF_CHAIN_PROXY_SOURCE_GUID, "")
            if (!saved) {
                toastError(R.string.toast_chain_proxy_config_invalid)
                return@launchLoading
            }
            _chainProxySelection.value = ChainProxySelection(picked.second, "", fromProfile = false)
            SettingsChangeManager.makeRestartService()
            toastSuccess(R.string.toast_success)
        }
    }

    /**
     * @return the file text and its display name, or null when it cannot be read or is larger than
     * [ChainProxyConfig.MAX_CONFIG_BYTES].
     */
    private fun readChainProxyConfig(uri: Uri): Pair<String, String>? {
        return try {
            val resolver = getApplication<Application>().contentResolver
            val out = ByteArrayOutputStream()
            val completed = resolver.openInputStream(uri)?.use { input ->
                val chunk = ByteArray(8 * 1024)
                var total = 0
                while (true) {
                    val read = input.read(chunk)
                    if (read < 0) break
                    total += read
                    if (total > ChainProxyConfig.MAX_CONFIG_BYTES) return@use false
                    out.write(chunk, 0, read)
                }
                true
            } ?: false
            if (!completed) return null

            val name = resolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { cursor ->
                if (cursor.moveToFirst()) cursor.getString(0) else null
            }
            val text = out.toString(Charsets.UTF_8.name()).removePrefix("\uFEFF")
            text to (name ?: uri.lastPathSegment ?: "config.json")
        } catch (e: Exception) {
            LogUtil.e(AppConfig.TAG, "Failed to read chain proxy config", e)
            null
        }
    }
}
