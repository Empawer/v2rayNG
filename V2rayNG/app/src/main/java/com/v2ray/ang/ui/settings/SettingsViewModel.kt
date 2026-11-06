package com.v2ray.ang.ui.settings

import android.app.Application
import android.content.Intent
import android.net.Uri
import android.provider.OpenableColumns
import android.provider.Settings
import com.v2ray.ang.AppConfig
import com.v2ray.ang.R
import com.v2ray.ang.core.ChainProxyConfig
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

class SettingsViewModel(application: Application) : BaseViewModel(application) {

    private val _systemVpnSettingsAvailable = MutableStateFlow(false)
    val systemVpnSettingsAvailable = _systemVpnSettingsAvailable.asStateFlow()

    private val _chainProxyConfigName = MutableStateFlow(
        MmkvManager.decodeSettingsString(AppConfig.PREF_CHAIN_PROXY_CONFIG_NAME, "").orEmpty()
    )

    /** Display name of the stored chain proxy relay config, empty when none is selected. */
    val chainProxyConfigName = _chainProxyConfigName.asStateFlow()

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
                MmkvManager.encodeSettings(AppConfig.PREF_CHAIN_PROXY_CONFIG_NAME, picked.second)
            if (!saved) {
                toastError(R.string.toast_chain_proxy_config_invalid)
                return@launchLoading
            }
            _chainProxyConfigName.value = picked.second
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
