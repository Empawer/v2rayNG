package com.v2ray.ang.ui.main

import android.app.Application
import com.v2ray.ang.AppConfig
import com.v2ray.ang.R
import com.v2ray.ang.core.ChainProxyConfig
import com.v2ray.ang.enums.EConfigType
import com.v2ray.ang.handler.MmkvManager
import com.v2ray.ang.ui.base.BaseViewModel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.withContext

/** A custom JSON profile that can be used as the chain config. An empty [guid] means no chain config. */
data class ChainRelayOption(val guid: String, val remarks: String)

/**
 * Holds which profile of the app is the chain config. The choice is stored as the profile id, so the
 * chain follows later edits of that profile. The switch that turns the chain on lives in settings.
 */
class ChainRelayViewModel(application: Application) : BaseViewModel(application) {

    private val _selectedGuid = MutableStateFlow(
        MmkvManager.decodeSettingsString(AppConfig.PREF_CHAIN_PROXY_SOURCE_GUID, "").orEmpty()
    )

    /** Id of the profile used as chain config, empty when none is selected. */
    val selectedGuid: StateFlow<String> = _selectedGuid.asStateFlow()

    private val _options = MutableStateFlow<List<ChainRelayOption>>(emptyList())

    /** Custom JSON profiles of the app, the only profiles that are a complete core config. */
    val options: StateFlow<List<ChainRelayOption>> = _options.asStateFlow()

    suspend fun refreshOptions() {
        _options.value = withContext(Dispatchers.IO) {
            MmkvManager.decodeAllServerList().distinct().mapNotNull { guid ->
                val profile = MmkvManager.decodeServerConfig(guid) ?: return@mapNotNull null
                if (profile.configType != EConfigType.CUSTOM) return@mapNotNull null
                ChainRelayOption(guid, profile.remarks.ifBlank { guid })
            }
        }
    }

    /**
     * Stores [guid] as the chain config, an empty [guid] clears it.
     *
     * @return true when the stored choice changed, so a running service must restart to apply it.
     */
    fun select(guid: String): Boolean {
        if (guid == _selectedGuid.value) return false

        if (guid.isNotEmpty()) {
            val valid = ChainProxyConfig.validate(MmkvManager.decodeServerRaw(guid)) == ChainProxyConfig.Validation.Valid
            if (!valid) {
                toastError(R.string.toast_chain_proxy_config_invalid)
                return false
            }
        }
        if (!MmkvManager.encodeSettings(AppConfig.PREF_CHAIN_PROXY_SOURCE_GUID, guid)) {
            toastError(R.string.toast_failure)
            return false
        }
        _selectedGuid.value = guid
        toastSuccess(R.string.toast_success)
        return true
    }
}
