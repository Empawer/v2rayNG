package com.v2ray.ang.ui.main

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextDirection
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.DialogProperties
import com.v2ray.ang.R
import com.v2ray.ang.core.DnsChainConfigException
import com.v2ray.ang.core.DnsChainDefaults
import com.v2ray.ang.core.DnsChainSettings
import com.v2ray.ang.core.DnsChainStore
import com.v2ray.ang.core.LauncherManager
import com.v2ray.ang.extension.toast
import com.v2ray.ang.extension.toastError
import com.v2ray.ang.extension.toastSuccess

/**
 * The Chain dialog. It has two tabs, one for each chain method, and each tab has its own switch:
 *
 * - Relay config: the chain proxy relay core that runs a custom JSON profile.
 * - DNS chain: a proxy with DoH and SNI / Hello split, set up with the text of its ini file.
 *
 * Only one method works at a time: turning one switch on turns the other one off. The choice applies
 * when the person confirms, so a running service restarts once. The Save button of the DNS chain tab
 * stores the settings text alone.
 *
 * @param options custom JSON profiles that can be the chain config of the relay.
 * @param initialGuid the stored chain config of the relay, ignored when that profile no longer exists.
 */
@Composable
fun ChainDialog(
    options: List<ChainRelayOption>,
    initialEnabled: Boolean,
    initialGuid: String,
    onConfirm: (enabled: Boolean, guid: String) -> Unit,
    onDismiss: () -> Unit
) {
    val context = LocalContext.current

    val storedDnsEnabled = remember { DnsChainStore.isEnabled() }
    val storedIni = remember { DnsChainStore.loadIni() }
    val initialRelayGuid = initialGuid.takeIf { stored -> options.any { it.guid == stored } }.orEmpty()

    // The two methods are never on together. If the stored state says both, the DNS chain is the one that runs.
    var tab by remember { mutableStateOf(if (storedDnsEnabled) 1 else 0) }
    var relayEnabled by remember { mutableStateOf(initialEnabled && !storedDnsEnabled) }
    var guid by remember { mutableStateOf(initialRelayGuid) }
    var dnsEnabled by remember { mutableStateOf(storedDnsEnabled) }
    var iniText by remember { mutableStateOf(storedIni) }

    val noneOption = ChainRelayOption("", stringResource(R.string.chain_relay_none))
    val choices = listOf(noneOption) + options

    /** Checks the text. Shows the reason and returns false when it cannot be used. */
    fun checkIni(text: String): Boolean {
        return try {
            DnsChainSettings.parse(text)
            true
        } catch (e: DnsChainConfigException) {
            context.toastError(context.getString(R.string.dns_chain_toast_invalid, e.message.orEmpty()), true)
            false
        }
    }

    AlertDialog(
        onDismissRequest = onDismiss,
        properties = DialogProperties(usePlatformDefaultWidth = false),
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 12.dp),
        title = { Text(stringResource(R.string.title_chain_proxy_settings)) },
        text = {
            Column(modifier = Modifier.verticalScroll(rememberScrollState())) {
                ChainTabs(
                    selected = tab,
                    labels = listOf(
                        stringResource(R.string.dns_chain_tab_relay),
                        stringResource(R.string.dns_chain_tab_dns)
                    ),
                    onSelect = { tab = it }
                )
                Spacer(modifier = Modifier.height(8.dp))

                if (tab == 0) {
                    RelayTab(
                        enabled = relayEnabled,
                        onEnabledChange = {
                            relayEnabled = it
                            if (it) dnsEnabled = false
                        },
                        options = options,
                        choices = choices,
                        guid = guid,
                        onGuidChange = { guid = it }
                    )
                } else {
                    DnsTab(
                        enabled = dnsEnabled,
                        onEnabledChange = {
                            dnsEnabled = it
                            if (it) relayEnabled = false
                        },
                        text = iniText,
                        onTextChange = { iniText = it },
                        onDefault = {
                            iniText = DnsChainDefaults.DEFAULT_INI
                            context.toast(R.string.dns_chain_toast_default)
                        },
                        onSave = {
                            if (checkIni(iniText)) {
                                if (DnsChainStore.saveIni(iniText)) {
                                    context.toastSuccess(R.string.dns_chain_toast_saved)
                                    // A running chain takes the new text at once.
                                    if (DnsChainStore.isEnabled()) LauncherManager.restartService(context)
                                } else {
                                    context.toastError(R.string.toast_failure)
                                }
                            }
                        }
                    )
                }
            }
        },
        confirmButton = {
            TextButton(onClick = {
                val dnsChanged = dnsEnabled != storedDnsEnabled || (dnsEnabled && iniText != storedIni)
                if (dnsEnabled && !checkIni(iniText)) return@TextButton

                if (dnsChanged) {
                    val saved = DnsChainStore.saveIni(iniText) && DnsChainStore.setEnabled(dnsEnabled)
                    if (!saved) {
                        context.toastError(R.string.toast_failure)
                        return@TextButton
                    }
                }

                val relayChanged = relayEnabled != initialEnabled || guid != initialRelayGuid
                onConfirm(relayEnabled, guid)
                // A change of the relay restarts the service in onConfirm, a change of the DNS chain alone is done here.
                if (dnsChanged && !relayChanged) LauncherManager.restartService(context)
            }) { Text(stringResource(R.string.action_ok)) }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text(stringResource(R.string.action_cancel)) }
        },
        containerColor = MaterialTheme.colorScheme.surface
    )
}

/** Tabs side by side, the selected one has a thick line under its label. */
@Composable
private fun ChainTabs(selected: Int, labels: List<String>, onSelect: (Int) -> Unit) {
    Row(modifier = Modifier.fillMaxWidth()) {
        labels.forEachIndexed { index, label ->
            val isSelected = index == selected
            Column(
                modifier = Modifier
                    .weight(1f)
                    .clickable(role = Role.Tab) { onSelect(index) },
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                Text(
                    text = label,
                    style = MaterialTheme.typography.titleSmall,
                    color = if (isSelected) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(vertical = 10.dp)
                )
                if (isSelected) {
                    HorizontalDivider(thickness = 3.dp, color = MaterialTheme.colorScheme.primary)
                } else {
                    HorizontalDivider(thickness = 1.dp, color = MaterialTheme.colorScheme.outlineVariant)
                }
            }
        }
    }
}

/** One switch row: title, summary, switch. */
@Composable
private fun SwitchRow(title: String, summary: String, checked: Boolean, onCheckedChange: (Boolean) -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .toggleable(value = checked, onValueChange = onCheckedChange, role = Role.Switch)
            .padding(vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(text = title, style = MaterialTheme.typography.bodyLarge)
            Text(
                text = summary,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
        Spacer(modifier = Modifier.width(12.dp))
        Switch(checked = checked, onCheckedChange = null)
    }
}

@Composable
private fun RelayTab(
    enabled: Boolean,
    onEnabledChange: (Boolean) -> Unit,
    options: List<ChainRelayOption>,
    choices: List<ChainRelayOption>,
    guid: String,
    onGuidChange: (String) -> Unit
) {
    Column {
        SwitchRow(
            title = stringResource(R.string.title_pref_chain_proxy_enabled),
            summary = stringResource(R.string.summary_pref_chain_proxy_enabled),
            checked = enabled,
            onCheckedChange = onEnabledChange
        )

        Text(
            text = stringResource(R.string.dns_chain_exclusive_note),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )

        HorizontalDivider(modifier = Modifier.padding(vertical = 8.dp))

        Text(
            text = stringResource(R.string.title_chain_relay_dialog),
            style = MaterialTheme.typography.labelLarge,
            color = MaterialTheme.colorScheme.primary
        )
        Spacer(modifier = Modifier.height(4.dp))

        if (options.isEmpty()) {
            Text(
                text = stringResource(R.string.toast_chain_proxy_profile_none),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(vertical = 4.dp)
            )
        }

        LazyColumn(modifier = Modifier.height(240.dp)) {
            items(choices) { choice ->
                val selected = choice.guid == guid
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .selectable(selected = selected, onClick = { onGuidChange(choice.guid) }, role = Role.RadioButton)
                        .padding(vertical = 12.dp, horizontal = 4.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    RadioButton(selected = selected, onClick = null)
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        text = choice.remarks,
                        style = MaterialTheme.typography.bodyMedium,
                        modifier = Modifier.weight(1f)
                    )
                }
            }
        }
    }
}

@Composable
private fun DnsTab(
    enabled: Boolean,
    onEnabledChange: (Boolean) -> Unit,
    text: String,
    onTextChange: (String) -> Unit,
    onDefault: () -> Unit,
    onSave: () -> Unit
) {
    Column {
        SwitchRow(
            title = stringResource(R.string.dns_chain_title_enabled),
            summary = stringResource(R.string.dns_chain_summary_enabled),
            checked = enabled,
            onCheckedChange = onEnabledChange
        )

        Text(
            text = stringResource(R.string.dns_chain_exclusive_note),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )

        HorizontalDivider(modifier = Modifier.padding(vertical = 8.dp))

        Text(
            text = stringResource(R.string.dns_chain_title_settings),
            style = MaterialTheme.typography.labelLarge,
            color = MaterialTheme.colorScheme.primary
        )
        Text(
            text = stringResource(R.string.dns_chain_hint),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.padding(vertical = 4.dp)
        )

        // The settings are the text of an ini file: always left to right, in a fixed width font.
        OutlinedTextField(
            value = text,
            onValueChange = onTextChange,
            modifier = Modifier
                .fillMaxWidth()
                .height(340.dp),
            textStyle = TextStyle(
                fontFamily = FontFamily.Monospace,
                fontSize = 11.sp,
                lineHeight = 15.sp,
                textDirection = TextDirection.Ltr
            ),
            singleLine = false
        )

        Spacer(modifier = Modifier.height(8.dp))
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            OutlinedButton(onClick = onDefault, modifier = Modifier.weight(1f)) {
                Text(stringResource(R.string.dns_chain_action_default))
            }
            Button(onClick = onSave, modifier = Modifier.weight(1f)) {
                Text(stringResource(R.string.dns_chain_action_save))
            }
        }
    }
}
