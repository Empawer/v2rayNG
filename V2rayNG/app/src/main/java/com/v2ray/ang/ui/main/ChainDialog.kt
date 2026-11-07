package com.v2ray.ang.ui.main

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
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.selection.toggleable
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
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
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.unit.dp
import com.v2ray.ang.R

/**
 * The Chain dialog: a switch that turns the chain proxy on or off, and the choice of the profile that is
 * the chain config. Changes apply together when the person confirms, so a running service restarts once.
 *
 * @param options custom JSON profiles that can be the chain config.
 * @param initialGuid the stored chain config, ignored when that profile no longer exists.
 */
@Composable
fun ChainDialog(
    options: List<ChainRelayOption>,
    initialEnabled: Boolean,
    initialGuid: String,
    onConfirm: (enabled: Boolean, guid: String) -> Unit,
    onDismiss: () -> Unit
) {
    var enabled by remember { mutableStateOf(initialEnabled) }
    var guid by remember { mutableStateOf(initialGuid.takeIf { stored -> options.any { it.guid == stored } }.orEmpty()) }

    val noneOption = ChainRelayOption("", stringResource(R.string.chain_relay_none))
    val choices = listOf(noneOption) + options

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.title_chain_proxy_settings)) },
        text = {
            Column {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .toggleable(value = enabled, onValueChange = { enabled = it }, role = Role.Switch)
                        .padding(vertical = 8.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = stringResource(R.string.title_pref_chain_proxy_enabled),
                            style = MaterialTheme.typography.bodyLarge
                        )
                        Text(
                            text = stringResource(R.string.summary_pref_chain_proxy_enabled),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                    Spacer(modifier = Modifier.width(12.dp))
                    Switch(checked = enabled, onCheckedChange = null)
                }

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

                LazyColumn(modifier = Modifier.weight(1f, fill = false)) {
                    items(choices) { choice ->
                        val selected = choice.guid == guid
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .selectable(selected = selected, onClick = { guid = choice.guid }, role = Role.RadioButton)
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
        },
        confirmButton = {
            TextButton(onClick = { onConfirm(enabled, guid) }) { Text(stringResource(R.string.action_ok)) }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text(stringResource(R.string.action_cancel)) }
        },
        containerColor = MaterialTheme.colorScheme.surface
    )
}
