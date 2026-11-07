package com.v2ray.ang.core

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.IBinder
import com.v2ray.ang.AppConfig
import com.v2ray.ang.service.ChainProxyService
import com.v2ray.ang.util.LogUtil

/**
 * Daemon-side control of the chain proxy relay. The relay core runs in [ChainProxyService], in a process
 * of its own, and lives exactly as long as this launcher holds the binding to it.
 *
 * It belongs to the daemon process and is driven by [CoreServiceManager], which decides when the relay
 * starts and stops together with the profile core. The profile core does not depend on the relay, the user
 * reaches the relay with a proxy profile of their own, so starting does not wait for the relay.
 */
object ChainProxyLauncher {

    private var boundContext: Context? = null
    private var connection: ServiceConnection? = null

    /**
     * Starts the relay for the custom profile [sourceGuid], replacing a relay that already runs.
     *
     * @return false when the relay service could not be bound.
     */
    @Synchronized
    fun start(context: Context, sourceGuid: String): Boolean {
        unbindLocked()

        val appContext = context.applicationContext
        val newConnection = object : ServiceConnection {
            override fun onServiceConnected(name: ComponentName?, service: IBinder?) = Unit
            override fun onServiceDisconnected(name: ComponentName?) = Unit
        }
        val intent = Intent(appContext, ChainProxyService::class.java)
            .putExtra(ChainProxyService.EXTRA_GUID, sourceGuid)

        val bound = try {
            appContext.bindService(intent, newConnection, Context.BIND_AUTO_CREATE)
        } catch (e: SecurityException) {
            LogUtil.e(AppConfig.TAG, "StartCore-ChainProxy: cannot bind relay service", e)
            false
        }
        if (!bound) {
            runCatching { appContext.unbindService(newConnection) }
            return false
        }
        boundContext = appContext
        connection = newConnection
        return true
    }

    /** Stops the relay. Calling it when no relay runs is a no-op. */
    @Synchronized
    fun stop() {
        unbindLocked()
    }

    private fun unbindLocked() {
        val currentConnection = connection
        val currentContext = boundContext
        connection = null
        boundContext = null
        if (currentConnection != null && currentContext != null) {
            try {
                currentContext.unbindService(currentConnection)
            } catch (e: IllegalArgumentException) {
                LogUtil.w(AppConfig.TAG, "StartCore-ChainProxy: relay service was not bound")
            }
        }
    }
}
