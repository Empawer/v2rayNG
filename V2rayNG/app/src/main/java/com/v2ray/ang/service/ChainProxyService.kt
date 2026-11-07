package com.v2ray.ang.service

import android.app.Service
import android.content.Intent
import android.os.Binder
import android.os.IBinder
import com.v2ray.ang.AppConfig
import com.v2ray.ang.R
import com.v2ray.ang.core.ChainProxyConfig
import com.v2ray.ang.core.ChainProxyCore
import com.v2ray.ang.core.CoreNativeManager
import com.v2ray.ang.extension.toastError
import com.v2ray.ang.handler.MmkvManager
import com.v2ray.ang.util.LogUtil
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.launch
import java.util.concurrent.Executors

/**
 * Runs the chain proxy relay core in its own process (`:chainproxy`), apart from the profile core in
 * `:daemon`, so the two native cores share no runtime state.
 *
 * The daemon binds this service while it runs and unbinds it when it stops. The binding is the whole
 * lifecycle: when the daemon unbinds, or dies, Android destroys this service and the relay stops with it.
 * The service is not a foreground service and never calls `startForeground`: it only exists while the
 * foreground daemon holds the binding.
 *
 * The daemon passes the id of the chain profile, this process reads the config from the settings storage
 * itself. The user connects to the relay's own inbound with a proxy profile of their own, so nothing about
 * the relay is reported back to the daemon, a failed start is shown to the user from here.
 */
class ChainProxyService : Service() {

    companion object {
        const val EXTRA_GUID = "chain_proxy_guid"

        // Shared by every instance of this service in the process. A stop queued by a destroyed
        // instance and the start of the next instance run on one thread, in the order they were queued,
        // so they can never overlap on the one native core.
        private val core = ChainProxyCore()
        private val worker = Executors
            .newSingleThreadExecutor { Thread(it, "chain-proxy-core").apply { isDaemon = true } }
            .asCoroutineDispatcher()
    }

    private val scope = CoroutineScope(SupervisorJob() + worker)
    private var startJob: Job? = null

    override fun onBind(intent: Intent?): IBinder {
        val guid = intent?.getStringExtra(EXTRA_GUID).orEmpty()
        LogUtil.i(AppConfig.TAG, "StartCore-ChainProxy: relay service bound")
        // Native work stays off the service main thread.
        startJob = scope.launch { startRelay(guid) }
        return Binder()
    }

    private fun startRelay(guid: String) {
        try {
            CoreNativeManager.initCoreEnv(this)

            val raw = MmkvManager.decodeServerRaw(guid)
            check(ChainProxyConfig.validate(raw) == ChainProxyConfig.Validation.Valid) { "chain config is missing or invalid" }

            core.start(raw!!)
            LogUtil.i(AppConfig.TAG, "StartCore-ChainProxy: relay core running in its own process")
        } catch (e: Exception) {
            // The config is not logged, it may hold credentials.
            LogUtil.e(AppConfig.TAG, "StartCore-ChainProxy: relay core failed to start", e)
            val reason = e.message?.takeUnless { it.isBlank() } ?: e.javaClass.simpleName
            applicationContext.toastError(getString(R.string.toast_chain_proxy_start_failed, reason), true)
        }
    }

    override fun onDestroy() {
        LogUtil.i(AppConfig.TAG, "StartCore-ChainProxy: relay service destroyed")
        // A start that has not begun is dropped. The stop below is queued behind one that has, and the
        // scope is not cancelled, because cancelling it would cancel this stop.
        startJob?.cancel()
        scope.launch {
            try {
                core.stop()
            } catch (e: Exception) {
                LogUtil.e(AppConfig.TAG, "StartCore-ChainProxy: relay core stop failed", e)
            }
        }
        super.onDestroy()
    }
}
