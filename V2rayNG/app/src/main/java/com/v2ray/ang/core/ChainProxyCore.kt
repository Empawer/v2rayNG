package com.v2ray.ang.core

import com.v2ray.ang.AppConfig
import com.v2ray.ang.util.LogUtil
import libv2ray.CoreCallbackHandler
import libv2ray.CoreController

/**
 * Native core that runs the user's chain proxy relay config.
 *
 * It lives in the `:chainproxy` process, owned by [com.v2ray.ang.service.ChainProxyService], and has its
 * own [CoreController], so it never shares a config, a listener, a stop call or Go runtime state with the
 * profile core in the daemon process. It never owns a tun descriptor.
 *
 * Calls are blocking native calls and must run off the main thread. Every method takes [lock], so a
 * stop and a start issued back to back cannot interleave.
 */
class ChainProxyCore {
    private val lock = Any()
    private var controller: CoreController? = null

    /** True while the relay core runs. The controller is created on first start, nothing native exists while the feature is off. */
    fun isRunning(): Boolean = synchronized(lock) { controller?.isRunning == true }

    /**
     * Starts the relay core with [content], replacing a relay that is already running.
     *
     * @throws Exception when the core rejects the config, for example because an inbound port is taken.
     */
    @Throws(Exception::class)
    fun start(content: String) {
        synchronized(lock) {
            stopLocked()
            val core = controller ?: CoreNativeManager.newCoreController(RelayCallback()).also { controller = it }
            try {
                // No tun descriptor: the relay only serves its own inbound.
                core.startLoop(content, 0)
                if (!core.isRunning) {
                    error("Chain proxy core failed to start")
                }
            } catch (e: Exception) {
                stopLocked()
                throw e
            }
        }
    }

    /** Stops the relay core. Calling it when nothing runs is a no-op. */
    fun stop() {
        synchronized(lock) { stopLocked() }
    }

    private fun stopLocked() {
        val core = controller ?: return
        try {
            if (core.isRunning) core.stopLoop()
        } catch (e: Exception) {
            LogUtil.e(AppConfig.TAG, "StartCore-ChainProxy: Failed to stop relay core", e)
        }
    }

    private class RelayCallback : CoreCallbackHandler {
        override fun startup(): Long {
            LogUtil.i(AppConfig.TAG, "StartCore-ChainProxy: CoreCallback startup")
            return 0
        }

        override fun shutdown(): Long {
            LogUtil.i(AppConfig.TAG, "StartCore-ChainProxy: CoreCallback shutdown")
            return 0
        }

        override fun onEmitStatus(l: Long, s: String?): Long {
            LogUtil.i(AppConfig.TAG, "StartCore-ChainProxy: CoreCallback onEmitStatus $s")
            return 0
        }
    }
}
