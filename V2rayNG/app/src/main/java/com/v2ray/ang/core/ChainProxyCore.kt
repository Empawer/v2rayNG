package com.v2ray.ang.core

import com.v2ray.ang.AppConfig
import com.v2ray.ang.util.LogUtil
import libv2ray.CoreCallbackHandler
import libv2ray.CoreController

/**
 * Second, fully independent native core that runs the user's chain proxy relay config.
 *
 * It exists next to the profile core owned by [CoreServiceManager] and has its own
 * [CoreController], so the two never share a config, a listener or a stop call. This is a different
 * owner from the profile core: its config is chosen in settings and not from a profile, and it
 * never owns a tun descriptor. [CoreServiceManager] decides when it starts and stops.
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
