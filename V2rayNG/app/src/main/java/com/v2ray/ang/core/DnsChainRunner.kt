package com.v2ray.ang.core

import android.util.Log
import com.v2ray.ang.AppConfig
import java.io.IOException
import java.util.Locale

/**
 * Starts and stops the DNS chain proxy and sends its log to logcat, filtered by the log_level of the settings.
 * It runs in the chain process.
 */
class DnsChainRunner {

    private var proxy: DnsChainProxy? = null

    /**
     * Starts the proxy with [settings], replacing one that runs.
     *
     * @throws IOException when the listening address cannot be used.
     */
    @Synchronized
    @Throws(IOException::class)
    fun start(settings: DnsChainSettings) {
        stop()
        val minLevel = when (settings.logLevel.uppercase(Locale.ROOT)) {
            "DEBUG", "NOTSET" -> DnsChainProxy.DEBUG
            "WARNING", "WARN" -> DnsChainProxy.WARNING
            "ERROR" -> DnsChainProxy.ERROR
            "CRITICAL", "FATAL" -> 50
            else -> DnsChainProxy.INFO
        }
        val log = DnsChainLog { level, message ->
            if (level >= minLevel) {
                val priority = when {
                    level >= DnsChainProxy.ERROR && level < DnsChainProxy.PRINT -> Log.ERROR
                    level >= DnsChainProxy.WARNING && level < DnsChainProxy.PRINT -> Log.WARN
                    level >= DnsChainProxy.INFO -> Log.INFO
                    else -> Log.DEBUG
                }
                Log.println(priority, AppConfig.TAG, "DnsChain: $message")
            }
        }
        val created = DnsChainProxy(settings, log) { DnsChainProxy.androidTune(it) }
        created.start()
        proxy = created
    }

    @Synchronized
    fun stop() {
        proxy?.stop()
        proxy = null
    }

    @Synchronized
    fun isRunning(): Boolean = proxy?.isRunning() == true
}
