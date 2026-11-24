package com.v2ray.ang.core

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import com.v2ray.ang.AppConfig
import com.v2ray.ang.util.LogUtil

/**
 * Keeps the sockets of the chain process out of the VPN tunnel.
 *
 * Both chain methods (the relay core and the DNS chain) run in the chain process. In VPN mode the app
 * package is already left out of the tunnel by the VPN service, this class adds a second guard that does
 * not depend on that setting: the whole chain process is bound to the physical network, the one that is
 * not a VPN. Every socket it opens then leaves through that network, never through the tunnel, and the
 * name lookups of the process use the DNS of that network.
 *
 * The binding follows the physical network when it changes (Wi-Fi to mobile data and back).
 * It only changes the chain process, the daemon process and the profile core are not touched.
 */
object DnsChainNetwork {

    private const val TAG = "StartCore-ChainNetwork"

    private var manager: ConnectivityManager? = null
    private var callback: ConnectivityManager.NetworkCallback? = null
    private var users = 0
    private var bound: Network? = null

    /** Starts the binding. Calls are counted, [stop] must be called once for each [start]. */
    @Synchronized
    fun start(context: Context) {
        users += 1
        if (callback != null) return

        val cm = context.applicationContext.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
        if (cm == null) {
            LogUtil.w(AppConfig.TAG, "$TAG: no connectivity service")
            return
        }
        manager = cm

        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            .build()
        val cb = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) = refresh()
            override fun onLost(network: Network) = refresh()
            override fun onCapabilitiesChanged(network: Network, networkCapabilities: NetworkCapabilities) = refresh()
        }
        try {
            cm.registerNetworkCallback(request, cb)
            callback = cb
        } catch (e: Exception) {
            LogUtil.w(AppConfig.TAG, "$TAG: cannot watch the physical network: ${e.message}")
        }
        refresh()
    }

    /** Ends one [start]. The last one releases the binding. */
    @Synchronized
    fun stop() {
        if (users > 0) users -= 1
        if (users > 0) return

        val cm = manager
        val cb = callback
        callback = null
        manager = null
        if (cm != null && cb != null) {
            try {
                cm.unregisterNetworkCallback(cb)
            } catch (_: Exception) {
            }
        }
        if (cm != null && bound != null) {
            try {
                cm.bindProcessToNetwork(null)
            } catch (_: Exception) {
            }
        }
        bound = null
    }

    @Synchronized
    @Suppress("DEPRECATION")
    private fun refresh() {
        val cm = manager ?: return
        try {
            var best: Network? = null
            var bestScore = -1
            for (network in cm.allNetworks) {
                val caps = cm.getNetworkCapabilities(network) ?: continue
                if (!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) continue
                if (caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN).not()) continue
                var score = 0
                if (caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)) score += 100
                if (caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)) {
                    score += 30
                } else if (caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) {
                    score += 20
                } else if (caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) {
                    score += 10
                }
                if (score > bestScore) {
                    bestScore = score
                    best = network
                }
            }

            if (best == bound) return
            // Without a physical network the process is released, so it is never bound to a dead one.
            if (cm.bindProcessToNetwork(best)) {
                bound = best
                LogUtil.i(AppConfig.TAG, "$TAG: chain process bound to ${best ?: "default network"}")
            }
        } catch (e: Exception) {
            LogUtil.w(AppConfig.TAG, "$TAG: cannot bind the chain process: ${e.message}")
        }
    }
}
