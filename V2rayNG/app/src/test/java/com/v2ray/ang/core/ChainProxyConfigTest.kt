package com.v2ray.ang.core

import com.google.gson.JsonArray
import com.google.gson.JsonObject
import com.google.gson.JsonParser
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class ChainProxyConfigTest {

    private val validConfig = """
        {
          "inbounds": [{"listen": "127.0.0.1", "port": 20808, "protocol": "socks"}],
          "outbounds": [{"protocol": "freedom"}]
        }
    """.trimIndent()

    private val endpoint = ChainProxyConfig.RelayEndpoint("socks", "127.0.0.1", 20808)

    private fun inbounds(vararg inbound: String) = """{"inbounds": [${inbound.joinToString(",")}], "outbounds": [{"protocol": "freedom"}]}"""

    private fun outboundsOf(json: String): JsonArray =
        JsonParser.parseString(json).asJsonObject.getAsJsonArray("outbounds")

    private fun JsonArray.byTag(tag: String): JsonObject =
        first { it.asJsonObject.get("tag")?.asString == tag }.asJsonObject

    private fun JsonObject.dialerProxy(): String? =
        getAsJsonObject("streamSettings")?.getAsJsonObject("sockopt")?.get("dialerProxy")?.asString

    // region validate

    @Test
    fun validateAcceptsJsonWithInboundAndOutbound() {
        assertEquals(ChainProxyConfig.Validation.Valid, ChainProxyConfig.validate(validConfig))
    }

    @Test
    fun validateRejectsMissingOrBlankContent() {
        assertEquals(ChainProxyConfig.Validation.Empty, ChainProxyConfig.validate(null))
        assertEquals(ChainProxyConfig.Validation.Empty, ChainProxyConfig.validate("   "))
    }

    @Test
    fun validateRejectsContentThatIsNotAJsonObject() {
        assertEquals(ChainProxyConfig.Validation.NotJson, ChainProxyConfig.validate("vless://abc@host:443"))
        assertEquals(ChainProxyConfig.Validation.NotJson, ChainProxyConfig.validate("[1, 2]"))
        assertEquals(ChainProxyConfig.Validation.NotJson, ChainProxyConfig.validate("{\"inbounds\": ["))
    }

    @Test
    fun validateRejectsConfigWithoutInbound() {
        val noInbounds = """{"outbounds": [{"protocol": "freedom"}]}"""
        val emptyInbounds = """{"inbounds": [], "outbounds": [{"protocol": "freedom"}]}"""
        val wrongType = """{"inbounds": {}, "outbounds": [{"protocol": "freedom"}]}"""

        assertEquals(ChainProxyConfig.Validation.NoInbound, ChainProxyConfig.validate(noInbounds))
        assertEquals(ChainProxyConfig.Validation.NoInbound, ChainProxyConfig.validate(emptyInbounds))
        assertEquals(ChainProxyConfig.Validation.NoInbound, ChainProxyConfig.validate(wrongType))
    }

    @Test
    fun validateRejectsConfigWithoutOutbound() {
        val noOutbounds = """{"inbounds": [{"port": 1080, "protocol": "socks"}]}"""
        val emptyOutbounds = """{"inbounds": [{"port": 1080, "protocol": "socks"}], "outbounds": []}"""

        assertEquals(ChainProxyConfig.Validation.NoOutbound, ChainProxyConfig.validate(noOutbounds))
        assertEquals(ChainProxyConfig.Validation.NoOutbound, ChainProxyConfig.validate(emptyOutbounds))
    }

    // endregion

    // region shouldStartRelay and isMainProfile

    @Test
    fun relayStartsOnlyWhenSwitchIsOnAndConfigIsRunnable() {
        assertTrue(ChainProxyConfig.shouldStartRelay(true, validConfig))
    }

    @Test
    fun relayNeverStartsWhenSwitchIsOff() {
        assertFalse(ChainProxyConfig.shouldStartRelay(false, validConfig))
        assertFalse(ChainProxyConfig.shouldStartRelay(false, null))
    }

    @Test
    fun relayDoesNotStartWithoutAUsableConfig() {
        assertFalse(ChainProxyConfig.shouldStartRelay(true, null))
        assertFalse(ChainProxyConfig.shouldStartRelay(true, "not json"))
        assertFalse(ChainProxyConfig.shouldStartRelay(true, """{"inbounds": []}"""))
    }

    @Test
    fun isMainProfileDetectsTheProfileRunByTheMainCore() {
        assertTrue(ChainProxyConfig.isMainProfile("guid-1", "guid-1"))
        assertFalse(ChainProxyConfig.isMainProfile("guid-1", "guid-2"))
        assertFalse(ChainProxyConfig.isMainProfile("guid-1", null))
        assertFalse(ChainProxyConfig.isMainProfile("", ""))
        assertFalse(ChainProxyConfig.isMainProfile(null, "guid-1"))
    }

    // endregion

    // region findRelayEndpoint

    @Test
    fun endpointIsReadFromTheSocksInbound() {
        assertEquals(endpoint, ChainProxyConfig.findRelayEndpoint(validConfig))
    }

    @Test
    fun endpointPrefersSocksOverHttp() {
        val config = inbounds(
            """{"listen": "127.0.0.1", "port": 8080, "protocol": "http"}""",
            """{"listen": "127.0.0.1", "port": 1080, "protocol": "socks"}"""
        )
        assertEquals(ChainProxyConfig.RelayEndpoint("socks", "127.0.0.1", 1080), ChainProxyConfig.findRelayEndpoint(config))
    }

    @Test
    fun endpointFallsBackToHttp() {
        val config = inbounds("""{"listen": "127.0.0.1", "port": 8080, "protocol": "http"}""")
        assertEquals(ChainProxyConfig.RelayEndpoint("http", "127.0.0.1", 8080), ChainProxyConfig.findRelayEndpoint(config))
    }

    @Test
    fun endpointUsesLoopbackForWildcardOrMissingListen() {
        val wildcard = inbounds("""{"listen": "0.0.0.0", "port": 1080, "protocol": "socks"}""")
        val missing = inbounds("""{"port": 1080, "protocol": "socks"}""")

        assertEquals("127.0.0.1", ChainProxyConfig.findRelayEndpoint(wildcard)?.address)
        assertEquals("127.0.0.1", ChainProxyConfig.findRelayEndpoint(missing)?.address)
    }

    @Test
    fun endpointKeepsAnExplicitListenAddress() {
        val config = inbounds("""{"listen": "127.0.0.2", "port": 1080, "protocol": "socks"}""")
        assertEquals("127.0.0.2", ChainProxyConfig.findRelayEndpoint(config)?.address)
    }

    @Test
    fun endpointAcceptsAPortGivenAsText() {
        val config = inbounds("""{"port": "1080", "protocol": "socks"}""")
        assertEquals(1080, ChainProxyConfig.findRelayEndpoint(config)?.port)
    }

    @Test
    fun endpointIsNullWithoutAUsablePortOrAddress() {
        assertNull(ChainProxyConfig.findRelayEndpoint(inbounds("""{"port": "1000-2000", "protocol": "socks"}""")))
        assertNull(ChainProxyConfig.findRelayEndpoint(inbounds("""{"port": 0, "protocol": "socks"}""")))
        assertNull(ChainProxyConfig.findRelayEndpoint(inbounds("""{"port": 70000, "protocol": "socks"}""")))
        assertNull(ChainProxyConfig.findRelayEndpoint(inbounds("""{"protocol": "socks"}""")))
        assertNull(ChainProxyConfig.findRelayEndpoint(inbounds("""{"listen": "/tmp/relay.sock", "port": 1080, "protocol": "socks"}""")))
    }

    @Test
    fun endpointIsNullWithoutASocksOrHttpInbound() {
        val config = inbounds("""{"port": 5353, "protocol": "dokodemo-door"}""")
        assertNull(ChainProxyConfig.findRelayEndpoint(config))
        assertNull(ChainProxyConfig.findRelayEndpoint("not json"))
        assertNull(ChainProxyConfig.findRelayEndpoint(null))
    }

    @Test
    fun endpointCarriesSocksCredentialsOnlyWhenPasswordAuthIsOn() {
        val withAuth = inbounds(
            """{"port": 1080, "protocol": "socks", "settings": {"auth": "password", "accounts": [{"user": "u", "pass": "p"}]}}"""
        )
        val authOff = inbounds(
            """{"port": 1080, "protocol": "socks", "settings": {"auth": "noauth", "accounts": [{"user": "u", "pass": "p"}]}}"""
        )

        assertEquals(ChainProxyConfig.RelayEndpoint("socks", "127.0.0.1", 1080, "u", "p"), ChainProxyConfig.findRelayEndpoint(withAuth))
        assertNull(ChainProxyConfig.findRelayEndpoint(authOff)?.user)
    }

    @Test
    fun endpointCarriesHttpCredentials() {
        val config = inbounds(
            """{"port": 8080, "protocol": "http", "settings": {"accounts": [{"user": "u", "pass": "p"}]}}"""
        )
        assertEquals(ChainProxyConfig.RelayEndpoint("http", "127.0.0.1", 8080, "u", "p"), ChainProxyConfig.findRelayEndpoint(config))
    }

    // endregion

    // region applyRelayHop

    @Test
    fun hopMakesTheProfileOutboundDialThroughTheRelay() {
        val main = """{"outbounds": [{"tag": "proxy", "protocol": "vless", "settings": {}}]}"""

        val result = ChainProxyConfig.applyRelayHop(main, endpoint)

        assertNotNull(result)
        val outbounds = outboundsOf(result!!)
        assertEquals(ChainProxyConfig.RELAY_TAG, outbounds.byTag("proxy").dialerProxy())
        val hop = outbounds.byTag(ChainProxyConfig.RELAY_TAG)
        assertEquals("socks", hop.get("protocol").asString)
        assertEquals("127.0.0.1", hop.getAsJsonObject("settings").get("address").asString)
        assertEquals(20808, hop.getAsJsonObject("settings").get("port").asInt)
    }

    @Test
    fun hopLeavesDirectAndBlockOutboundsAlone() {
        val main = """
            {"outbounds": [
              {"tag": "proxy", "protocol": "vless"},
              {"tag": "direct", "protocol": "freedom"},
              {"tag": "block", "protocol": "blackhole"}
            ]}
        """.trimIndent()

        val outbounds = outboundsOf(ChainProxyConfig.applyRelayHop(main, endpoint)!!)

        assertNull(outbounds.byTag("direct").dialerProxy())
        assertNull(outbounds.byTag("block").dialerProxy())
        assertEquals(4, outbounds.size())
    }

    @Test
    fun hopKeepsExistingStreamSettings() {
        val main = """{"outbounds": [{"tag": "proxy", "protocol": "vless", "streamSettings": {"network": "ws", "security": "tls"}}]}"""

        val proxy = outboundsOf(ChainProxyConfig.applyRelayHop(main, endpoint)!!).byTag("proxy")

        assertEquals("ws", proxy.getAsJsonObject("streamSettings").get("network").asString)
        assertEquals("tls", proxy.getAsJsonObject("streamSettings").get("security").asString)
        assertEquals(ChainProxyConfig.RELAY_TAG, proxy.dialerProxy())
    }

    @Test
    fun hopOnlyReachesTheFirstHopOfAProfileChain() {
        val main = """
            {"outbounds": [
              {"tag": "proxy", "protocol": "vless", "streamSettings": {"sockopt": {"dialerProxy": "chain-1"}}},
              {"tag": "chain-1", "protocol": "trojan"}
            ]}
        """.trimIndent()

        val outbounds = outboundsOf(ChainProxyConfig.applyRelayHop(main, endpoint)!!)

        assertEquals("chain-1", outbounds.byTag("proxy").dialerProxy())
        assertEquals(ChainProxyConfig.RELAY_TAG, outbounds.byTag("chain-1").dialerProxy())
    }

    @Test
    fun hopSkipsTransportsThatCannotUseAHop() {
        val onlyKcp = """{"outbounds": [{"tag": "proxy", "protocol": "vless", "streamSettings": {"network": "kcp"}}]}"""
        val onlyWireguard = """{"outbounds": [{"tag": "proxy", "protocol": "wireguard"}]}"""

        assertNull(ChainProxyConfig.applyRelayHop(onlyKcp, endpoint))
        assertNull(ChainProxyConfig.applyRelayHop(onlyWireguard, endpoint))
    }

    @Test
    fun hopReturnsNullWhenThereIsNothingToChain() {
        assertNull(ChainProxyConfig.applyRelayHop("""{"outbounds": [{"protocol": "freedom"}]}""", endpoint))
        assertNull(ChainProxyConfig.applyRelayHop("""{"outbounds": []}""", endpoint))
        assertNull(ChainProxyConfig.applyRelayHop("""{"inbounds": []}""", endpoint))
        assertNull(ChainProxyConfig.applyRelayHop("not json", endpoint))
    }

    @Test
    fun hopIsNotDuplicatedWhenAppliedTwice() {
        val main = """{"outbounds": [{"tag": "proxy", "protocol": "vless"}]}"""

        val once = ChainProxyConfig.applyRelayHop(main, endpoint)!!
        val twice = ChainProxyConfig.applyRelayHop(once, endpoint)!!

        val hops = outboundsOf(twice).count { it.asJsonObject.get("tag")?.asString == ChainProxyConfig.RELAY_TAG }
        assertEquals(1, hops)
    }

    @Test
    fun hopCarriesCredentials() {
        val withAuth = ChainProxyConfig.RelayEndpoint("http", "127.0.0.1", 8080, "u", "p")
        val main = """{"outbounds": [{"tag": "proxy", "protocol": "vless"}]}"""

        val settings = outboundsOf(ChainProxyConfig.applyRelayHop(main, withAuth)!!)
            .byTag(ChainProxyConfig.RELAY_TAG).getAsJsonObject("settings")

        assertEquals("http", outboundsOf(ChainProxyConfig.applyRelayHop(main, withAuth)!!).byTag(ChainProxyConfig.RELAY_TAG).get("protocol").asString)
        assertEquals("u", settings.get("user").asString)
        assertEquals("p", settings.get("pass").asString)
    }

    // endregion
}
