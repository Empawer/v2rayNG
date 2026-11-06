package com.v2ray.ang.core

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class ChainProxyConfigTest {

    private val validConfig = """
        {
          "inbounds": [{"listen": "127.0.0.1", "port": 20808, "protocol": "socks"}],
          "outbounds": [{"protocol": "freedom"}]
        }
    """.trimIndent()

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
}
