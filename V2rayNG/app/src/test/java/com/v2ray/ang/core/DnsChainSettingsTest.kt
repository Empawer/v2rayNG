package com.v2ray.ang.core

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class DnsChainSettingsTest {

    @Test
    fun defaultTextIsTheOriginalIni() {
        val s = DnsChainSettings.defaults()
        assertEquals("127.0.0.1", s.listenIp)
        assertEquals(18081, s.listenPort)
        assertEquals("pages.dev", s.testDomain)
        assertEquals(
            listOf("https://1.1.1.1/dns-query", "https://[2606:4700:4700::1001]/dns-query"),
            s.dohServers,
        )
        assertEquals(300, s.idleTimeout)
        assertEquals(10.0, s.connectTimeout)
        assertEquals(15.0, s.handshakeTimeout)
        assertEquals(5.0, s.dohTimeout)
        assertEquals(30.0, s.dohCooldown)
        assertEquals("INFO", s.logLevel)
        // [sni split] is off and [hello split] is on in the original file.
        assertNull(s.sniSplit)
        val hello = s.helloSplit!!
        assertEquals("tcp", hello.method)
        assertEquals(10, hello.sniPieces)
        assertEquals(0.005, hello.delay, 1e-9)
        assertEquals(0.0, hello.jitter, 1e-9)
        assertNull(hello.firstDelay)
        assertTrue(hello.points.contains("random:5"))
        assertTrue(s.warnings.isEmpty())
    }

    @Test
    fun sniSplitIsReadWhenEnabled() {
        val s = DnsChainSettings.parse("[proxy]\nlisten_port = 1\n[sni split]\nEnable = 1\npieces = 1\ndelay = 2 ms\n")
        val sni = s.sniSplit!!
        assertEquals(2, sni.pieces)
        assertEquals(0.002, sni.delay, 1e-9)
    }

    @Test
    fun dohKeysAreSortedAndDeduplicated() {
        val text = "[proxy]\nDOH_10 = https://c/dns\nDOH_02 = https://b/dns\nDOH = https://a/dns\n" +
            "DOH_03 = https://b/dns\nDOH_04 =\nDOH_05 = http://insecure/dns\n"
        val s = DnsChainSettings.parse(text)
        assertEquals(listOf("https://a/dns", "https://b/dns", "https://c/dns"), s.dohServers)
        assertEquals(1, s.warnings.size)
    }

    @Test
    fun invalidHelloSectionIsSkippedWithAWarning() {
        val s = DnsChainSettings.parse("[proxy]\n[hello split]\nEnable = 1\npoints = nonsense\n")
        assertNull(s.helloSplit)
        assertEquals(1, s.warnings.size)
    }

    @Test
    fun testDomainIsCleaned() {
        assertEquals("example.com", DnsChainSettings.parse("[proxy]\nDomain = https://Example.com:8443/path\n").testDomain.lowercase())
        assertEquals("example.com", DnsChainSettings.parse("[proxy]\nDomain =\n").testDomain)
    }

    @Test
    fun brokenTextIsRefused() {
        assertThrows(DnsChainConfigException::class.java) { DnsChainSettings.parse("listen_port = 1") }
        assertThrows(DnsChainConfigException::class.java) { DnsChainSettings.parse("[proxy]\nlisten_port = abc") }
        assertThrows(DnsChainConfigException::class.java) { DnsChainSettings.parse("[proxy]\njust a line") }
        assertThrows(DnsChainConfigException::class.java) { DnsChainSettings.parse("[proxy]\na = 1\na = 2") }
        assertNotNull(DnsChainSettings.parse(""))
    }
}
