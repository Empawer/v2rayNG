package com.v2ray.ang.core

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * The expected values come from running the original Python proxy (main.py, the fragment version)
 * on the same input: the same settings text, the same pieces of the client data.
 */
class DnsChainWireTest {

    // ---------------------------------------------------------------- fragment settings

    @Test
    fun readsTheFragmentSectionLikeThePythonProxy() {
        val settings = DnsChainSettings.parse(
            "[fragment]\nEnable = 1\nlength = 10-20\ninterval = 5-10 ms\nmax_split = 30\n",
        )
        val fragment = settings.fragment!!
        assertEquals(listOf(10 to 20), fragment.lengths)
        assertEquals(0.005 to 0.01, fragment.interval)
        assertEquals(30, fragment.maxSplit)
    }

    @Test
    fun readsAListOfLengthsWithRanges() {
        val settings = DnsChainSettings.parse("[fragment]\nEnable = 1\nlength = 20, 5-9, 1\ninterval = 0\n")
        val fragment = settings.fragment!!
        assertEquals(listOf(20 to 20, 5 to 9, 1 to 1), fragment.lengths)
        assertEquals(0.0 to 0.0, fragment.interval)
        assertEquals(0, fragment.maxSplit)
    }

    @Test
    fun missingMaxSplitMeansUnlimited() {
        val settings = DnsChainSettings.parse("[fragment]\nEnable = 1\nlength = 10\n")
        assertEquals(0, settings.fragment!!.maxSplit)
    }

    @Test
    fun fragmentOffOrMissingMeansNull() {
        assertNull(DnsChainSettings.parse("[fragment]\nEnable = 0\nlength = 10\n").fragment)
        assertNull(DnsChainSettings.parse("[proxy]\nlisten_port = 18081\n").fragment)
    }

    @Test
    fun invalidFragmentSectionIsSkippedWithAWarning() {
        // length is a time, not a size
        val ms = DnsChainSettings.parse("[fragment]\nEnable = 1\nlength = 10 ms\n")
        assertNull(ms.fragment)
        assertTrue(ms.warnings.any { it.contains("length is in bytes, not ms") })

        // a range must be written low-high
        val reversed = DnsChainSettings.parse("[fragment]\nEnable = 1\nlength = 10-5\n")
        assertNull(reversed.fragment)

        // length must be whole bytes
        val fractional = DnsChainSettings.parse("[fragment]\nEnable = 1\nlength = 1.5\n")
        assertNull(fractional.fragment)

        // an empty length list
        val empty = DnsChainSettings.parse("[fragment]\nEnable = 1\nlength =\n")
        assertNull(empty.fragment)

        // max_split cannot be negative
        val negative = DnsChainSettings.parse("[fragment]\nEnable = 1\nlength = 10\nmax_split = -1\n")
        assertNull(negative.fragment)
    }

    // ---------------------------------------------------------------- fragment plan

    @Test
    fun fixedLengthSplitsInEqualPieces() {
        val settings = DnsChainSettings.parse("[fragment]\nEnable = 1\nlength = 10\ninterval = 0\n")
        val frag = DnsChainWire.Fragmenter(settings.fragment!!)
        val data = ByteArray(35)

        val plan = DnsChainWire.fragmentPlan(data, frag)

        // [10, 10, 10, 5]; pauses inside because max_split = 0 (unlimited)
        assertEquals(listOf(10, 10, 10, 5), plan.map { it.bytes.size })
        assertEquals(listOf(true, true, true, false), plan.map { it.pauseAfter })
        assertTrue(data.contentEquals(plan.fold(ByteArray(0)) { acc, p -> acc + p.bytes }))
        assertEquals(4, frag.count)
        assertTrue(frag.active)
    }

    @Test
    fun theLengthListWrapsAround() {
        val settings = DnsChainSettings.parse("[fragment]\nEnable = 1\nlength = 20, 9, 1\ninterval = 0\n")
        val frag = DnsChainWire.Fragmenter(settings.fragment!!)
        val data = ByteArray(45)

        val plan = DnsChainWire.fragmentPlan(data, frag)

        // 20 + 9 + 1 + 15: after the list ends it starts again from the first item
        assertEquals(listOf(20, 9, 1, 15), plan.map { it.bytes.size })
        assertEquals(4, frag.count)
    }

    @Test
    fun maxSplitLimitsTheFragmentedPieces() {
        val settings = DnsChainSettings.parse("[fragment]\nEnable = 1\nlength = 10\ninterval = 0\nmax_split = 3\n")
        val frag = DnsChainWire.Fragmenter(settings.fragment!!)
        val data = ByteArray(50)

        val plan = DnsChainWire.fragmentPlan(data, frag)

        // three pieces of 10 bytes are fragmented, the remaining 20 bytes pass through untouched
        assertEquals(listOf(10, 10, 10, 20), plan.map { it.bytes.size })
        assertEquals(listOf(true, true, false, false), plan.map { it.pauseAfter })
        assertTrue(data.contentEquals(plan.fold(ByteArray(0)) { acc, p -> acc + p.bytes }))
        assertEquals(3, frag.count)
        assertFalse(frag.active)
    }

    @Test
    fun anInactiveFragmenterLeavesTheDataAsItIs() {
        val settings = DnsChainSettings.parse("[fragment]\nEnable = 1\nlength = 10\ninterval = 0\nmax_split = 3\n")
        val frag = DnsChainWire.Fragmenter(settings.fragment!!)
        // use the quota up
        DnsChainWire.fragmentPlan(ByteArray(30), frag)

        val plan = DnsChainWire.fragmentPlan(ByteArray(40), frag)

        assertEquals(1, plan.size)
        assertEquals(40, plan[0].bytes.size)
        assertFalse(plan[0].pauseAfter)
        assertEquals(3, frag.count)
    }

    @Test
    fun aRangeLengthStaysInsideItsBounds() {
        val settings = DnsChainSettings.parse("[fragment]\nEnable = 1\nlength = 10-20\ninterval = 0\n")
        val frag = DnsChainWire.Fragmenter(settings.fragment!!)
        val data = ByteArray(1000)

        val plan = DnsChainWire.fragmentPlan(data, frag)

        assertTrue(plan.size > 50) // pieces of at most 20 bytes cannot be fewer than 50
        for (piece in plan.dropLast(1)) {
            assertTrue(piece.bytes.size in 10..20)
        }
        assertTrue(data.contentEquals(plan.fold(ByteArray(0)) { acc, p -> acc + p.bytes }))
    }

    @Test
    fun theIntervalRangeIsDrawnBetweenItsBounds() {
        val settings = DnsChainSettings.parse("[fragment]\nEnable = 1\nlength = 10\ninterval = 5-10 ms\n")
        val frag = DnsChainWire.Fragmenter(settings.fragment!!)
        for (i in 0 until 100) {
            val delay = frag.nextDelay()
            assertTrue(delay in 0.005..0.010)
        }
    }

    @Test
    fun tlsClientHelloIsStillRecognisedForTheFirstPacketLog() {
        assertTrue(DnsChainWire.isTlsClientHello(byteArrayOf(0x16, 0x03, 0x01, 0x00, 0x05, 0x01)))
        assertFalse(DnsChainWire.isTlsClientHello(byteArrayOf(0x16, 0x03, 0x01, 0x00, 0x05, 0x02)))
        assertFalse(DnsChainWire.isTlsClientHello(byteArrayOf(0x17, 0x03, 0x01, 0x00, 0x05, 0x01)))
    }

    // ---------------------------------------------------------------- DNS, HTTP, urls

    @Test
    fun dnsQueryMatchesThePythonProxy() {
        assertEquals(
            "000001000001000000000000057061676573036465760000010001",
            DnsChainWire.buildDnsQuery("pages.dev", 1).toHex(),
        )
        assertEquals(
            "0000010000010000000000000570616765730364657600001c0001",
            DnsChainWire.buildDnsQuery("pages.dev", 28).toHex(),
        )
    }

    @Test
    fun readsAnAnswerOfADohServer() {
        val answer = (
            "00008180000100010000000005" + "7061676573" + "03646576" + "0000010001" +
                "c00c0001000100000078" + "0004" + "68120102"
            ).chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        assertEquals("104.18.1.2" to 120L, DnsChainWire.parseDnsResponse(answer, 1))
        assertNull(DnsChainWire.parseDnsResponse(answer, 28))
    }

    @Test
    fun decodesPlainAndChunkedHttpBodies() {
        val plain = "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc".toByteArray()
        assertTrue(DnsChainWire.httpComplete(plain))
        assertEquals("abc", String(DnsChainWire.decodeHttpBody(plain) { }!!))

        val chunked = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n".toByteArray()
        assertTrue(DnsChainWire.httpComplete(chunked))
        assertEquals("abcde", String(DnsChainWire.decodeHttpBody(chunked) { }!!))

        var bad = ""
        assertNull(DnsChainWire.decodeHttpBody("HTTP/1.1 503 Busy\r\n\r\n".toByteArray()) { bad = it })
        assertEquals("HTTP/1.1 503 Busy", bad)
        assertFalse(DnsChainWire.httpComplete("HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nabc".toByteArray()))
    }

    @Test
    fun parsesDohUrls() {
        val v6 = DnsChainWire.parseDohUrl("https://[2606:4700:4700::1001]/dns-query")!!
        assertEquals("2606:4700:4700::1001", v6.host)
        assertNull(v6.port)
        assertEquals("/dns-query", v6.path)

        val named = DnsChainWire.parseDohUrl("https://Dns.Example.com:8443")!!
        assertEquals("dns.example.com", named.host)
        assertEquals(8443, named.port)

        assertNull(DnsChainWire.parseDohUrl("https:///dns-query"))
        assertNotNull(DnsChainWire.parseDohUrl("https://1.1.1.1/dns-query"))
    }

    @Test
    fun recognisesIpLiterals() {
        assertTrue(DnsChainWire.isIpLiteral("1.1.1.1"))
        assertTrue(DnsChainWire.isIpLiteral("2606:4700:4700::1001"))
        assertFalse(DnsChainWire.isIpLiteral("example.com"))
        assertFalse(DnsChainWire.isIpLiteral("999.1.1.1"))
    }

    @Test
    fun encodesBase64WithoutPadding() {
        assertEquals("AAABAAAB", DnsChainWire.base64Url(byteArrayOf(0, 0, 1, 0, 0, 1)))
        assertEquals("_-8", DnsChainWire.base64Url(byteArrayOf(0xFF.toByte(), 0xEF.toByte())))
        assertEquals("_w", DnsChainWire.base64Url(byteArrayOf(0xFF.toByte())))
    }

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }
}
