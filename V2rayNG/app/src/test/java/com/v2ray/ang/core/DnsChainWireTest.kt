package com.v2ray.ang.core

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * The expected values come from running the original Python proxy (main.py) on the same input:
 * a real TLS ClientHello for www.example.pages.dev.
 */
class DnsChainWireTest {

    private val hello: ByteArray = HELLO_HEX.chunked(2).map { it.toInt(16).toByte() }.toByteArray()

    private fun cuts(points: String, sniPieces: Int = 10): List<Int> {
        val info = DnsChainWire.parseClientHello(hello)!!
        return DnsChainWire.computeCuts(points.split(",").map { it.trim() }, info, hello, sniPieces)
    }

    @Test
    fun recognisesClientHelloAndFindsTheHostname() {
        assertEquals(517, hello.size)
        assertTrue(DnsChainWire.isTlsClientHello(hello))
        assertEquals(153 to 21, DnsChainWire.findSniSpan(hello))

        val info = DnsChainWire.parseClientHello(hello)!!
        assertEquals(76, info.sessionId)
        assertEquals(78, info.csStart)
        assertEquals(140, info.cipherSuites)
        assertEquals(142, info.compression)
        assertEquals(144, info.extensions)
        assertEquals(153 to 21, info.sni)
    }

    @Test
    fun cutsMatchThePythonProxy() {
        assertEquals(listOf(153, 155, 157, 159, 161, 163, 165, 167, 169, 171, 174), cuts("sni"))
        assertEquals(
            listOf(9, 140, 144, 153, 155, 157, 159, 161, 163, 165, 167, 169, 171, 174),
            cuts("handshake_header,cipher_suites,extensions,sni,ext:alpn"),
        )
        assertEquals(
            listOf(
                5, 9, 43, 76, 108, 140, 142, 144, 153, 155, 157, 159, 161, 163, 165, 167, 169, 171, 174,
                182, 208, 212, 216, 220, 266, 275, 281, 323,
            ),
            cuts(DnsChainHello.PRESETS.getValue("aggressive")),
        )
        assertEquals(listOf(5, 100, 200, 300, 400, 500, 507), cuts("5,-10,every:100"))
    }

    @Test
    fun hostnameSplitKeepsEveryByte() {
        val pieces = DnsChainWire.planSniSplit(hello, 10)!!
        assertTrue(pieces.size >= 2)
        assertTrue(hello.contentEquals(pieces.fold(ByteArray(0)) { acc, p -> acc + p }))
    }

    @Test
    fun recordMethodWrapsEveryPieceInItsOwnRecord() {
        val settings = DnsChainSettings.parse("[hello split]\nEnable = 1\npoints = sni\nmethod = record\n")
        val pieces = DnsChainWire.planHelloSplit(hello, settings.helloSplit!!)!!
        var payload = ByteArray(0)
        for (piece in pieces) {
            assertEquals(0x16, piece[0].toInt())
            val length = ((piece[3].toInt() and 0xFF) shl 8) or (piece[4].toInt() and 0xFF)
            assertEquals(piece.size - 5, length)
            payload += piece.copyOfRange(5, piece.size)
        }
        assertTrue(hello.copyOfRange(5, hello.size).contentEquals(payload))
    }

    @Test
    fun tcpMethodKeepsTheStreamUnchanged() {
        val settings = DnsChainSettings.parse("[hello split]\nEnable = 1\npreset = paranoid\n")
        val pieces = DnsChainWire.planHelloSplit(hello, settings.helloSplit!!)!!
        assertTrue(pieces.size > 10)
        assertTrue(hello.contentEquals(pieces.fold(ByteArray(0)) { acc, p -> acc + p }))
    }

    @Test
    fun maxPiecesLimitsTheCount() {
        val settings = DnsChainSettings.parse("[hello split]\nEnable = 1\npreset = aggressive\nmax_pieces = 4\n")
        val pieces = DnsChainWire.planHelloSplit(hello, settings.helloSplit!!)!!
        assertEquals(4, pieces.size)
    }

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
        assertEquals("/dns-query", named.path)

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

    private companion object {
        val HELLO_HEX: String =
            "1603010200010001fc03032fe1a4b68dcf32e04afeff73e29ea4832e4bdfbed09c9555296808d4c374538c20c2a565c27ec8" +
        "85f0e43d0211c724b3f91f8c143cd72f3b2e09a05d9c3be2cd98003e130213031301c02cc030009fcca9cca8ccaac02bc02f" +
        "009ec024c028006bc023c0270067c00ac0140039c009c0130033009d009c003d003c0035002f00ff010001750000001a0018" +
        "0000157777772e6578616d706c652e70616765732e646576000b000403000102000a00160014001d0017001e001900180100" +
        "0101010201030104002300000016000000170000000d002a0028040305030603080708080809080a080b0804080508060401" +
        "05010601030303010302040205020602002b00050403040303002d00020101003300260024001d0020396ba8f0b94f75f29f" +
        "65b715f5c37f05673383c430c7c9bfa72b7dd6a8b8a718001500be0000000000000000000000000000000000000000000000" +
        "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
        "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
        "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
        "0000000000000000000000000000000000"
    }
}
