package com.v2ray.ang.core

/**
 * Default content of the DNS chain settings text. It is the same text as the dns_chain.ini that
 * ships with the original Python proxy, the user edits it in the Chain dialog.
 *
 * It is a raw string and must stay free of dollar signs and triple quotes.
 */
object DnsChainDefaults {

    const val DEFAULT_INI: String = """[proxy]
listen_ip = 127.0.0.1
listen_port = 18081

; Domain resolved to test the DoH servers (startup test and doh_tester.py).
; Must be a real domain that has an A record. You can use your own domain.
Domain = pages.dev

; Add as many DoH servers as you like with new numbers (DOH_04, DOH_05, ...).
; All are queried at the same time and the first successful answer is used.
; To remove one, delete its line or leave its value empty.
; If all are empty, the system DNS is used.
DOH_01 = https://1.1.1.1/dns-query
DOH_02 = https://[2606:4700:4700::1001]/dns-query

; Timeouts in seconds (0 = disabled where noted)
idle_timeout = 300
connect_timeout = 10
handshake_timeout = 15
doh_timeout = 5
; A DoH server that fails is skipped for this many seconds.
; The pause doubles after each failure, up to a maximum of 300.
doh_cooldown = 30
; Max wait for the system DNS when all DoH servers have failed.
system_dns_timeout = 5
; DEBUG / INFO / WARNING / ERROR
log_level = INFO

; ---------------------------------------------------------------
; SNI split: cuts the first TLS packet (ClientHello) inside the
; hostname (SNI), so DPI never sees the full name in one packet.
; The server rebuilds the TCP stream and still sees the real name.
;   pieces : number of parts the hostname is cut into (2 or more)
;   delay  : pause between parts
; ---------------------------------------------------------------
[sni split]
Enable = 0
pieces = 10
delay = 5 ms

; ---------------------------------------------------------------
; HELLO SPLIT (comprehensive): cuts the first TLS packet (ClientHello)
; at many structural points, not only inside the hostname. When this
; section is enabled it takes priority over [sni split].
;
;   preset  : basic | standard | aggressive | paranoid
;             (used only when 'points' is empty)
;               basic      = sni
;               standard   = handshake_header, cipher_suites, extensions,
;                            sni, ext:alpn
;               aggressive = record_header, handshake_header, random,
;                            session_id, cipher_suites_mid, cipher_suites,
;                            compression, extensions, ext_each, sni,
;                            sni_labels
;               paranoid   = aggressive + random:5
;   points  : your own comma-separated list of cut points. Available:
;               record_header      after the 5-byte TLS record header
;               handshake_header   after the 4-byte handshake header
;               random             after the 32-byte client random
;               session_id         after the session id
;               cipher_suites      after the cipher suite list
;               cipher_suites_mid  in the middle of the cipher suite list
;               compression        after the compression methods
;               extensions         where the extension block starts
;               ext_each           before every extension
;               ext_end            after the last extension
;               ext:NAME           before and after one extension. NAME is
;                                  sni, status_request, groups, ec_formats,
;                                  sigalgs, alpn, sct, padding, ems,
;                                  compress_cert, ticket, psk, versions,
;                                  psk_modes, key_share, reneg, ech
;                                  or a number such as ext:16
;               sni_edges          right before and after the hostname
;               sni                sni_edges + cuts inside the hostname
;               sni_labels         after every dot: example. | pages. | dev
;               every:N            every N bytes
;               random:K           K random cut points
;               N                  a fixed byte offset (negative = from end)
;   sni_pieces : parts the hostname is cut into by 'sni' (2 or more)
;   method  : tcp    = one TLS record sent in several TCP packets
;             record = the ClientHello is re-wrapped into several TLS
;                      records, each in its own packet (test it: some
;                      servers do not accept a fragmented ClientHello)
;   delay        : pause between pieces
;   delay_jitter : random extra pause (0 to this value) per piece
;   first_delay  : pause after the first piece (empty = same as delay)
;   min_piece    : cuts closer than this many bytes are merged
;   max_pieces   : max number of pieces (0 = unlimited)
; ---------------------------------------------------------------
[hello split]
Enable = 1
preset = paranoid
points =
sni_pieces = 10
method = tcp
delay = 5 ms
delay_jitter = 0 ms
first_delay =
min_piece = 1
max_pieces = 0
"""
}
