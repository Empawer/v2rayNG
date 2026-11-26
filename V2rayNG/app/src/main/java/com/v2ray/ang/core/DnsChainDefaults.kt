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
; FRAGMENT: cuts the data sent by the client (starting with the TLS
; ClientHello) into small TCP pieces, so DPI never sees a full packet
; in one piece. The server rebuilds the stream as usual.
;
;   length    : size of each piece in bytes. Accepted forms:
;                 length = 10          one fixed number
;                 length = 10-20       a range (random size per piece)
;                 length = 20, 9, 1    a list: pieces are sent with these
;                                      sizes in this order. An item may also
;                                      be a range: 20, 5-9, 1
;               When the list ends it starts again from the first item,
;               until the data is finished.
;   interval  : pause between pieces. Accepted forms:
;                 interval = 0         no pause at all
;                 interval = 5 ms      fixed pause
;                 interval = 5-10 ms   random pause inside the range
;   max_split : how many pieces are fragmented, per connection.
;                 max_split = 0        unlimited (all data is fragmented)
;                 max_split = 10       only the first 10 pieces are
;                                      fragmented, everything after that
;                                      passes through untouched
; ---------------------------------------------------------------
[fragment]
Enable = 1
length = 5, 1
interval = 1 ms
max_split = 16
"""
}
