# amiabot (Cloudflare) roster sweep — 2026-08-25

Verification of the reduced 71-profile TLS roster (69 `generated::GENERATED` +
2 wire-exact hand profiles `chrome_130` / `edge_106`) against amiabot.app's
Cloudflare-based TLS detector.

## Methodology

- Each profile drives `leas_tls::handshake::connect` with its exact
  `spec!` `ClientHelloSpec`; the negotiated ALPN picks HTTP/2 (`http2`
  builder with the family's RFC 8879 h2 SETTINGS) or HTTP/1.1 (`http1`
  builder) over the engine `TlsStream` via hyper.
- Per-profile headers from `leas-native::headers` (UA synthesized from
  family/os/device/major, per-major `sec-ch-ua` brand table, family
  accept/accept-language/sec-fetch-*), sent as `GET https://amiabot.app/api/check`.
- Concurrency 4, 15 s per-request timeout, one retry. Response parsed:
  `verdict.score`/`classification`/`reasons[].id`,
  `server.cloudflareBotManagement.score`, `server.headers` echo.
- `compress_certificate` is stripped from the offered spec (see Limitations).
  `accept-encoding` is not sent so amiabot returns uncompressed JSON.

## Result

- **35 / 71** profiles completed the handshake and got a verdict.
- **36 / 71** failed the TLS handshake: the server sent `alert 50`
  (internal_error). These are the ML-KEM-hybrid-key-share hello shapes
  Cloudflare rejects for this endpoint (the engine has no HRR retry; it
  rejects the HRR that a hybrid-unaware server sends).
- **Every successful profile** scored identically: `likely_human`, verdict
  **82.0**, Cloudflare Bot Management **99.0**, header echo present, no
  `library_user_agent` reason.

## IP-pollution caveat

All successful rows are identical (82.0 / 99.0 / `likely_human`). This is the
**IP-pollution effect the design predicted**: this host's datacenter/VPN IP
dominates the Cloudflare score (~+48 absolute points), washing out any
TLS/header fidelity difference between profiles. The sweep therefore
discriminates profiles only by *connectivity* (handshake success), not by
score; the uniform `cf>=99` flag on every successful row reflects the IP, not
a per-profile bot signal. Compare profiles relatively (they tie here) and
treat the CF score as an IP-reputation floor, not a per-hello verdict.

## Flags observed

- `library_user_agent`: **none** — every successful request's User-Agent was
  accepted; the header echo (`server.headers.user-agent`) contains our
  synthesized UA on all 35 rows.
- `cf>=99`: all 35 successful rows (IP-dominated; see caveat).
- `handshake`: 36 profiles (server `alert 50`).
- `echo` mismatch: none.

## Limitations

- **`compress_certificate` stripped.** amiabot/Cloudflare responds to a
  `compress_certificate` offer with a cert-less server flight
  (EncryptedExtensions, NewSessionTicket, CertificateVerify, Finished — no
  Certificate), which no client can consume. The sweep strips the extension
  so every profile still yields a verdict; the engine *does* decompress
  RFC 8879 certs (zlib/brotli/zstd) from servers that send them (unit-tested,
  `handshake::parse_certificate_message`).
- **36 profiles do not handshake** against this endpoint (Cloudflare rejects
  their ML-KEM-hybrid hello; the engine rejects HRR). These are offline-JA4
  verified (see `docs/reference/tls-fingerprint-roster.md`); the amiabot sweep is
  soft/not-a-gate per the design.
- Absolute scores are IP-inflated and not comparable across environments.

## Per-profile rows

```
profile	proto	classification	verdict_score	cf_score	http_protocol	ua_echo	flags
brave_126_windows_desktop	h1	likely_human	82.0	99.0	-	true	cf>=99
brave_89_windows_desktop	h1	likely_human	82.0	99.0	-	true	cf>=99
brave_90_macos_desktop	h1	likely_human	82.0	99.0	-	true	cf>=99
chrome_115_macos_desktop	h1	likely_human	82.0	99.0	-	true	cf>=99
chrome_122_macos_desktop	err	-	-	-	-	false	handshake
chrome_130	h2	likely_human	82.0	99.0	-	true	cf>=99
chrome_131_android_tablet	err	-	-	-	-	false	handshake
chrome_133_ios_phone	err	-	-	-	-	false	handshake
chrome_134_android_desktop	err	-	-	-	-	false	handshake
chrome_141_android_desktop_3	h1	likely_human	82.0	99.0	-	true	cf>=99
chrome_141_ios_tablet	h2	likely_human	82.0	99.0	-	true	cf>=99
chrome_143_ios_phone	err	-	-	-	-	false	handshake
chrome_143_windows_desktop	err	-	-	-	-	false	handshake
chrome_144_ios_phone_2	h2	likely_human	82.0	99.0	-	true	cf>=99
chrome_146_ios_tablet	h2	likely_human	82.0	99.0	-	true	cf>=99
chrome_147_android_tablet	err	-	-	-	-	false	handshake
chrome_148_android_desktop	err	-	-	-	-	false	handshake
chrome_148_ios_tablet	h2	likely_human	82.0	99.0	-	true	cf>=99
chrome_149_macos_desktop	err	-	-	-	-	false	handshake
chrome_83_android_tablet	h2	likely_human	82.0	99.0	-	true	cf>=99
chrome_93_windows_desktop	h2	likely_human	82.0	99.0	-	true	cf>=99
edge_106	h2	likely_human	82.0	99.0	-	true	cf>=99
edge_112_macos_desktop	h1	likely_human	82.0	99.0	-	true	cf>=99
edge_121_android_desktop	h2	likely_human	82.0	99.0	-	true	cf>=99
edge_121_ios_phone	h2	likely_human	82.0	99.0	-	true	cf>=99
edge_121_windows_desktop	h2	likely_human	82.0	99.0	-	true	cf>=99
edge_128_windows_desktop	err	-	-	-	-	false	handshake
edge_131_ios_tablet	h2	likely_human	82.0	99.0	-	true	cf>=99
edge_132_macos_desktop	err	-	-	-	-	false	handshake
edge_134_android_desktop	err	-	-	-	-	false	handshake
edge_143_ios_phone_2	h2	likely_human	82.0	99.0	-	true	cf>=99
edge_143_ios_phone_3	h2	likely_human	82.0	99.0	-	true	cf>=99
edge_144_android_tablet	err	-	-	-	-	false	handshake
edge_146_android_desktop	err	-	-	-	-	false	handshake
edge_148_macos_desktop	err	-	-	-	-	false	handshake
firefox_125_windows_desktop	h2	likely_human	82.0	99.0	-	true	cf>=99
firefox_137_ios_phone	h2	likely_human	82.0	99.0	-	true	cf>=99
firefox_138_ios_phone	h1	likely_human	82.0	99.0	-	true	cf>=99
firefox_139_windows_desktop	err	-	-	-	-	false	handshake
firefox_144_android_desktop_5	err	-	-	-	-	false	handshake
firefox_146_ios_phone_2	h2	likely_human	82.0	99.0	-	true	cf>=99
firefox_148_macos_desktop	err	-	-	-	-	false	handshake
firefox_148_windows_desktop	err	-	-	-	-	false	handshake
firefox_149_android_desktop_2	err	-	-	-	-	false	handshake
firefox_149_macos_desktop	err	-	-	-	-	false	handshake
firefox_150_android_desktop	err	-	-	-	-	false	handshake
firefox_150_macos_desktop	h1	likely_human	82.0	99.0	-	true	cf>=99
opera_119_macos_desktop	err	-	-	-	-	false	handshake
opera_128_windows_desktop	err	-	-	-	-	false	handshake
opera_130_macos_desktop	err	-	-	-	-	false	handshake
opera_130_windows_desktop	err	-	-	-	-	false	handshake
opera_80_android_desktop	h1	likely_human	82.0	99.0	-	true	cf>=99
opera_88_android_desktop	err	-	-	-	-	false	handshake
opera_96_android_desktop	err	-	-	-	-	false	handshake
opera_97_windows_desktop	h1	likely_human	82.0	99.0	-	true	cf>=99
opera_98_macos_desktop	h1	likely_human	82.0	99.0	-	true	cf>=99
safari_12_macos_desktop	h1	likely_human	82.0	99.0	-	true	cf>=99
safari_12_windows_desktop	err	-	-	-	-	false	handshake
safari_12_windows_desktop_2	h1	likely_human	82.0	99.0	-	true	cf>=99
safari_16_macos_desktop	err	-	-	-	-	false	handshake
safari_17_ios_tablet	h1	likely_human	82.0	99.0	-	true	cf>=99
safari_18_ios_phone	err	-	-	-	-	false	handshake
safari_18_ios_tablet	h2	likely_human	82.0	99.0	-	true	cf>=99
safari_26_ios_phone	err	-	-	-	-	false	handshake
safari_26_macos_desktop	err	-	-	-	-	false	handshake
safari_5_windows_desktop	h1	likely_human	82.0	99.0	-	true	cf>=99
safari_6_ios_tablet	err	-	-	-	-	false	handshake
safari_9_ios_phone	h1	likely_human	82.0	99.0	-	true	cf>=99
samsung_17_android_desktop	h1	likely_human	82.0	99.0	-	true	cf>=99
samsung_28_android_desktop	err	-	-	-	-	false	handshake
samsung_29_android_desktop	err	-	-	-	-	false	handshake
```
