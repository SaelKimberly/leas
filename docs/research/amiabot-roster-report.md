# amiabot (Cloudflare) roster sweep — 2026-08-25 baseline, 2026-11-02 re-run

**Status: baseline + re-run.** This file holds the 2026-08-25 run of
the reduced 71-profile TLS roster (69 `generated::GENERATED` + the 2 wire-exact
hand profiles `chrome_130` / `edge_106`) against amiabot.app's Cloudflare-based
TLS detector, plus the 2026-11-02 re-analysis that corrected the failure cause.
A post-fix re-run was **executed on 2026-11-02** (§ Re-run results): **71/71
profiles handshake**, all `likely_human`. The 2026-08-25 numbers stay here as
the pre-fix baseline and must not be quoted as current engine behaviour.

## Methodology

- Each profile drives `leas_native`'s `amiabot_sweep` example, which calls
  `leas_tls::handshake::connect` with the profile's exact `spec!`
  `ClientHelloSpec`; the negotiated ALPN picks HTTP/2 (`http2` builder with the
  family's RFC 8879 h2 SETTINGS) or HTTP/1.1 (`http1` builder) over the
  resulting `TlsStream` via hyper.
- Per-profile headers come from `leas-native::headers` (UA synthesized from
  family/os/device/major, per-major `sec-ch-ua` brand table, family
  accept/accept-language/sec-fetch-*), sent as `GET https://amiabot.app/api/check`.
- Concurrency 4, 15 s per-request timeout, one retry. Response parsed:
  `verdict.score`/`classification`/`reasons[].id`,
  `server.cloudflareBotManagement.score`, `server.headers` echo.
- `compress_certificate` is stripped from the offered spec (see Limitations).
  `accept-encoding` is not sent, so amiabot returns uncompressed JSON.

## Result (2026-08-25 run)

- **35 / 71** profiles completed the handshake and got a verdict.
- **36 / 71** failed the TLS handshake with server `alert 50`.
- **Every successful profile** scored identically: `likely_human`, verdict
  **82.0**, Cloudflare Bot Management **99.0**, header echo present, no
  `library_user_agent` reason.

## Correction (2026-11-02): the 36 failures were the ECH body, not HRR

The original text attributed the 36 failures to HRR ("the engine has no HRR
retry and rejects the HRR a hybrid-unaware server sends"). That attribution is
**wrong**, and it is not supported by the run's own rows. Cross-tabulating each
failing profile against the spec it compiles to:

| spec attribute | failing rows (36) | passing rows (35) |
| --- | --- | --- |
| offers `encrypted_client_hello` | **36** | **0** |
| offers `compress_certificate` | 35 | 12 |
| hybrid `key_share` (`mlkem768` + `x25519`) | 10 | 9 |
| `key_share[x25519]` only | 26 | 26 |

The split on ECH is perfect; the hybrid share appears on both sides, so HRR is
not the discriminator. The cause was the **0-byte `encrypted_client_hello`
body** these rows shipped at the time — recorded with its fix in
`docs/reference/native-core.md` ("What tier 1's roster gate cannot see"):
Cloudflare answers `alert 2 50 (decode_error)`, and the gate that closes it is
`profiles::tests::every_roster_hello_has_rfc_minimal_extension_bodies` (the
exact RFC 9849 §5.1 body shape) plus the tier-2
`tests/strict_peer_presets.rs`.

Two engine changes landed after this run and are relevant to the re-run:

- **HelloRetryRequest retry** (one attempt, plain TLS, `key_share` + `cookie`,
  `message_hash` transcript). Not implicated in these rows.
- **`compress_certificate` is now derived from the hello actually sent**
  (`drive` no longer receives a caller-supplied list), so a hello that offers
  compression can decompress a peer's `CompressedCertificate` instead of
  rejecting it with "which the ClientHello did not offer".

## Re-run

From the workspace root:

```sh
# one profile first — cheapest smoke that the roster still dials
cargo run -p leas-native --example amiabot_sweep -- --sample chrome_143_windows_desktop
# the full roster
cargo run -p leas-native --example amiabot_sweep
```

Record, per profile: `proto`, `classification`, verdict, CF score,
`http_protocol`, `ua_echo`, `flags` — the same columns as the tables below, so
runs diff directly. A future run replaces § Re-run results and appends its own
per-profile table; never overwrite the baseline or a previous re-run.

### Re-run results — 2026-11-02

Executed on this host against the same endpoint, from `native-core-stub` with
the ECH-body fix, the HRR retry, the hello-derived `compress_certificate` list
and the ALPN/`KeyShare` typing all in place.

| | 2026-08-25 | 2026-11-02 |
| --- | --- | --- |
| handshake completed | 35 / 71 | **71 / 71** |
| `handshake` flag | 36 | **0** |
| verdict score | 82.0 | 100.0 |
| CF Bot Management | 99.0 | 99.0 |
| `library_user_agent` | none | none |
| header echo present | yes | yes |

Delta against the baseline table: **36 rows fixed, 0 regressed**, and 35 rows
unchanged in CONNECTIVITY — their verdict column moved 82.0 → 100.0, which the
IP caveat below explains as unattributable.
Every one of the 36 previously failing rows is the ECH row set from the
correction above — the pattern is exactly as predicted, and the sample run of
`chrome_143_windows_desktop` (one of the 36) already showed it before the
sweep.

Two honest limits on this evidence:

- **What this run proves is *connectivity*** — every kept profile now completes
  the TLS handshake against a Cloudflare front. The verdict jump (82.0 → 100.0)
  is not a fidelity claim; see the IP-pollution caveat.
- **`http_protocol` is `-` on every row** — the sweep does read
  `server.httpProtocol` (`amiabot_sweep.rs`), but this endpoint does not echo
  the field, so the column stays empty. The `proto` column is which request
  path the sweep itself used. Not a regression, just an absent echo.

The full per-profile output is the third table below.

## IP-pollution caveat

**Every successful row is identical within a run** — 82.0 / 99.0 /
`likely_human` in 2026-08-25, **100.0 / 99.0 / `likely_human` in 2026-11-02** —
and no profile stands out. That is the **IP-pollution effect the design
predicted**: this host's datacenter/VPN IP dominates the Cloudflare score,
washing out any TLS/header fidelity difference between profiles. A sweep
therefore discriminates profiles only by *connectivity* (handshake success),
not by score; the uniform `cf>=99` flag on every successful row reflects the
IP, not a per-profile bot signal.

The 82.0 → 100.0 shift between the two runs is **not attributable**. The same
host faced the same endpoint 69 days apart, so the delta could be IP-reputation
drift, an amiabot model change, or (least likely) hello fidelity — a sweep
cannot separate them, so no fidelity claim is made from it. Treat the score as
an IP-reputation floor that can move under you, and compare runs by
connectivity and flags.

## Flags observed

2026-08-25 run:

- `library_user_agent`: **none** — every successful request's User-Agent was
  accepted; the header echo (`server.headers.user-agent`) contains our
  synthesized UA on all 35 rows.
- `cf>=99`: all 35 successful rows (IP-dominated; see caveat).
- `handshake`: 36 profiles (server `alert 50`, cause above).
- `echo` mismatch: none.

2026-11-02 re-run:

- `library_user_agent`: **none**.
- `cf>=99`: all **71** rows (IP-dominated; see caveat).
- `handshake`: **0** profiles.
- `echo` mismatch: none.

## Limitations

- **`compress_certificate` stripped.** amiabot/Cloudflare responds to a
  `compress_certificate` offer with a cert-less server flight
  (EncryptedExtensions, NewSessionTicket, CertificateVerify, Finished — no
  Certificate), which no client can consume. The sweep strips the extension so
  every profile still yields a verdict; the engine itself *does* decompress
  RFC 8879 certs (zlib/brotli/zstd) from servers that send them (unit-tested,
  `handshake::parse_certificate_message` + `compressed_algorithms`).
- **The 36 failures are historical.** They were the empty-ECH-body defect,
  fixed since; they remain listed as run evidence, not as current capability.
  They are offline-JA4 verified (see
  `docs/reference/tls-fingerprint-roster.md`); the amiabot sweep is
  soft/not-a-gate per the design.
- Absolute scores are IP-inflated and not comparable across environments.
- The 2026-08-25 run predates the tier-1 gate that now rejects a 0-byte ECH
  body; the 2026-11-02 re-run is that proof (71/71, no `handshake` flag).

## Per-profile rows (2026-08-25 run)

`ech` / `mlkem` are **current-spec attributes**, read from the spec each
profile compiles to today; they describe the hello shape, never the historical
failure cause. In the 2026-08-25 run, offering ECH and shipping the defective
0-byte ECH *body* were perfectly confounded (every offering row had the bad
body), which is why presence alone cannot be read as causal here — the run's
own `flags` column plus the re-run are the comparison. The columns describe the
unfiltered spec: the sweep additionally strips `compress_certificate` from every
hello it sends (see Limitations), so a row may say `compress` in the spec while
the dialled hello carried none.

| profile | proto | classification | verdict | cf | http | ua_echo | flags | ech | mlkem |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `brave_126_windows_desktop` | h1 | likely_human | 82.0 | 99.0 | - | true | cf>=99 | no | yes |
| `brave_89_windows_desktop` | h1 | likely_human | 82.0 | 99.0 | - | true | cf>=99 | no | yes |
| `brave_90_macos_desktop` | h1 | likely_human | 82.0 | 99.0 | - | true | cf>=99 | no | yes |
| `chrome_115_macos_desktop` | h1 | likely_human | 82.0 | 99.0 | - | true | cf>=99 | no | yes |
| `chrome_122_macos_desktop` | err | - | - | - | - | false | handshake | yes | yes |
| `chrome_130` | h2 | likely_human | 82.0 | 99.0 | - | true | cf>=99 | no | no |
| `chrome_131_android_tablet` | err | - | - | - | - | false | handshake | yes | no |
| `chrome_133_ios_phone` | err | - | - | - | - | false | handshake | yes | no |
| `chrome_134_android_desktop` | err | - | - | - | - | false | handshake | yes | no |
| `chrome_141_android_desktop_3` | h1 | likely_human | 82.0 | 99.0 | - | true | cf>=99 | no | no |
| `chrome_141_ios_tablet` | h2 | likely_human | 82.0 | 99.0 | - | true | cf>=99 | no | no |
| `chrome_143_ios_phone` | err | - | - | - | - | false | handshake | yes | no |
| `chrome_143_windows_desktop` | err | - | - | - | - | false | handshake | yes | yes |
| `chrome_144_ios_phone_2` | h2 | likely_human | 82.0 | 99.0 | - | true | cf>=99 | no | no |
| `chrome_146_ios_tablet` | h2 | likely_human | 82.0 | 99.0 | - | true | cf>=99 | no | no |
| `chrome_147_android_tablet` | err | - | - | - | - | false | handshake | yes | no |
| `chrome_148_android_desktop` | err | - | - | - | - | false | handshake | yes | no |
| `chrome_148_ios_tablet` | h2 | likely_human | 82.0 | 99.0 | - | true | cf>=99 | no | no |
| `chrome_149_macos_desktop` | err | - | - | - | - | false | handshake | yes | yes |
| `chrome_83_android_tablet` | h2 | likely_human | 82.0 | 99.0 | - | true | cf>=99 | no | no |
| `chrome_93_windows_desktop` | h2 | likely_human | 82.0 | 99.0 | - | true | cf>=99 | no | yes |
| `edge_106` | h2 | likely_human | 82.0 | 99.0 | - | true | cf>=99 | no | no |
| `edge_112_macos_desktop` | h1 | likely_human | 82.0 | 99.0 | - | true | cf>=99 | no | yes |
| `edge_121_android_desktop` | h2 | likely_human | 82.0 | 99.0 | - | true | cf>=99 | no | no |
| `edge_121_ios_phone` | h2 | likely_human | 82.0 | 99.0 | - | true | cf>=99 | no | no |
| `edge_121_windows_desktop` | h2 | likely_human | 82.0 | 99.0 | - | true | cf>=99 | no | yes |
| `edge_128_windows_desktop` | err | - | - | - | - | false | handshake | yes | yes |
| `edge_131_ios_tablet` | h2 | likely_human | 82.0 | 99.0 | - | true | cf>=99 | no | no |
| `edge_132_macos_desktop` | err | - | - | - | - | false | handshake | yes | yes |
| `edge_134_android_desktop` | err | - | - | - | - | false | handshake | yes | no |
| `edge_143_ios_phone_2` | h2 | likely_human | 82.0 | 99.0 | - | true | cf>=99 | no | no |
| `edge_143_ios_phone_3` | h2 | likely_human | 82.0 | 99.0 | - | true | cf>=99 | no | no |
| `edge_144_android_tablet` | err | - | - | - | - | false | handshake | yes | no |
| `edge_146_android_desktop` | err | - | - | - | - | false | handshake | yes | no |
| `edge_148_macos_desktop` | err | - | - | - | - | false | handshake | yes | yes |
| `firefox_125_windows_desktop` | h2 | likely_human | 82.0 | 99.0 | - | true | cf>=99 | no | no |
| `firefox_137_ios_phone` | h2 | likely_human | 82.0 | 99.0 | - | true | cf>=99 | no | no |
| `firefox_138_ios_phone` | h1 | likely_human | 82.0 | 99.0 | - | true | cf>=99 | no | no |
| `firefox_139_windows_desktop` | err | - | - | - | - | false | handshake | yes | no |
| `firefox_144_android_desktop_5` | err | - | - | - | - | false | handshake | yes | no |
| `firefox_146_ios_phone_2` | h2 | likely_human | 82.0 | 99.0 | - | true | cf>=99 | no | no |
| `firefox_148_macos_desktop` | err | - | - | - | - | false | handshake | yes | no |
| `firefox_148_windows_desktop` | err | - | - | - | - | false | handshake | yes | no |
| `firefox_149_android_desktop_2` | err | - | - | - | - | false | handshake | yes | no |
| `firefox_149_macos_desktop` | err | - | - | - | - | false | handshake | yes | no |
| `firefox_150_android_desktop` | err | - | - | - | - | false | handshake | yes | no |
| `firefox_150_macos_desktop` | h1 | likely_human | 82.0 | 99.0 | - | true | cf>=99 | no | no |
| `opera_119_macos_desktop` | err | - | - | - | - | false | handshake | yes | yes |
| `opera_128_windows_desktop` | err | - | - | - | - | false | handshake | yes | yes |
| `opera_130_macos_desktop` | err | - | - | - | - | false | handshake | yes | yes |
| `opera_130_windows_desktop` | err | - | - | - | - | false | handshake | yes | yes |
| `opera_80_android_desktop` | h1 | likely_human | 82.0 | 99.0 | - | true | cf>=99 | no | no |
| `opera_88_android_desktop` | err | - | - | - | - | false | handshake | yes | no |
| `opera_96_android_desktop` | err | - | - | - | - | false | handshake | yes | no |
| `opera_97_windows_desktop` | h1 | likely_human | 82.0 | 99.0 | - | true | cf>=99 | no | yes |
| `opera_98_macos_desktop` | h1 | likely_human | 82.0 | 99.0 | - | true | cf>=99 | no | yes |
| `safari_12_macos_desktop` | h1 | likely_human | 82.0 | 99.0 | - | true | cf>=99 | no | no |
| `safari_12_windows_desktop` | err | - | - | - | - | false | handshake | yes | no |
| `safari_12_windows_desktop_2` | h1 | likely_human | 82.0 | 99.0 | - | true | cf>=99 | no | no |
| `safari_16_macos_desktop` | err | - | - | - | - | false | handshake | yes | no |
| `safari_17_ios_tablet` | h1 | likely_human | 82.0 | 99.0 | - | true | cf>=99 | no | no |
| `safari_18_ios_phone` | err | - | - | - | - | false | handshake | yes | no |
| `safari_18_ios_tablet` | h2 | likely_human | 82.0 | 99.0 | - | true | cf>=99 | no | no |
| `safari_26_ios_phone` | err | - | - | - | - | false | handshake | yes | no |
| `safari_26_macos_desktop` | err | - | - | - | - | false | handshake | yes | no |
| `safari_5_windows_desktop` | h1 | likely_human | 82.0 | 99.0 | - | true | cf>=99 | no | no |
| `safari_6_ios_tablet` | err | - | - | - | - | false | handshake | yes | no |
| `safari_9_ios_phone` | h1 | likely_human | 82.0 | 99.0 | - | true | cf>=99 | no | no |
| `samsung_17_android_desktop` | h1 | likely_human | 82.0 | 99.0 | - | true | cf>=99 | no | no |
| `samsung_28_android_desktop` | err | - | - | - | - | false | handshake | yes | no |
| `samsung_29_android_desktop` | err | - | - | - | - | false | handshake | yes | no |

## Per-profile rows (2026-11-02 re-run)

Same columns as the baseline table, so the two diff directly.

| profile | proto | classification | verdict | cf | http | ua_echo | flags | ech | mlkem |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `brave_126_windows_desktop` | h1 | likely_human | 100.0 | 99.0 | - | true | cf>=99 | no | yes |
| `brave_89_windows_desktop` | h1 | likely_human | 100.0 | 99.0 | - | true | cf>=99 | no | yes |
| `brave_90_macos_desktop` | h1 | likely_human | 100.0 | 99.0 | - | true | cf>=99 | no | yes |
| `chrome_115_macos_desktop` | h1 | likely_human | 100.0 | 99.0 | - | true | cf>=99 | no | yes |
| `chrome_122_macos_desktop` | h2 | likely_human | 100.0 | 99.0 | - | true | cf>=99 | yes | yes |
| `chrome_130` | h2 | likely_human | 100.0 | 99.0 | - | true | cf>=99 | no | no |
| `chrome_131_android_tablet` | h2 | likely_human | 100.0 | 99.0 | - | true | cf>=99 | yes | no |
| `chrome_133_ios_phone` | h2 | likely_human | 100.0 | 99.0 | - | true | cf>=99 | yes | no |
| `chrome_134_android_desktop` | h2 | likely_human | 100.0 | 99.0 | - | true | cf>=99 | yes | no |
| `chrome_141_android_desktop_3` | h1 | likely_human | 100.0 | 99.0 | - | true | cf>=99 | no | no |
| `chrome_141_ios_tablet` | h2 | likely_human | 100.0 | 99.0 | - | true | cf>=99 | no | no |
| `chrome_143_ios_phone` | h2 | likely_human | 100.0 | 99.0 | - | true | cf>=99 | yes | no |
| `chrome_143_windows_desktop` | h2 | likely_human | 100.0 | 99.0 | - | true | cf>=99 | yes | yes |
| `chrome_144_ios_phone_2` | h2 | likely_human | 100.0 | 99.0 | - | true | cf>=99 | no | no |
| `chrome_146_ios_tablet` | h2 | likely_human | 100.0 | 99.0 | - | true | cf>=99 | no | no |
| `chrome_147_android_tablet` | h2 | likely_human | 100.0 | 99.0 | - | true | cf>=99 | yes | no |
| `chrome_148_android_desktop` | h2 | likely_human | 100.0 | 99.0 | - | true | cf>=99 | yes | no |
| `chrome_148_ios_tablet` | h2 | likely_human | 100.0 | 99.0 | - | true | cf>=99 | no | no |
| `chrome_149_macos_desktop` | h2 | likely_human | 100.0 | 99.0 | - | true | cf>=99 | yes | yes |
| `chrome_83_android_tablet` | h2 | likely_human | 100.0 | 99.0 | - | true | cf>=99 | no | no |
| `chrome_93_windows_desktop` | h2 | likely_human | 100.0 | 99.0 | - | true | cf>=99 | no | yes |
| `edge_106` | h2 | likely_human | 100.0 | 99.0 | - | true | cf>=99 | no | no |
| `edge_112_macos_desktop` | h1 | likely_human | 100.0 | 99.0 | - | true | cf>=99 | no | yes |
| `edge_121_android_desktop` | h2 | likely_human | 100.0 | 99.0 | - | true | cf>=99 | no | no |
| `edge_121_ios_phone` | h2 | likely_human | 100.0 | 99.0 | - | true | cf>=99 | no | no |
| `edge_121_windows_desktop` | h2 | likely_human | 100.0 | 99.0 | - | true | cf>=99 | no | yes |
| `edge_128_windows_desktop` | h2 | likely_human | 100.0 | 99.0 | - | true | cf>=99 | yes | yes |
| `edge_131_ios_tablet` | h2 | likely_human | 100.0 | 99.0 | - | true | cf>=99 | no | no |
| `edge_132_macos_desktop` | h2 | likely_human | 100.0 | 99.0 | - | true | cf>=99 | yes | yes |
| `edge_134_android_desktop` | h2 | likely_human | 100.0 | 99.0 | - | true | cf>=99 | yes | no |
| `edge_143_ios_phone_2` | h2 | likely_human | 100.0 | 99.0 | - | true | cf>=99 | no | no |
| `edge_143_ios_phone_3` | h2 | likely_human | 100.0 | 99.0 | - | true | cf>=99 | no | no |
| `edge_144_android_tablet` | h2 | likely_human | 100.0 | 99.0 | - | true | cf>=99 | yes | no |
| `edge_146_android_desktop` | h2 | likely_human | 100.0 | 99.0 | - | true | cf>=99 | yes | no |
| `edge_148_macos_desktop` | h2 | likely_human | 100.0 | 99.0 | - | true | cf>=99 | yes | yes |
| `firefox_125_windows_desktop` | h2 | likely_human | 100.0 | 99.0 | - | true | cf>=99 | no | no |
| `firefox_137_ios_phone` | h2 | likely_human | 100.0 | 99.0 | - | true | cf>=99 | no | no |
| `firefox_138_ios_phone` | h1 | likely_human | 100.0 | 99.0 | - | true | cf>=99 | no | no |
| `firefox_139_windows_desktop` | h2 | likely_human | 100.0 | 99.0 | - | true | cf>=99 | yes | no |
| `firefox_144_android_desktop_5` | h2 | likely_human | 100.0 | 99.0 | - | true | cf>=99 | yes | no |
| `firefox_146_ios_phone_2` | h2 | likely_human | 100.0 | 99.0 | - | true | cf>=99 | no | no |
| `firefox_148_macos_desktop` | h2 | likely_human | 100.0 | 99.0 | - | true | cf>=99 | yes | no |
| `firefox_148_windows_desktop` | h2 | likely_human | 100.0 | 99.0 | - | true | cf>=99 | yes | no |
| `firefox_149_android_desktop_2` | h2 | likely_human | 100.0 | 99.0 | - | true | cf>=99 | yes | no |
| `firefox_149_macos_desktop` | h2 | likely_human | 100.0 | 99.0 | - | true | cf>=99 | yes | no |
| `firefox_150_android_desktop` | h2 | likely_human | 100.0 | 99.0 | - | true | cf>=99 | yes | no |
| `firefox_150_macos_desktop` | h1 | likely_human | 100.0 | 99.0 | - | true | cf>=99 | no | no |
| `opera_119_macos_desktop` | h2 | likely_human | 100.0 | 99.0 | - | true | cf>=99 | yes | yes |
| `opera_128_windows_desktop` | h2 | likely_human | 100.0 | 99.0 | - | true | cf>=99 | yes | yes |
| `opera_130_macos_desktop` | h2 | likely_human | 100.0 | 99.0 | - | true | cf>=99 | yes | yes |
| `opera_130_windows_desktop` | h2 | likely_human | 100.0 | 99.0 | - | true | cf>=99 | yes | yes |
| `opera_80_android_desktop` | h1 | likely_human | 100.0 | 99.0 | - | true | cf>=99 | no | no |
| `opera_88_android_desktop` | h2 | likely_human | 100.0 | 99.0 | - | true | cf>=99 | yes | no |
| `opera_96_android_desktop` | h2 | likely_human | 100.0 | 99.0 | - | true | cf>=99 | yes | no |
| `opera_97_windows_desktop` | h1 | likely_human | 100.0 | 99.0 | - | true | cf>=99 | no | yes |
| `opera_98_macos_desktop` | h1 | likely_human | 100.0 | 99.0 | - | true | cf>=99 | no | yes |
| `safari_12_macos_desktop` | h1 | likely_human | 100.0 | 99.0 | - | true | cf>=99 | no | no |
| `safari_12_windows_desktop` | h2 | likely_human | 100.0 | 99.0 | - | true | cf>=99 | yes | no |
| `safari_12_windows_desktop_2` | h1 | likely_human | 100.0 | 99.0 | - | true | cf>=99 | no | no |
| `safari_16_macos_desktop` | h2 | likely_human | 100.0 | 99.0 | - | true | cf>=99 | yes | no |
| `safari_17_ios_tablet` | h1 | likely_human | 100.0 | 99.0 | - | true | cf>=99 | no | no |
| `safari_18_ios_phone` | h2 | likely_human | 100.0 | 99.0 | - | true | cf>=99 | yes | no |
| `safari_18_ios_tablet` | h2 | likely_human | 100.0 | 99.0 | - | true | cf>=99 | no | no |
| `safari_26_ios_phone` | h2 | likely_human | 100.0 | 99.0 | - | true | cf>=99 | yes | no |
| `safari_26_macos_desktop` | h2 | likely_human | 100.0 | 99.0 | - | true | cf>=99 | yes | no |
| `safari_5_windows_desktop` | h1 | likely_human | 100.0 | 99.0 | - | true | cf>=99 | no | no |
| `safari_6_ios_tablet` | h2 | likely_human | 100.0 | 99.0 | - | true | cf>=99 | yes | no |
| `safari_9_ios_phone` | h1 | likely_human | 100.0 | 99.0 | - | true | cf>=99 | no | no |
| `samsung_17_android_desktop` | h1 | likely_human | 100.0 | 99.0 | - | true | cf>=99 | no | no |
| `samsung_28_android_desktop` | h2 | likely_human | 100.0 | 99.0 | - | true | cf>=99 | yes | no |
| `samsung_29_android_desktop` | h2 | likely_human | 100.0 | 99.0 | - | true | cf>=99 | yes | no |
