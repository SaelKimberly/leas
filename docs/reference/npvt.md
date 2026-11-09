# NapsterV Tunnel exchange formats (`.npvt` / `.npvs`)

This page specifies the configuration and subscription exchange formats used by
NapsterV Tunnel / NpvTunnel (`com.napsternetlabs.napsternetv`, package version
`124.0.37`). It covers four containers:

| Marker | Container | Key material | Status |
|---|---|---|---|
| `NPVT1` | legacy text bundle | whitebox tables only, no user secret | verified against `ALL NET 2.npvt` |
| `NPVTSUB1` | same payload as `NPVT1`, transport prefix | same | inferred; the app strips and treats it identically |
| `NPVO1` | open JSON bundle | none | schema read from app serializer |
| `NPVS` | sealed binary envelope | recipient / passphrase / app key | v5 passphrase verified; v1 app-key implemented but sample-less; v5 app-key unsupported; recipient unsupported |

The document owns the wire format, key derivation, and field schemas. It does
not own how `leas` maps the contained profiles onto `ParsedProto`; that mapping
is a separate consumer concern.

## 1. Detection

Input is detected by bytes, not by extension.

| Condition | Container |
|---|---|
| first 4 bytes `4E 50 56 53` (`NPVS`) | sealed envelope; byte 4 is the envelope version |
| text, after leading whitespace, starts with `NPVO1` | open JSON |
| text starts with `NPVT1` or `NPVTSUB1` | legacy text bundle |
| anything else | unsupported |

`NPVO1`, `NPVT1`, and `NPVTSUB1` are ASCII markers. The app strips each marker
with and without a trailing newline, so both `NPVT1\n<payload>` and
`NPVT1<payload>` are accepted.

## 2. Legacy bundle (`NPVT1` / `NPVTSUB1`)

After stripping the marker, the body is one line of three comma-separated
segments. The split is strict: exactly three segments. Each segment is standard
base64 (padding accepted, whitespace ignored) and decrypts independently:

| Segment | Plaintext |
|---|---|
| 0 | decimal version string, currently `1` |
| 1 | JSON array of `Config` |
| 2 | JSON object `LockConfig` (user info and lock policy) |

Each segment's base64-decoded bytes are `16-byte nonce || ciphertext`. The
cipher is a 16-byte-block whitebox AES-like construction in big-endian counter
mode: the nonce is the initial counter, the counter increments as a 128-bit
big-endian integer after each block, and the keystream XORs the ciphertext.

### 2.1 Whitebox block

The block function uses four embedded tables:

| Table | Shape | Role |
|---|---|---|
| `xor` | `96 x 16 x 16` bytes | nibble XOR network |
| `ty` | `16 x 256` u32 | first substitution layer |
| `mbl` | `16 x 256` u32 | second substitution layer |
| `last` | `16 x 256` bytes | final byte substitution |

With `state` a 16-byte block:

1. Apply the row permutation `P = [0,5,10,15,4,9,14,3,8,13,2,7,12,1,6,11]`:
   `out[i] = state[P[i]]`.
2. For each group `g` in `0..4` (bytes `4g..4g+3`):
   - read `a,b,c,d` from `ty[4g+0..3][state[4g+0..3]]`;
   - for `k` in `0..4`, build one output byte from `xor[24g+6k .. 24g+6k+5]`:
     the high nibble uses shifts `28-8k`, the low nibble `24-8k`;
   - write the four output bytes back to the group.
3. Repeat the same group transform with `mbl` instead of `ty`.
4. Apply the permutation again.
5. Replace every byte with `last[i][state[i]]`.

The table bytes shipped in the client are the only secret; there is no key
derivation and no user secret. The supplied client ships one `last` table; a
second variant is reported by third-party tooling but is not confirmed here.
The legacy container is therefore obfuscation, not confidentiality.

### 2.2 Legacy JSON

`Config` is a JSON object. Kotlin serialization writes fields in this order;
unknown fields must be ignored.

| Field | Type | Meaning |
|---|---|---|
| `name` | string | display name |
| `address` | string | `host:port` |
| `type` | string enum | `v2ray`, `ssh`, `issuer-backed` |
| `v2rayProfile` | object, optional | V2Ray profile (§2.3) |
| `sshConfig` | object, optional | SSH profile |
| `lockConfig` | object | per-config lock policy |
| `issuerBacked` | object, optional | `issuerUrl`, `creatorPubkeyB64`, `configIdB64` |
| `creatorPin` | object, optional | `configIdB64`, `creatorFpB64` |
| `sealedAtRestB64` | string, optional | sealed-at-rest payload |
| `sealedContentIdB64` | string, optional | sealed-at-rest content id |
| `sealedIsCustom` | bool | sealed payload is a custom config |
| `sealedIsRenderableV2ray` | bool | sealed payload renders as V2Ray |
| `sealedIsSsh` | bool | sealed payload is SSH |
| `sealedIsHysteria2` | bool | sealed payload is Hysteria2 |

`LockConfig` (also the legacy user-info segment) fields:

| Field | Type | Meaning |
|---|---|---|
| `version` | int | schema version, currently `1` in observed files |
| `isLocked` | bool | client enforces lock policy |
| `password` | string | legacy lock password |
| `onlyMobileNetwork` | bool | lock to mobile network |
| `blockRootedAndJailbroken` | bool | device integrity gate |
| `onlyOfficialStores` | bool | install-source gate |
| `expiryDate` | string | empty or date text |
| `deviceIds` | string | comma-separated device ids |
| `message` | string | creator message |
| `customServerMessage` | string | extra creator message |

### 2.3 V2Ray profile

`v2rayProfile` is the endpoint-free profile plus the core config. Field order
and names:

| Field | Type |
|---|---|
| `configVersion` | int, default `4` |
| `configType` | int, default `2` (`CUSTOM`), see below |
| `subscriptionId` | string |
| `addedTime` | epoch milliseconds |
| `remarks` | string |
| `server` | string |
| `serverPort` | string (numeric text) |
| `password` | string |
| `method` | string |
| `flow` | string |
| `username` | string |
| `network` | string |
| `headerType` | string |
| `host` | string |
| `path` | string |
| `seed` | string |
| `kcpMtu` | int |
| `kcpTti` | int |
| `quicSecurity` | string |
| `quicKey` | string |
| `mode` | string |
| `serviceName` | string |
| `authority` | string |
| `xhttpMode` | string |
| `xhttpExtra` | string |
| `security` | string: `none`, `tls`, `reality` |
| `sni` | string |
| `alpn` | string |
| `fingerPrint` | string |
| `insecure` | bool |
| `tlsAllowInsecure` | bool |
| `pinnedPeerCertSha256` | string |
| `verifyPeerCertByName` | string |
| `echConfigList` | string |
| `mldsa65Verify` | string |
| `fragmentPackets` | string |
| `fragmentLength` | string |
| `fragmentInterval` | string |
| `fragmentMaxSplit` | int? |
| `finalMask` | string |
| `publicKey` | string |
| `shortId` | string |
| `spiderX` | string |
| `secretKey` | string |
| `preSharedKey` | string |
| `localAddress` | string |
| `reserved` | string |
| `mtu` | int |
| `obfsPassword` | string |
| `uploadMbps` | int64 |
| `downloadMbps` | int64 |
| `portHopping` | string |
| `portHoppingInterval` | string |
| `pinSHA256` | string |
| `v2rayJson` | string, optional |
| `persistJson` | bool |

`configType` uses the v2rayN numbering, and `2` is `CUSTOM`:

| Value | Kind |
|---|---|
| 1 | VMess |
| 2 | Custom (the full config is in `v2rayJson`) |
| 3 | Shadowsocks |
| 4 | SOCKS |
| 5 | VLESS |
| 6 | Trojan |
| 7 | WireGuard |
| 8 | HTTP |
| 9 | Hysteria2 |

When `v2rayJson` is present it is a complete Xray JSON configuration. The first
proxy outbound (normally tag `proxy`) carries `protocol`, `settings`, and
`streamSettings`; the profile fields mirror it. A consumer that cannot ingest a
full Xray config can reconstruct a share URL from the corresponding outbound.

## 3. Open bundle (`NPVO1`)

After stripping `NPVO1` and a trailing newline, the body is JSON:

```json
{ "configs": [ ConfigBody, ... ] }
```

`ConfigBody` is a reduced `Config`:

| Field | Type |
|---|---|
| `name` | string |
| `address` | string |
| `type` | `v2ray` / `ssh` / `issuer-backed` |
| `v2rayProfile` | object, optional |
| `sshConfig` | object, optional |
| `message` | string |
| `customServerMessage` | string |

There is no key material. Strings may contain the sentinel encoding described
in §5.5; the app decodes sentinels before display.

## 4. Sealed envelope, version 1 (`NPVS`, byte 4 = 1)

### 4.1 Binary layout

All integers are big-endian.

| Offset | Size | Field |
|---|---|---|
| 0 | 4 | magic `NPVS` |
| 4 | 1 | envelope version (`1` for this layout) |
| 5 | 4 | header length `H` |
| 9 | `H` | header JSON |
| `9+H` | 12 | body nonce |
| `H+21` | 4 | body ciphertext length `B` |
| `H+25` | `B` | body ciphertext + Poly1305 tag |
| `H+25+B` | 64 | P-1363 ECDSA signature |

The app rejects a file shorter than 89 bytes and requires the signature to end
exactly at EOF. The signature is over the creator identity and is not needed to
decrypt a file; a consumer that does not verify it must say so.

### 4.2 Header JSON

Field names are the Kotlin serialization names:

| Field | Type | Notes |
|---|---|---|
| `v` | int | envelope version |
| `configId` | string | base64 of 16 bytes |
| `issuedAt` | string | timestamp |
| `creator` | object | `{ "fp": string, "pk": string }`, base64 |
| `policy` | object | `onlyMobileNetwork`, `attestationLevel`, `expiresAt`, `displayMessage`, `customServerMessage`, `configVersion` |
| `recipients` | array | `{ "fp": string, "wrap": string }` |
| `passphrase` | object, optional | `kdf`, `salt`, `iters`, `wrap` |
| `appKey` | object, optional | `kdf`, `keyId`, `salt`, `wrap` |
| `manifest` | array, optional | reserved |

Unsealing rules:

- `appKey` present and `keyId == 1` and `kdf == "wbaes-ctr-sha256"`: use the
  app-key derivation in §4.4.
- `passphrase` present and `kdf == "pbkdf2-hmac-sha256"`: derive the key with
  PBKDF2-HMAC-SHA256 from the user passphrase, `salt`, and `iters`.
- `recipients` non-empty: each entry wraps the same content-encryption key to a
  P-256 recipient. Opening needs the matching recipient private key and the
  device-derived `sharedX`/`myFp`; a generic client cannot open it.
- More than one mechanism may be present; try the mechanisms the caller can
  satisfy in the order above.

### 4.3 Wrapped key

`wrap` is base64 of three concatenated parts:

```text
12-byte nonce || ChaCha20-Poly1305 ciphertext of the 32-byte content key
```

The AEAD key is the KDF output. The AEAD associated data is the KDF salt:

- passphrase: the `salt` field bytes;
- app key: the `salt` field bytes.

### 4.4 App key, v1

The app-key KDK is:

```text
material = 32 bytes = salt[16] || 00*16
stream   = whitebox_CTR(nonce = material[0..16], plaintext = material[16..32])
KDK      = SHA-256("npvtunnel/appkey/v1 " || stream)
```

`whitebox_CTR` is §2.1 with one of the two `last` table variants. A consumer
should try both and accept the first that unwraps the CEK. The parser currently
ships the variant extracted from the supplied client and does not implement the
second variant.

### 4.5 Body

The body is `ChaCha20-Poly1305(content_key, nonce, ciphertext, AAD = header JSON
bytes)`. The plaintext is the sealed payload. It is not necessarily JSON: later
app versions use the sentinel encoding in §5.5 for key material, and the app
decodes sentinels before parsing.

## 5. Sealed envelope, version 5 (`NPVS`, byte 4 = 5, “gen2”)

Version 5 replaces the JSON header with a compact binary header and splits the
payload into encrypted fields.

### 5.1 Binary layout

| Offset | Size | Field |
|---|---|---|
| 0 | 4 | magic `NPVS` |
| 4 | 1 | version `5` |
| 5 | 4 | header length `H` |
| 9 | `H` | compact header |
| `9+H` | 12 | body nonce |
| `H+21` | 4 | body length `B` |
| `H+25` | `B` | body |
| `H+25+B` | 64 | P-1363 signature |

### 5.2 Compact header

| Offset | Size | Field |
|---|---|---|
| 0 | 1 | header version `1` |
| 1 | 16 | `configId` |
| 17 | 33 | creator public key, P-256 compressed |
| 50 | 1 | unlock method: `0` recipient, `1` passphrase, `2` app key |
| 51 | 2 | recipient count `R` |
| 53 | `R * 125` | recipient blocks |
| next | variable | method block (§5.3) |
| next | 4 | sealed metadata length `M` |
| next | `M` | sealed metadata |

A recipient block is `32-byte X coordinate || 93-byte wrap`; the `93` bytes are
`33-byte ephemeral public key || 12-byte nonce || AES-256-GCM ciphertext+tag`
for the content key.

### 5.3 Method blocks

Passphrase (`method = 1`):

| Size | Field |
|---|---|
| 4 | PBKDF2 iteration count |
| 16 | salt |
| 60 | wrap (`12-byte nonce || ChaCha20-Poly1305 ciphertext+tag`) |

App key (`method = 2`):

| Size | Field |
|---|---|
| 2 | method marker `2` |
| 16 | salt |
| 60 | wrap (`12-byte nonce || ChaCha20-Poly1305 ciphertext+tag`) |

The wrap AEAD key is the KDK; the AEAD associated data is the salt.

### 5.4 Body and field encryption

The body starts with `NPF\x01`, followed by `32-byte contentId`, a big-endian
`u16` field count, then that many records:

```text
u16 seq || u16 flags || u16 blob_len || blob_len bytes
```

Each blob is `ciphertext || Poly1305 tag`; the plaintext is JSON text.

Key schedule, all HKDF-SHA256 with a 32-byte output:

| Purpose | IKM | salt | info |
|---|---|---|---|
| metadata | content key | body nonce | `NPVS-v5/metadata` |
| field | content key | contentId | `NPV-fields-v1/field/` + `BE16(seq)` |

Field AEAD is ChaCha20-Poly1305 with a zero 12-byte nonce. Its associated data is
`NPV-fields-v1/record/` + contentId + `BE16(seq)` + `BE32(plaintext_len)`.

Metadata is ChaCha20-Poly1305 with the metadata key, the body nonce, and the
header prefix as associated data.

The record with `seq = 0xFFFF` is the sentinel table. It is either a config list
(`{"configs":[...]}`) or a subscription descriptor
(`{"kind":1,"name":2,"url":3,"autoUpdateHours":4}`). In that table, numeric
leaves are references to field records: `0` is an empty/absent field, `0xFFFF`
is the table itself, and any other integer `n` is replaced by the decrypted text
of field `n`. Text leaves may contain the sentinel encoding in §5.5.

### 5.5 Sentinel encoding

A string may contain tokens introduced by `npvs1:`. The token continues while
the byte is in the base64 alphabet (`A-Z a-z 0-9 + / = _ -`). It is decoded as
standard base64; if that fails, as URL-safe base64, padded or unpadded. Invalid
tokens are left verbatim. This is a key-material transport, not encryption.

### 5.6 App key, v5

The gen2 app key uses a 749,568-byte whitebox table image: 13 blocks of 57,344
bytes plus one 4,096-byte page. The client ships this image as `assets/rt.dat`
(observed file length 749,617 bytes; the 49-byte difference is container
framing, not table content).

For a 16-byte salt:

1. Copy the salt into the 16-byte state.
2. For each of the 13 blocks, apply the row permutation and run the block’s
   `0x6000` and `0xA000` table halves over the four groups of four bytes.
3. Index the trailing page with `page[0x100*i + state[P[i]]]` to produce the
   16-byte `A16`.
4. `KDK = SHA-256("npvtunnel/appkey/v2 " || A16 || configId)`.

The v5 wrap and content key use that KDK exactly like §5.3/§5.4.

## 6. Verification evidence

Observed and executed during this investigation:

| Input | Result |
|---|---|
| `ALL NET 2.npvt` | `NPVT1`, version `1`, one `V2RAY` config, `CUSTOM` profile with a VLESS `v2rayJson` outbound; user-info message decoded |
| `sinavm` `5254.npvs` | `NPVS` v5, method `1`, passphrase `@sinavm`, metadata and 119 field records decoded |
| `sinavm` `5176.npvs` | `NPVS` v5, method `1`, same passphrase, 156 field records decoded |
| `sinavm` `5254.npvs` | v5 mapped directly: one Hysteria2 row and one absent-`configType` `CUSTOM`/VLESS row |
| app-key v1 / v5 | derivation documented; **no real sealed sample tested** |
| recipient v1 / v5 | documented; requires an unavailable device private key |

Consumption is direct, no share-URL round trip:

```rust
let bundle = leas_config::npvt::decode(&bytes, passphrase)?;
for config in bundle.typed_configs() {
    let parsed = config.to_parsed_proto()?; // leas_proto::proto_spec::ParsedProto
}
```

`to_parsed_proto` maps VLESS, VMess, Trojan, Shadowsocks, and Hysteria2.
`CUSTOM` profiles map their first supported Xray outbound for VLESS, VMess,
Trojan, or Shadowsocks. SOCKS, HTTP, WireGuard, SSH, and issuer-backed configs
return `Unsupported`; they are never half-built.

`leas_config::subscription::parse_subscription_data` detects the container and
uses this direct mapper, so an `.npvt`/`.npvs` body imports without becoming a
URL list. Passphrase-sealed containers currently fail there because the
subscription API carries no passphrase.

The parser is `crates/leas-config/src/npvt.rs`. Its committed fixtures are two
real outputs: the owner-supplied legacy export and one 1,017-byte passphrase
sample from the public `sinavm` channel (password `@sinavm`). The larger samples
stay external; the fixture policy is in
`crates/leas-config/tests/fixtures/npvt/README.md` and the test-file header.
The 1,017-byte passphrase fixture is a public channel export used only as a
test vector.

## 7. Provenance and licensing

The format facts above come from the supplied XAPK’s decompiled Kotlin
(`com.vonmatrix.npvtunnel.crypto.*`, `sh.k4`, `fh.*`, `wh.*`), its native
`libnpvtunnel.so`/`libgojni.so` symbols, and observed files. A third-party
decryptor (`Pantegnos`, AGPL-3.0) was consulted as a behavioral cross-check for
the v5 layout and app-key labels. No Pantegnos code, table asset, or binary is
included here; the parser is written to this document, not copied from that
implementation. The embedded table bytes are extracted from the supplied
client, not from Pantegnos.

This page is a format description for interoperability and security research.
It does not grant rights to redistribute the client’s table data or embedded
key material. The parser does not implement the version-5 app-key table walker;
that path returns `Unsupported` until the walker is reimplemented from the
client in a clean room. The version-1 app-key path is implemented from §4.4 but
has no real sealed sample to test against.
