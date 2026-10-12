# Cryptography: where we are not on a crate default, why, and the rules

This file is the authority for every place `leas` produces a cryptographic
byte through something other than a maintained crate's public API — a
hand-rolled construction, a hazmat-labelled crate, or a documented exception —
and for the dependency advisories we have triaged instead of fixed. If you are
adding a primitive and wondering whether hand-rolling is allowed, the answer is:
read §2 first and prefer a crate.

Related records: `AGENTS.md` decisions 17 (TLS engine) and 19 (secret wiping),
`docs/reference/native-core.md` (the native/TLS crates), `docs/aegis/specs/2026-09-18-crypto-dependency-hardening-design.md`
(why liboqs left and what the sweeps found), `docs/aegis/adr/0007-*.md` (the
accepted posture).

> **Scope note.** Wiping of key material is governed by `AGENTS.md` decision 19,
> not by this file. This file covers *production* of cryptographic bytes and the
> advisory state of the crates that do it. A site that appears here is not
> automatically a defect: each has a cause, an independent oracle, and a
> retirement trigger.

## 1. The rule

- **Crate default first.** Primitives come from ring (the workspace TLS
  standard) or RustCrypto. `crates/leas-tls` and `crates/leas-native`
  both carry `#![forbid(unsafe_code)]`, so no hand-written unsafe can creep into
  the crypto core.
- **A non-default site needs a cause from §2**, a comment at the site, and an
  entry in §3. "It was easier" is not a cause.
- **Every site needs an independent oracle.** A test that runs our
  implementation against itself — our own client against our own server double,
  our own encoder against our own decoder — passes with the same bug on both
  ends and is therefore not evidence. The oracle is an RFC/NIST vector, the
  peer's own implementation (Go/xray, or the reference crate), or a real peer.
- **Every dependency exception has a recorded advisory state** in §4,
  whether fixed, unreachable, or accepted.

## 2. The causes

| Cause | Consequence |
| --- | --- |
| **C1. Wire-format mandate.** The peer's bytes fix the construction: xray's VLESS encryption, legacy Shadowsocks/VMess KDFs, TLS 1.2's PRF, RFC 9001's QUIC Initial. | We implement the mandated construction; a "better" primitive would change the wire. |
| **C2. Upstream API gap.** The primitive exists upstream, but not the mode, context, or parameter we need. | A narrow hand-rolled layer over the crate's own primitives, or a hazmat-labelled crate that is the only implementation of that mode. |
| **C3. Build constraint.** A dependency's build needs a toolchain or generator the target cannot assume. | Replaced, or the site is not adopted in the first place. |
| **C4. Accepted risk.** A reachable advisory with no in-range fix from this workspace, or a transitive pin we do not own. | Recorded in §4 with reachability and a re-evaluation trigger; never silently ignored. |

## 3. The inventory (every site, its cause, its oracle, its retirement)

| Site | What it is | Cause | Independent oracle | Retire when |
| --- | --- | --- | --- | --- |
| `leas-native/src/protocol/vless/encryption/b3.rs` | Hand-rolled BLAKE3 derive-key mode (481 lines: compression, chunk tree, the `DERIVE_KEY_CONTEXT`/`DERIVE_KEY_MATERIAL` flag pair) | C2 — xray derives keys with `blake3.DeriveKey(k, ctx, key)` over **binary** contexts (the 16-byte client IV, a 1216-byte PFS public key, record bytes); the `blake3` crate exposes `derive_key`/`hash_derive_key_context` for `&str` contexts only, and `guts` is deprecated with a hash-mode-only `ChunkState`/`parent_cv` | `derive_key_matches_reference_crate` (byte-equal to the `blake3` crate for string contexts, including multi-chunk), `derive_key_binary_context_go_vectors` (Go `lukechampine.com/blake3` v1.3.0 — xray's own dependency — for binary contexts), `hash32_matches_reference_crate`, `ss2022_subkey_matches_hand_rolled_derive_key` | An upstream byte-context derive-key API exists (then this file shrinks by 481 lines) |
| `leas-native/src/protocol/vless/encryption/mlkem.rs` — `new_ctr` (`ctr 0.10`, hazmat-labelled) | xray `XorConn`: AES-256-CTR keystream, keyed by `blake3.DeriveKey("VLESS", key)`, masking relay blocks (`xorpub`/`random`) and the 5-byte record headers (`random`) | C1 (that is what the peer unmasks) + C2 (no RustCrypto API for raw AES-CTR other than this crate) | `nist_sp800_38a_aes256_ctr_matches_the_published_vector` (counter-mode semantics), `xray_new_ctr_keystream_matches_go` (composition, Go `crypto/aes` + `cipher.NewCTR`), `xray_relay_chain_masking_matches_go` (the continuing-keystream offset across the `hash32` region), `random_mode_masks_headers_only` (structure: headers only, +5 B per record) | Never, while xray's `mlkem768x25519plus` wire format stands |
| `leas-tls/src/{crypto,handshake,record}/` | The TLS 1.3 client: key schedule, transcript, record layer, HelloRetryRequest, certificate handling — hand-rolled over ring primitives | C1 — the crate exists to send a *browser-fingerprint* ClientHello, which rustls cannot produce | `hkdf_expand_label_matches_rfc8448`, `finished_matches_rfc8448`, `expand_label_known_answer`, `x25519_rfc7748_alice_vector`, plus peer tests: a real rustls server, and `tests/strict_peer_presets.rs` against a BoringSSL front (which catches bodies this crate's own parser accepts) | Never — this is the crate's purpose (`docs/reference/native-core.md`) |
| `leas-tls/src/crypto/tls12.rs` | TLS 1.2 PRF (ECDHE + AEAD suites) for a server that answers with a 1.2 ServerHello | C1 — ring exposes no TLS 1.2 PRF. CBC suites are **refused**, not hand-rolled: HMAC-then-encrypt is exactly the construction that must not be written here | `prf_sha256_golden_vector` | A server population that never negotiates 1.2 for these profiles |
| `leas-route/src/sniff.rs` | QUIC Initial decryption (RFC 9001 §5.2 key schedule + header-protection removal) to route on the ClientHello SNI | C1 — routing decisions need the SNI before the tunnel exists | The `quic_*` sniff tests, driven by a test-side Initial encryptor built independently from RFC 9001 (`sniff/tests.rs`), plus multi-datagram `ClientHello` reassembly cases | A routing engine that does not need pre-tunnel SNI |
| `leas-native/src/crypto/kdf.rs`, `protocol/vmess/*` | Protocol-mandated legacy KDFs: `EVP_BytesToKey`-MD5 password keys, classic-AEAD `HKDF-SHA1(psk, salt, b"ss-subkey")`, 2022-blake3 session subkeys, VMess `KDF64`/`KDF16` and its AES-CFB-era body ciphers | C1 — the ciphers are fixed by servers in the wild | `evp_bytes_to_key_md5_vectors`, `hkdf_sha1_matches_independent_vectors`, `ss_subkey_matches_independent_vector`, `blake3_helper_uses_the_spec_context`, the VMess protocol suites | Never for legacy methods; new ciphers are not added to this set |
| `leas-native/src/crypto/salamander.rs` | Hysteria2 Salamander packet obfuscation: `payload XOR blake2b256(psk ‖ salt)` with an 8-byte per-packet salt | C1 — the transform is the protocol | `keystream_matches_reference_blake2b`, plus `roundtrip`/`roundtrip_spanning_blocks`/`different_salt_gives_different_wire` | Never while hysteria2's `obfs: salamander` is supported |
| `leas-tls/src/handshake/mod.rs` — RFC 8879 decompression (`zstd` via `zstd-sys`) | The one decompressor fed **server-supplied** bytes (a `CompressedCertificate` with algorithm 0x0003) | C4-ish tradeoff: bundled libzstd is heavily fuzzed (OSS-Fuzz) while pure-Rust `ruzstd` is young; the decode is bounded by `decompress_bounded` + `MAX_CERT_BYTES`, and the client never encodes | `decompression_bomb_is_bounded` and the `CompressedCertificate` decode tests | A `ruzstd` with comparable fuzzing coverage — and note the adoption cost: the current test's encoder call (`zstd::stream::encode_all`) must become a pinned compressed fixture, because a `zstd` *dev*-dependency would still build `zstd-sys`. Switching would **not** remove a C toolchain from the graph: `zstd-sys` also arrives via `turso_core → tantivy-sstable → zstd` |

## 4. Accepted advisories (`cargo audit`, `.cargo/audit.toml`)

Fixed by the 2026-09-18 sweep: `chacha20 0.10.1` (**yanked** upstream) bumped to
0.10.2; `smartstring` (unmaintained, RUSTSEC-2026-0249) replaced by
`compact_str`; `heapless 0.7`/`atomic-polyfill` removed by turning off
`postcard`'s default `heapless-cas` feature. `liboqs` (`oqs`) left the tree for
`ml-kem` (C3).

Still visible and triaged (rationale lives in `.cargo/audit.toml` next to each
entry; they are deliberately **not** in `ignore` so they keep showing up):

| Advisory | Reachability | Why not fixed here |
| --- | --- | --- |
| RUSTSEC-2023-0071 (`rsa`, Marvin attack) | `toasty-driver-mysql → sqlx-mysql`, a driver no workspace member enables (SQLite/turso only) | ignored as unreachable; no fixed release |
| RUSTSEC-2026-0253 (`lru 0.16.4`, unsound: `LruCache::pop` panic safety) | `leas-db/src/driver/ (the crate's own turso driver fork) → turso_core 0.8.2 → tantivy → lru` | 0.16.4 is the newest 0.16.x and tantivy pins `^0.16.3`; we never call `pop`, and the UB needs a panic inside tantivy's cache (the FTS path this app does not populate). **Provenance updated 2026-10-08**: the chain used to run through the published `toasty-driver-turso`; that crate is no longer a dependency (ADR 0012), so the same `turso_core` arrives via our own `driver/` fork |
| RUSTSEC-2025-0141 (`bincode 1.3.3`, unmaintained) | `heed → heed-types` | upstream owns the migration to bincode 2's different API |
| RUSTSEC-2025-0134 (`rustls-pemfile`, unmaintained) | `toasty-driver-postgresql → tokio-postgres`, an unactivated optional driver chain | disappears with the driver chain |
| `yoke-derive 0.8.3` (**yanked**, a registry warning rather than a RUSTSEC advisory) | `turso_core 0.8.2 → icu_* → yoke → yoke-derive` | arrives with the turso 0.8.2 bump (ADR 0012); a proc-macro, build-time only, and no fixed version is reachable while ICU 2.3 pins this major. Not in `ignore`: it keeps showing up so a future bump notices it |

## 5. Rejected alternatives (so they are not re-proposed)

- **Hand-rolling AES-CTR over `aes` to drop the hazmat-labelled `ctr`.** The
  banner warns that ciphertexts are unauthenticated; this site is a keystream
  *mask* whose integrity comes from the NFS AEAD and the `hash32` chain, and
  hand-rolling counter mode trades a maintained crate for in-repo mode code.
  Kept, with the Go-pinned oracles above (user decision, 2026-09-18).
- **Replacing ring.** rustls (ring backend), quinn (`rustls-ring`), hickory and
  reqwest (`rustls-no-provider` with ring installed in code) all land on it; a
  RustCrypto route means a custom rustls `CryptoProvider` plus X.509 signature
  verification (RSA/ECDSA/EdDSA, which `rustls-webpki` provides only through
  ring/aws-lc-rs). That is a TLS-provider migration, i.e. a separate epic.
- **`aws-lc-rs` as the workspace provider.** C/asm build, worse for
  `x86_64-pc-windows-gnu`, no security win at this threat model.
- **Keeping liboqs for ML-KEM.** Its build needed CMake, libclang (bindgen) and
  a C/C++ toolchain; RustCrypto `ml-kem` 0.3.2 is pure Rust with
  `unsafe_code = "deny"`, and the FIPS 203 bytes are unchanged
  (`mlkem768_seed_derivation_matches_liboqs_and_go_stdlib`). What that does
  **not** claim: `bindgen`/`clang-sys` still resolve as `turso_sdk_kit`'s
  non-optional build-dependency, and `cc` is still needed for
  `zstd-sys`/`lmdb-master-sys`/`libsqlite3-sys`/ring. The bindgen pair is
  compiled but never invoked — turso_sdk_kit ships pre-generated
  `src/bindings.rs` (regenerated by hand via its `bindgen.sh`) and its
  `build.rs` never calls bindgen, while `clang-sys` resolves with the `runtime`
  feature (libclang is dlopen'd only on use). Only `cmake` actually left the
  graph.
- **Forking `blake3` to expose a byte-context derive-key.** Maintaining a fork
  of a security crate is a larger liability than the vector-pinned
  implementation it would replace.
- **`ruzstd` today.** See the `zstd` row in §3: it is a real hardening direction,
  but not obviously a net win yet, and it does not remove a C toolchain.

## 6. Adding a hazmat site — checklist

1. Name the cause from §2 in a comment at the site (what the peer/crate constraint
   is, and what the alternative was).
2. Add an **independent** oracle: an RFC/NIST vector, the peer implementation's
   own output, or a reference crate. A self-consistent round-trip is not one.
3. State the wire/format compatibility boundary: what a peer sees if this
   changes.
4. State the retirement trigger (what upstream change deletes this site).
5. Add the row to §3.
6. If a dependency is involved, comment the manifest and record the advisory
   state in §4 after `cargo audit` + `cargo tree` checks.

## 7. Vector generators (so the oracles can be regenerated)

Both programs run with Go 1.27.1 (`lukechampine.com/blake3` is in the module
cache; the mask program needs no network).

**ML-KEM seed → encapsulation key** (`crypto/mlkem.rs` KAT). Seeds: A = 64 zero
bytes, B = bytes `0..=63`:

```go
package main

import ("crypto/mlkem"; "encoding/hex"; "fmt")

func main() {
    for _, tc := range []struct{ name string; seed []byte }{
        {"SEED_A", make([]byte, 64)},
        {"SEED_B", func() []byte { s := make([]byte, 64); for i := range s { s[i] = byte(i) }; return s }()},
    } {
        dk, err := mlkem.NewDecapsulationKey768(tc.seed)
        if err != nil { panic(err) }
        fmt.Printf("%s ek = %s\n", tc.name, hex.EncodeToString(dk.EncapsulationKey().Bytes()))
    }
}
```

The retired liboqs implementation produced byte-identical output for both seeds
(`cargo run -p leas-tls --example kat_dump` before the swap), which is what
makes the constant a *migration* pin and not just a Go pin.

**VLESS XOR mask** (`encryption/mlkem.rs` KATs). Inputs: `iv = 0..15`, and keys
`[base + 0..31]` for `base` 0x40 (`k0`), 0x80 (`k1`), 0xa0 (`s0`):

```go
package main

import ("crypto/aes"; "crypto/cipher"; "encoding/hex"; "fmt"; "lukechampine.com/blake3")

func newCTR(key, iv []byte) cipher.Stream {
    k := make([]byte, 32)
    blake3.DeriveKey(k, "VLESS", key)   // xray proxy/vless/encryption/xor.go
    block, _ := aes.NewCipher(k)
    return cipher.NewCTR(block, iv)     // 16-byte IV = initial counter block
}

func keystream(key, iv []byte, n int) []byte {
    out := make([]byte, n)
    newCTR(key, iv).XORKeyStream(out, out)
    return out
}

func ramp(base byte) []byte { s := make([]byte, 32); for i := range s { s[i] = base + byte(i) }; return s }

func main() {
    iv := make([]byte, 16)
    for i := range iv { iv[i] = byte(i) }
    k1, s0 := ramp(0x80), ramp(0xa0)

    fmt.Printf("BLOCK0 %s\n", hex.EncodeToString(keystream(ramp(0x40), iv, 32)))

    h := blake3.Sum256(k1)
    for i, b := range keystream(s0, iv, 32) { h[i] ^= b }
    fmt.Printf("HASH32 %s\n", hex.EncodeToString(h[:]))

    k1ks, s0ks := keystream(k1, iv, 64), keystream(s0, iv, 96)
    b1 := make([]byte, 64)
    copy(b1, k1ks)
    for i := 0; i < 32; i++ { b1[i] ^= s0ks[32+i] }   // the continuing instance
    fmt.Printf("BLOCK1 %s\n", hex.EncodeToString(b1))
}
```
