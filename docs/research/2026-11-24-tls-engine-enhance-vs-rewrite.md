# TLS engine: enhance or rewrite

Read of `crates/leas-tls`, the five reference trees under `thirdparty/tls-engine/`
(`utls`, `geektls`, `curl-impersonate`, `purecrypto`) and `thirdparty/ferrox`,
against the stated goal: an *extremely fast* and *absolutely correct* TLS
client that can supersede the current engine.

**Verdict up front: enhance, do not rewrite — but the enhancement includes a
committed Sans-I/O core refactor.** The engine is already the right shape for
this product (one client lane, spec-as-data hellos, in-place ring AEAD, a
zero-allocation record path, REALITY/ECH/TLS 1.2 in the same core), and none of
the references offers a core that is both faster and more correct for this
workload. What is missing is a bounded set of correctness gates, a small set of
performance features (including compile-time hello caps), and a structural
split of protocol logic from async I/O.
§9 gives the staged plan; §10 states the measurable conditions under which a
from-scratch rewrite would become the cheaper option.

The refactor is not a rewrite: the crate, its public `connect`/`TlsStream`
seam, its profiles and its crypto stack stay; only the boundary between
protocol state and I/O moves. The differentiator this protects is wire-exact
fingerprint hellos (71 JA4-gated profiles), ECH sealing and REALITY — the
reasons the rustls client path was deliberately removed
(`crates/leas-native/src/security/mod.rs:1-6`). "Fast" is judged by
`just hotpath` exact allocation counts plus the `just bench` record rows and
the new handshake/relay rows (§5 B7); "correct" by the tier-1 tests,
`tests/strict_peer_presets.rs`, `tests/generated_ja4_gate.rs` and the
real-core rows in `leas-oracles`. Ring-only crypto,
`#![forbid(unsafe_code)]` and the `docs/reference/crypto-dependencies.md`
gate are fixed, not variables.

Not authoritative. Every leas claim carries a `file:line`; reference-repo
claims come from targeted reads of the named files. Benchmark numbers are from
this machine only and are labelled as such.

---

## 1. Basis and limits

| Basis | What was read | What it proves |
|---|---|---|
| leas code | all of `crates/leas-tls/src` (module map, call sites), `Cargo.toml`, `benches/record.rs`, `tests/` | architecture, gaps, data path |
| leas consumers | `crates/leas-native/src/{security,transport/http,probe,headers}.rs`, `crates/leas-hotpath/src/main.rs` | real integration and measured gates |
| Executed | `LEAS_BENCH_MB=16 cargo bench -p leas-tls --bench record -- --quick` | record-layer throughput on this host |
| Reference trees | `thirdparty/tls-engine/{utls,geektls,curl-impersonate,purecrypto}`, `thirdparty/ferrox` TLS modules | what to copy, what to reject |
| Prior work | `docs/research/2026-11-23-ferrox-comparison.md`, `docs/reference/tls-fingerprint-roster.md` | ferrox comparison, JA4 roster provenance |

Limits: no live network sweep was run; no handshake benchmark exists in the
tree, so per-connect cost is asserted from code shape, not measured; the
reference repositories were read for design, not executed.

---

## 2. What exists today

### 2.1 Module map

`crates/leas-tls` is ≈33.6k lines, of which 11.7k are generated catalog data
(`src/fingerprints/catalog/catalog_data.rs`). The engine proper is ≈19k.

| Area | File | Role |
|---|---|---|
| Public entry | `src/client.rs` | `TlsConfig` → `connect`; dispatches plain TLS / REALITY; resolves the fingerprint and builds the spec per connect |
| Handshake 1.3 | `src/handshake/mod.rs` (3 258 lines) | ClientHello write, ServerHello/HRR parse, key schedule, server flight, Finished, KeyUpdate setup |
| Server flight | `src/handshake/flight.rs` | EncryptedExtensions/Certificate/CertificateVerify/Finished, RFC 8879 decompression, reassembly |
| Handshake 1.2 | `src/handshake/tls12.rs` | ECDHE + AEAD only, 6 suites, EMS required |
| Record layer | `src/record/stream.rs` (1 688) | `TlsStream`: in-place seal/open, read state machine, KeyUpdate, Vision direct modes |
| Crypto | `src/crypto/mod.rs` (1 100) | TLS 1.3 schedule, `AeadKey` over ring, X25519; `mlkem.rs`, `mldsa.rs`, `hpke.rs`, `tls12.rs` |
| Hello spec | `src/spec/mod.rs` (1 016) | `ClientHelloSpec` + `ExtensionSpec` enum, wire encoders, GREASE |
| Hello builder | `src/hello/mod.rs` (1 319) | GREASE fill, Chrome permutation, BoringSSL 512-byte padding, record framing, HRR replay RNG |
| Profiles | `src/profiles/` | 71 identities (69 generated JA4-faithful + 2 wire-exact hand) |
| Fingerprint resolution | `src/fingerprints/` | query/resolve, JA3/JA4 codecs, 11.7k-entry evidence catalog |
| Verify | `src/verify/mod.rs` (792) | `rustls-webpki` chain + SAN, SPKI pin, CertificateVerify |
| ECH | `src/ech.rs` (835) | RFC 9849 client subset, split hello, HPKE seal, acceptance confirmation |
| REALITY | `src/reality/` (≈2.4k) | sealed session id, HMAC+Ed25519 auth, ML-DSA-65, Spider-X |
| HTTP/2 | `src/http2/mod.rs` | minimal client used by the grader; not a fingerprint surface |
| HTTP/2 identity | `src/http2_profile.rs` | window sizes + UA/headers per browser, consumed by `leas-native` |

### 2.2 One seam, one lane

Everything above the engine consumes
`TlsStream<S>: AsyncRead + AsyncWrite` (`src/record/stream.rs:314`) through
`leas_tls::client::connect` (`src/client.rs:130`). `leas-native` wraps that
call in its own security phase and bounds it with `timeouts::SECURITY`
(`crates/leas-native/src/security/mod.rs:113`). There is no second TLS lane:
no rustls fallback, no BoringSSL, no subprocess TLS in production. That is the
correct architecture for this workspace, and it is the first reason not to
rewrite. Its one structural cost is that the protocol modules are generic over
`AsyncRead + AsyncWrite` (e.g. `drive` at `src/handshake/mod.rs:355` and
`TlsStream` itself), so they cannot be replayed or fuzzed without a runtime;
§9 Phase 1 removes that coupling while keeping the seam.

### 2.3 What is already right

1. **Spec-as-data + one encoder.** Hellos are `ClientHelloSpec` values, emitted
   by one two-pass builder (`src/hello/mod.rs:171`), with GREASE, Chrome
   permutation and BoringSSL padding implemented once. This is the same
   abstraction uTLS uses (`u_common.go:182`, `u_conn.go:601`) without the Go
   fork cost.
2. **Fidelity is gated, not asserted.** 69 generated profiles reproduce their
   source JA4 offline (`tests/generated_ja4_gate.rs`), the roster was swept
   live 71/71 on 2026-08-25 (`docs/reference/tls-fingerprint-roster.md`), and
   the two hand profiles pin JA4/JA3 constants.
3. **AEAD in place, zero allocation.** `AeadKey::seal_in_place` /
   `open_in_place` over `ring::aead::LessSafeKey`; the hotpath gate asserts
   0 allocations, 0 reallocs, 0 zeroed bytes for both 16 KiB rows
   (`crates/leas-hotpath/src/main.rs:155,177`).
4. **Record buffer reuse.** `rec_buf` and `pending` are allocated once per
   stream and reused (`src/record/stream.rs:314-360`); a partial write uses a
   cursor, not `drain`.
5. **REALITY and ECH are real implementations**, not wrappers: constant-time
   HMAC compare (`src/reality/verify.rs:83`), ML-DSA-65 extension check,
   HPKE-sealed inner hello, acceptance confirmation (`src/ech.rs:370`).
6. **TLS 1.2 fallback exists** with extended master secret enforced
   (`src/handshake/tls12.rs:288`), 6 AEAD suites, and no CBC/RSA.
7. **Trust story is coherent:** `#![forbid(unsafe_code)]` (`src/lib.rs:11`),
   ring for TLS primitives, RustCrypto for ML-KEM/ML-DSA, `zeroize` on owned
   key buffers.

---

## 3. Measured baseline

Command and configuration:

```
LEAS_BENCH_MB=16 cargo bench -p leas-tls --bench record -- --quick
```

The bench writes 16 KiB plaintext per `write_all` through `TlsStream` over
`tokio::io::duplex` (256 KiB), so every sample is one seal + one open plus the
duplex copy; it is not a network throughput test (`benches/record.rs:1-40`).

| Row | Time (16 MiB) | Throughput |
|---|---|---|
| `tls_record/aes128gcm/seal` | 2.69 ms | 5.81 GiB/s |
| `tls_record/aes128gcm/open` | 2.97 ms | 5.26 GiB/s |
| `tls_record/chacha20/seal` | 7.80 ms | 2.00 GiB/s |
| `tls_record/chacha20/open` | 7.70 ms | 2.03 GiB/s |

Interpretation: the AEAD path is not the bottleneck for a proxy client. A
1 Gbps tunnel moves ~125 MB/s; AES-GCM at 5 GiB/s leaves >40× headroom, and
even ChaCha20 at 2 GiB/s leaves >16×. **"Extremely fast" will not be won inside
`ring`.** It will be won by removing per-connect work (spec construction,
handshake, no resumption) and per-burst syscalls (one record per `poll_write`).

There is no handshake benchmark and no end-to-end relay throughput benchmark in
the tree. That is itself a gap: the two costs that matter are unmeasured.

---

## 4. Correctness audit

Severity: **S1** = a legal server can make the handshake fail; **S2** = spec
non-conformance with no common failure; **S3** = trust or DoS posture worth a
recorded decision.

| # | Issue | Evidence | Failure mode | Sev |
|---|---|---|---|---|
| A1 | **Advertised signature schemes cannot be verified.** `tls13_algorithm` maps only 0x0403/0503/0804/0805/0806/0807. Generated Chrome rows advertise 0x0603 (P-521) and 0x0808/0809/080a/080b (Ed448, RSA-PSS-PSS). | `src/verify/mod.rs:277-290`; `src/profiles/generated/chrome.rs:193,396,411,426,441` | A server with a P-521 or PSS-only certificate selects an advertised scheme; the client aborts with a typed error (no silent downgrade). Rare key types, but a real legal server. | **S1 (rare)** |
| A2 | **ALPN is accepted without checking it was offered.** `parse_encrypted_extensions` returns any protocol; `drive` stores it unvalidated. | `src/handshake/flight.rs:164`; `src/handshake/mod.rs:655`; RFC 7301 §3.1 says the client MUST abort | A broken or hostile server selects an unoffered protocol; the client proceeds and the caller may trust `negotiated_alpn()`. | **S1** |
| A3 | **Unsolicited and duplicate ServerHello extensions are ignored.** The extension scan's default arm is `_ => {}`; no duplicate tracking; RFC 8446 §4.2 requires `unsupported_extension`. | `src/handshake/mod.rs:1197-1212` | A server can inject extensions the client never offered; no interop harm today, but the client is not conforming and cannot detect a stripping middlebox. | S2 |
| A4 | **Graceful shutdown sends no `close_notify`.** `poll_shutdown` flushes and calls the inner shutdown. | `src/record/stream.rs:1045-1056`; RFC 8446 §6.1 | The peer sees a truncation, not a clean close. The type docs make this a deliberate tunnel trade-off (`stream.rs:304-309`), but it is a spec deviation and can lose a peer's final bytes. | S2 |
| A5 | **No session resumption.** `NewSessionTicket` is parsed and dropped; TLS 1.2 tickets appear only in a test. | `src/record/stream.rs:16,756-757,908`; `src/handshake/mod.rs:3193` | Every TLS dial pays a full handshake. Correct, and an **opt-in** tradeoff rather than a free win: `pre_shared_key` + binder changes the resumed hello's JA3/JA4 (the catalog drops PSK-bearing rosters, `gen_specs.py:386,429-435,628`) and REALITY's sealed session id is bound to the first hello. | S3 (perf, opt-in) |
| A6 | **OCSP/SCT are advertised but never validated.** `status_request` and `signed_certificate_timestamp` are in the extension model and in every Chrome hello; the verifier has no OCSP or SCT path. | `src/spec/mod.rs:917-922`; `src/verify/mod.rs` (no OCSP/SCT) | Not a protocol violation (stapling is optional), but the client claims a capability it does not consume. A revoked-but-stapled cert is accepted. | S3 |
| A7 | **ECH has no retry-config handling and a single suite.** Only X25519/HKDF-SHA256/AES-128-GCM; a server ECH rejection is terminal. | `src/ech.rs:148-160`, no `retry_config` symbol | Fails closed (no SNI leak), which is defensible for a circumvention client, but it is a subset of RFC 9849. | S3 |
| A8 | **No client certificate / post-handshake auth.** TLS 1.2 rejects `CertificateRequest`; TLS 1.3 skips it as an unknown message. | `src/handshake/tls12.rs:100-108`; `src/handshake/flight.rs:112` | mTLS endpoints cannot be dialled. Declared scope, not a bug. | S3 |
| A9 | **No bound on consecutive `KeyUpdate`s.** A peer can force unbounded HKDF work and record churn. | `src/record/stream.rs:455-475` (no counter) | Cheap remote CPU amplification; RFC permits KeyUpdate at any time. | S3 |
| A10 | **16 MiB handshake reassembly bound per connection.** | `src/handshake/mod.rs:177` | A malicious server can make each dial hold 16 MiB. Real chains are <256 KiB. | S3 |
| A11 | **CertificateVerify scheme is not checked against what was offered.** Any scheme the verifier knows is accepted. | `src/verify/mod.rs:277` (no offered list) | RFC 8446 §4.4.3 conformance gap; no practical attack because the signature still verifies. | S3 |
| A12 | **No engine-level handshake deadline.** `connect` has none; `leas-native` wraps it. | `src/client.rs:130`; `crates/leas-native/src/security/mod.rs:113` | A direct engine user can hang on a silent peer. Document or add a deadline option. | S3 |

### A1 in detail (the one real handshake failure)

`rustls-webpki` 0.103 with the `ring` feature has no P-521 verifier:
`ring_algs.rs` exposes P-256/P-384 ECDSA only (`.../rustls-webpki-0.103.17/
src/ring_algs.rs:48-69`). P-521 exists only in the `aws-lc-rs` backend
(`.../src/aws_lc_rs_algs.rs:121`), and `aws-lc-rs` is not in `Cargo.lock`.
RSA-PSS-PSS (`rsa_pss_pss_*`) is absent from both backends; only
`..._LEGACY_KEY` (rsa_pss_rsae) exists.

Three ways out, in cost order:

1. **Document the accept/fail boundary (default).** The engine already fails
   with a typed error and never downgrades; note the unverifiable schemes in
   the roster/reference docs and leave the hello bytes untouched. This is the
   proportional answer for a rare leaf key type and keeps ring as the single
   crypto provider.
2. **Add verification, keep the list (ADR-sized).** `rustls-webpki`'s
   `aws-lc-rs` feature would add P-521 but also a second crypto provider, a C
   build and cross-compile friction; RSA-PSS-PSS needs a manual SPKI verify.
   That is a crypto-dependency decision under
   `docs/reference/crypto-dependencies.md`, not a maintenance edit.
3. **Drop the unverifiable schemes from the emitted list.** Cheapest in
   dependencies, but changes the signature_algorithms extension, which is
   inside the JA4 extension hash — every affected profile would need
   re-derivation and a new golden. Not acceptable as a silent change.

Recommendation: (1). **No aws-lc-rs, now or later in this crate**: the
workspace permits one crypto provider and it is ring, so option (2) is rejected
unless ring itself is replaced wholesale (out of scope here). The invariant to
enforce in every case is **advertised schemes ⊆ verifiable schemes ∪
documented-unverifiable schemes**, gated by a test over the whole roster so the
boundary can never drift silently.

---

## 5. Performance audit

| # | Cost | Evidence | Impact | Fix |
|---|---|---|---|---|
| B1 | **One TLS record per `poll_write`.** `take = min(len, 16 KiB)`, seal, flush. A 64 KiB relay write is 4 records and up to 4 socket writes. | `src/record/stream.rs:922-1010` | Syscall count scales with record count; on high-BDP links this costs throughput and CPU. | Seal up to N records into the reused `pending` buffer, then one `write_vectored`/`write_all`. Ferrox bounds this at 32 KiB with a 7-iovec coalesce (`tls/rustls_backend.rs:1762`). |
| B2 | **Spec is rebuilt per connect.** `(row.spec)()` constructs a Vec-heavy `ClientHelloSpec` on every dial; `resolve()` walks both tiers first. | `src/fingerprints/resolve.rs:238`; `src/client.rs:140` | Cold-path allocations per dial; avoidable. | Cache resolved specs by identity (`Arc<ClientHelloSpec>`), clone only the per-connection key-share slots. |
| B3 | **No resumption** (A5), an **opt-in** policy not a default. | as A5 | A full TLS 1.3 handshake + certificate chain + signature verify per dial. Real win for probe/fast dials; mux already amortizes carrier handshakes. | Ticket cache keyed by `(SNI, profile, ALPN)`; the resumed hello is a separately-gated shape (PSK changes JA4/JA3), never used for REALITY (session id binding) and never for profiles whose roster row is PSK-free. |
| B4 | **One plaintext copy per read.** `rec_buf` → caller buffer. | `src/record/stream.rs:844-852` | One memcpy per record; fine at 16 KiB granularity, but it is the only copy left. | Leave it. Removing it needs kTLS (see §8). |
| B5 | **No dynamic record sizing.** Always 16 KiB. | `src/record/stream.rs:75` | uTLS has real dynamic sizing; we do not, but record-size policy is not part of the JA3/JA4 fingerprint. | Low priority; only if a middlebox test shows a difference. |
| B6 | **Handshake flight copies each message** (`raw = ... .to_vec()`). | `src/handshake/flight.rs:95` | Cold path, O(chain). | Ignore. |
| B7 | **No handshake or end-to-end bench.** | `benches/` has only `record.rs` | Cannot prove a speed claim or a regression. | Add two rows: connects/second + allocations/connect against a local rustls server; relay MiB/s over loopback. |
| B8 | **Spec predicates are linear scans.** `spec_has_grease`, `supports_tls13_aead`, `offers_x25519_key_share`, `offers_mlkem_hybrid`, `reality_eligible` walk `Vec`s; `compressed_algorithms` re-parses the hello per handshake; permutation/padding search for positions. | `src/hello/mod.rs:487,526`; `src/spec/mod.rs:169-243`; `src/handshake/mod.rs:781` | O(N) per connect for declared-profile questions, on top of B2's spec build. | Const `HelloCaps` sidecar for the declared profile + static profile tables; mutated specs recompute a runtime mask or keep the targeted check (§8). |

The dominant cost is B3 (opt-in), then B2/B8 and B1. AES-GCM is already 5+ GiB/s
(§3), so cipher micro-optimisation is not on the critical path.

---

## 6. Fidelity audit

| # | Gap | Evidence | Consequence |
|---|---|---|---|
| C1 | **ALPS is offered in the hello but its settings are never applied.** The extension body is emitted as a raw extension (`raw[0x44cd, "000c02683208687474702f312e31"]` across the generated Chrome/Android/Firefox/Safari/Safari-iOS rows; draft `0x4469` in `profiles/mod.rs:492`), but the client never sends the post-Finished ALPS EncryptedExtensions that carries the actual settings. | `src/profiles/generated/*.rs` (the `0x44cd` raw bodies); `src/spec/mod.rs:122`; no ALPS emission in `src/record/stream.rs`; uTLS does send it (`u_handshake_client.go:165-200`) | The hello side is faithful; the post-handshake side is not. A target that consumes ALPS sees an offer with no settings, a cross-layer tell of the class `http2_profile.rs` exists to avoid. |
| C2 | **Production HTTP/2 is not browser-shaped.** `leas-native` sets hyper window sizes from `Http2Profile` but does not emit ordered/browser SETTINGS, priority frames or pseudo-header order; `leas-tls/src/http2` is a grader-only minimal client with empty SETTINGS. | `crates/leas-native/src/transport/http/conn.rs:56`; `src/http2/mod.rs:190-201` | An Akamai-style h2 fingerprint does not match the TLS identity. This is the next fingerprint surface after TLS. |
| C3 | **Profile corpus is 71, not 394.** | `docs/reference/tls-fingerprint-roster.md`; geektls `profiles/builtin` | Fewer identities, but ours are JA4-gated. Expand only from captures with an oracle gate, not by importing names. |

---

## 7. What the references actually offer

| Tree | What it is | Take | Reject |
|---|---|---|---|
| **utls** (Go) | A fork of `crypto/tls` that replaces ClientHello construction; 41 presets + 3 randomized. No REALITY, no record-layer fingerprint control, no real record sizing. | The spec model (ordered extensions, two-pass marshal), BoringSSL GREASE seeding, Chrome permutation invariants, capture→spec parsing, in-place PSK binder patching. | The fork-and-subtree-merge model, public/private struct mirroring, per-connection reflection clone, `context.Context` plumbing. |
| **geektls** (Go) | A fingerprinting HTTP client on stock utls, with in-tree forks of fhttp/quic-go. 394 presets (docs disagree: 368). No TLS core of its own. | Profile JSON schema + evidence grading, ClientHello compile rules (permutation/GREASE/padding/ECH shapes), h2 SETTINGS/priority/pseudo-header/HPACK knobs, h3 transport-parameter model, resumption policy. | Everything TLS protocol: it delegates to Go. No REALITY. No kTLS. GC/FFI model. |
| **curl-impersonate** (C) | Patches curl + BoringSSL to expose per-browser knobs; BoringSSL does the handshake. | The fidelity method: one preset table drives wrapper generation and test expectations; consistency rules that reject contradictory captures; h2/h3 knob list. | The C/BoringSSL patch set; porting BoringSSL into a Rust binary. |
| **purecrypto** (Rust) | A one-crate OpenSSL-breadth toolkit: primitives → X.509 → TLS 1.2/1.3/DTLS/QUIC/ECH. No public ClientHello shaping; no third-party audit. | Maybe AES-GCM/ChaCha kernels and reusable X25519 as a benchmark comparator; alloc-free ML-KEM API as a shape reference. | The TLS stack (no fingerprint control), the primitive swap (API churn, unaudited, `unsafe` SIMD), its X.509 verifier (would orphan our pinning/REALITY paths). |
| **ferrox** (Rust) | Closest architecture: `TlsProvider` trait, three lanes (rustls / shaped / BoringSSL), 32 presets, custom REALITY/ECH/kTLS, `unsafe` present. | The trait seam (`Read+Write` above, nothing depends on the stack), profile-as-static-data with a uTLS byte golden (50 cases), `open`/`seal_into` split, record batching, test-counted zero-copy claims. | Three lanes, BoringSSL FFI, `unsafe` kTLS/`init_room`, the shaped lane's missing resumption, 32 vs 71 profiles. |

The important negative result: **no reference contains a client TLS core that
is both a superset of leas-tls functionally and more correct.** uTLS/Geektls/
curl are Go/C shapes we cannot embed without a second runtime; purecrypto and
ferrox are Rust but each loses a required property (fingerprint control, or
`forbid(unsafe_code)` + audited crypto).

---

## 8. Architecture decision

### Keep

1. **One client lane.** The product dials client-side only; a second TLS
   implementation is a maintenance tax with no client capability gain. Ferrox
   needs three lanes because rustls cannot shape bytes or carry its BCP suites;
   a hand-written engine already does both.
2. **`TlsStream: AsyncRead + AsyncWrite` seam.** Everything above it is
   protocol code; nothing above knows the TLS stack. That is ferrox's best
   idea, already present.
3. **ring + RustCrypto + `forbid(unsafe_code)`.** An unaudited hand-written
   AEAD/SIMD stack (ferrox, purecrypto) is not a correctness upgrade for a
   censorship-circumvention client. **One provider only**: aws-lc-rs is not
   permitted alongside ring, so a capability ring cannot verify stays a
   documented boundary (see A1), not a second backend.
4. **Spec-as-data and the 71-profile roster.** The roster is the product's
   differentiator; it is gated, reproducible and evidence-graded.

### Compile-time hello knowledge (O(1) predicates)

The spec predicates are linear scans over `Vec`s today: `spec_has_grease`
iterates `extensions` (`src/hello/mod.rs:487`), `supports_tls13_aead` /
`offers_x25519_key_share` / `offers_mlkem_hybrid` / `reality_eligible` walk
`cipher_suites` and `extensions` (`src/spec/mod.rs:169-243`),
`compressed_algorithms` re-parses the built hello on every handshake
(`src/handshake/mod.rs:781`), and the permutation/padding rules search for
`pre_shared_key`/padding positions (`src/hello/mod.rs:526`). N is ≤ ~20, so the
absolute cost is small, but every one of them sits on the per-connect path and
multiplies with per-connect spec construction (B2).

Target property, scoped precisely: **every question about what the *declared
roster profile* advertises is a bit test on a compile-time constant**, never a
search. The mask is not a description of the per-connection effective spec, and
it does not replace checks on received wire bytes (see the scope bullets).

```rust
/// Sidecar compiled with the profile; no heap, no iteration.
/// Bit positions are dense enum discriminants (known set), not raw wire ids.
pub struct HelloCaps {
    ext: u64,     // 1 << ExtensionKind::bit()
    suites: u16,  // 1 << CipherSuiteId::bit() (3 TLS 1.3 + GREASE)
    sigalgs: u32, // 1 << SigScheme::bit() (the schemes the roster can emit)
    groups: u64,  // 1 << Group::bit()
    flags: u32,   // GREASE, ECH, ALPS, PSK, X25519, MLKEM, PADDING, ...
}

impl HelloCaps {
    pub const fn has_ext(self, k: ExtKind) -> bool { self.ext & k.bit() != 0 }
    pub const fn offers_suite(self, suite: CipherSuiteId) -> bool { ... }
    pub const fn offers_group(self, g: Group) -> bool { ... }
    pub const fn offers_sigalg(self, s: u16) -> bool { ... }
}
```

- **Generated profiles** carry the mask as a `caps: HelloCaps` field on
  `GenEntry`, emitted by `gen_specs.py` next to the spec; the hand `spec!`
  declaration computes the same value from its tokens with `const fn`s, so no
  runtime derivation is needed.
- **The runtime `ClientHelloSpec` stays the wire-order source of truth.** CAPS
  is a validated sidecar, not a replacement: extension order is still data.
- **Scope: declared profile only.** `client.rs` mutates the resolved spec with
  `apply_curve_preferences` (`src/client.rs:145`), REALITY calls
  `graft_hybrid_key_share` (`src/reality/mod.rs:116,142,269`), and HRR/ECH
  rebuild the hello. CAPS answers roster-level predicates (does this profile
  declare extension X / cipher Y / group Z) **before** those mutations; a
  decision that must see the effective spec either recomputes a runtime mask
  once after mutation (still O(1) per predicate, no scan) or keeps its existing
  targeted check. Code must not read CAPS as if it described the mutated spec.
- **Wire truth stays wire truth.** `hello_lists_u16` and
  `key_share_lists_group` (`src/handshake/mod.rs:998,1012`) parse the built
  hello after GREASE and permutation; they remain as-is.
- **Drift gate (emitted, not just built):** a CI test builds each profile's
  hello with a fixed-seed RNG, parses the emitted extensions/ciphers/groups/
  signature-algorithms, recomputes CAPS, and asserts equality across the whole
  roster. That catches both a stale constant and a generator change that alters
  the wire.
- **Deeper step (optional, same phase):** make static profiles
  `const`-constructible (`&'static [ExtSlot]` with borrowed payloads instead of
  `Vec`), so resolution returns a static profile and a connect copies only the
  slots it mutates (REALITY session id, HRR cookie, curve override). That
  removes B2's per-connect spec build entirely rather than caching it.
- **Use sites:** ALPS/ECH/PSK advertisement decisions, pre-graft REALITY
  eligibility, GREASE/permutation/padding policy, compressed-algorithm offer,
  and roster filtering without constructing a spec.
- **Not replaced:** checks against *received* bytes (`ensure_offered_suite`,
  `ensure_offered_key_share` in `src/handshake/mod.rs:814,970`) stay on the
  parsed hello; they are wire truth, not spec predicates.

Acceptance: every declared-profile predicate on the `connect` path is a
`const fn` bit test (no `extensions.iter().any/contains/position` or
equivalent); no code reads CAPS for a spec that has been mutated without
recomputing it; the CAPS/emitted-hello equality gate covers every profile; an
allocation row shows connects do not regress (they should drop).

### Change (ordered)

1. **Correctness gates first** (§4 A1-A4, A9-A11): advertised ⊆ verifiable
   schemes, ALPN validation, unsolicited/duplicate extension rejection,
   `close_notify`, KeyUpdate bound, offered-scheme check. These are cheap,
   local, and each gets a discriminating test.
2. **Baseline measurements** (B7): handshake connects/s and allocations/connect,
   relay MiB/s. No performance claim without them.
3. **Sans-I/O core, committed** (§9 Phase 1). Protocol logic must become a
   pure state machine (`feed(bytes) → events`, `poll_transmit() → bytes`,
   `poll_event() → Event`) with `TlsStream` reduced to an async adapter. This
   is the structural fix for the correctness and performance work above: a
   handshake that cannot touch a socket is deterministically testable against
   recorded flights, fuzzable without a runtime, and reusable by a second
   transport. It is not optional, and it lands before the performance work so
   that batching and resumption are written once.
4. **Hello caps + resumption + spec cache + record batching** (B8, B3, B2,
   B1), each behind a measured gate. B8 makes the *declared-profile* predicates
   O(1); B3 is opt-in because `pre_shared_key` changes the resumed hello's
   JA3/JA4 (the catalog deliberately excludes PSK-bearing rosters,
   `gen_specs.py:386,429-435,628`) and REALITY binds its sealed session id to
   the first hello.
5. **ALPS emission and h2 fingerprinting** (C1, C2) only if the production h2
   carriers need it; decide after measuring which surface the target CDNs
   actually inspect.

### Reject now

| Option | Why not |
|---|---|
| Rewrite on rustls with a shaped hello | rustls cannot emit our hello bytes; it would become a second lane, i.e. ferrox's problem, plus a `0x00ff` SCSV and suite-order divergence. |
| Vendor BoringSSL | C build + FFI + CVEs to gain CBC/static-RSA/ECH-server we do not need. |
| Swap primitives to purecrypto | API churn, no audit, `unsafe` SIMD; measured gain unproven and bounded by the record path, not the cipher. |
| kTLS | Needs `unsafe` syscalls; breaks `forbid(unsafe_code)`. Would only remove the one remaining read copy (B4), which is not the bottleneck. Revisit only as a separate opt-in crate. |
| Full rewrite "to be modern" | Re-earns 71-profile fidelity, REALITY, ECH and TLS 1.2 from zero with no measured gain. |
| Big-bang Sans-I/O rewrite in one change | The refactor is committed, but the handshake is 3 258 lines; land record → handshake → adapter separately behind a differential harness. |

---

## 9. Staged plan

### Phase 0 — correctness and baseline (no API change)

| Item | Change | Acceptance |
|---|---|---|
| A1 | Document the accept/fail boundary for P-521/PSS-only leaves; verification is a separate crypto-deps ADR | Roster test: every advertised scheme is classified verifiable or documented-unverifiable; no silent drift. |
| A2 | Pass offered ALPN into `parse_encrypted_extensions`; abort on mismatch | Test: server selects `h2` when only `http/1.1` was offered → typed error. |
| A3 | Track seen extension types; reject duplicates and unsolicited non-HRR extensions | Unit test over a crafted ServerHello. |
| A4 | `poll_shutdown` sends `close_notify` (with an abort path for tunnels) | Test: peer sees alert 0, not EOF; Vision/relay rows still green. |
| A9 | Cap consecutive `KeyUpdate`s per connection | Test: N+1 updates → typed error, no unbounded work. |
| A10 | Lower `MAX_FLIGHT_BUFFER` to a realistic bound (e.g. 512 KiB) | Test: oversized chain rejected at the bound. |
| A11 | Verify the CertificateVerify scheme was offered | Unit test. |
| B7 | Add handshake and relay-throughput benches | Baseline recorded before any structural change. |

Phase 0's tests become the differential harness for Phase 1: each fixed
behaviour gets a recorded transcript that the refactor must reproduce exactly.

### Phase 1 — Sans-I/O core (committed, not trigger-based)

Protocol logic moves into a pure, socket-free state machine; `TlsStream`
becomes a thin async adapter so every caller and the public API stay
unchanged.

```
trait Engine {
    fn feed(&mut self, bytes: &[u8]) -> Result<Consumed>;   // no I/O, no await
    fn poll_transmit(&mut self, out: &mut Vec<u8>) -> bool; // bytes to write
    fn poll_event(&mut self) -> Option<Event>;              // data/closed/alert
    fn state(&self) -> State;                               // handshaking/established/closed
}
```

Scope and sequencing (smallest reversible steps):

1. **Record layer first.** Extract `RecordCipher` + framing + KeyUpdate into
   `record::Engine` with a byte-in/byte-out interface. `TlsStream` keeps its
   buffers and drives it. Behavioural gate: every existing record/KeyUpdate
   test and the Vision direct-mode rows stay green, and the two hotpath rows
   still measure 0 allocations.
2. **Handshake next.** Move `drive`, the server-flight reader and the TLS 1.2
   flight into a `Handshake` state machine that consumes bytes and produces
   messages; the async driver only moves bytes and enforces deadlines. This
   removes the `AsyncRead`/`AsyncWrite` bounds from the protocol code and makes
   the flight parser directly fuzzable.
3. **Adapter last.** Re-implement `TlsStream` as `Engine` + `poll_read`/
   `poll_write`. Add a differential harness that drives the old and new engines
   over recorded handshake/record transcripts and asserts byte-identical
   output and event sequences before deleting the old path.
4. **Deadlines and cancellation stay in the adapter**: the engine reports
   `NeedsMoreData`, never sleeps; the caller's `timeout(SECURITY)` remains the
   single deadline (`crates/leas-native/src/security/mod.rs:113`).

Acceptance for the phase:

- Public API unchanged (`client::connect`, `TlsStream` traits,
  `reality::connect_reality`); all `leas-tls`, `leas-oracles` and hotpath rows
  green.
- The engine's sans-I/O modules contain no `tokio` imports and are exercised
  by tests that never build a reactor; one deterministic replay test covers
  each handshake branch: TLS 1.3, HRR, TLS 1.2, REALITY, ECH.
- A coverage-guided fuzz target feeds arbitrary bytes to `feed` and asserts
  no panic and a bounded state.
- No allocation regression: the hotpath rows and the memtrace boot profile are
  unchanged or better.

Risk: this is the largest single change in the plan (the handshake module is
3 258 lines). Mitigate with the differential harness and by landing the three
steps separately; do not combine it with the Phase 2 performance changes.

### Phase 2 — speed, measured

Runs after Phase 1, so batched sealing and resumption are written once against
the steady-state engine rather than twice.

| Item | Change | Acceptance |
|---|---|---|
| B8 | `HelloCaps` const sidecar + static profile tables (§8) | Declared-profile predicates are O(1); CAPS/emitted-hello equality gate; mutated specs never read stale CAPS; connect allocations drop. |
| B2 | Cache resolved specs by identity (or make them static per B8) | Allocations/connect before/after; roster gate unchanged. |
| B1 | Batch seals (≤32 KiB or ≤7 records) into one write | Syscalls per 64 KiB ≤ 2; latency test for a lone small write. |
| B3 | Ticket cache + resumed-hello policy (opt-in) | Resumed connect skipped a full flight; JA4 gate for the resumed shape; cache bounded; REALITY rows excluded. |

### Phase 3 — fidelity

| Item | Change | Acceptance |
|---|---|---|
| C1 | Emit ALPS EncryptedExtensions after Finished for profiles that offer it | Live grader shows the same ALPS presence as the reference browser; no profile without the extension emits it. |
| C2 | Browser-shaped h2 SETTINGS/priority/pseudo-header order in the production carrier | h2 fingerprint matches the TLS identity on a live target. |

---

## 10. When a rewrite would actually be justified

Any one of these, measured — not asserted:

1. The engine must ingest browser captures automatically (capture→spec), which
   the current typed-spec + generated-profile flow cannot express without a
   parser and a profile-compiler, and the Sans-I/O core's message parser cannot
   be reused for it.
2. After Phases 0-2, a reference implementation beats leas by >2× on the real
   workload (connect + first byte, or relay MiB/s) with the same roster.
3. `forbid(unsafe_code)` or ring becomes untenable for a required platform
   capability, forcing a crypto-stack change anyway.
4. The Sans-I/O refactor exposes a state-machine defect class that cannot be
   fixed incrementally (e.g. the transcript/state model is wrong rather than
   the I/O coupling).

A second transport needing the same core is **not** a rewrite trigger: the
Sans-I/O split is already committed in Phase 1, so QUIC/DTLS/kTLS can consume
the same engine without a new implementation.

Absent one of those, a rewrite trades working fidelity and a clean trust story
for re-implementation risk.

---

## 11. Evidence index

leas:

- `crates/leas-tls/src/{lib,client,spec,hello,ech}.rs`, `src/verify/mod.rs`,
  `src/handshake/{mod,flight,tls12}.rs`, `src/record/{mod,stream}.rs`,
  `src/crypto/{mod,tls12}.rs`, `src/reality/verify.rs`,
  `src/fingerprints/resolve.rs`, `src/profiles/generated/chrome.rs`,
  `src/http2_profile.rs`, `src/http2/mod.rs`, `benches/record.rs`, `tests/`.
- `crates/leas-native/src/{security/mod.rs,transport/http/conn.rs,headers.rs,probe.rs}`.
- `crates/leas-hotpath/src/main.rs:155,177`.
- `docs/reference/tls-fingerprint-roster.md`,
  `docs/research/2026-11-23-ferrox-comparison.md`,
  `docs/research/2026-11-13-allocation-profile.md`.

References:

- utls: `u_common.go:182`, `u_conn.go:601`, `u_parrots.go:3022`,
  `u_handshake_client.go:165`, `u_clone.go`, `CONTRIBUTORS_GUIDE.md`.
- geektls: `core/tls/{compile,client,fingerprint,check}.go`,
  `core/profiles/{profile,entries,registry}.go`, `core/h2/h2.go`,
  `core/h3/h3.go`, `docs/07-capability-gaps.md`.
- curl-impersonate: `patches/curl.patch` (preset table, setopt mapping),
  `patches/boringssl.patch` (extension order/permutation/key shares/record
  limit), `tests/test_impersonate.py`.
- purecrypto: `src/cipher/{mod,gcm,aes,aesni,wide_x86}.rs`,
  `src/tls/{mod,connection,config}.rs`, `docs/benchmarks.md`, `SECURITY.md`.
- ferrox: `crates/ferrox-core/src/tls/{mod,rustls_backend,legacy,reality,ech,hpkt}.rs`,
  `tls/shaped/{mod,hello,client,record}.rs`, `docs/function/security-utls.md`.
- `rustls-webpki-0.103.17/src/{ring_algs,aws_lc_rs_algs}.rs` (signature scheme
  coverage).

Benchmark caveat: single host, `--quick`, 16 MiB per row, includes the duplex
copy; use it for regression direction, not as an absolute network figure.
