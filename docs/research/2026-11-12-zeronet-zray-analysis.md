# ZeroNet / Zray-core — protocol and performance audit

**Date: 2026-11-12.**
**Subject: `thirdparty/ZeroNet` @ `29e7a95eaaf7e0158b96cba83d7118f5f3d87bfd` (tag `v0.3.6`, commit date 2026-10-14), shallow clone of `https://github.com/zeghostwriter/ZeroNet.git`.**

**Status: source audit.** Nothing was built or run. Every claim below is read from
the clone's source, its own `docs/`, or its committed benchmark artifacts. The
performance numbers in section 5 are the project's own measurements and are
quoted as such, not reproduced.

## 1. What the project is

Zray is a from-scratch Rust networking core, MIT licensed, with a TUI/desktop
front end (ZeroNet) and an Android host. It speaks Xray's JSON config directly
and implements both client and server sides. Workspace: 22 crates
(`zero-core`, `zero-config`, `zero-net`, `zero-dns`, `zero-router`,
`zero-security`, `zero-transport`, `zero-protocol`, `zero-runtime`,
`zero-evasion`, `zero-observatory`, `zero-tun`, `zero-scanner`,
`zero-discovery`, `zero-tor`, `zero-masterdns`, `zero-provision`,
`zray-cli`, `zray-mobile`, `zeronet-tui`, plus two benchmark members).

The most consequential structural decision: **ordinary TLS runs on a vendored
fork of rustls; REALITY runs on a hand-written TLS 1.3 record and handshake
stack** (`crates/zero-security/src/tls13/`, 4,978 lines including a client and
a server). The fork exists only to shape the ClientHello
(`vendor/rustls/PATCHES.md`): extension order, GREASE and padding are not
expressible through rustls' public API. Two local patches on top of it: a
`legacy_version` field override, and answering ALPS so BoringSSL servers do not
kill the connection.

Each crate carries a `PROVENANCE.md` stating what is original and what was
reimplemented from a public contract. `zero-protocol/PROVENANCE.md` names Xray
documentation and a pinned oracle as behavioural references and states that no
upstream source file is copied.

## 2. Protocol implementation details worth knowing

### VLESS

- Request layout is `version, uuid[16], addons_len, addons, cmd, port BE,
  atyp, addr` — **port before address**, the opposite order from Trojan and
  SOCKS (`zero-protocol/src/vless.rs:224-246`).
- `CMD_MUX` and `CMD_RVS` (reverse) carry **no** port or address; the target
  lives in the first mux frame (`vless.rs:265-276`).
- The response header is parsed **lazily** and never blocks the stream: a
  client that waits for the response header before writing deadlocks
  Cloudflare-Worker-hosted servers that wait for the first payload
  (`vless.rs:493-527`). Bytes arriving together with the header are kept in a
  spill buffer, not dropped (`vless.rs:586-588`).

### First-flight coalescing

A shared wrapper holds the protocol request header until the application's
first write, then emits both as one write: one TLS record, one packet, no
small recognisable opener (`zero-protocol/src/first_flight.rs:1-40`). Because
some protocols are server-first (SSH, SMTP), the first read starts a 100 ms
timer after which the header leaves alone; server responses hold the header
indefinitely (`first_flight.rs:70-76`).

### Vision (`xtls-rprx-vision`)

- First frame per direction carries the 16-byte UUID; frames are
  `cmd, content_len u16 BE, padding_len u16 BE, content, padding`
  (`vision.rs:380-397`).
- Padding seed `[900, 500, 900, 256]`: while the inner stream still looks like
  a TLS handshake and content is under 900 bytes, pad to 900 plus a random
  amount below 500; otherwise pad below 256 (`vision.rs:571-587`).
- State machine latches `inner_looks_tls` on bytes `16 03 xx .. .. 01`, and
  ends padding on a write that is entirely complete `17 03 03` application-data
  records, or after 8 writes that never looked TLS (`vision.rs:239-247`).
- Padding bytes are zero; the outer TLS/REALITY layer encrypts them, so only
  length is observable (`vision.rs:596-600`).
- **This implementation emits `PaddingEnd` only, never `PaddingDirect`**
  (`vision.rs:23-29`). Direct splicing would require handing an
  already-record-aligned raw TCP socket back out of the TLS layer.

### Mux (mux.cool)

- Frame: `u16 metadata_len, session_id u16 BE, status, option, [target],
  [u16 data_len, data]`; metadata capped at 512 bytes (`mux.rs:35-51`).
- Padding is **step-shaped, not random**: the first three data frames of each
  session whose write is under 1024 bytes are rounded up to the next multiple
  of 640 plus a random amount under 128, by appending a real data frame of
  filler on the same write. The source comment states the reasoning: random
  padding averages away, a step does not (`mux.rs:14-20`).

### REALITY client

- The authentication tag is sealed with **AES-256-GCM**, not HMAC: nonce is
  `client_random[20..32]`, AAD is the ClientHello with the session-id field
  still zeroed, and the 16-byte plaintext is
  `reported_version[3], 0x00, unix_secs u32 BE, short_id[8]`
  (`zero-security/src/reality.rs:144-180`). The 32-byte result occupies
  `legacy_session_id`.
- `AuthKey = HKDF-SHA256(ikm = X25519(ephemeral, server_static),
  salt = client_random[0..20], info = "REALITY")`, derived from the **same**
  ephemeral key as the TLS key share (`reality.rs:134-141`).
- The certificate check is not a CA chain: the leaf must have a 32-byte SPKI
  key and a 64-byte signature field, and validity is
  `HMAC-SHA512(AuthKey, spki_key)` compared in constant time
  (`reality.rs:192-228`). An optional ML-DSA-65 extension adds a second check
  over `spki || client_hello || server_hello` (`reality.rs:230-256`).
- Any mismatch is classified `RealityFallback` and **must abort** — continuing
  would send proxy traffic into the decoy connection (`reality.rs:10-13`).
- The hybrid `X25519MLKEM768` share is offered first by default because
  current REALITY servers refuse a hello without it, and refuse it by relaying
  to the decoy site rather than by erroring (`reality.rs:47-53`).

### VMess, Shadowsocks, Trojan, AnyTLS

- VMess AEAD key ladder and header layout are documented in the crate's
  module comments; the transferable trap is that the per-chunk draw order is
  protocol: **padding length first, then the SHAKE128 mask**, per chunk. A
  reversed order desyncs the stream permanently (`vmess.rs:495-533`).
- Shadowsocks legacy AEAD uses a 12-byte **little-endian** nonce counter; a
  big-endian implementation agrees at zero, which is why the bug survived
  (`shadowsocks.rs:120-132`).
- Trojan uses SOCKS5 address-type codes with the address before the port, and
  the password is the 56-byte **hex text** of sha224 (`trojan.rs:1-20`).
- AnyTLS prologue is `SHA256(password), padding_len u16 BE, padding`; this
  client always sends a zero padding length, and its server-side comparison of
  the password hash uses `==` on raw bytes rather than a constant-time compare
  (`anytls.rs:155-226`). That is a flaw, recorded in section 6.

### XHTTP, gRPC, Hysteria2, TUIC, AmneziaWG, MasterDNS

- XHTTP: one persistent chunked POST for stream-one; split modes pair a GET and
  a POST by a session id in the path. The download leg **must** be answered
  before the first packet POST or the POSTs overtake the GET and the session
  dies silently (`xhttp.rs:154-162`). Packet-up reordering is a
  `BTreeMap<u64, payload>` bounded at 30 buffered posts. Padding is protocol,
  not decoration: the server answers 400 without it, and the placement of
  session id, sequence and payload is independently switchable across path,
  query, header, cookie and body (`xhttp_request.rs:619-745`).
- XHTTP over HTTP/2 sets a 4 MiB stream and connection window so one logical
  flow cannot consume the default 65,535-byte connection credit
  (`xhttp.rs:34-37`).
- gRPC: 5-byte envelope plus `Hunk{bytes data = 1}`; no sequence layer at all,
  ordering is HTTP/2's; several tunnels share one connection, one stream each
  (`grpc.rs:3-6,68-118`).
- Hysteria2: HTTP/3 authentication, success is status **233**; TCP negotiation
  is `varint 0x401, len, authority, varint padlen, padding`
  (`hysteria2.rs:305-353,514-540`).
- TUIC v5: authentication on a **unidirectional** stream with
  `export_keying_material(uuid, password)` (`tuic.rs:78-96`).
- AmneziaWG: receive scans each candidate `S`-byte prefix and overwrites the
  obfuscated type word with the real one **in place**, returning an offset
  rather than copying (`amnezia.rs:263-300`); unmatched datagrams return
  `Ok(None)` and are never fed to the tunnel engine.
- MasterDNS: payload encoded to base36 text and chopped into `≤63`-byte DNS
  labels, with every 7-byte group mapping to exactly 11 characters
  (`codec.rs:96-190`). Method 2 (ChaCha20, unauthenticated upstream) is
  deliberately unimplemented and returns an error rather than downgrade.

## 3. Memory and CPU mechanisms

| Mechanism | What it does | Where |
| --- | --- | --- |
| Glibc tuning at startup | `M_MMAP_THRESHOLD=64 KiB`, `M_ARENA_MAX=1`. Measured: 300 TUN connections repeated six times climbed 37 → 136 MB with defaults, level at ~87 MB with one arena, for ~10% aggregate throughput at 2.9 Gbit/s | `zero-runtime/src/lib.rs:34-57` |
| Adaptive relay buffers | start at 16 KiB, promote a direction to 64 KiB only when a 16 KiB read fills completely. 128 KiB bought no measurable throughput and doubled per-busy-connection cost | `zero-runtime/src/relay.rs:20-33,290-304` |
| Bounded buffer pool | 256 × 16 KiB plus 32 × 64 KiB recycled on connection close (4 MiB + 2 MiB ceiling) | `relay.rs:96-118` |
| Custom bidirectional copy | no `tokio::io::split`, no `tokio::sync::Mutex`; one contiguous buffer per direction | `relay.rs:402-410` |
| Framed-protocol read-ahead | one reusable `ReadBuffer` per stream, parser decrypts in place, so one read yields several frames and steady state allocates nothing | `zero-protocol/src/io_util.rs:1-13` |
| Vision zero-copy delivery | frame content is a `split_to` slice of the read buffer rather than a fresh `Vec`: one copy per downloaded byte instead of two, one allocation per frame fewer | `vision.rs:7-11` |
| Padding RNG | thread-local `thread_rng` instead of `OsRng`, removing one `getrandom` syscall per padded frame | `vision.rs:570-576` |
| Mux read path | `reserve` then `read_buf` straight into the payload's spare capacity — no 16 KiB memset per chunk, no scratch buffer, no copy | `mux.rs:1070-1080` |
| Per-thread UDP scratch | one 65,535-byte scratch per thread instead of 64 KiB per idle flow | `zero-runtime/src/server.rs:7153-7196` |
| TUN windows | 64 KiB per direction per connection against the library's ~1.3 MB default; the hop is a few hundred microseconds, so the window is not the bottleneck | `zero-tun/src/lib.rs:1532-1556` |
| Vendored netstack patches | no socket per retransmitted SYN; orphan reclaim after 30 s; `MAX_LIVE_SOCKETS = 512` with a RST past the cap; handshake slots returned after 120 s; staging rings halved | `vendor/netstack-smoltcp/PATCHES.md` |
| Socket options | `TCP_USER_TIMEOUT`, `TCP_NODELAY`, `TCP_QUICKACK` on dial and accept; `TCP_MAXSEG` policy that descends from 1360 to 1220 after three stalled handshakes with no success between | `zero-net/src/dial.rs:251-259`, `zero-core/src/path_mss.rs` |
| Release profile | `opt-level = "s"`, fat LTO, `codegen-units = 1`, `panic = "abort"`, stripped; measured the same speed as `-O3` within noise at about a third less size. Only the packet stack is `-O3` | `Cargo.toml:131-148` |
| Mobile profile | panics unwind so every JNI entry point can catch them; runtime clamped to 1–3 workers because "more workers only cost battery"; `-Wl,--icf=all` | `Cargo.toml:150-170`, `zray-mobile/src/lib.rs:313-323` |
| Router matchers | two hash sets, one Aho-Corasick automaton for keywords, and `Vec<Regex>` rather than `RegexSet`, because `RegexSet`'s size limit applies to the whole set and fails in aggregate on large rule lists | `zero-router/src/matcher.rs:1-7,369-423` |
| Compile-time selection | balancer selector prefixes expanded once at config compile time, so no string walk per session; `ArcSwap<ServerState>` for reloads | `zero-config/src/model.rs:3429`, `server.rs:648` |

## 4. Measurement gates

Two benchmark workspace members exist so they resolve the shipped dependency
versions and inherit the shipped release profile.

- `bench/hotpath` installs a **counting global allocator** and gates on
  allocation counts, not wall clock: "a duration on a shared runner is a
  distribution, an allocation count is a fact"
  (`bench/hotpath/src/main.rs:18-22`). Zero-filled allocations are counted
  separately, so a needless memset is visible even when the allocation count
  is unchanged (`alloc_count.rs:20-30`). Gated rows: mux and Vision byte
  identity against the code they replaced, and an allocation ceiling per read.
- `bench/shape` replays one scripted page load through each real framing,
  turns the writes into packets, and gates the features the USENIX Security
  2024 encapsulated-handshake classifier uses: size bins, bursts, the first
  burst after the outer handshake, and the number of round trips after it.
  CI runs both as separate jobs, with the stated rationale that allocation
  counts are machine-independent while timings are not.

## 5. The project's own benchmark claims

Reproduced from `docs/benchmarks/README.md` and `results.json`; 4 vCPU Xeon,
15 GB, loopback, Xray-core v26.3.27 server for both clients, medians of three
runs, 2 GB per test.

| Metric | Xray-core | Zray |
| --- | ---: | ---: |
| TLS, 1 stream down | 349 MB/s | **532 MB/s** |
| TLS, 8 streams down | 826 MB/s | **911 MB/s** |
| TLS, 64 streams down | 758 MB/s | **828 MB/s** |
| TLS, 1 stream up | 342 MB/s | **353 MB/s** |
| TLS CPU per GB | 3.01 s | **1.62 s** |
| Plain TCP, 1 stream down | **873 MB/s** | 799 MB/s |
| Plain TCP, 8 streams down | 1239 MB/s | **1345 MB/s** |
| Plain TCP, 64 streams down | 1085 MB/s | **1344 MB/s** |
| Idle RSS | 29.3 MB | **8.0 MB** |
| Peak RSS (TLS run) | 51.5 MB | **21.1 MB** |

Two readings that the project does not spell out:

1. Idle RSS is sampled **1.5 s after start, before any traffic**
   (`docs/benchmarks/harness/run.py:12-13`), and the value is identical in the
   plain and TLS runs (8.004 vs 8.027 MB). The gap is therefore a fixed
   process baseline — no Go runtime and GC, plus a stripped fat-LTO image
   (inference; the repository never attributes it) — not the buffer
   architecture. The buffer work is what explains the **peak** win.
2. The one loss, plain TCP single-stream download, is where the 16→64 KiB
   adaptive relay and the absence of vectored writes or `splice` plausibly
   cost throughput.

## 6. Flaws observed

- The TUN bridge allocates a `Vec` per inbound packet
  (`zero-tun/src/lib.rs:1599`) — the one remaining packet-hot-path allocation.
- `VlessStream::poll_read` copies through an 8 KiB stack scratch rather than
  reading into the caller's buffer (`vless.rs:558-560`).
- AnyTLS password comparison is not constant time (`anytls.rs:220-226`).
- No `splice`/`MSG_ZEROCOPY`; the TCP relay does not use vectored writes.
- `PaddingDirect` is not emitted, so Vision never gets Xray's direct-splice
  fast path.

## 7. What leas can take

Ranked by value against leas' code **at audit time (2026-11-12, before the plans this
report seeded)**. Each candidate that survived has an Aegis spec; the rows marked
"adopted" were implemented the same day and the specs record the after-state. The rest
are recorded as rejected so they are not re-proposed.

| Candidate | leas state today | Verdict |
| --- | --- | --- |
| Adaptive relay buffers 16 → 64 KiB plus a bounded pool | `RELAY_BUF = 16 * 1024`, one fresh `vec![0u8; n]` per direction, no promotion, no pool (`leas-native/src/inbound/outbound.rs:168,235`) | **adopt** — spec `2026-11-12-relay-buffer-escalation-design.md` |
| Withhold the protocol header until the first payload write | VLESS, Trojan and VMess each `write_all` the header as its own write (`vless/mod.rs:105,126,317,410,466`, `trojan/mod.rs:92,545`, `vmess/mod.rs:88,104`) | **adopt** — spec `2026-11-12-first-flight-coalescing-design.md` |
| Path-MTU descent (`TCP_MAXSEG`) for ICMP-blackholed paths | no `TCP_MAXSEG` anywhere; `sockopt.rs` exposes only `TCP_USER_TIMEOUT`, keepalive, `SO_REUSEPORT` | **adopt** — spec `2026-11-12-path-mtu-descent-design.md` |
| Allocation-count gate in a bench binary | impossible inside the `leas` binary: it owns the process-wide mimalloc `#[global_allocator]` (`src/alloc.rs:33`), and the existing cost lab records that a second one is a compile error (`src/ops/ping/flow_cost.rs:14-20`) | **adopted 2026-11-12** — `crates/leas-hotpath`, five rows; on its first run it found a real second allocation per VLESS/VMess connect (`encode_addr`), now fixed |
| Traffic-shape gate (packet-size classifier features) | `leas-oracles` drives real cores for byte fidelity; nothing gates packet size or direction | **candidate, deferred** — named as a non-goal in the allocation gate spec; it needs a framing harness first |
| `mallopt(M_ARENA_MAX, 1)` | not applicable: leas uses mimalloc, already tuned in `src/alloc.rs` | **rejected** — glibc-only; the transferable lesson (cap arenas, return freed memory) is already owned by `2026-11-10-memory-reduction-design.md` |
| Replace `RegexSet` with `Vec<Regex>` | `leas-route` uses `RegexSet` (`leas-route/src/matchers.rs:47,87`) | **rejected** — ZeroNet's reason is aggregate failure on very large regex lists; leas compiles small per-ruleset lists, and `RegexSet` is one DFA pass instead of N. Revisit only if a real ruleset exceeds the set-size limit |
| Vendored netstack buffer/limits patches | leas has no userspace IP stack | **rejected** — not applicable |
| Clamp tokio workers on mobile | leas is a desktop TUI; the desktop default (one worker per core) is already the right shape | **rejected** — not applicable |
| `opt-level = "s"` release profile | leas builds `release` with its own profile | **rejected for now** — not measured on this codebase; would need an A/B on the relay path, and size is not a stated constraint here |

## 8. Limitations of this audit

- No build, no test run, no benchmark reproduction. Every performance figure
  above is the project's own, single-machine and loopback.
- `zero-runtime/src/server.rs` (357 KB) and `outbound.rs` (142 KB) were sampled,
  not read end to end; conclusions about them are drawn from the modules they
  are composed of.
- Permission and licensing were checked only at the file header level: the
  workspace is MIT, the vendored rustls fork is MPL-2.0 for its own files.
- Adoption verdicts assume leas' current inbound/relay shape as read on
  2026-11-12; a change to that shape invalidates the ranking, not the audit.
