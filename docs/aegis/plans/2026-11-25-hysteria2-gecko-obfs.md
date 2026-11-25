# Hysteria2 Gecko obfuscation and Salamander cleanup — implementation

## Goal

Close the Gecko gap found in `docs/research/2026-11-23-ferrox-comparison.md:38`:
a `hysteria2://…?obfs=gecko&obfs-password=…` row is parsed, stored, marked
dialable and then dialed as Salamander-only, so the handshake is dropped by a
Gecko server (its receive path reads the unfragmented QUIC long header as a
Gecko frame, `totalChunks` = 0, frame invalid, silent drop). Outcome:

1. Gecko rows dial: frames, padding and reassembly per the wire shared by
   hysteria, sing-box 1.14+ and mihomo 1.19+.
2. Undialable obfs shapes are refused at ingestion and retire once from an
   existing DB, instead of failing as a timeout.
3. `hy2://` links round-trip custom Gecko sizes using v2rayN's de facto
   `minPacketSize`/`maxPacketSize` params; defaults are elided.
4. The Salamander receive path sheds its scratch copy; the SIMD engine changes
   only if a measured bench clears the bar.

## Architecture / ownership

| Concern | Owner |
| --- | --- |
| Typed obfs shape + normalization | `leas_proto::proto_spec::hysteria2` (`Hysteria2Config::obfs_spec`) |
| "Is this shape undialable" | `leas_proto::proto_spec::is_undialable_shape` + `leas-config::import_export` ingest |
| Connect-time verdict | `leas_native::capability::hysteria2_reason` |
| Stored-row verdict | `leas-db::database::purge_invalid_shapes_once` (marker v3) |
| Gecko frame codec + reassembly (sans-io) | new `leas-native/src/crypto/gecko.rs` |
| Socket adapters | `leas-native/src/protocol/hysteria2/quic.rs` |
| Link round-trip | `Hysteria2Config::{try_parse_proto,reconstruct_proto}` |
| Corers | `inject_singbox` (gecko sizes), `ClashHysteria2` (kebab keys + sizes) |
| Oracle coverage | `leas-oracles` hysteria2 case/config builders |

No new crate. No DDL: the DB step is the existing `app_meta.invalid_shapes_purged`
DATA step, version 2 → 3.

## Tech stack

Rust 2024, quinn 0.11 `AsyncUdpSocket`, `wide` 1.7 (existing) as the Salamander
XOR engine, `blake2` (existing). `macerator 0.6.0` is a **dev-dependency of the
bench only** until T0 clears the gate; MSRV 1.94 is satisfied (stable 1.100).

## Baseline / authority refs

Requirements basis: the 2026-11-25 grilling ledger, locked by the user before
this plan (Option A config, Option A layering, S1 sans-io, Z1 allocation
contract, P1 gates, L2 link params with default elision, S1 size repair, T1
bench gate); each decision is restated in Compatibility boundary/Tasks below.

- sing-box (requested reference): `thirdparty/sing-box/constant/hysteria2.go`,
  `option/hysteria2.go` (`Hysteria2ObfsGecko`, `obfs.type salamander|gecko`),
  `protocol/hysteria2/outbound.go:62-76,141-143`,
  `docs/configuration/outbound/hysteria2.md` §obfs (defaults 512/1200).
- Wire: `thirdparty/hysteria/extras/obfs/gecko.go` (send/recv, reassembly caps
  and 8 s TTL), `gecko_frame.go` (5-byte header, 2..8 chunks), `gecko_test.go`,
  `gecko_frame_test.go` (golden vectors). Corroborated byte-for-byte by
  `thirdparty/Xray-core/transport/internet/finalmask/salamander/gecko.go`.
- Link params: `thirdparty/v2rayN/…/Hysteria2Fmt.cs:191-211,240-250`
  (`minPacketSize`/`maxPacketSize`, camelCase, gecko only; its own comment
  admits the params are unofficial).
- mihomo server/client support: `thirdparty/mihomo/adapter/outbound/hysteria2.go`
  (`obfs-min-packet-size`/`obfs-max-packet-size`), `listener/inbound/hysteria2.go`.
- Repo rules: `AGENTS.md` (hysteria2 identity/gate rules, QUIC endpoint note,
  ingest gate ADR 0018 D-C, no raw `sqlite3`), `docs/reference/protocols.md`,
  `docs/reference/clash.md`.
- In-tree gap record: `docs/research/2026-11-23-ferrox-comparison.md:38`.

## Compatibility boundary

- Wire: Gecko = frame → pad → Salamander, 2..8 chunks, 5-byte header
  `0x80 | msgID | chunkIdx<<4|totalChunks | padLen BE16`, salted datagram size
  in `[min,max]`, defaults 512/1200, max 2048. Short headers pass through.
- Links: `obfs=gecko` unchanged; `minPacketSize`/`maxPacketSize` are emitted
  only for gecko and only when the normalized value differs from the default;
  absent = defaults; other params untouched. Other cores ignore unknown keys.
- Stored JSON: two new optional fields; old rows decode unchanged.
- Identity: new tags 0x53/0x54, written only for gecko with a non-default
  normalized value, so every existing sig and default-size gecko sig is
  unchanged. Credentials and all other fields keep their bytes.
- Ingest: unknown obfs name and cert-less `obfs` password cases refuse; invalid
  sizes are repaired (never refused); `salamander` tolerates size fields and
  keeps them out of identity/export.
- DB: marker v3 marks only shapes `is_undialable_shape` reports; rows stay in
  place (Purgatory semantics unchanged).
- Clash: correct `ClashHysteria2` kebab keys (`obfs-password`,
  `skip-cert-verify`, `hop-interval`) plus the two new size keys. This is a
  required repair: the current snake_case spelling means a mihomo YAML's
  `obfs-password` is silently ignored on import and lost on export.

## TDD Route

- Mode: `auto` (no explicit user TDD request).
- Decision: **strict** for T1–T6 (wire codec, config contract, persistence
  verdict, adapter behaviour); **skipped** for T0 (measurement) and T7 docs;
  T8 verification runs the full suites.
- Authority: Aegis auto rule — protocol/wire, contract and persistence change.
- Posture: failing test first for every behaviour in T1–T6, then implement.

## Change Necessity

No config/docs-only path can make a Gecko row dial: the transform is a wire
protocol (framing + reassembly) and the dial dispatches on the obfs type it
currently ignores. Minimum code boundary: one resolver in `leas-proto`, one
sans-io codec + one socket adapter in `leas-native`, one ingest predicate arm,
one marker bump, plus exporters/forms/oracle touched by the same field.

## Ripple Signal Triage

- Canonical owner for "what obfs shape is this": `Hysteria2Config::obfs_spec`;
  capability, dial, identity, exporters and forms all consume it (net effect:
  one rule, five consumers).
- Producer/consumer: link parse/reconstruct, Clash import/export, sing-box
  inject, identity, DB stored rows.
- Persistence: `invalid_shapes_purged` v3 (DATA step, no cursor bump).
- Retirement: none; the old `obfs_password`-only dial path is replaced, not
  kept as a fallback.

## Plan Pressure Test

- Owner fit: the transform belongs in `crypto/` beside `salamander`; quinn
  adaptation stays in the protocol module (same split as today).
- Contract fit: flat fields preserve stored JSON; the resolver keeps one truth.
- Verification: golden vectors (offline), fake-socket adapter tests, sing-box
  oracle row, criterion bench. No harness expansion for large payloads — Gecko
  only reshapes long headers; short-header data is the existing Salamander
  path and is covered by the current oracle row plus a pass-through unit test.
- Executability: every task names files and commands; the macerator branch is
  gated on a recorded number, not a judgement call.

## Tasks

### T0 — bench harness and the macerator gate (measurement)

Files: `crates/leas-native/benches/hysteria2_obfs.rs`,
`crates/leas-native/Cargo.toml` (`[[bench]] name = "hysteria2_obfs",
harness = false`; dev-dep `macerator = { version = "0.6.0",
default-features = false, features = ["std"] }`).

- Bench groups: Salamander `obfuscate_into` and `deobfuscate_in_place` at 64,
  1200, 1500 B; the XOR slice alone under `wide` and under a bench-local
  `macerator` engine; Gecko frame encoding at 2/4/8 chunks.
- Decision rule: the XOR slice must be a large enough share of the whole
  transform that halving it moves `obfuscate_into` by ≥15% at 1200 B with no
  64 B regression (a slice under ~30% cannot clear the gate with any XOR
  engine). If it passes, T9 implements and re-measures; if not, the dev-dep is
  removed and `wide` stays.
- Run `cargo bench -p leas-native --bench hysteria2_obfs` and record the table in
  the Outcome section.

### T1 — typed obfs resolver, link params, exporters (RED → GREEN)

Files: `crates/leas-proto/src/proto_spec/hysteria2.rs`,
`crates/leas-proto/src/clash/mod.rs`, tests beside them.

- `Hysteria2Config` gains
  `obfs_min_packet_size: Option<u16>`, `obfs_max_packet_size: Option<u16>`
  (serde default; stored JSON stays readable).
- `pub enum ObfsSpec<'a> { None, Salamander { psk: &'a [u8] }, Gecko { psk: &'a [u8], min: u16, max: u16 } }`
  and `pub fn obfs_spec(&self) -> Result<ObfsSpec<'_>, ObfsShapeError>`;
  `ObfsShapeError` carries one static message per shape: unknown name,
  missing password. Normalization: gecko absent/invalid sizes → 512/1200;
  `salamander` ignores size fields; name match is exact lowercase.
- `try_parse_proto`: read `minPacketSize`/`maxPacketSize` only when
  `obfs=gecko`; keep them out of a salamander config.
- `reconstruct_proto`: emit the two camelCase params only when gecko and the
  normalized value differs from its default.
- `inject_singbox`: add `min_packet_size`/`max_packet_size` to the obfs object
  under the same elision rule.
- `ClashHysteria2`: add `obfs_min_packet_size`/`obfs_max_packet_size` with
  `#[serde(rename = "obfs-min-packet-size"/"obfs-max-packet-size")]`, and
  correct the existing multiword keys to kebab (`obfs-password`,
  `skip-cert-verify`, `hop-interval`); map both directions in
  `to_clash_proto`/`try_from_clash_proto`.
- Identity: add `ID_GECKO_MIN = 0x53`, `ID_GECKO_MAX = 0x54`; write the
  normalized pair (default 512/1200) only for gecko.
- Tests: parse→reconstruct round-trip with custom and default sizes (defaults
  elided); invalid sizes normalize; salamander with sizes stays salamander and
  exports no size keys; v2rayN-shaped link imports sizes; Clash import reads
  `obfs-password` + size keys and export emits kebab keys; identity sig equal
  for absent/default sizes and different for a custom pair.

### T2 — ingestion and connect gates (RED → GREEN)

Files: `crates/leas-proto/src/proto_spec/mod.rs`,
`crates/leas-config/src/import_export.rs`,
`crates/leas-native/src/capability.rs`,
`crates/leas-db/src/database.rs`.

- `is_undialable_shape`: Hysteria2 arm = `obfs_spec().is_err()` (unknown name /
  missing password). Invalid sizes never reach it (normalized).
- Ingest: call the predicate where the other undialable shapes are refused
  (`validate_required_fields`/`parse` boundary) so the import error names the
  hysteria2 shape instead of importing a dead row.
- `hysteria2_reason`: return the resolver's static reason; gecko with valid
  credentials stays supported.
- DB: `SHAPE_MARKER_VERSION = 3`; extend the existing purge test with one
  unknown-obfs row (retired) and one gecko row (survives), marker seeded at 2.
- Tests: import tables (unknown name refused, missing password refused,
  gecko+password accepted, salamander+sizes accepted), capability table, DB
  marker v2→v3.

### T3 — sans-io Gecko frame codec (RED → GREEN)

Files: new `crates/leas-native/src/crypto/gecko.rs`,
`crates/leas-native/src/crypto/mod.rs`.

- Constants: `FRAME_HEADER_LEN = 5`, `FLAG_FRAGMENT = 0x80`,
  `MIN_CHUNKS = 2`, `MAX_CHUNKS = 8`, `MAX_PACKET = 2048`,
  `DEFAULT_MIN/MAX = 512/1200`.
- `FrameHeader { pad_len: u16, msg_id: u8, chunk_idx: u8, total_chunks: u8 }`.
- `encode_frame_into(h, payload, out, fill_pad: impl FnOnce(&mut [u8])) -> Result<usize, FrameError>`
  (header, random padding via the callback, payload; validates chunk bounds and
  buffer length).
- `decode_frame(&[u8]) -> Result<(FrameHeader, &[u8]), FrameError>` (zero-copy
  payload slice; the same rejections as upstream).
- `plan_fragments(len, chunks) -> impl Iterator`/pair helper and
  `pad_len(chunk_len, min, max) -> u16` (`base = 8 + 5 + chunk_len`; `0` when
  `base > max`; else uniform in `[max(min,base), max]`); chunk split is
  `len/chunks`, last chunk takes the remainder.
- No `quinn`, no clock, no socket types in this file.
- Tests mirror `gecko_frame_test.go`: the full encode/decode table (total 2..8,
  every idx, pad 0/1/64/127/512/1100, header equality, payload equality),
  invalid encode cases, short buffer, decode rejections (`empty`, truncated,
  marker clear, total 0/1/9, idx == total, pad overrun), pad-length bounds.

### T4 — sans-io reassembler (RED → GREEN)

Files: `crates/leas-native/src/crypto/gecko.rs`.

- `GeckoReassembler` with bounded on-demand slots (Z1): at most
  `MAX_IN_FLIGHT = 8` messages (upstream's per-source cap), each up to
  `MAX_CHUNKS`, chunk storage reused through a free list; slots released on
  completion, TTL expiry, or capacity eviction.
- `push(&mut self, peer: SocketAddr, h: FrameHeader, payload: &[u8], now: Instant, out: &mut [u8]) -> Push`
  where `Push::{Complete(usize), Buffered, Dropped}`; key = `(peer, msg_id)`;
  duplicate chunk, inconsistent `total_chunks`, out-of-range index, oversized
  chunk (> `MAX_PACKET`) drop that datagram; expired entries are swept on push
  and evicted oldest-first at capacity.
- Allocation policy: each slot's chunk `Vec` is allocated on first use and
  reused; steady-state pushes must not allocate once the slot set has warmed.
- Tests: in-order and out-of-order completion, interleaved msgIDs, duplicate,
  missing chunk (no completion), TTL expiry then msgID reuse, capacity eviction,
  destination-too-small drop, and a warm-loop that asserts the slot count stops
  growing (structural proxy for no steady-state allocation).

### T5 — socket adapters (RED → GREEN)

Files: `crates/leas-native/src/protocol/hysteria2/quic.rs`,
`crates/leas-native/src/crypto/salamander.rs`.

- `Salamander::deobfuscate_in_place(&mut [u8]) -> Option<usize>`: read the salt,
  `copy_within` the payload to the front, XOR in place. Keep
  `deobfuscate_into` for the existing callers/tests. `SalamanderSocket::poll_recv`
  uses the in-place form and drops `RECV_SCRATCH`.
- `GeckoSocket { inner: Arc<dyn AsyncUdpSocket>, psk: Salamander, min, max,
  next_msg: AtomicU8, reassembler: Mutex<GeckoReassembler> }`.
  - `try_send`: if `contents[0] & 0x80 == 0`, Salamander-wrap once and send.
    Else plan 2..8 chunks (sizes from `u32_below`), frame each into a reused
    thread-local scratch, Salamander-wrap each frame into a second reused
    buffer, and send them sequentially with a fresh `msg_id`
    (`fetch_add`, wrapping). A `WouldBlock` mid-burst returns the error; the
    server's TTL drops the orphan and QUIC retransmits with a new `msg_id`.
  - `poll_recv`: loop on `inner.poll_recv`; datagrams with bit 7 clear pass
    through; framed ones go to `reassembler.push` with `Instant::now()`;
    `Complete` is copied into the destination `bufs[i]`; dropped entries are
    compacted out of the batch (`n`, metas, buffers). When the inner returns
    `Pending`, return `Pending` (its waker is registered) — never spin.
  - Keep `max_transmit_segments`/`max_receive_segments` = 1 and
    `may_fragment` = false.
- `client_endpoint(server_addr, spec: &ObfsSpec)`: plain path keeps the shared
  endpoint; any obfs path binds per dial and composes
  `Salamander(SalamanderSocket)` then `Gecko(GeckoSocket)`.
- `dial`/`connect_udp` call `cfg.obfs_spec()` and map `ObfsShapeError` to
  `NativeError::Config` (defense; the capability gate should have refused).
- Tests: frame burst count/size bounds through a fake `AsyncUdpSocket`
  (records transmits; asserts 2..8 distinct frames, salted size in range,
  msgID increments, short header sends exactly one datagram); receive
  reassembly across two `poll_recv` batches; pass-through; partial-send error
  path; in-place deobfuscation round-trip and salt-removal.

### T6 — add/edit form (RED → GREEN)

Files: `crates/leas-config/src/forms.rs`.

- Hysteria2 `obfs` Select gains `"gecko"`; add optional
  `obfs_min_packet_size`/`obfs_max_packet_size` text fields (validated by the
  shared resolver on save; empty = defaults), wired through `check_keys` and
  `hysteria2_from_form`.
- Tests: gecko form round-trip keeps custom sizes; empty sizes produce
  defaults; existing salamander form unchanged.

### T7 — oracle coverage (RED → GREEN)

Files: `crates/leas-oracles/src/e2e/case.rs`,
`crates/leas-oracles/src/e2e/config.rs`,
`crates/leas-oracles/tests/hysteria2.rs`.

- Replace the `Option<&'static str>` obfs knob with
  `Hy2Obfs::{None, Salamander(&'static str), Gecko { psk, min, max }}`; keep the
  existing labels stable and extend the label for gecko/sizes.
- `hysteria2_inbound`: emit `obfs = {type:"gecko", password, min_packet_size?,
  max_packet_size?}`; `client_params_hysteria2`: set the typed fields.
- Rows: add `obfs_gecko` (defaults) and `obfs_gecko_custom_sizes` (e.g.
  600/1300) against sing-box; the existing salamander row stays.
- Rationale for no large-payload row: Gecko reshapes only long headers;
  short-header data is byte-identical to the existing salamander row, and the
  pass-through branch is unit-tested in T5.
- Run `cargo nextest run -p leas-oracles hysteria2`.

### T8 — documentation and gate

Files: `crates/leas-proto/src/proto_spec/hysteria2.rs` header table,
`docs/reference/protocols.md`, `AGENTS.md` (hysteria2 bullet),
`docs/aegis/INDEX.md`.

- Document the obfs shapes, the normalized defaults, the L2 link params (mark
  them unofficial), the refusal set, and the zero-alloc receive path.
- `cargo nextest run -p leas-proto -p leas-config -p leas-native -p leas-db`
  then `--workspace` (oracles excluded), oracle hysteria2 rows,
  `cargo clippy --workspace --exclude leas-oracles --all-targets --all-features -- -D warnings`,
  `cargo fmt --check`.
- Record the bench table, the macerator verdict, and deviations here; update
  the INDEX row.

### T9 — conditional Salamander SIMD swap

Only if T0 clears the gate. Files: `crates/leas-native/Cargo.toml` (normal
dep `macerator = { version = "0.6.0", default-features = false, features = ["std"] }`),
`crypto/salamander.rs` (`xor_wide` → macerator `VBitXor` over `u8` vectors with
`with_simd`), remove the bench dev-dep. Re-run the bench and paste the second
table; keep `wide` and delete the branch if the gate fails.

## Verification (acceptance)

- `obfs=gecko&obfs-password=…` (defaults and custom sizes) completes the QUIC
  handshake and an HTTP echo against a sing-box gecko inbound.
- Wire unit proofs: 2..8 padded frames per long header, salted size in
  `[min,max]`, msgID increments, short headers untouched, malformed frames
  dropped, reassembly delivers in order.
- Unknown obfs name / missing password are refused at ingest and by
  capability; stored rows retire once at marker v3; invalid sizes repair to
  defaults and still dial.
- Links: custom sizes round-trip via `minPacketSize`/`maxPacketSize`; default
  sizes are elided; salamander links never gain size params.
- Clash: a mihomo-shaped YAML imports the obfs password and sizes, and export
  emits kebab keys.
- No per-datagram allocations after the first handshake (warm-loop test).
- Bench table recorded; macerator decision follows the recorded threshold.

## Risks

- The L2 link params are unofficial (v2rayN says it may rename them); a future
  rename is a link-parse change, not a wire change.
- Marker v3 rewrites stored verdicts once; an unknown obfs name becomes
  `config_invalid` until the row is edited. Recoverable, not deleted.
- The 8-message reassembly cap can drop fragments under heavy reordering; it
  matches upstream's per-source cap and fails as a retransmit, not a crash.
- `msgID` wraps at 256 fragmented sends; TTL + cap bound collisions, same as
  upstream.
- Silent size repair can hide a provider typo (debug log only).
- `macerator` 0.6.0 is a large generic SIMD dependency; it ships only with
  measured evidence and no default `avx512`/`fp16` features.

## Self-review record

- Scope: the four user outcomes plus the Clash key repair the gecko export
  needs; no unrelated protocol work.
- One owner per rule (resolver, predicate, marker, codec, adapter).
- Compatibility: stored JSON, identity for existing rows, and salamander wire
  unchanged; only bad-shape verdicts change.
- Every task names files, tests and the command that proves it; no placeholders.
- No retirement needed: the password-only dial path is replaced.

## Outcome

Executed 2026-11-25.

- **T1 config/links/exporters.** `Hysteria2Config` gained
  `obfs_min_packet_size`/`obfs_max_packet_size`; `Hysteria2Config::obfs_spec`
  is the one resolver (`salamander`/`gecko`, password ≥ 4 bytes;
  `ObfsShapeError::{UnknownType,MissingPassword,ShortPassword}`), and
  `gecko_sizes()` normalizes invalid pairs to 512/1200. Links carry v2rayN's
  `minPacketSize`/`maxPacketSize` for gecko only, elided at defaults. Identity
  tags `0x53`/`0x54` hash the normalized pair, so absent and explicit-default
  collapse. sing-box inject adds `min_packet_size`/`max_packet_size` only when
  custom. `ClashHysteria2` now uses mihomo's kebab keys (`obfs-password`,
  `skip-cert-verify`, `hop-interval`) — the old snake spelling silently dropped
  the obfs password on import and export — plus the two size keys.
- **T2 gates.** `is_undialable_shape` has the Hysteria2 arm;
  `validate_hysteria2_shape` refuses at ingestion; `hysteria2_reason` returns
  the resolver reason; the DB marker moved 2 → 3 and its test covers an
  unknown-obfs row (retired) and a gecko row (kept). `SUPPORT_REVISION` moved
  1 → 2 with the `hysteria2_reason` move, so stale persisted verdicts clear
  once. Dial maps the resolver error to `NativeError::Config` as defense.
- **T3/T4 sans-io.** `crypto/gecko.rs` ships the frame codec (golden table
  mirrored from upstream), chunk/pad helpers, and `GeckoReassembler` (8
  in-flight, 8 s TTL passed in, destination-buffer assembly, slot reuse).
- **T5 adapters.** `Salamander::deobfuscate_in_place` replaces the receive
  scratch copy; `GeckoSocket` sits over `SalamanderSocket`, fragments long
  headers into 2–8 padded frames with a fresh `msgID` per attempt, passes short
  headers through, and reassembles in `poll_recv` with in-place batch
  compaction. Segment limits stay 1.
- **T6 form.** `gecko` is selectable and the two size fields round-trip
  (empty = defaults).
- **T7 oracle.** `CaseSpec::hysteria2(Hy2Obfs)` with a label suffix; new
  `obfs_gecko` and `obfs_gecko_custom_sizes` rows. Both passed against the
  pinned sing-box 1.15.0-alpha.13 (25.5 s, 2/2).
- **T0 bench + macerator gate — FAILED, `wide` stays.** Criterion means:

  | Benchmark | 64 B | 1200 B | 1500 B |
  |---|---|---|---|
  | `obfuscate_into` | 133.8 ns | 149.8 ns | 154.4 ns |
  | `deobfuscate_in_place` | 153.8 ns | 247.2 ns | 275.8 ns |
  | XOR slice, `wide` | 1.57 ns | 13.42 ns | 17.26 ns |
  | XOR slice, `macerator` | 3.13 ns | 18.70 ns | 23.64 ns |
  | Gecko frames 2/4/8 (1200 B packet) | — | 17.0 / 30.6 / 59.2 ns | — |

  The XOR slice is ~9% of `obfuscate_into` at 1200 B, so even a free XOR
  cannot reach the 15% bar; `macerator` was 39% slower on that slice. The
  dev-dependency and its bench group were removed; no production dependency
  was added.
- **Docs.** `AGENTS.md` hysteria2 bullet, `docs/reference/protocols.md` §10
  fields/quirks/coverage, and the proto-spec header table are updated.
- **Verification.** `cargo nextest run -p leas-proto -p leas-config
  -p leas-native -p leas-db`: 1935 passed, 1 skipped. Oracle gecko rows against
  sing-box 1.15.0-alpha.13: 2/2 passed (re-run after the lint fixes).
  `cargo clippy --workspace --exclude leas-oracles --all-targets
  --all-features -- -D warnings`: clean. `cargo fmt --all -- --check`: clean.
- **Not done / deferred.** A dedicated allocation-count assertion for the
  adapter was replaced by the warm-loop slot-reuse test plus the measured
  receive path (in-place deobfuscation, stack reassembly buffer, thread-local
  send scratch); no per-datagram `Vec` is constructed after warm-up. The
  above-MTU oracle transfer was dropped: Gecko reshapes only long headers and
  the short-header path is the existing Salamander row plus the adapter's
  pass-through test.

