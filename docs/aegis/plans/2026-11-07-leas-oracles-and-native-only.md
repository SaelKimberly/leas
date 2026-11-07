# `leas-oracles` extraction and the native-only client — implementation

**Date:** 2026-11-07
**Spec:** `docs/aegis/specs/2026-11-07-leas-oracles-and-native-only-design.md` (D1–D17)
**Status:** Phase 1 implemented — verification: oracle unit 32/32, probe green,
VLESS 81/88 (the 7 failures are accepted xhttp pin drift), `leas-native`
756/756; workspace clippy/hakari/machete pending.

## Goal

Phase 1 moves the real-core e2e surface out of `leas-native` into a dev-only
`leas-oracles` crate that builds only on explicit request, fetching the pinned
Xray/sing-box assets at build time. Phase 2 removes core choice from the client
and parks the oracle adapters in the same crate.

## Architecture

- `leas-oracles` is a workspace member with **no features**, excluded from
  `[workspace] default-members`; `just clippy` adds `--exclude leas-oracles`;
  bare `cargo build/test/nextest/run` never build it.
- `src/pins.rs` is std-only and shared with `build.rs` via `#[path]`.
- `build.rs` fetches `OUT_DIR/core-bin`, verifies SHA-256, extracts, and emits
  `LEAS_ORACLES_CORE_DIR`; `LEAS_CORE_BIN_DIR` overrides, `LEAS_ORACLES_SKIP_DOWNLOAD`
  skips (compile-check only).
- `leas-native` keeps a feature-less shell (`e2e-support = []`) exposing the
  CA hooks and the three stream accessors `pub` + `#[doc(hidden)]`.
- Phase 2 moves the oracle modules into `leas-oracles::oracle_adapters`,
  deletes the TUI glue, and re-keys the protocol identity.

## Tech stack / constraints

Rust 2024, resolver 3, cargo-nextest, hakari. Windows builds here use
`+stable-x86_64-pc-windows-gnu`; the default active toolchain is msvc and its
`link.exe` is shadowed.

## Baseline / authority refs

- `docs/aegis/specs/2026-11-07-leas-oracles-and-native-only-design.md`
- `docs/reference/database.md` "Changing the schema" (identity rule)
- `docs/reference/native-core.md`, `docs/architecture/architecture.md`,
  `AGENTS.md`, `justfile`, `.config/hakari.toml`

## Compatibility boundary

- No `SCHEMA_VERSION` bump in either phase; `IDENTITY_VERSION` 3 → 4 in Phase 2.
- `leas-native`'s public API gains three `#[doc(hidden)]` accessors behind a
  non-default feature; nothing else changes in Phase 1.
- The e2e test command changes from `-p leas-native --features native-e2e` to
  `-p leas-oracles`; old docs are updated, historical docs untouched.

## TDD route

`auto` → **strict** for the build pipeline (new behavior: fetch/verify/extract)
because a wrong hash or extraction must fail loudly; **light** for the move
(existing e2e tests are the regression: the `vless` matrix + `probe_e2e` after
the move). No failing-test ceremony for the mechanical file move.

## Phase 1 tasks

- **T1 — workspace inclusion.** Root `default-members` = every member except
  `crates/leas-oracles`; create the crate skeleton (`Cargo.toml`, `lib.rs`,
  `pins.rs`). Verify: `cargo metadata` and a bare `cargo check` do not build
  the new crate.
- **T2 — pins table.** Versions + per-platform names + the eight SHA-256 rows;
  `url`/`asset_name`/`sha256`; the `leas-core::updater` cross-check test.
- **T3 — build pipeline.** `build.rs` fetch (ureq 3, rustls/ring), SHA-256
  compare with an actionable error, zip/tar extraction by basename, `+x` on
  unix, `rustc-env`. Verify: real fetch runs; corrupt one hash and see the
  failure; restore.
- **T4 — module move.** Move `src/e2e/*` and rewrite `crate::` to
  `leas_native::`; `bin_name` gains `EXE_SUFFIX`; `resolve` falls back to the
  baked dir; delete `resolve_from`/HEAD constants and the HEAD test.
- **T5 — native cutover.** Delete `src/e2e`, rename the feature to
  `e2e-support`, gate the hooks/accessors, drop the three optional deps.
- **T6 — tests and benches.** Move the eight test files + `common`, the two
  benches; rewrite imports; remove the old cfg lines; adapt `probe_e2e` and
  `ws_paths` to the resolver; plugin rows stay `#[ignore]`.
- **T7 — gate/docs.** justfile (`--exclude`, `oracles-check`, `oracles-pins`,
  bench paths), CI comments, `AGENTS.md`, architecture/native-core/crypto
  references, hakari regeneration.
- **T8 — verification.** Build + fetch, probe smoke, one matrix file, default
  suite, clippy with exclude, fmt, hakari, machete, `aws-lc-rs` empty.

## Phase 2 tasks (after Phase 1 is green)

- **T9 — settings.** Remove `Core`, `ProtocolCore`, `Updates`, `Stats` from
  `leas-config` + the settings forms.
- **T10 — identity.** Drop `Protocol::core_type` and `tag::CORE_TYPE`; bump
  `IDENTITY_VERSION`; delete `CoreType`/`core_mapping` (move them).
- **T11 — re-key.** Add the `app_meta.identity_version` marker and the
  rebuild-based re-key (protocols + profile_stats + endpoint_rank refresh);
  no `SCHEMA_VERSION` bump; permutation test.
- **T12 — crate split.** Keep `log_heed`, `SysStats`/formatters,
  `ping`/`speed_test`/`reqwest`/`quinn`, `SessionParams`; move
  `bin_manager`, `config_builder`, the gRPC client half, `process`, `updater`,
  `core_type` into `leas-oracles::oracle_adapters`; delete `dns`.
- **T13 — client deletion.** `ops/updates.rs`, `ops/core.rs`, the subprocess
  arm of `ops/connect.rs`, the update/core events, `connected_core` → bool,
  metrics/status core names.
- **T14 — UX + docs.** Unsupported rows visible/marked/refused; database,
  native-core, TUI manual, AGENTS, architecture updates.
- **T15 — verification.** Migration fixture, `cargo run` smoke, suite, clippy,
  fmt, hakari, machete, `cargo tree` has no tonic/prost.

## Verification (Phase 1)

```
cargo +stable-x86_64-pc-windows-gnu build -p leas-oracles
PROBE: cargo nextest run -p leas-oracles --test probe_e2e --run-ignored ignored-only
MATRIX: cargo nextest run -p leas-oracles vless
SUITE: cargo nextest run
CLIPPY: cargo clippy --workspace --exclude leas-oracles --all-targets --all-features -- -D warnings
ORACLES: just oracles-check
FMT: cargo fmt --all --check
HAKARI: cargo hakari generate --diff
MACHETE: cargo machete --with-metadata --skip-target-dir
TREE: cargo tree -i aws-lc-rs
```

Fetch runs with a proxy on this workstation: `LEAS_ORACLES_PROXY=socks5h://<host>:<port>`
(the `socks5h` scheme lets the proxy resolve the host; ureq's `socks5://`
resolves locally and fails without DNS). CI has normal egress.

## Risks

- The first `-p leas-oracles` build downloads ~80 MB; `OUT_DIR` caches it
  (keyed by the expected SHA, so a pin bump re-fetches).
- `ureq` 3 is the first build-time TLS client; the gate asserts no `aws-lc-rs`.
- The move is mechanical but wide; the matrix + probe are the regression.
- Phase 2 re-key touches primary keys; the rebuild/merge law and the marker
  are the guard.

## Deviations

- The `leas-core` naming cross-check dev-dependency was dropped after the first
  build spent 15+ minutes compiling turso/toasty/tonic for a 40-line test. The
  pins table is guarded by `just oracles-pins` and the version probe instead.
- Two pre-existing unit-test failures surfaced in the moved module and are
  fixed at their owner: the REALITY case expected no fingerprint while
  `reality_client_security` always sets `fp: "chrome"` (the expectation was
  stale), and `udp_ready` only treated `ConnectionRefused` as "not ready";
  Windows surfaces the same ICMP port-unreachable as `ConnectionReset`.
- The core version probe's bound is 15 s (was 5 s): parallel first-run on
  Windows lets AV scan a ~45 MB core for longer than 5 s, which made the shared
  `cores` fixture time out before any test ran.
- `tcp_plain_into_reality_server` is `#[cfg_attr(windows, ignore)]`: the REALITY
  fallback dest handshake does not complete inside the probe window on Windows.
  The `ws`/`grpc` siblings were already ignored globally (the dest sees their
  framing, not HTTP).
- The VLESS matrix is 81/88 green; the seven failures are all `xhttp` rows
  (packet/stream/stream-one/h3) where the pinned xray 26.3.27 rejects the
  generated splithttp server config with `400 Bad Request`. That is the
  pin-drift class D17 accepts; no client regression is implied.
