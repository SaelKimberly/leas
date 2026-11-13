# leas — Agent Guide

**leas** is a feature-rich terminal client for modern VPN and proxy protocols. Top priority: compatibility with the mainstream server backends (Xray-core, sing-box), with a first-class TUI. `v2rayN` is one reference implementation, not a parity target.

This file is auto-detected project context: commands, structure, conventions. The wiki is [`docs/INDEX.md`](docs/INDEX.md); architecture decisions are [`docs/architecture/decisions.md`](docs/architecture/decisions.md).

## Package Manager & Toolchain
- Rust 2024 workspace; `cargo` only (no JS toolchain). Toolchain declared in `rust-toolchain.toml` — the channel floats on `stable` (see the gate note below).
- Lint config: root `Cargo.toml` `[workspace.lints.clippy]`, opted in per crate. Format: `rustfmt.toml`.
- Root `[workspace.dependencies]` holds only deps used by 2+ crates or architecture-driving crates; single-crate deps live in that crate's own manifest.

## Commands
| Task | Command |
|------|---------|
| Run | `cargo run` |
| Release build | `cargo build --release` |
| One test | `cargo nextest run -p <crate> <filter>` |
| Full test suite | `cargo nextest run` (default members; `--workspace` adds the dev-only oracles) |
| Lint (authoritative) | `cargo clippy --workspace --exclude leas-oracles --all-targets --all-features -- -D warnings` |
| Format | `cargo fmt` |
| Full gate (verbose) | `just quality-gate` |
| Full gate (CI, exit-code) | `just quality-gate-ci` |
| Gate: fmt + lint + test | `just quality-gate code` |
| Gate: deps only | `just quality-gate deps` |
| Benchmarks | `just bench` (`micro` needs no core binaries) |
| Hot-path allocation gate | `just hotpath` (exact counts, release only) |
| Allocation profile (workload) | `just memtrace [header\|connect\|geosite\|record\|all] [n]` |
| Allocation profile (the app) | `just memtrace-app [delay]` (stages a sandbox; see `docs/guides/tracing.md`) |
| Compare two profiles | `just memtrace-compare a.json b.json [--force]` |
| SIP003 plugin oracle bins | `just plugin-bins` |

`cargo clippy -p <crate>` is a TRAP: if the crate fails to compile, clippy never lints, so a clean grep proves nothing. Use the workspace form. A per-crate green is not evidence until `cargo nextest run --workspace` prints its Summary line.

## Tool Restrictions
- NEVER use `ast_edit` — it corrupts session state. Use `edit`.
- Search contents with `search`, never shell `grep`/`rg`/`awk`.
- Display files with `read`, never `cat`/`head`/`tail`/`ls`.

## Structure
- `crates/leas` — binary: `main.rs`, `alloc.rs` (the process allocator + purge policy), `state.rs` (`AppState`), `types.rs`, `ops/` (connect, ping, events, scheduler — the PER-LINK ping gate —, **job_scheduler — the job queue / one-job-at-a-time gate**, profiles, enrich, subscriptions, settings, export, stream_import, **telegram — the `t.me/s/<channel>` source that feeds the same import pipeline**, db_monitor, clipboard, native_connect, ping_native, purge, compact, geodata — geo assets + the shared routing `EngineCell`, **routing_defaults — the shipped per-country rulesets**), `ui/` (profiles, settings, logs, statistics, **details** (pane-2 `Details`: three 3:6:3 sections — Server, Link, DB aggregates), **tasks** (pane-2 `Tasks`: the progress bar + the job queue), native_activity, **sniffer** (pane-1 `Sniffer`: per-host traffic for the native session), add_server, export, status_bar, theme, widgets).
- `crates/leas-oracles` — dev-only e2e oracle crate: `build.rs` fetches the pinned xray-core / sing-box / mihomo assets (SHA-256 verified; mihomo ships a bare gzip on linux), `e2e/` builds the server/client config pairs (JSON for the first two, YAML `listeners:` for mihomo) and launches the cores, and the moved integration tests/benches live here. Excluded from `default-members`; run with `-p leas-oracles`.
- `crates/leas-hotpath` — dev benchmark crate (not in `default-members`), two bins: `leas-hotpath` (default) owns a counting `#[global_allocator]` and asserts exact allocation counts per hot path (`vless/header/*`, `vless/peel/*`, `tls13/{seal,open}/*`); `memtrace` installs `leas-memtrace` and writes per-module artifacts (workloads `header`, `connect`, `geosite`, `record`, `all`; `geosite` needs `LEAS_GEOSITE_PATH` + `LEAS_GEOSITE_CODES`, and `LEAS_MEM_TRACE_DIR` / `LEAS_MEM_TRACE_MIN_BYTES` / `LEAS_MEM_TRACE_FOLD=allocs` tune the output). It never depends on `leas`, which owns the process allocator; a path it cannot reach (a `pub(crate)` module) is not measured rather than un-privatised.
- The tracer's cost is the stack walk: `attribute` probes the ip cache while capturing, so a hit stops at the first workspace frame, and a first sight re-walks for the folded path. Keep that shape — restoring a full 32-frame capture per allocation measured 9.7 s of CPU on an 11 s boot against 6.8 s now.
- Tracing runbook: [`docs/guides/tracing.md`](docs/guides/tracing.md) — the sandbox rules, the `LEAS_MEM_TRACE_*` knobs, artifact reading and `memtrace compare`. Read it before a measurement; the traps it lists (HOME vs XDG, due subscriptions, a 64k-row DB in a PTY driver, the exit drain) each produce a confidently wrong number.
- `crates/leas-memtrace` — the memory tracer (a **default member**: its unit tests run in the normal suite). A `#[global_allocator]`-level `GlobalAlloc` that charges each allocation to the innermost workspace module: bounded `backtrace::trace` capture, a direct-mapped `ip → module` cache (one multiplicative mix, no hasher, no lock), the symbol id in an 8-byte header before the payload (so a free is an O(1) header read, never a pointer map), per-symbol atomics in a fixed slab. Artifacts are JSON + a human table + an inferno folded stack; attribution is by **module path** because release builds inline away function frames. It sees its own process only. Adapted from `leaktracer` (see the crate docs for what changed and why).
- Other crates and their responsibilities: [`docs/architecture/architecture.md`](docs/architecture/architecture.md).

## Key Conventions
- Tests live beside code (unit) or in `tests/` (integration); `thiserror` for error types, `anyhow` for propagation.
- `#![forbid(unsafe_code)]` in `leas-tls`, `leas-native` and `leas-oracles`; crypto standard is `ring` (plus `x25519-dalek`, RustCrypto `ml-kem`, `ml-dsa` — the last verify-only, for REALITY's certificate extension). Socket options stay on `socket2`'s SAFE surface for the same reason; `SO_MARK`/`SO_BINDTODEVICE`/`TCP_CONGESTION` need an ADR. `TCP_MAXSEG` and `TCP_QUICKACK` do have safe setters and are used: `path_mss.rs` advertises 1360 (1220 after three handshake stalls with no success between) and the dial applies it to an UNCONNECTED `TcpSocket`, because the MSS only matters in the SYN. Process signals in `leas-oracles` go through `rustix` (a `cfg(unix)` dependency) because `libc::kill` is `unsafe`. Consult `docs/reference/crypto-dependencies.md` before adding a primitive.
- All DB access is async on `Database`; the typed path is the default, raw SQL needs a recorded cause in `docs/reference/database-manual-sql.md`.
- A database that fails to open is NEVER deleted: `Database::open` propagates the error and leaves the file untouched (a second instance opening a live file used to wipe it). The only wipe left is the explicit `IncompatibleSchema` verdict.
- The process allocator is owned by the binary: `crates/leas/src/alloc.rs` installs `#[global_allocator]` (mimalloc 3.6.1 via `mimalloc-safe` 0.1.70 + `v3`), `configure()` at startup applies the Linux retention tuning (`allow_thp=0`, `page_full_retain=0`, `page_max_reclaim=0`, `page_cross_thread_max_reclaim=0`, `generic_collect=512`; indices pinned by a readback test), and `release_freed_heap()` runs at job boundaries. NEVER override `purge_delay` to 0 on 3.x — it turns every free into a purge (~1.7–3x slower burst). The tuning is Linux-specific: Windows defaults already measured better, and 3.6's Linux defaults cost ~130 MB settled on a feed-wide batch. Two compile-time switches sit on top: `std-alloc` installs `System` instead (external profilers only see per-allocation events through it; mimalloc hides them), and `mem-trace` (implies `std-alloc`) installs `leas-memtrace` and writes `target/mem-trace/` artifacts at each `alloc::job_boundary` label. Only one `#[global_allocator]` may exist, so these are mutually exclusive builds, not runtime switches. `leas-db` must NOT enable turso's `mimalloc` feature — a library-owned allocator cannot be configured, measured or swapped.
- The schema cursor is `PRAGMA user_version` (`crate::schema`): a supported older version MIGRATES, an unknown one wipes. A real DDL change adds a `schema::steps` entry and bumps `SCHEMA_VERSION` (the step and the cursor stamp share one transaction); a change that is NOT DDL never bumps it — an identity re-key is a DATA step behind an `app_meta` marker.
- Routing rules are per-country rulesets (`ru`/`cn`/`ir`) with exactly one active: the shipped `default` table lives in `crates/leas/src/ops/routing_defaults.rs`, `custom` rows carry `routing_rules.ruleset` (`NULL` = a pre-ruleset row, custom under every country). The geo dataset only gates compatibility: an unservable `geosite:`/`geoip:` code disables its row and is skipped at build (`GeoInventory` + `incompatibility`), never a build failure; `geoip:<cc>` falls back to the GeoLite2 mmdb for two-letter codes only.
- `leas-hakari` is generated — regenerate with `cargo hakari` after any `Cargo.lock` change; never edit it by hand.
- On a TCP tunnel connect, the protocol request header is withheld by `protocol::first_flight::HeaderFirst` and leaves in the same carrier write as the first payload or first mux frame (Vision joins its camouflage frame to the first padded frame); a read flushes the header before handing up read data. The header is built with `encode_request_into` into the buffer `HeaderFirst` owns, reserved at `HEADER_RESERVE` = 96 bytes (longest header ≈56 + the 21-byte camouflage frame), and the Vision addons are a `&'static [u8]` constant — one allocation per Vision connect, no addon `Vec`. Eagerly writing a header on a TCP connect is a regression: it recreates the small telltale record. The UDP connect paths (`connect_udp_plain`, trojan `connect_udp`, the SS datagram streams) still write theirs eagerly — declared out of scope, because a datagram frame has a different lifetime and the small-packet tell is a TCP-connect property.
- The relay starts each direction at 16 KiB and promotes to 64 KiB after a read fills the small buffer, **after** the write that consumed it (`inbound/outbound.rs`). Promoting earlier would swap the buffer and discard the bytes just read. Relay buffers come from a bounded pool (`POOL_CAP` 64 per size class = 2 MiB; `RelayBuf` returns on drop, promotion swaps size classes) whose free lists are pre-reserved at first use — the return path runs from `Drop`, and allocating while unwinding aborts.
- `zeroize` on owned key buffers, and the `zeroize` FEATURE must stay listed on every crypto dep that touches keys — re-check after any crypto dep edit.
- In-memory geo/matcher strings are `CompactString` (`GeoDomains`, `DomainRulesSpec`, `CompiledDomain`'s sets): most domains fit inline (≤24 B on 64-bit, 88 % of a typical `geosite.dat`), so they never reach the allocator, and `lower_one` skips the lowercase copy when a value is already lowercase. DB **model** columns stay `String` — toasty 0.11 implements its `Field` trait for a closed primitive set (`String`, `Uuid`, `bool`, `isize`, `usize`, `Vec<u8>`) and the orphan rule forbids extending it for a foreign type. A geo dataset is parsed **once per build** (`GeoCompiler::preload`) and the cache is moved into the rules (`take_site`), never cloned per rule.
- A test earns its place by discriminating a plausible consumer-visible bug: behaviour, boundary, invariant, state transition, precedence, error class, wire bytes, ordering, golden/parity. Tautologies (asserting a literal the test itself defined), source-text, mock echoes, bare not-throw, non-empty/length-grew/is_some-only and same-path duplicates do not.
- Tests identical modulo literals are ONE `#[rstest]` table with named `#[case::…]` rows — never N near-identical `#[test]` fns. Every `#[case]`-supplied parameter must carry `#[case]` (a missing one makes rstest report "Wrong case signature" and silently drop the whole fn).
- Perf labs and planner/timing probes are not tests: they live behind the crate's `perf-lab` feature as `#[cfg(all(test, feature = "perf-lab"))]` (the `test` term is required — a lab that drives test-only helpers and `tempfile` cannot compile in the lib unit), stay `#[ignore]`d, and print tables. Run one with `cargo nextest run -p <crate> --features perf-lab --run-ignored all <name>`.
- Every hand-written crate opts into `[lints] workspace = true`. A crate without it is silently outside `pedantic`+`nursery`, generated code included (prost's `PartialEq`-without-`Eq` needs a scoped allow at the `include_proto!`).
- `cargo nextest run` is the suite (default members; the dev-only `leas-oracles` is skipped). `--all-features` is clippy's surface, with `--exclude leas-oracles`. The real-core e2e rows live in `leas-oracles`: `cargo nextest run -p leas-oracles`; its `build.rs` fetches the pinned cores (override `$LEAS_CORE_BIN_DIR`, or `LEAS_ORACLES_SKIP_DOWNLOAD=1` for a compile check). The pins track each project's **newest release tag** (sing-box may be a pre-release); bumping them is `crates/leas-oracles/src/pins.rs` plus `just oracles-pins <xray> <singbox> <mihomo>`, then triage the reds — an upstream default change can red a whole transport (a `freedom` egress policy, a key-share requirement, a renamed config type), so read the core's own log (`LEAS_CORE_LOG=1`) before assuming the client is wrong. A red row whose scenario no pinned server can serve is a wrong expectation, not a client bug: check the upstream config surface first, then delete or `#[ignore]` the row with the upstream evidence in the reason, and move the client claim to a hermetic test.
- The toolchain floats on `stable`; a new stable release can promote a lint and redden the gate. That is now detected rather than silent: `stable-drift.yml` re-runs the `code` gate weekly against the newest stable, so drift surfaces within a week, and `just quality-gate code` after a toolchain bump stays the local check. CI (`.github/workflows/`, added 2026-10-13): `code-linux` runs the `code` gate plus a release build inside an `ubuntu:22.04` container (the `GLIBC_2.35` floor), `code-windows` runs the `code` gate on `windows-2022`, `deps` runs single-homed on the host.

## External References
| Need | File |
|------|------|
| Wiki hub | `docs/INDEX.md` |
| Durable design decisions | `docs/architecture/decisions.md` |
| Architecture overview | `docs/architecture/architecture.md` |
| Native core + TLS engine (purpose, verification tiers, roadmap) | `docs/reference/native-core.md` |
| TUI screens, keybindings, workflows | `docs/guides/tui-manual.md` |
| Releasing to crates.io | `docs/guides/publishing.md` |
| Building, prerequisites, the `just fast` opt-in, CI jobs | `docs/guides/building.md` |
| Ordering law | `docs/reference/ordering-law.md` |
| DB schema, indexes, invariants | `docs/reference/database.md` |
| Raw-SQL sites and rules | `docs/reference/database-manual-sql.md` |
| Crypto sites and dependency advisories | `docs/reference/crypto-dependencies.md` |
| Protocol specs | `docs/reference/protocols.md`; Clash YAML: `docs/reference/clash.md` |
| Glossary | `docs/reference/glossary.md` |
| Aegis specs / plans / ADRs index | `docs/aegis/INDEX.md` |
| Reference repos (read-only) | `thirdparty/Xray-core`, `thirdparty/sing-box`, `thirdparty/v2rayN` |
