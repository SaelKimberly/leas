# `leas-oracles` extraction and the native-only client

**Date:** 2026-11-07
**Status:** approved 2026-11-07 (grilling interview, D1–D17); implemented
**Owns:** the `leas-oracles` dev crate (build-time pinned cores, config-pair
generation, process launch), its build-inclusion model (no features), and
the client's native-only cutover (core-choice settings, protocol identity,
external-core adapters).
**Supersedes, deliberately:**
- the manual `--features native-e2e` + `LEAS_CORE_BIN_DIR` workflow repeated in
  `AGENTS.md`, `crates/leas-native/tests/*.rs`, `justfile` and
  `docs/reference/native-core.md` — the suite is now `-p leas-oracles`, and the
  binaries are fetched by `build.rs` unless overridden;
- `crates/leas-native/benches/baseline.md`'s and
  `.benchmarks/baseline-memory.md`'s command lines only. Their recorded
  measurements are historical evidence and are not rewritten.

`docs/reference/database.md` "Changing the schema" step 3 stays the rule:
identity changes bump `IDENTITY_VERSION`, never `SCHEMA_VERSION`. This spec
implements the missing re-key detector it names.

Historical specs/plans that mention the old test workflow are left as written;
this spec owns the current contract.

Scope: Phase 1 is `leas-native` + a new crate + benches; Phase 2 is
`leas-proto`, `leas-db`, `leas-config`, `leas-core`, `leas`. No e2e execution in
CI, no macOS claim, no SIP003 plugin download, no pin version bump (the user
performs the bump and regenerates the table), no deletion of the never-applied
`Tun`/`Mux`/`SystemProxy` config (deferred by D11).

---

## 1. Decisions (user-owned; settled 2026-11-07)

| # | Decision | Rejected alternative |
|---|---|---|
| D1 | **Two phases**: extraction first, native-only cutover second; each compiles and ships independently | one combined cut; cleanup before extraction |
| D2 | **Self-contained `leas-oracles`**: lib + `tests/` + `relay`/`throughput` benches; **no features**; excluded from `default-members`, so only an explicit `-p leas-oracles` builds it | lib-only crate or a dev-dependency cycle (always builds e2e); an `e2e` feature |
| D3 | `build.rs` **hard-fails** when a fetch fails; `LEAS_CORE_BIN_DIR` is the unconditional override, `LEAS_ORACLES_SKIP_DOWNLOAD=1` the offline/compile-check escape | soft warning; opt-in fetch only |
| D4 | Pin mapping lives in **`src/pins.rs`**, shared by `build.rs` (`#[path]` include) and the lib; extraction stays in `build.rs` | new `leas-release` crate; inline-only pins |
| D5 | Cache at **`OUT_DIR/core-bin`** | shared `target/` dir (locking); user cache dir |
| D6 | **Mandatory SHA-256** per `(core, os, arch)`; a mismatch is a build error | pin-only; optional env checksum |
| D7 | Platforms: **linux/windows × x86_64/aarch64**; anything else errors | adding macOS |
| D8 | **`just oracles-pins <xray> <singbox>`** prints the 8-row table (curl + awk, print-only, no source rewrite) | build-time print mode; manual lookup |
| D9 | `leas-native` feature renamed **`e2e-support`**; the three stream accessors become `pub` + `#[doc(hidden)]` under it | keeping `native-e2e`; unconditional public hooks |
| D10 | **No e2e in CI**; the gate excludes `leas-oracles` from clippy and uses `default-members` for tests | opt-in job; run in the PR gate |
| D11 | Phase 2 removes only the core-choice settings: `Core`, `ProtocolCore`, `Updates`, `Stats` | removing the never-applied `Tun`/`Mux`/`SystemProxy` too; hiding only |
| D12 | `Protocol.core_type` is **removed from the identity and re-keyed**; `IDENTITY_VERSION` 3 → 4 | inert legacy field; identity-only removal |
| D13 | `CoreType` + `core_mapping` **move to `leas-oracles`**; both published definitions are deleted | dedupe into an inert `leas-proto` API; keep both |
| D14 | **Slim `leas-core`**: shared session glue only | dissolve the crate; repurpose/rename |
| D15 | Adapters move to `leas-oracles::oracle_adapters`, compiled whenever the crate is built; the TUI-level core glue is deleted, not moved | moving the state-coupled ops layer; a state shim; a second feature |
| D16 | Unsupported profiles stay **visible and marked**, and refuse connect/ping with `support_reason` | hide; purge |
| D17 | **No HEAD peer**: only the two latest-stable pins exist. `XRAY_HEAD_VERSION`/`LEAS_CORE_HEAD_BIN_DIR`, `CoreUnderTest::resolve_from` and `vless_pq_enc_against_head` are deleted. A pin bump may red some e2e rows; that is accepted, not a blocker | keeping the HEAD differential; gating the bump on a green matrix |

---

## 2. Evidence base (verified against the tree, 2026-11-07)

| Fact | Anchor |
|---|---|
| The e2e module is ~4.4k lines across 6 files | `crates/leas-native/src/e2e/{case 829, config 1669, core 113, harness 1015, mod 350, variant 447}.rs` |
| All 8 integration test files are e2e (6 feature-gated, 2 `#[ignore]`-only) | `crates/leas-native/tests/{hysteria2,plugin_3a,plugin_sip003,probe_e2e,shadowsocks,trojan,vless,vmess,ws_paths}.rs`; `tests/common/mod.rs` |
| Two benches consume the e2e harness | `crates/leas-native/benches/{relay 308, throughput 340}.rs`; `dispatch`/`ss_codec` are hermetic |
| `native-e2e` also gates the harness CA hooks | `security/fingerprint.rs:148-158`; `transport/quic.rs:74-86` |
| The PQ assertion reaches crate-private accessors | `lib.rs:148-152` (`inner_stream`), `protocol/vless/stream.rs:235-239`, `protocol/vmess/stream.rs:754-758` |
| The e2e lib deps are optional and feature-gated | `crates/leas-native/Cargo.toml:137-154` |
| `CoreType` appears 618× in 40 files and is defined **twice** | `leas-proto/src/proto_spec/mod.rs:101`; `leas-core/src/core_type.rs:7` |
| `Protocol.id = uid = sig ^ cred_hash`; `write_identity` writes `core_type` | `leas-db/src/models_toasty.rs:533-540`; `leas-proto/src/proto_spec/endpoint.rs:90-95` |
| `IDENTITY_VERSION` is 3 | `leas-proto/src/proto_spec/identity.rs:54` |
| The schema cursor is 19 and a non-idempotent change appends a step + bumps `SCHEMA_VERSION` | `leas-db/src/database.rs:102`; `schema/steps.rs:56-62`; `docs/reference/database.md` "Changing the schema" |
| An identity re-key must **not** bump `SCHEMA_VERSION`; no detector exists; `StepKind::Rebuild` is reserved and unused | `docs/reference/database.md:598-614`; `schema/steps.rs:28-42`; unimplemented at `schema/mod.rs:207` |
| Endpoint identity is `stable_hash(canonical_name, port)` — protocol-independent | `models_toasty.rs:389-391` |
| Endpoint merge already owns the link-collision evidence law | `leas-db/src/merge.rs:1-40` |
| `AppConfig` is `~/.config/leas/config.json`; serde ignores removed keys | `leas-config/src/app_config.rs:319-370` |
| `tun` and `system_proxy` are never applied | only `ops/settings.rs` + `ui/settings.rs` reference them |
| `mux` and `core.log_level` feed only the oracle builder | `ops/connect.rs:217-241` |
| `SysStats`, `format_*`, `TestType`, `log_heed::LogMessage`, `ping` adapters and `speed_test` are native-shared | `ops/native_connect.rs:14-16`; `ui/metrics.rs:19`; `ops/events.rs:5`; `main.rs`/`ui/logs.rs`; `ops/ping.rs:214,495,550`; `start_tcp_ping`/`start_speed_test`/`start_udp_test` |
| `BuildParams` is oracle-shaped; native uses `listen`/`local_port` only | `config_builder/mod.rs:21-46`; `native_connect.rs:40` |
| The pinned releases exist; the API exposes per-asset SHA-256; both assets fetch through a `socks5h://` proxy | GitHub API `releases/tags/v26.3.27`, `v1.13.16`; `curl` 200/299-byte probe |
| Upstream naming is already encoded in `leas-core` and mirrored by `pins.rs` (no cross-check dep) | `leas-core/src/updater.rs:395-470`; `bin_manager.rs:164-210` |

The proxy note is operational, not a design property: this workstation cannot
resolve external hosts directly, so `build.rs` honours `LEAS_ORACLES_PROXY`
first and then the standard proxy variables. Use a **`socks5h://`** URL: ureq's
`socks5://` resolves the target locally before contacting the proxy
(`ProxyProtocol::Socks5 => true`), which fails on a host with no DNS; `socks5h`
sends the hostname to the proxy. `curl` for `just oracles-pins` uses the same
`ALL_PROXY`/`socks5h://` convention.

---

## 3. Phase 1 — `leas-oracles`

### 3.1 Crate and build inclusion

```
crates/leas-oracles/
  Cargo.toml
  build.rs
  src/lib.rs
  src/pins.rs
  src/e2e/{mod,case,config,core,harness,variant}.rs
  tests/{common/mod.rs, hysteria2, plugin_3a, plugin_sip003,
         probe_e2e, shadowsocks, trojan, vless, vmess, ws_paths}.rs
  benches/{relay, throughput}.rs
```

`publish = false`, `[lints] workspace = true`, **no features**. The crate stays
a workspace member (shared `Cargo.lock`, `[workspace.dependencies]`, hakari) but
is excluded from `default-members`:

```toml
# root Cargo.toml
[workspace]
resolver = "3"
members = ["crates/*"]
default-members = [ /* every member except "crates/leas-oracles" */ ]
```

Bare `cargo build`, `cargo test`, `cargo nextest run`, `cargo run` and the
`just` gate (which also adds `--exclude leas-oracles` to clippy) never build it.
It is built only by an explicit `-p leas-oracles` / `--manifest-path`, which is
also the only path that runs `build.rs` and fetches. `--workspace` remains an
explicit request and does include it; the documented full suite becomes
`cargo nextest run` (default members), and `AGENTS.md` is updated accordingly.
Because there is no feature to gate on, `build.rs` fetches whenever the crate
is built; the override and skip variables below are the only switches.

```toml
[dependencies]
leas-native = { path = "../leas-native", features = ["e2e-support"] }
leas-proto.workspace = true
leas-tls.workspace = true
tokio = { workspace = true, features = ["net", "io-util", "time", "sync", "rt", "process"] }
rustls = { workspace = true, features = ["ring"] }
ring.workspace = true
serde_json.workspace = true
tempfile.workspace = true
rcgen.workspace = true
tiny_http = "0.12.0"
tokio-rustls.workspace = true
x25519-dalek.workspace = true
base64.workspace = true
# oracle_adapters
reqwest.workspace = true
tonic = "0.14.9"
prost = "0.14.4"
zip = "9.1.3"
tar = "0.4.46"
flate2.workspace = true
semver = "1.0.28"
async-trait.workspace = true
# workspace-hack (hakari requires every hand-written crate to depend on it)
leas-hakari = { version = "0.1", path = "../leas-hakari" }
```

Every dependency is ordinary: it compiles only when the crate is built.
`#[allow(dead_code)]` covers the adapters that no test calls yet.

Dev-dependencies (test/bench targets): `tokio`, `rstest`, `criterion`,
`tokio-tungstenite`, `futures-core`, `leas-route`. The `leas-core` naming
cross-check was dropped — it pulls the ORM/HTTP/tonic graph into every e2e
build; `just oracles-pins` and the post-extract version probe are the guards.

`[build-dependencies]` are independent of the member exclusion and run only on
the explicit builds: `ureq` (rustls + ring), `zip` (deflate), `tar`, `flate2`,
`sha2`.

### 3.2 `pins.rs` contract

Std-only (no crate references) so `build.rs` can `#[path = "src/pins.rs"] mod
pins;` and the lib can `pub mod pins;` against one body.

```rust
pub enum Core { Xray, SingBox }
pub const XRAY_VERSION: &str = "26.3.27";
pub const SINGBOX_VERSION: &str = "1.13.16";
pub fn asset_name(core: Core, os: &str, arch: &str) -> Option<String>;
pub fn sha256(core: Core, os: &str, arch: &str) -> Option<&'static str>;
pub fn version(core: Core) -> &'static str;
pub fn url(core: Core, os: &str, arch: &str) -> Option<String>; // repo + tag + name
```

The table (read from the release API on 2026-11-07; the user's pin bump
regenerates it with `just oracles-pins`):

| core | os | arch | asset | sha256 |
|---|---|---|---|---|
| Xray | linux | x86_64 | `Xray-linux-64.zip` | `23cd9af937744d97776ee35ecad4972cf4b2109d1e0fe6be9930467608f7c8ae` |
| Xray | windows | x86_64 | `Xray-windows-64.zip` | `d004c39288ce9ada487c6f398c7c545f7d749e44bdfdd59dbc9f865afba4e1ad` |
| Xray | linux | aarch64 | `Xray-linux-arm64-v8a.zip` | `4d30283ae614e3057f730f67cd088a42be6fdf91f8639d82cb69e48cde80413c` |
| Xray | windows | aarch64 | `Xray-windows-arm64-v8a.zip` | `35d4ed6ec21224fb22b07c2c3f672e2350cd536f2c74d309150175a76365ea88` |
| SingBox | linux | x86_64 | `sing-box-1.13.16-linux-amd64.tar.gz` | `e37c312859dfa84cba148f41072ff6369f08361ae91d622dc1fd3aab49611a8d` |
| SingBox | windows | x86_64 | `sing-box-1.13.16-windows-amd64.zip` | `6cbf90ec4ee87122ffce09b73928fb31e763bc1c75a119f79c61d24734c78807` |
| SingBox | linux | aarch64 | `sing-box-1.13.16-linux-arm64.tar.gz` | `d587fb00bdc3c044227f35d15d154f271bc75108475091eda2542e4b82bb2949` |
| SingBox | windows | aarch64 | `sing-box-1.13.16-windows-arm64.zip` | `8412e9751a776a1cd5138fde8a6b60784af91b0fe596cba1b6efcd05144ef511` |

The two constants are the only peers (D17). A bump is: edit the constants, run
`just oracles-pins`, paste the new table, then run the suite — a red row after a
bump is accepted and triaged separately; it is not a blocker for the bump or for
this extraction. There is no HEAD build, no `LEAS_CORE_HEAD_BIN_DIR`, and
`CoreUnderTest::resolve_from` / `vless_pq_enc_against_head` are deleted with it.

### 3.3 `build.rs` pipeline

| Input / output | Behaviour |
|---|---|
| `cargo:rerun-if-changed=src/pins.rs` + `rerun-if-env-changed` for the three vars | always emitted |
| `LEAS_CORE_BIN_DIR` set | no fetch; emit that path as `LEAS_ORACLES_CORE_DIR` so a build-time-only value still reaches tests |
| `LEAS_ORACLES_SKIP_DOWNLOAD` set | return; no fetch, no env |
| `LEAS_ORACLES_PROXY` (then `ALL_PROXY`/`HTTPS_PROXY`/`HTTP_PROXY`) | optional HTTP/SOCKS proxy for the fetch; prefer a `socks5h://` URL so the proxy resolves the host |
| `HOST` | `x86_64-unknown-linux-gnu`, `aarch64-…-linux-…`, `x86_64-pc-windows-msvc/gnu`, `aarch64-pc-windows-msvc`; anything else = **error** naming the accepted triples |
| output | `cargo:rustc-env=LEAS_ORACLES_CORE_DIR=<OUT_DIR>/core-bin` |

Steps: resolve `pins::asset_name`/`url`/`sha256` → skip when
`<out>/core-bin/<bin><EXE_SUFFIX>` already exists → GET with a ureq agent
configured for the ring provider and webpki roots (redirects followed) →
SHA-256 compare; on mismatch error with expected, actual, and
`run 'just oracles-pins <xray> <singbox>'` → extract by **basename**
(`xray`/`xray.exe`; `sing-box`/`sing-box.exe`; the sing-box tar has a
`sing-box-<v>-<os>-<arch>/` prefix) → write, `0o755` on unix → emit the env.

A failed fetch is fatal (D3). The message names the URL, the env overrides, and
the skip flag, so the recovery is one line.

### 3.4 Module moves

`crates/leas-native/src/e2e/*` moves verbatim to
`crates/leas-oracles/src/e2e/*`; only the crate root changes:

| Old | New |
|---|---|
| `leas_native::e2e::*` | `leas_oracles::e2e::*` |
| `crate::connect` / `connect_udp` / `connect_mux` | `leas_native::{connect, connect_udp, connect_mux}` |
| `crate::{NativeConnectParams, NativeError, BoxStream}` | `leas_native::…` |
| `crate::protocol::vless::PacketMode` | `leas_native::PacketMode` |
| `crate::e2e::config::BODY` | `self::config::BODY` |
| `SINGBOX_VERSION` / `XRAY_VERSION` | `leas_oracles::pins::*`, re-exported from `e2e` |

`CoreKind::bin_name` gains `std::env::consts::EXE_SUFFIX` (today it misses
`xray.exe`, so `Path::is_file()` fails on Windows).
`CoreUnderTest::resolve` precedence: runtime `LEAS_CORE_BIN_DIR` →
`option_env!("LEAS_ORACLES_CORE_DIR")` → error naming both. It is the only
resolver: `resolve_from` and its env-named variant are deleted with the HEAD
peer (D17).

### 3.5 `leas-native` cutover

- Delete `src/e2e/`; remove `pub mod e2e`.
- `Cargo.toml`: replace `native-e2e = ["dep:…"]` with `e2e-support = []`;
  delete the `x25519-dalek`, `tiny_http` and `tokio-rustls` optional deps.
  `rcgen`/`serde_json`/`tempfile` remain only where lib unit tests use them
  (`cargo machete` decides).
- `security/fingerprint.rs` and `transport/quic.rs`: the `TEST_CA`
  thread-local and `set_test_ca` are `#[cfg(any(test, feature =
  "e2e-support"))]`; inside `verifier_for`/`quic_tls_config` only the
  `TEST_CA` branch is gated — the functions themselves stay in production.
- `NativeTunnel::inner_stream`, `VlessClientStream::inner`,
  `VmessClientStream::inner`: `#[cfg(feature = "e2e-support")] #[doc(hidden)]
  pub`, with the `cfg_attr(..., allow(dead_code))` shims removed. No internal
  caller remains (verified); they exist only for the PQ assertion.
- `transport::xhttp::e2e_http_version` is the same kind of doc-hidden wrapper
  around the private `http_version`, because a moved config unit test asserts
  the xhttp3 ALPN decision.

### 3.6 Tests and benches

All eight test files plus `tests/common/mod.rs` move and switch their import
root. The existing `#![cfg(feature = "native-e2e")]` lines are removed (the
files exist only when the crate is built); the `#[ignore]` markers stay.
`probe_e2e`/`ws_paths` stop hardcoding the binary directory and use
`CoreUnderTest::resolve`. The two plugin files keep their
`#[ignore]` + `just plugin-bins` workflow (plugin binaries are not downloaded).

`relay` and `throughput` move to `crates/leas-oracles/benches/`; neither
declares `required-features`; `dispatch` and `ss_codec` stay in `leas-native`.

### 3.7 Gate, CI, docs

- `justfile`: `bench` points at `-p leas-oracles`; the clippy recipe becomes
  `--workspace --exclude leas-oracles`; a new `oracles-check` recipe runs
  `LEAS_ORACLES_SKIP_DOWNLOAD=1 cargo clippy -p leas-oracles --all-targets --
  -D warnings` (kept out of `_gate code`, so adapter drift is checked on
  demand); a new `oracles-pins` recipe queries
  `api.github.com/repos/{XTLS/Xray-core,SagerNet/sing-box}/releases/tags/v<ver>`
  and pairs `"name"`/`"digest"` with awk, printing the 8 rows (no jq, no
  download).
- `.github/workflows/*`: the gate needs no flag — clippy excludes the crate and
  `nextest` uses `default-members`; only `oracles-check` exports the skip flag.
- `cargo hakari generate` after the lockfile changes.
- Docs updated in place: `AGENTS.md` (suite command `cargo nextest run`, crate
  graph), `docs/architecture/architecture.md`,
  `docs/reference/native-core.md`, `docs/reference/crypto-dependencies.md`
  (`x25519-dalek` edge moves), `docs/guides/building.md`, `justfile` comments.
  Historical specs/plans are not edited.

### 3.8 Acceptance

1. `cargo build -p leas-oracles` fetches both archives, verifies both hashes,
   and the extracted binaries print the pinned versions.
2. Corrupting one table entry fails the build with expected-vs-actual; restoring
   it passes (manual one-shot check).
3. `cargo nextest run -p leas-oracles --test probe_e2e --run-ignored ignored-only`
   is green (real xray-core smoke).
4. `cargo nextest run -p leas-oracles --test vless` is green except the
   `xhttp` rows, which the pinned xray rejects with `400 Bad Request` (D17's
   accepted pin drift); all other rows pass.
5. `cargo nextest run` (default members) is green and does **not** build
   `leas-oracles`; `cargo build` at the root likewise.
6. `cargo clippy --workspace --exclude leas-oracles --all-targets --all-features -- -D warnings`,
   `just oracles-check`, `cargo fmt --all --check`, `cargo hakari generate --diff`,
   `cargo machete`.
7. `cargo tree -i aws-lc-rs` stays empty.

---

## 4. Phase 2 — native-only client

### 4.1 Settings

Remove from `AppConfig` (`leas-config/src/app_config.rs`):

| Field | Consumer today |
|---|---|
| `core: CoreConfig` (`xray_path`, `sing_box_path`, `log_level`, `protocol_core_overrides`, `skip_cert_verify`) | oracle builder + core-choice gate |
| `updates: UpdateConfig` (`check_on_startup`, `last_check`, `xray_latest_known`, `sing_box_latest_known`) | core updater |
| `statistics: StatisticsConfig` (`enabled`, `clash_api_port`) | gRPC stats |
| `clash_api_port`, `clash_mixin` (top-level) | clash API surface |

Also remove `SettingsSection::{Core, ProtocolCore, Updates, Stats}` and their
form builders in `ops/settings.rs`/`ui/settings.rs`.

Kept deliberately (D11): `gui`, `inbound`, `tun`, `mux`, `system_proxy`,
`speed_test`, `logging`, `parsing`, `geo`, `purgatory`, `import`, plus the
DB-backed `Routing`/`Dns` sections.

Persistence: `~/.config/leas/config.json` is plain serde JSON with no
`deny_unknown_fields`, so an existing file loads with the removed keys ignored
and `save()` rewrites it without them. No migration, no wipe.

### 4.2 Identity removal and the re-key

`leas-proto`:

- delete `ProtocolEssentials::core_type` and the `tag::CORE_TYPE` write
  (`endpoint.rs:90-95`);
- delete `CoreType` (`proto_spec/mod.rs:101`) and `proto_spec/core_mapping.rs`;
- bump `IDENTITY_VERSION` 3 → 4 (`identity.rs:54`) and re-pin the goldens.

`leas-db` — the detector the database guide says is missing:

- `app_meta.identity_version` becomes the marker; `migrate` calls
  `rekey_identity_once(conn)` after `ensure_raw_ddl` on both the current and
  fresh arms. Absent = 0. Current = no-op.
- The re-key is a marker-guarded data step, **not** a `STEPS` entry:
  `SCHEMA_VERSION` stays 19. `StepKind::Rebuild` remains reserved (it is
  cursor-gated, and an identity-only change must not advance the cursor).
- Algorithm, one immediate transaction:
  1. read every `protocols` row (`id`, `proto_kind`, `config`) and recompute
     `sig`/`cred_hash`/`uid` with the new writer. The row stores `proto_kind`
     + `Json<ProtocolConfig>` and `sig`/`id`, never `core_type`, so the stored
     state is sufficient to recompute the identity;
  2. group old ids by new id and pick each collision group's survivor (the
     **lowest old id**). The re-key is a **full rebuild of `protocols` and
     `profile_stats` into fresh tables, then an atomic rename** — never an
     in-place PK update, because a new id can equal another row's old id
     (permutation/cycle) and `profile_stats` is keyed
     `(protocol_id, endpoint_id)`;
  3. copy the survivors with their new ids; for a loser's `profile_stats` row:
     if the survivor has no row for that endpoint, copy it under the survivor;
     if it does, apply the `merge.rs` link-collision law (measured latency beats
     untested, then the lower `RankLink::key`; the survivor's **traffic
     counters and `purge_reason` are kept**, matching `merge.rs`, so duplicate
     identities cannot double-count) and drop the loser row;
  4. `endpoints.manual_protocol_override` pointing at a loser is re-pointed to
     the survivor;
  5. swap the rebuilt tables in, then refresh `endpoint_rank` for every
     endpoint whose stats changed (`merge.rs` does this after its own re-key:
     the rank row caches the ordering keys and `selected_protocol`);
  6. stamp `app_meta.identity_version = 4`.
- Endpoint rows do **not** move: endpoint identity is
  `stable_hash(canonical_name, port)`, protocol-independent.
- Failures abort the transaction and leave the marker untouched, so the next
  open retries.

### 4.3 Crate split

`leas-core` keeps (D14):

| Keep | Why |
|---|---|
| `log_heed` (879) | TUI log store; native telemetry writes `LogMessage` |
| `grpc_client::SysStats` + `format_bytes`/`format_uptime` | native telemetry + Metrics/Details |
| `speed_test` (346, incl. `TestType`) + `reqwest` | the single Speed test / UDP test dial the **connected native proxy**; `tcp_ping`/`udp_ping` are direct transport probes |
| `ping` (481, incl. the QUIC adapter) + `quinn` (`quic-ping`) | `FastPingManager`/`TcpPingAdapter`/`UdpPingAdapter`/`QuicPingAdapter` are the client's Fast ping; they dial the endpoint directly, never a core |
| `SessionParams { listen, local_port }` (new, replaces `BuildParams` for the client) | native session |

Move to `leas-oracles::oracle_adapters` (compiled whenever the crate is built; D15):

| Move | Size |
|---|---|
| `bin_manager` | 710 |
| `config_builder` (incl. `BuildParams`, `clash_mixin`) | 2,292 |
| `grpc_client` **client half** (`StatsProvider`, `create_stats_provider`, `API_ENDPOINT`, `GrpcError`); `SysStats`/formatters stay | ~200 |
| `build.rs` + `proto/stats.proto` (protox/tonic codegen) | small |
| `process` (`CoreManager`) | 589 |
| `updater` | 769 |
| `core_type` (`CoreType`) + `leas-proto`'s `core_mapping` | 112 + ~300 |

`dns.rs` (48 lines, no consumer) is deleted outright.
`leas-core` keeps `reqwest`, `quinn`, `tokio`, `serde_json`, `futures-util`,
`heed`, `rustls`; the oracle-only edges (`tonic`, `prost`, `zip`, `tar`,
`flate2`, `semver`, `async-trait`) move to `leas-oracles`. The client graph
must not contain tonic/prost.

### 4.4 Client deletions

| File | Action |
|---|---|
| `ops/updates.rs` (164) | delete |
| `ops/core.rs` (empty, 0 bytes) | delete |
| `ops/connect.rs` (1,140) | keep the capability gate + native start; delete `ConfigBuilder`, `RealCoreManager`, `find_binary`, `BuildParams` assembly and the subprocess arm |
| `ops/ping.rs` (5,808) | **no core arm exists** — the file is already native (`ping_native::real_ping`, `FastPingManager`, direct speed/UDP probes through the native inbound). Keep it; only the `connected_core.is_none()` guards become `!connected` |
| `ops/events.rs` (3,310) | drop update progress/available variants and core-progress handling; `Connected(CoreType)` → unit |
| `ops/{scheduler,job_scheduler}.rs` | no core spawn exists; keep the task/job queues, drop only the `CoreType` plumbing |
| `ops/settings.rs`, `ui/settings.rs` | drop the four sections |
| `ui/metrics.rs` | drop `API_ENDPOINT`/core name; keep native traffic, sys stats, activity |
| `ui/status_bar.rs` | drop the core name |
| `state.rs` | `connected_core: Option<CoreType>` → `connected: bool`; delete `update_status`, `resolved_core` |
| `types.rs` | delete `CoreType` imports and the core-update events |
| `ops/native_connect.rs` | `SessionParams` instead of `BuildParams` |

`CoreEvent` keeps its name (the event bus is still the session's); only the
deleted variants go. `TestType` continues to classify native tests.

### 4.5 Unsupported profiles

The capability gate is unchanged (`leas-native::capability`). A row whose
`support_reason(kind, config)` is `Some(reason)` stays in the Profiles view,
renders that reason as its marker, and connect/ping/speed-test refuse with the
same text. No fallback exists, no row is hidden or purged.

### 4.6 Acceptance

1. Migration test: a pre-migration DB seeded with two protocols identical
   except for `core_type` → after open, one protocol remains, its id is the
   recomputed identity, `profile_stats` rows for the shared endpoint are merged
   by the evidence law, `manual_protocol_override` is re-pointed, and a
   non-colliding row's id changes exactly once. The fixture also includes a
   **permutation pair** (new A = old B, new B = old A) to prove the rebuild,
   not an in-place update. Re-opening is a no-op (marker).
2. `cargo run` smoke: native connect; Metrics/Logs/Sniffer populate; Settings
   has no Core/ProtocolCore/Updates/Stats; an unsupported profile is visible,
   marked, and refuses connect with `support_reason`.
3. `cargo nextest run --workspace` green; `LEAS_ORACLES_SKIP_DOWNLOAD=1 cargo
   clippy --workspace --all-targets --all-features -- -D warnings` green;
   `cargo fmt --check`; `cargo hakari generate --diff`; `cargo machete`.
4. `cargo tree -p leas | grep -E 'tonic|prost'` is empty (reqwest stays for the
   native speed test).
5. `cargo build -p leas-oracles` compiles the adapters; `just oracles-check`
   type-checks them offline with the skip flag.

### 4.7 Gate and docs

- `docs/reference/database.md`: step 3's "a re-key has no detector today"
  paragraph is replaced by the detector's contract (marker key, rebuild,
  collision law). `IDENTITY_VERSION` is 4; `SCHEMA_VERSION` stays 19.
- `docs/reference/native-core.md`: the client is native-only; the oracle
  adapters live in `leas-oracles`.
- `AGENTS.md`: crate list and test/bench commands (no core choice, no
  `native-e2e`).
- `docs/architecture/architecture.md`: crate graph and the new dev crate.
- `docs/guides/tui-manual.md`: the Settings tabs `Core`, `ProtocolCore`,
  `Updates`, `Stats` are gone.
- `docs/reference/crypto-dependencies.md`: the `x25519-dalek`/QUIC edges are
  updated by Phase 1/2.
- `cargo hakari generate` after the lockfile changes; `cargo machete` must be
  clean.

---

## 5. Risks and mitigations

| Risk | Mitigation |
|---|---|
| Hard-fail fetch runs whenever the crate is built | the gate excludes the crate; `oracles-check` sets `LEAS_ORACLES_SKIP_DOWNLOAD=1`; a local run fetches once and `OUT_DIR` caches |
| Pin bump with a stale hash table | mandatory check fails loudly with expected/actual; `just oracles-pins` prints the table |
| Re-key data loss on collisions | only provably duplicate rows (same config, different core) merge; survivor = lowest id; link collisions use the existing evidence law; one transaction; marker-gated retry |
| Phase 2 deletes the subprocess arm, the updater and the settings sections (~1–2k lines) and the compiler is the only proof | each phase's acceptance list is run before the next; clippy `--all-features` compiles the moved dead code |
| `aws-lc-rs` sneaks in via ureq | ureq's `rustls` feature is `rustls-no-provider + _ring`; gate asserts `cargo tree -i aws-lc-rs` is empty |
| Proxy/TLS failures on this workstation | documented; official CI runners are unaffected |

## 6. Non-goals

- Running e2e in CI.
- Downloading SIP003 plugin binaries (`just plugin-bins` stays manual).
- macOS support.
- Pin version bumps (user-owned; the table is regenerated after).
- Deleting the never-applied `Tun`/`Mux`/`SystemProxy` config (D11).
- Re-implementing core-as-client orchestration in `leas-oracles` (D15).
- Keeping `native-e2e` as an alias.

## 7. ADR signals

- **New crate + dependency direction**: `leas-oracles` is a dev-only crate;
  `leas-native` keeps a test-support feature. Durable owner boundary.
- **Identity format**: `IDENTITY_VERSION` 3 → 4 and the first marker-guarded
  re-key detector; this is the completion of ADR 0012 D-C's reserved
  `StepKind::Rebuild` purpose.
- **Published API removal**: `leas-proto` loses `CoreType`/`core_mapping` and
  `Protocol::core_type`; `leas-core` loses its oracle modules. 0.x, but it is a
  contract change.
- **Build-time network**: the first build-time fetch in the workspace; pinned
  versions + SHA-256, hard failure, documented overrides.
