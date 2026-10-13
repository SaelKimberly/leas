# Toolchain Portability & Repository Weight — Design Spec

- **Status:** draft — awaiting user review
- **Date:** 2026-10-13
- **Scope:** build configuration, build-dependency graph, CI, contributor documentation, git object store
- **Authority affected:** `.cargo/config.toml`, `rust-toolchain.toml`, `deny.toml`, `.config/hakari.toml`, `justfile`, `crates/leas-core/{Cargo.toml,build.rs}`, `crates/leas-tls/**` (comment), `docs/reference/{crypto-dependencies,native-core}.md`, `docs/history/roadmap.md`, `AGENTS.md`, `docs/aegis/INDEX.md`
- **Frozen by decision:** `docs/aegis/**` (per `docs/INDEX.md:12`) — this spec adds; it never edits `adr/0007-cryptographic-dependency-posture.md`

## 1. Summary

The workspace builds only on a machine that already carries an undeclared toolchain, and its git object store carries ~98 MB of reclaimable weight. Both were measured, not assumed:

- **A — Portability.** The committed `.cargo/config.toml` hard-requires `sccache`, `clang` and `mold` on every machine, injects a host-specific `/tmp` path, and bakes `-Ctarget-cpu=native`; the `leas-core` build script shells out to an external `protoc`; the declared cross-target (`x86_64-pc-windows-gnu`) is unbuildable without an undeclared mingw/zig toolchain and is verified by nothing.
- **B — Weight.** `.git` is 116 MB against ~18 MB of unique packed content; the reclaim does **not** require a history rewrite.

One structural change removes the protoc dependency at its source (`protox` → `prost-build::compile_fds`), and one ownership change makes the fast build path an explicit opt-in (`just fast`) rather than the repository's default.

## 2. Goal / Non-goals / Acceptance

**Goal.** A clean checkout plus the documented prerequisites builds, tests and gates on a machine that has none of this contributor's tooling; the declared targets are the ones CI actually proves; and the repository does not carry three times its own content in git objects.

**Non-goals.**
- No product behaviour change. No proxy/TUI/native logic is touched except where a Windows build *forces* it (§5.4, fix-on-evidence).
- No history rewrite (no `filter-repo`/`filter-branch`), no fixture deletion, no fixture compression (§5.6).
- No restructuring inside `docs/aegis/**`; no edit to ADR 0007 (a new ADR supersedes it **after** §5.4 is proven).
- No new protocol, schema, DB or crypto surface.

**Acceptance.**
1. **Clean-machine proof (local):** from a clean checkout **outside `/home/user`** — so no ancestor `.cargo/config.toml` is read — and with a minimal environment (`CC`, `CXX`, `RUSTC_WRAPPER`, `RUSTFLAGS` unset; `CARGO_HOME` pointing at a directory whose only content is a symlink to the registry cache; a C compiler on `PATH`, since `ring`, `zstd-sys` and `libsqlite3-sys` need one): `cargo build --workspace --all-targets -v` succeeds with no `sccache`/`clang`/`fuse-ld`/`target-cpu=native` anywhere in the log and `cc` as the linker, then a `just quality-gate code` run is green. Zero protoc, zero wrapper.
2. **Codegen parity:** the generated `OUT_DIR` file is byte-identical to the protoc-produced baseline `sha256:e3547e5f170dbbdaf9f1844502927d7c4738fbba9571f43014ad828b1adecbe4` (8601 B), compared across **all** `target/**/build/leas-core-*/out/v2ray*.rs` after a cold rebuild.
3. **CI:** the Linux job runs `just quality-gate-ci` (code + deps) on `ubuntu-24.04` with the gate executed inside an `ubuntu:22.04` container; the Windows job runs `just quality-gate-ci code` on `windows-2022`, blocking. A produced binary's highest required symbol is ≤ `GLIBC_2.35`.
4. **Declared targets are honest:** `rust-toolchain.toml`, `deny.toml [graph] targets` and `.config/hakari.toml platforms` name the same target set CI proves; `cargo hakari generate`/`manage-deps`/`verify` green after each dependency/target change.
5. **Weight:** `git count-objects -vH` after the repack reports a single pack; the loose objects it absorbed are gone (573 remain — all unreachable, deliberately kept), and every ref **and reflog entry** resolves to the same SHA as before (no rewrite).
6. **No stale rationale:** no editable file still justifies a crypto decision by the retired triple; ADR 0013 exists and is registered in `docs/aegis/INDEX.md`.

## 3. Locked decisions (from the design interview)

| # | Decision |
|---|---|
| D1 | The committed `.cargo/config.toml` carries **only portable settings** (`[build] incremental = false`). `rustc-wrapper = "sccache"`, `linker = "clang"` + `-fuse-ld=mold`, `-Ctarget-cpu=native` and `[env] LEAS_CORE_BIN_DIR = "/tmp/core-bin"` are removed. |
| D2 | `just fast <cmd>` owns the speed path (`RUSTC_WRAPPER=sccache`, mold, `-Ctarget-cpu=native`), Linux-guarded. `just bench` and the documented perf-lab command **opt into the same environment**, and the recipe says in-line that perf numbers are only comparable under it. |
| D3 | `protoc` is replaced by **`protox` at build time** (`protox = "0.9"`, not the 5-day-old 0.10.0), wired through `prost-build::compile_fds`. |
| D4 | The declared Windows ABI becomes **`x86_64-pc-windows-msvc`** (user decision, overriding the recommendation to keep `windows-gnu`). |
| D5 | CI: Linux = `code` + `deps`; Windows = **`code` only** (the host-specific half); `deps` stays single-homed on Linux. |
| D6 | The `aegis` workspace is frozen: the ABI change is recorded by a **new ADR (0013)** that amends/supersedes 0007, never by editing 0007. |
| D7 | Repository weight is addressed by **repack only** — no history surgery, no fixture deletion, no compression. |
| D8 | The toolchain keeps floating on `stable`; a **scheduled job** runs `just quality-gate code` against latest stable. The silent-redden risk between runs is accepted. |
| D9 | `justfile` gains an explicit `set windows-shell` (the file has no `set shell` directive, and `_gate`/`bench`/`plugin-bins` are bash-shebang recipes using `set -uo pipefail`, arrays and `case`). |
| D10 | Prove-then-record: the target/triple flip and the CI job land **first**; the five rationale sites are rewritten only once the Windows job is green. |
| D11 | **Binary compatibility floor (confirmed 2026-10-13).** Linux runs on a supported runner but builds and tests inside an **`ubuntu:22.04` build container**, so the glibc floor is 2.35 (the reference machine's) rather than the runner's 2.39. `windows-2022` is pinned. CI never enables `just fast`, so `-Ctarget-cpu=native` cannot leak a runner-only CPU baseline into a binary. Fallback if the container proves awkward: `cargo zigbuild --target x86_64-unknown-linux-gnu.2.35` (floor in the command, not the environment); alternative if GNU coupling is unwanted entirely: `x86_64-unknown-linux-musl` + `+crt-static`. |

## 4. Current-state inventory (evidence)

Observed on this machine, 2026-10-13. Claims carry the check that produced them.

**Portability blockers**

| Finding | Evidence |
|---|---|
| `sccache` is a hard requirement | `PATH=/usr/bin:/bin cargo check -p leas-proto` → `error: could not execute process 'sccache rustc -vV' (never executed)` |
| `clang` + `mold` and `-Ctarget-cpu=native` are applied to every rustc invocation | `cargo build -v` output: `-C linker=clang`, `-Clink-arg=-fuse-ld=mold`, `-Ctarget-cpu=native` |
| `protoc` is required externally | `PROTOC=/bin/false cargo check -p leas-core` → `Error: … "protoc failed: "`; no `protoc-bin-vendored`/`protobuf-src` in `Cargo.lock`; `prost-build` reaches `protoc_from_env` only from `compile_protos` (`prost-build-0.14.4/src/config.rs:1032, 1271`) |
| The declared cross target does not build here | `cargo check --target x86_64-pc-windows-gnu` → `E0463 can't find crate for std` (Homebrew rustc owns only the Linux std); with sccache disabled it fails later at `zstd-sys`'s `cc-rs` (`clang --target=x86_64-pc-windows-gnu`, no mingw sysroot) |
| No CI exists | no `.github/`; `just quality-gate-ci` is written and unused |
| A working cross-build recipe exists but is orphaned | `docs/history/roadmap.md:356-359` (`cargo zigbuild … RUSTC` pointed at the rustup rustc, mingw-capable `llvm-windres`, "builds warning-free") cites an `AGENTS.md § Verification` section that no longer exists after `0d9a458` |
| `bindgen` is **not** a libclang requirement | `turso_sdk_kit-0.8.2/build.rs:8` returns early unless `CARGO_CFG_WINDOWS`; `turso_sync_sdk_kit` ships no `build.rs`; `bindgen` is invoked only by the committed helper `bindgen.sh`; `clang-sys` deps are `glob, libc, libloading` (runtime dlopen) |
| Windows branches exist in code | `#[cfg(not(unix))]` × 6 (`bin_manager.rs:46,100`; `process.rs:69,119,339`; `app_config.rs:325`), `native_connect.rs:240`, `leas-tls/fingerprints/query.rs:118,130,210` |

**Host-level sources a repository change cannot reach** (found while building the clean-machine proof — they are why a naive check lies):

| Source | Evidence | Why it survives a repo fix |
|---|---|---|
| Env `CC`/`CXX` | `CC='sccache clang -fuse-ld=mold -Wno-unused-command-line-argument'`, `CXX='sccache clang++ …'` (+ `SCCACHE_DIR=/disk-ext/.sccache`, `SCCACHE_CACHE_SIZE=20G`) | cc-rs reads `CC`/`CXX` from the environment; cargo config never overrides them |
| `/home/user/.cargo/config.toml` is an **ancestor** config | it carries `linker = "clang"`, `rustflags = ["-Clink-arg=-fuse-ld=mold"]`, `rustc-wrapper = "/home/user/.cargo/bin/sccache"`; with `HOME` **and** `CARGO_HOME` relocated, and again with `env -i`, a plain `cargo build -v` still emits `-C linker=clang` (316 matching lines) | cargo reads `.cargo/config.toml` from the CWD's ancestors, not only from `$CARGO_HOME` — every checkout under `/home/user` inherits it |
| `PATH` | `cargo`/`just` live in `/home/linuxbrew/.linuxbrew/bin`, `cargo-nextest` in `/home/user/.cargo/bin` (the same directory as `sccache`) | stripping `PATH` produces `cargo: command not found`, a defect that is not real |

Consequence: the repository-level removal (D1) is correct but locally **invisible** on this machine, so the clean-machine proof must run from a checkout whose ancestors carry no `.cargo/config.toml` (`/tmp`) under a minimal environment. Note the two wrappers differ: the repository's was a bare `sccache` (which is what failed with *could not execute process `sccache rustc -vV`*), the ancestor's is an absolute path.

**Repository weight** (mirror measurements first, then the real repository)

| Stage | `.git` |
|---|---|
| a throwaway mirror, as copied | 113 MB |
| that mirror after `git gc --prune=now` | 18 MB |
| that mirror after additionally dropping `tests/fixtures` from all history | 7 MB |
| **the real repository after `git repack -adf --window=250 --depth=250` + `prune-packed`** | **69 MB** (116 → 69; pack 58.6 MiB + 573 loose objects, 10.2 MiB raw) |

The mirror's 18 MB is *not* what a plain repack achieves, and the gap is instructive: **421 objects are reachable only through reflogs and they are 157 MiB raw** (`git rev-list --objects --reflog` minus `--all`) — the old snapshot states from 2026-06-18 onward, which delta poorly precisely because they are isolated. The mirror's `gc --prune=now` expired reflogs and pruned them; a plain repack keeps them, and every ref still resolves. Reclaiming that remainder is a separate, user-owned decision (§5.6), not part of the repack.

Tracked tree = 103 MB, of which `tests/fixtures/m1n1-5ub-*.txt` (36 files) = 85.5 MB. Those fixtures are **not** dead weight: `docs/aegis/specs/2026-10-12-docs-and-identity-revamp-design.md` §5 records "Tracked fixtures (do not delete)", and the ss-plugin Tier 1b corpus test plus plan T4 consume them.

**Retired assumptions** (kept as evidence of what was checked): `bindgen ⇒ libclang`; "18 unix-only sites vs 1 `cfg(windows)` site ⇒ Windows needs a port" (wrong predicate — `cfg(not(unix))` is the branch); "a plain `gc` reclaims ~50 MB" (real ≈ 95 MB); "gzip the corpus is free" (compressed blobs cannot delta against their raw predecessors, so it *grows* `.git`).

## 5. Design

### 5.1 Committed configuration (D1, D2, D9)

`.cargo/config.toml` keeps `[build] incremental = false` and nothing host-specific. `just fast <cmd>` becomes the fast path; `just bench` exports the same environment before driving `cargo criterion` (`justfile:131-153`), and both the recipe and the perf-lab invocation documented in `AGENTS.md` state that recorded medians are only comparable under it. `justfile` gains `set windows-shell := ["bash", "-c"]` so the three bash-shebang recipes resolve deterministically on the Windows runner.

`LEAS_CORE_BIN_DIR` loses its `.cargo/config.toml [env]` default (which `just bench` already sets at `justfile:142`); the e2e tests that read it keep their existing skip/panic behaviour.

### 5.2 Removing `protoc` (D3)

`crates/leas-core/build.rs` becomes:

```rust
let fds = protox::compile(["proto/stats.proto"], ["proto"])?;
tonic_prost_build::configure()
    .build_server(false)
    .compile_fds(fds)?;
```

`compile_fds` consumes the builder, so `build_server(false)` must be applied first. `protox::compile` returns `prost_types::FileDescriptorSet`; `protox 0.9` requires `prost`/`prost-types ^0.14`, which unifies with the locked `0.14.4`, so no conversion layer is needed (`tonic-prost-build-0.14.6/Cargo.toml:68-72`). `compile_fds` never runs `protoc` on this path (`prost-build/src/config.rs:826` → `write_file_if_changed`, :1179; `protoc_from_env` is reachable only from `compile_protos`, :1032, :1271).

`protox` is added to `crates/leas-core/Cargo.toml`'s `[package.metadata.cargo-machete] ignored` list alongside `prost`/`tonic-prost`/`tonic-prost-build` (build-script-only use is invisible to machete). `protox::Error` implements `std::error::Error` (verified on docs.rs 0.9.1), so the existing `fn main() -> Result<(), Box<dyn std::error::Error>>` signature stays valid and needs no `miette` dependency. Because `leas-hakari` carries a `[build-dependencies]` block (`crates/leas-hakari/Cargo.toml:122`), the new build-dep must be followed by `cargo hakari generate` + `manage-deps` + `verify`. `proto/stats.proto` has no `import`, so no include path for well-known types is required.

Verification is the byte parity of §2.2, not a green build.

### 5.3 Decision flow for the ABI (D4, D10)

`x86_64-pc-windows-msvc` replaces `x86_64-pc-windows-gnu` in `rust-toolchain.toml` `targets`, `deny.toml [graph] targets` and `.config/hakari.toml platforms`; `cargo hakari generate` follows. The Windows runner provides nasm (ring 0.17.14 assembles via `NASM`/`WIN32N` — `build.rs:216,237-238`, and cannot use `.S` on Windows, `:455`) and the VS build tools' `rc.exe` (`turso_sdk_kit`'s version-resource step, `build.rs:60-72`).

**Known cost, accepted:** `windows-gnu` is load-bearing in five authority sites — `adr/0007` §1, `crypto/mlkem.rs:8-15`, `leas-tls/Cargo.toml:48-51`, `crypto-dependencies.md:90-94`, `native-core.md:71-76,108-111` — each justifying the RustCrypto-over-liboqs swap by the triple's inability to assume CMake/libclang/C++. Those five must be re-derived under msvc, and the recorded gnu cross recipe (`roadmap.md:356-359`) must be marked obsolete. Per D10 this rewrite happens **after** the Windows job is green, because msvc buildability is untestable from this host: the CI run is the experiment.

### 5.4 Windows fallout (fix on evidence only)

Three items are already recorded as open in `roadmap.md` §Phase 27 and are *not* in scope unless the blocking gate demands them: `bin_manager::find_binary` searches `PATH` through `which` and matches extensionless `xray`/`sing-box` (not `xray.exe`); `updater::release_asset_url`/`asset_name` are Linux-only; `proc_rss_bytes` is Linux-only by design. Two test-side hazards are known: `crates/leas-core/src/updater.rs:641` writes and runs a `#!/bin/sh` script, and `/tmp` literals appear in unit tests (`process.rs:537,578`; `forms.rs:3184`; `resolve.rs:282`).

### 5.5 CI (D5, D8)

| Job | Runner | Command |
|---|---|---|
| lint + test | `ubuntu-24.04`, **inside an `ubuntu:22.04` container** | `just quality-gate-ci code`, then a release build asserted against the `GLIBC_2.35` floor |
| dependency hygiene | `ubuntu-24.04`, host (no container) | `just quality-gate-ci deps` |
| lint + test | `windows-2022` | `just quality-gate-ci code` (blocking) |
| stable-drift | the same Linux image + container, weekly schedule | `just quality-gate-ci code` on latest `stable` |

The container carries only the job that produces artifacts: `deps` reads `deny.toml [graph] targets` / `.config/hakari.toml platforms` plus the registry, so it is host-independent and a second environment would add provisioning cost with no signal.

Line endings are a Windows prerequisite the first CI run exposed: git's Windows default `core.autocrlf=true` rewrites the checkout to CRLF, and `rustfmt.toml` pins `newline_style = "Unix"`, so `cargo fmt --check` fails before anything compiles. The repository therefore carries a `.gitattributes` (`* text=auto eol=lf`, with the `.bin` fixtures marked binary) rather than relying on each runner's git configuration.

**Runner images are pinned to a generation, not `-latest`** (user decision, 2026-10-13: wider compatibility over newest tooling). `windows-2022` settles the Windows half. On Linux the durable pin is the *container*, not the runner label: `ubuntu-22.04` began runner deprecation **2026-09-17** and is unsupported from **2027-04-17** ([actions/runner-images#14254](https://github.com/actions/runner-images/issues/14254)), so pinning the label buys a few months and then breaks, while pinning the container holds the floor indefinitely.

**The floor is measured, not hypothetical.** The reference machine is Linux Mint 21.3 (Ubuntu 22.04 base) with **glibc 2.35** (`ldd --version`: `Ubuntu GLIBC 2.35-0ubuntu3.15`, kernel 6.8.0-138). glibc is forward-compatible only, so a binary linked against `ubuntu-24.04`'s 2.39 will not start there. Measured on the existing build: `objdump -T target/debug/leas | grep -o 'GLIBC_[0-9.]*' | sort -uV | tail -1` → **`GLIBC_2.34`**, i.e. the current build already sits below 2.35 and the check discriminates (a 2.39-linked build would report 2.38+).

**D11 (confirmed):** keep the runner current and run the gate inside an `ubuntu:22.04` container, so the floor is a property of the environment rather than a label GitHub retires — and the tests exercise the user's libc, not a newer one. Equivalent alternatives if the container proves awkward: `cargo zigbuild --target x86_64-unknown-linux-gnu.2.35` (floor in the command; reuses a tool the project already used for the Windows cross target, though the msvc switch removes that other use), or `x86_64-unknown-linux-musl` + `+crt-static` (no glibc coupling at all, at the cost of changing the runtime's libc). Note the crates publish as source, so the floor binds only for binaries CI produces.

`-Ctarget-cpu=native` must never be present in a CI build for the same reason in the CPU dimension: a runner-only baseline (AVX-512 on a modern host, for instance) produces a binary the reference machine may refuse to execute. D1 removes it from committed config; CI does not opt into `just fast`.

The stable-drift job stays on whichever image the full gate uses, so the only variable it isolates is the toolchain.

`deps` is single-homed because its inputs are config- and registry-derived (`deny.toml [graph] targets`, `.config/hakari.toml platforms`, source + registry for machete/outdated/audit); a second OS adds provisioning cost and no signal. The toolchain stays unpinned (D8), so the weekly job is the only guard against a stable promotion silently reddening the gate.

### 5.6 Repository weight (D7)

`git repack -adf --window=250 --depth=250` + `prune-packed` only: **the real repository went 116 MB → 69 MB** (pack 57.41 → 58.62 MiB absorbing the loose set; 5814/53.70 MiB loose → 573/5.21 MiB, all of them unreachable objects kept for recovery), with every ref and reflog entry still resolving to the same SHA. A plain `-ad` gave 60.0 MiB and the deeper delta window bought 1.4 MiB on top, so the pack is not delta-starved — it is carrying the 421 reflog-only objects that are **157 MiB raw**. Those, not the fixtures, are where the remainder sits: expiring reflogs (`git reflog expire --expire=now --all`, then `repack --prune`) would reclaim roughly the mirror's extra 50 MB without changing any reachable commit or clone, but it destroys local recovery of those states — **its own decision, deliberately not taken** (the mirror's 18 MB figure came from a `gc --prune=now` that did exactly this). Fixtures stay tracked and untouched; no compression, because gzipping tracked blobs would add ~19 MB of non-delta-able content on top of the ~11 MB of raw revisions. History *surgery* stays rejected as a ~11 MB vanity item (`grep -rn 'filter-repo\|filter-branch\|history rewrite' docs` → 0 hits at design time; no spec owns it).

### 5.7 Documentation (D2, D6, D10)

- A build/prereq surface returns somewhere authoritative: `docs/guides/building.md` (the revamp taxonomy puts task-oriented instructions in `guides/`), a row in `docs/guides/INDEX.md`, and an `AGENTS.md` External References row — its predecessor, the `AGENTS.md § Verification` section, was dropped in `0d9a458` and now survives only as `docs/history/roadmap.md:357`. The guide carries the detail; AGENTS.md stays at one pointer row and does not grow.
  - **Build:** rustup + the `rustfmt`/`clippy` components, a C compiler (`ring`, `zstd-sys`, `libsqlite3-sys`), no `protoc`, no sccache/clang/mold unless opting into `just fast`, and `LEAS_CORE_BIN_DIR` (defaulted by `just bench` at `justfile:142`, not by cargo config).
  - **Gate:** `just` plus `cargo-nextest` (the suite), `cargo-hakari`, `cargo-deny`, `cargo-machete`, `cargo-audit`, `cargo-outdated` (the `deps` half needs the last four).
  - **Auxiliary recipes:** `python3` for `crates/leas-tls/src/fingerprints/catalog/gen_specs.py`; a `git`/`curl`/`tar` toolchain plus `libev` (or a user prefix) and `libtool`-style build tools for `just plugin-bins`, which fetches a prebuilt `v2ray-plugin` and builds `simple-obfs` from source.
  - **Perf qualifier:** recorded benchmark medians are only comparable under `just fast` / `just bench`; a plain `cargo` build moves `-Ctarget-cpu=native` out of the picture.
- `docs/history/roadmap.md`'s gnu recipe and Phase-27 ✅ line are marked obsolete/superseded rather than deleted.
- ADR `0013-public-toolchain-abi.md` (or the plan's final title) amends/supersedes 0007's ABI premise, plus a registry row in `docs/aegis/INDEX.md` — written after §5.3 proves out.

## 6. Verification

| Claim | Check | Where |
|---|---|---|
| Clean machine builds | fresh `CARGO_TARGET_DIR`, `PATH` without sccache/clang/mold, `PROTOC` unset → `cargo build --workspace --all-targets`, then `just quality-gate code` | local, before CI |
| Codegen unchanged | `sha256sum` of every `target/**/build/leas-core-*/out/v2ray*.rs` vs the baseline hash | local |
| Fast path still works | `just fast cargo check -p leas-core` succeeds; `just bench micro` runs with the flags applied | local |
| Deps graph consistent | `cargo hakari generate --diff`, `manage-deps --dry-run`, `verify`; `cargo deny check bans licenses sources`; `cargo machete --with-metadata` | `just quality-gate deps` |
| Targets honest | CI green on both runners; `grep` the three config files for the same triple | CI |
| Weight reclaimed | `git count-objects -vH` before/after; `git rev-parse` on all refs unchanged | local |
| Binary stays runnable on the reference machine | `objdump -T <bin> \| grep -o 'GLIBC_[0-9.]*' \| sort -uV \| tail -1` ≤ `GLIBC_2.35` (measured today: `GLIBC_2.34`) | CI + local |
| No stale rationale | `grep -rn 'windows-gnu'` over editable docs/comments → only deliberate history mentions | local |

## 7. ADR signals

- **Public contract / compatibility boundary:** the Windows ABI and the supported target set become the project's declared public surface.
- **Owner/contract:** `protoc` ceases to be a build prerequisite; the build-dependency graph gains `protox`.
- **Dependency direction:** speed-affecting rustflags move from committed config to an opt-in recipe, making the recorded performance medians environment-qualified.
- **Retirement:** the gnu rationale set (five sites) and the recorded gnu recipe retire **only after** ADR 0013 lands; no accepted architecture memory is created from an unproven ABI.

## 8. Risks / rollback

| Risk | Treatment |
|---|---|
| msvc hits a wall (a C dependency without an MSVC path, nasm/`rc.exe` provisioning) | D10 ordering: the flip + job land first; if the experiment fails, revert to `windows-gnu` and adopt the recorded gnu recipe + the Q4 option-1 shape |
| Windows-only test failures (shell scripts, `/tmp` literals) | §5.4; fix-on-evidence, each fix its own commit |
| Recorded perf medians lose comparability | D2 — `just bench` opts into the fast env, stated in the recipe |
| Floating toolchain reddens the gate between weekly runs | Accepted (D8); the weekly job shortens discovery |
| Pinned runner image reaches end of life (the `ubuntu-22.04` trap) | Pin a generation **deliberately** and record the reason + review trigger; prefer a container-based glibc floor so the pin is not the thing that expires |
| Repack breaks a local clone's expectations | Non-destructive: same commits, same SHAs; `git repack -a -d` is recoverable from any existing clone |

## 9. Phasing

| Phase | Content | Exit test |
|---|---|---|
| S1 | Portable `.cargo/config.toml`, `just fast`, `set windows-shell`, bench/perf-lab coupling, bench-env docs | local clean-machine proof (acceptance 1) |
| S2 | `protox` + `compile_fds`, machete list, hakari regen | byte parity (acceptance 2) + `just quality-gate code` |
| S3 | Triple flip in three configs, hakari regen, Windows CI job | CI green on both runners (acceptance 3, 4) — the experiment |
| S4 | Five rationale sites, ADR 0013 + registry row, roadmap obsolescence, build/prereq doc | acceptance 6 |
| S5 | `git repack -a -d` | acceptance 5 |

## 10. Evidence-dependent items (not open decisions)

1. Whether msvc actually builds — S3's CI run decides; the fallback is §8's first row.
2. Which Windows tests fail — S3's first run enumerates them; §5.4 fixes only what blocks.
3. Whether `bindgen`/`clang-sys` leaves the graph when `turso_sdk_kit`'s build-dep is reconsidered — out of scope; noted in `crypto-dependencies.md:93-94` already.

## 11. Sources

- Measurements and probes: this session's transcript (2026-10-13), commands as cited in §4.
- Baseline docs: `docs/INDEX.md`, `docs/aegis/BASELINE-GOVERNANCE.md` §1, `docs/aegis/specs/2026-10-12-docs-and-identity-revamp-design.md` (§5 fixtures, §9 publishing, §10 phasing), `docs/aegis/plans/2026-10-12-docs-and-identity-revamp.md` (executed).
- External: `protox` 0.9.1/0.10.0 (crates.io index), `prost-build` 0.14.4, `tonic-prost-build` 0.14.6, `ring` 0.17.14, `turso_sdk_kit` 0.8.2 sources as vendored in `~/.cargo/registry`.
