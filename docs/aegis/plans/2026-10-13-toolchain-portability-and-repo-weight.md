# Toolchain Portability & Repository Weight — Implementation Plan

- **Status:** draft — awaiting execution
- **Date:** 2026-10-13
- **Parent spec:** `specs/2026-10-13-toolchain-portability-and-repo-weight-design.md` (D1–D11, all confirmed)
- **Route:** inline (`executing-plans`); no independent task boundaries — every task edits shared config, the workspace manifest graph, or CI
- **User confirmation required:** no

## Goal

A clean checkout plus the documented prerequisites builds, tests and gates on a machine that has none of this contributor's tooling; the declared targets are the ones CI proves; and the repository stops carrying 3× its own content in git objects. Acceptance lives in the spec §2 and §6; this plan only sequences it.

## Architecture / Tech Stack

Rust 2024 workspace, `cargo` + `just`, 12 crates, cargo-nextest for the suite, `cargo hakari` for the workspace-hack, `cargo-deny`/`machete`/`audit`/`outdated` for dependency hygiene, GitHub Actions for CI (none exists today). Codegen: `tonic-prost-build` + `prost-build` in `crates/leas-core/build.rs`, currently driving an external `protoc`.

## Baseline / Authority Refs

- Spec `docs/aegis/specs/2026-10-13-toolchain-portability-and-repo-weight-design.md` — D1–D11, evidence tables, acceptance.
- `AGENTS.md` — commands, `cargo clippy -p <crate>` trap, "the toolchain floats on stable", "regenerate leas-hakari after any `Cargo.lock` change".
- `docs/INDEX.md:12` — `docs/aegis/**` is frozen. ADR 0007 is amended, never edited.
- `docs/aegis/specs/2026-10-12-docs-and-identity-revamp-design.md` §5 (fixtures: do not delete) and §9 (publishing order) — both constrain this plan.
- `docs/history/roadmap.md:356-359` + Phase 27 — the gnu cross recipe and the three open Windows items.

## Compatibility Boundary

- Declared targets: `x86_64-unknown-linux-gnu` + `x86_64-pc-windows-msvc` (after T7). No other triple is claimed.
- glibc floor 2.35 for Linux artifacts (T8), held by the build container.
- Public surface unchanged: crate names, binary name, env vars, config dir, DB schema, `#![forbid(unsafe_code)]`, crypto posture.
- Generated protobuf code must stay byte-identical (T6).
- Fixtures, `deny.toml` license policy, and the published crate set are untouched except where T7's target list requires.

## TDD Route

- Mode: `auto`.
- Decision: **`skipped`** for T1–T4, T7–T13 (config, CI, docs, git maintenance — verification is the command output, not a test).
- Decision: **`strict`** for T5/T6 (the codegen path changes: the parity check is the regression signal, written to fail before the swap and pass after) and for any T9 fallout fix that changes runtime behavior (a Windows-visible behavior change earns its own regression test).
- Authority: repo convention (AGENTS.md: a test earns its place by discriminating a plausible consumer-visible bug) + the spec's byte-parity acceptance.

## Requirement Ready Check

`ready` — approved spec with confirmed decisions D1–D11, observable acceptance in spec §2/§6, no decision-changing unknown (the two evidence-dependent items, spec §10, are CI discoveries with pre-agreed fallbacks).

## Change Necessity

- T1–T3, T7, T10–T11: **config/docs** — no code path changes; the defect is in what the repository declares.
- T5: **code required** — `build.rs` is the only owner of the protoc invocation; no config or docs change can remove that dependency.
- T8: **new surface** — `.github/workflows/` does not exist; the repository has no automation to edit.
- T13: **git maintenance** — object-store operation, no source change.

## Ripple Signal Triage

Fires on several surfaces:

- **Dependency graph / build-dep:** T5 adds `protox`; `leas-hakari` carries a `[build-dependencies]` block (`Cargo.lock` + generated hack crate both change) → T6 regen.
- **Public compatibility surface:** T7 changes the declared ABI → three config files + five rationale sites + a superseding ADR; `cargo package`/`deny` graph targets move with it.
- **Producer/consumer:** the `.cargo/config.toml` flags have consumers in `justfile` (bench, plugin-bins) and in every developer's shell → T2/T3 move them deliberately.
- **Retirement:** host-tuned flags retire now; the gnu rationale set retires at T11 (after T9 proves msvc).

## Plan Pressure Test

Owner fit is clean (build script owns codegen; `justfile` owns task recipes; `.github` owns CI; `docs/guides` owns contributor instructions). Verification is exact and command-shaped. Every task is executable in sequence; T9 is the only one whose exit depends on an external service.

## Tasks

### S1 — Portable configuration

**T1 — `.cargo/config.toml` becomes portable-only.**
*Files:* `.cargo/config.toml`.
*Change:* keep `[build] incremental = false`; delete `rustc-wrapper`, the `[target.'cfg(target_os = "linux")']` `linker`/`rustflags`, and the `[env] LEAS_CORE_BIN_DIR` entry.
*Verification:* (a) `cargo build -p leas-proto` in the repository with the default environment still succeeds — verified, `Finished dev profile … in 50.51s`; (b) a plain `cargo build -v` now emits **zero** `-Ctarget-cpu=native` (the only flag that lived solely in the repository config) — verified; (c) the portable claim itself is proven by T4, not here.
*Note:* the `clang`/`mold` lines a plain build still shows come from the host's `CC`/`CXX` environment and the **ancestor** `~/.cargo/config.toml`, neither of which a repository change can reach. On this host local DX is therefore unchanged by T1 — which is also why T4 must run outside the home tree.
*Risk:* none to shipped code.

**T2 — `just fast` + bench coupling + shell declaration.**
*Files:* `justfile`.
*Change:* add `set windows-shell := ["bash", "-c"]`; add `fast <cmd>` exporting `RUSTC_WRAPPER=sccache`, molded `RUSTFLAGS` (`-Clink-arg=-fuse-ld=mold -Ctarget-cpu=native`, Linux-guarded via `uname`) and the `LEAS_CORE_BIN_DIR` default; make `bench` export the same environment before `cargo criterion` (it already sets `LEAS_CORE_BIN_DIR`, `justfile:142`).
*Verification:* `just fast cargo check -p leas-proto` green; `cargo build -v -p leas-proto | grep -o 'linker=clang'` only when run through `just fast`.
*Risk:* none to shipped code. Note in the recipe that perf numbers are only comparable under this env (T10 documents it).

**T3 — `plugin-bins` is unaffected by the `[env]` removal.**
*Files:* `justfile` (verification only; change only if the assumption below is false).
*Change:* none expected — the recipe reads `LEAS_PLUGIN_BIN_DIR` (`justfile:197`), a different variable from the removed `[env] LEAS_CORE_BIN_DIR` default, and calls `curl`/`tar`/`make` directly rather than through cargo. The task exists so the removal is verified rather than assumed.
*Verification:* `just plugin-bins` reaches its download step (network-permitting) and fails at nothing related to a missing cargo-config default.

**T4 — clean-machine proof (spec acceptance 1).**
*Change:* none — evidence run.
*Why the obvious command is wrong:* three host sources cannot be neutralized from inside the repository, and each one makes a naive check lie:

| Source | Effect | Why a repo fix misses it |
|---|---|---|
| `CC='sccache clang -fuse-ld=mold -Wno-unused-command-line-argument'`, `CXX='sccache clang++ …'` (this shell) | every cc-rs C build goes through sccache + clang + mold | cc-rs reads `CC`/`CXX` from the environment, not from cargo config |
| `/home/user/.cargo/config.toml` | carries `linker="clang"`, `rustflags=["-Clink-arg=-fuse-ld=mold"]`, `rustc-wrapper="…/sccache"` | it is also an **ancestor** config for every checkout under `/home/user`, so it applies regardless of `CARGO_HOME`/`HOME` |
| `PATH` | `cargo`, `just`, `cargo-nextest` do not live in `/usr/bin:/bin`, and `cargo-nextest` shares a directory with `sccache` | stripping `PATH` makes the run fail with `cargo: command not found` — a fake portability defect |

*Verification:* copy the working tree outside `/home/user` and run it in a minimal environment:

```
mkdir -p /tmp/clean-clone && cd /home/user/oss/xray-tui \
  && git ls-files -z | tar --null -T - -cf - | tar -xf - -C /tmp/clean-clone
mkdir -p /tmp/clean-cargo && ln -sfn ~/.cargo/registry /tmp/clean-cargo/registry
cd /tmp/clean-clone
env -i PATH=/usr/bin:/bin:/home/linuxbrew/.linuxbrew/bin:/home/user/.cargo/bin \
    HOME=/tmp/cleanhome TERM=dumb CARGO_HOME=/tmp/clean-cargo CARGO_TARGET_DIR=/tmp/clean-target \
    cargo build --workspace --all-targets -v 2>&1 | tee /tmp/clean.log
grep -cE 'sccache|-fuse-ld=mold|target-cpu=native|linker=clang' /tmp/clean.log   # must be 0
grep -oE '\-C linker=[^ ]*' /tmp/clean.log                                        # must be empty (rustc default)
```

then `env -i … just quality-gate code` in the same clone. `git ls-files | tar` copies *tracked* files from the working tree (so uncommitted edits are included) and nothing from `target/`.
*Cost:* a cold workspace build with no sccache — tens of minutes.

### S2 — Remove the `protoc` dependency

**T5 — `protox` replaces `protoc` (strict).**
*Files:* `crates/leas-core/Cargo.toml`, `crates/leas-core/build.rs`.
*Change:* `[build-dependencies] protox = "0.9"`; `build.rs` → `let fds = protox::compile(["proto/stats.proto"], ["proto"])?;` then `tonic_prost_build::configure().build_server(false).compile_fds(fds)?;`. Add `protox` to `[package.metadata.cargo-machete] ignored`.
*Why code:* the build script is the sole owner of the invocation; `protoc` is an executable dependency, not a config value.
*Verification (RED first):* `PROTOC=/bin/false cargo check -p leas-core` must fail with `protoc failed:` **before** the change and succeed after — that is the discriminating pair. Then the parity check in T6.

**T6 — parity, hygiene, hakari.**
*Files:* `Cargo.lock`, `crates/leas-hakari/Cargo.toml` (generated).
*Change:* none manually — `cargo hakari generate` + `manage-deps` + `verify`.
*Verification:* cold rebuild (`CARGO_TARGET_DIR=$(mktemp -d)`) then, for every `target/**/build/leas-core-*/out/v2ray*.rs`, `sha256sum` must equal `e3547e5f170dbbdaf9f1844502927d7c4738fbba9571f43014ad828b1adecbe4`. `just quality-gate deps` green (deny licenses with `protox`/`miette`/`prost-reflect` in the graph).
*Measured (2026-10-13):* GREEN `PROTOC=/bin/false cargo check -p leas-core` → `Finished dev profile … in 1m 15s` (paired with the RED `protoc failed:` + exit 1); `cargo hakari generate` → *contents updated*, `manage-deps --dry-run` → *no operations*, `verify` → *works correctly*; parity **byte-identical** (`e3547e5f…adecbe4` from both the fresh `protox` output and the saved protoc baseline); `just quality-gate deps` → **5/5 passed**.
*Unexpected churn, characterized (four probes on a throwaway clone of the pre-T5 tree, `cargo hakari generate --diff` each time):*

| Probe | Diff |
|---|---|
| control (unmodified tree) | empty — so the committed file matched hakari 0.9.39 before the change; not staleness, not version drift |
| `protox = "0.9"` added to `leas-core` build-deps | removes `bytes` **and** `prost`, from both sections |
| `prost-reflect = "0.16"` (protox's own dep) | removes `prost` only |
| `bytes = "1"` | removes `bytes` only |
| `once_cell = "1"` (already build-dep-reachable) | empty |

The removal tracks exactly which crates the new **build-dependency edge** brings in: introducing `X` as a build-dep of a member drops `X` from the workspace-hack set, and a crate already in that state (`once_cell`) is unaffected. `protox` itself is never added. Consistent with all five rows; the internal rule is not documented by hakari, so the effect is stated as observed. Consequence to weigh: those two crates stop being feature-unified through the hack crate — which is why the code gate (build + clippy `--all-features` + nextest) is a required check, not a formality.
*Commit shape:* the regenerated `crates/leas-hakari/Cargo.toml` lands as **its own commit** (T6), separate from T5's manifest + `build.rs` + `Cargo.lock`, so the generated-file churn is reviewable on evidence rather than folded into the protox swap.
*Retirement:* the `protoc` requirement retires here; the CI image no longer installs it.

### S3 — Declared ABI + CI (the experiment)

**T7 — flip the triple.**
*Files:* `rust-toolchain.toml`, `deny.toml`, `.config/hakari.toml`, `crates/leas-hakari/Cargo.toml` (generated).
*Change:* `x86_64-pc-windows-gnu` → `x86_64-pc-windows-msvc` in all three configs; `cargo hakari generate` after.
*Verification:* `cargo hakari generate --diff` empty; `cargo deny check bans licenses sources` green; `grep -rn 'windows-gnu' rust-toolchain.toml deny.toml .config/hakari.toml` → 0 hits.
*Risk:* this commit knowingly leaves the five rationale sites stale until T11 — one change, ordered internally (spec D10).
*Measured (2026-10-13):* `x86_64-pc-windows-gnu` → `x86_64-pc-windows-msvc` in `rust-toolchain.toml`, `deny.toml` and `.config/hakari.toml`; `cargo hakari generate` → *contents updated*, `--diff` empty, `manage-deps --dry-run` → *no operations*, `verify` → *works correctly*; `cargo deny check bans licenses sources` → *bans ok, licenses ok, sources ok*; `cargo machete --with-metadata` → no unused dependencies (so the `protox` ignore-list entry is doing its job). The regenerated hack crate's only target-level change is exactly the pair of sections: `[target.x86_64-pc-windows-gnu.dependencies]` and `[…build-dependencies]` → `…msvc`, on top of T6's `bytes`/`prost`/`regex-automata` churn.

**T8 — CI workflows (new surface).**
*Files:* `.github/workflows/ci.yml`, `.github/workflows/stable-drift.yml` (or one file with a schedule trigger).
*Change (landed):* `.github/workflows/ci.yml` — three jobs: `code-linux` (`ubuntu-24.04` with `container: ubuntu:22.04`, installing a C toolchain, rustup via the official script so it resolves `rust-toolchain.toml`, then `just` + `cargo-nextest`), `code-windows` (`windows-2022`, `bash` shell, `choco install nasm` + its directory appended to `GITHUB_PATH` for ring's perlasm, then the `code` gate), `deps` (`ubuntu-24.04` host, installing `just cargo-hakari cargo-machete cargo-deny cargo-audit cargo-outdated`, then `just quality-gate-ci deps`). The `code-linux` job additionally **builds a release binary and asserts the floor** — `cargo build --release -p leas`, then `objdump -T target/release/leas | grep -o 'GLIBC_[0-9.]*' | sort -uV | tail -1` compared against `GLIBC_2.35` — because the `code` gate only ever produces test binaries and the floor would otherwise be an unverified claim. `.github/workflows/stable-drift.yml` — weekly + dispatch, `RUSTUP_TOOLCHAIN: stable` (which beats `rust-toolchain.toml`), `rustup update stable`, then the `code` gate in the same container. No job invokes `just fast`.
*Verification:* both files parse and expose the intended triggers/jobs (`code-linux`, `code-windows`, `deps`; `stable-drift`) — checked with a YAML load, since `actionlint` is not installed here. The real acceptance is the first CI run, which cannot be triggered from this machine: **T8 and T9 are blocked on the user pushing the branch.**
*Open risks for the first run (expected fallout, not surprises):* `actions/checkout` inside an `ubuntu:22.04` container needs `git` (installed) and the runner's Node for JS actions; `cargo install --locked` of six tools dominates wall-clock on a cold cache; nothing caches `target/` yet.

**T9 — absorb what the CI run surfaces (evidence-driven).**
*Change:* only if required. Candidates already known: `crates/leas-core/src/updater.rs:641` (`#!/bin/sh` test), `/tmp` literals in unit tests (`process.rs:537,578`, `forms.rs:3184`, `resolve.rs:282`), `bin_manager` `PATH`/`which`/`.exe` naming.
*Measured — CI run #1* (`ci` #1, id `38370247990`, branch `portability/msvc-ci`, sha `1f7ad2e`):

| Job | Outcome |
|---|---|
| `deps` | **success** on the first attempt — hakari-check, deny, machete, outdated and audit all green on a clean runner, with msvc in the graph and the regenerated hack crate |
| `code-linux` | failed on **one** test: `leas-native transport::xhttp::tests::h3_packet_up_seq_order_and_chunking` — 2368 run, 2367 passed, 1 failed |
| `code-windows` | failed at `cargo fmt --check`: *"Incorrect newline style"* for every file — git's Windows default `core.autocrlf=true` rewrites the checkout to CRLF while `rustfmt.toml` pins `newline_style = "Unix"` |

Both failures are environmental, and neither is a portability wall — but note the msvc experiment is **still unproven**: the Windows job died in fmt before clippy or nextest ever compiled anything.

*Fix 1 — CRLF.* New `.gitattributes`: `* text=auto eol=lf` plus `*.bin binary` (the four `crates/leas-route/tests/fixtures/*.bin` captures). This is the durable fix — it also protects Windows contributors — and existing Windows clones need one `git add --renormalize .`.
*Fix 2 — the pacing flake.* `assert_chunked_uploads` asserted `t1 - t0 ≥ 25 ms` on *server-arrival* timestamps. That bound is unsound: the client paces POST **starts** (`xhttp.rs:589-594` sleeps to `POST_INTERVAL` before stamping the next POST), so a first send that outlasts the window compresses the arrival delta while the client is correct — CI observed 12 ms against a 30 ms interval. A first attempt (anchoring on the upload start) was **rejected by its own mutation test**: with the sleep removed the test still passed, because the idle-window flush spaces the two POSTs anyway. The landed version records the client's own stamps in a `#[cfg(test)] static POST_STARTS` and asserts consecutive *client* starts are ≥ 25 ms apart. Mutation-verified: sleep removed → `FAIL … got 12.889835ms`; restored → pass. Sound because the sleep makes consecutive stamps ≥ `POST_INTERVAL` apart by construction, and scheduling can only widen that.
*Measured — CI run #2* (`38373382661`, sha `a4964d3`): `deps` green; **`code-linux` green in every step, including the release-floor check** — the `GLIBC_2.35` floor is now asserted by an executing check rather than claimed; `code-windows` **reached clippy**, i.e. the msvc toolchain compiles the workspace and the only failures were two lints on Windows-only `cfg` paths that had never been compiled before:

1. `crates/leas-core/src/updater.rs:502` — `unused import: use rstest::rstest`, because the module's only `#[rstest]` row sits behind `#[cfg(unix)]` → the import is now `#[cfg(unix)]`.
2. `crates/leas/src/ops/native_connect.rs:241` — `clippy::missing_const_for_fn` on the `#[cfg(not(target_os = "linux"))]` `proc_rss_bytes` stub → now `const fn`.

Both fixed and locally verified: `cargo clippy -p leas-core -p leas --all-targets --all-features -- -D warnings` clean, `updater` rows 9/9. Windows `nextest` is the remaining unknown; so far nothing indicates an msvc wall — no CMake, ring, nasm or `rc.exe` failure, and the whole compile phase passed.
*Verification:* `just quality-gate code` green on the change (fmt, clippy `--all-features`, nextest).
*Fallback:* if msvc cannot be made green, revert T7 and adopt the gnu recipe from `roadmap.md:356-359` with the Q4-option-1 job shape — record the outcome either way.

### S4 — Record the decision

**T10 — restore the contributor build surface.**
*Files:* `docs/guides/building.md` (new), `docs/guides/INDEX.md`, `AGENTS.md` (one External References row).
*Change:* prerequisites (rustup + `rustfmt`/`clippy`, a C compiler, **no protoc**, no sccache/clang/mold unless opting into `just fast`), the gate tooling list, auxiliary recipes (`python3`, `plugin-bins` needs), `LEAS_CORE_BIN_DIR`, the CI jobs, and the perf-median qualifier.
*Verification:* every command in the guide runs as written on this machine; `AGENTS.md` grows by exactly one row.

**T11 — retire the gnu rationale (four editable sites).**
*Files:* `crates/leas-tls/src/crypto/mlkem.rs:8-15`, `crates/leas-tls/Cargo.toml:48-51`, `docs/reference/crypto-dependencies.md:90-94`, `docs/reference/native-core.md:71-76,108-111`; `docs/history/roadmap.md:356-359` + Phase-27 ✅ line marked obsolete/superseded.
*Change:* restate each rationale against the *actual* reason it survives (pure-Rust/`forbid(unsafe_code)` posture, no CMake/libclang/C++ chain in the build) rather than the retired triple.
*Verification:* `grep -rn 'windows-gnu'` over editable files returns only deliberate history mentions; `just quality-gate code` still green (comment-only edits).

**T12 — ADR 0013.**
*Files:* `docs/aegis/adr/0013-*.md` (new), `docs/aegis/INDEX.md` row.
*Change:* record the ABI decision, the alternatives (keep gnu, two-stage, msvc), the evidence that forced it (the CI run), and that it amends `0007`. Compose `recording-architecture-decisions` when writing it.
*Verification:* ADR 0007 unmodified (`git diff --stat adr/0007-*` empty), registry row present.
*Authority:* only write this **after** T9 is green (spec §7: no accepted architecture memory from an unproven ABI).

### S5 — Repository weight

**T13 — repack.**
*Change:* none — `git repack -adf --window=250 --depth=250` + `git prune-packed` on the working repository.
*Verification:* `git count-objects -vH` and `du -sh .git` before/after; `git rev-parse --all | sort | sha256sum` **and** `git log --all --oneline | wc -l` unchanged.
*Measured (2026-10-13):* `.git` **116 MB → 69 MB** (pack 57.41 → 58.62 MiB absorbing the loose set, loose 5814/53.70 MiB → 573/5.21 MiB); refs hash **identical**, 872 commits either side. `-f --window=250 --depth=250` was tried because a plain `-ad` gave 60.0 MiB; the deeper window bought only 1.4 MiB, so the pack is not delta-starved — it is carrying content.
*What the remainder is:* 421 objects are reachable **only from reflogs** and are **157 MiB raw** — isolated pre-rename snapshot states that delta poorly. A `gc --prune=now` on a throwaway mirror expired reflogs and pruned them, which is why that mirror reached 18 MB. Expiring reflogs (`git reflog expire --expire=now --all` then `repack -ad --prune`) does **not** change any reachable commit or clone, but it destroys local recovery of those states — **user decision, not taken here**; the repack deliberately stops short of it.

## Verification Summary

| Task | Command-shaped exit |
|---|---|
| T1–T4 | clean-machine build + `just quality-gate code`, no protoc/sccache/clang/mold |
| T5–T6 | `PROTOC=/bin/false` fails before / passes after; byte parity `e3547e5f…adecbe4`; `just quality-gate deps` |
| T7–T9 | CI green on `ubuntu-24.04`+`ubuntu:22.04` container and `windows-2022` |
| T10–T12 | `grep 'windows-gnu'` clean outside history; `AGENTS.md` +1 row; ADR 0007 diff empty |
| T13 | `git count-objects -vH`; refs unchanged |

## Risks

- msvc wall (nasm/`rc.exe`/a C dep without an MSVC path) → T9 fallback recorded above.
- Windows test fallout larger than the known list → T9 absorbs it task-by-task; if it grows beyond the three recorded items, stop and re-scope with the user rather than silently widening.
- Repack on a dirty tree: the repack itself is safe, but run it last so it never interleaves with a working change.

## Retirement Track

| Retired | When | Note |
|---|---|---|
| `protoc` as a build prerequisite | T6 | no CI image installs it afterwards |
| host-tuned cargo config (`sccache`/clang/mold/native/`/tmp`) | T1 | re-enters only via `just fast` |
| `x86_64-pc-windows-gnu` as a declared target | T7 | rationale text retires at T11, ADR at T12 |
| the gnu cross recipe (`roadmap.md:356-359`) | T11 | marked obsolete, not deleted (history) |

## Sources

Spec `2026-10-13-toolchain-portability-and-repo-weight-design.md`; this session's probes (2026-10-13).
