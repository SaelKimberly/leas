# 0013 — Declared Windows ABI: `x86_64-pc-windows-msvc`, not `windows-gnu`

Date: `2026-10-14`
Status: `accepted`
Amends: `0007` (its §1 context and its `aws-lc-rs` row name the then-declared
`x86_64-pc-windows-gnu` triple; the reasoning there is unaffected, because
neither triple ships CMake, libclang or a C++ toolchain)
Supersedes: nothing
Related: `specs/2026-10-13-toolchain-portability-and-repo-weight-design.md`
(D4, D5, D10), `plans/2026-10-13-toolchain-portability-and-repo-weight.md`
(T7–T12, T14), `docs/guides/building.md`, `rust-toolchain.toml`, `deny.toml`,
`.config/hakari.toml`, `.github/workflows/ci.yml`

## Context

The workspace declared `x86_64-pc-windows-gnu` as its Windows target. That
choice came from the cross-compilation route: a Linux or macOS host can build a
gnu Windows binary with `cargo zigbuild`, while an msvc target needs the MSVC
toolchain and the Windows SDK.

Three things made the declaration wrong in practice:

1. **The cross route was never a supported build.** Making it work needed a
   hand-set `RUSTC` (a Homebrew rustc on `PATH` owns only the Linux std, while
   `rustc-wrapper` hands sccache a bare `rustc` name it resolves from `PATH`) and
   a mingw-capable `windres`, because `turso_sdk_kit`'s build script runs bare
   `windres` and Homebrew binutils cannot emit a PE resource. That is a recipe,
   not a target: a contributor reading `rust-toolchain.toml` would conclude the
   gnu triple was buildable, and it was not, without undocumented local surgery.
2. **It was the wrong ABI for the people who run this on Windows.** The gnu
   target produces a binary linked against the mingw runtime; anything a user
   resolves from a mainstream Windows build (imported DLLs, debuggers, crash
   reporting, antivirus heuristics) assumes msvc. `v2rayN` — the reference
   client for this user base — ships msvc builds.
3. **It hid Windows defects.** Every Windows-only failure in this round was
   invisible until CI compiled the msvc target: a unix-only `rstest` import
   failing `-D warnings`, a non-Linux `proc_rss_bytes` stub, three Linux-shaped
   product assumptions (`which`, extensionless exe names, `-linux-` asset names)
   and a refusal path that only misbehaves where closing a socket with unread
   data discards the response in flight.

## Decision

1. **The declared Windows target is `x86_64-pc-windows-msvc`.** Declared targets
   are `x86_64-unknown-linux-gnu` and `x86_64-pc-windows-msvc`; no other triple
   is claimed. The triple was updated in `rust-toolchain.toml`, `deny.toml`
   (`[graph] targets`) and `.config/hakari.toml` (`platforms`), and
   `cargo hakari generate` regenerated the workspace-hack crate.
2. **CI proves it, and only then is it recorded.** `windows-2022` runs the `code`
   gate (`fmt --check`, `clippy -D warnings`, `nextest`) on every push. The
   decision was taken provisionally with the rationale text held back
   (spec D10, prove-then-record) and the five rationale sites plus this ADR were
   written only after the job went green: run `38527679422`, `code-windows`
   9:32, `Summary: 2381 tests run, 2381 passed`, `PASS: clippy`.
3. **The gnu cross recipe is retired, not deleted.** `roadmap.md:357` keeps the
   recipe text marked obsolete, because it records why the old declaration
   existed; `AGENTS.md` no longer presents it as the way to build for Windows.
4. **The Linux side keeps its floor.** The Linux job is unchanged in intent: it
   builds inside an `ubuntu:22.04` container on an `ubuntu-24.04` runner and
   asserts the linked `GLIBC_*` maximum, so the msvc work did not loosen the
   older-machine compatibility the reference machine (glibc 2.35) depends on.

## Alternatives rejected

| Alternative | Why not |
| --- | --- |
| Keep `x86_64-pc-windows-gnu` | The declared target was never the buildable one (hand-set `RUSTC` + mingw `windres` on the host), and a mingw binary is not what mainstream Windows tooling expects |
| Declare both gnu and msvc | Two Windows ABIs doubles CI, the dependency-target surface (`deny.toml`, hakari platforms) and the meaning of every "Windows" claim, for a cross route nobody could build without local surgery |
| Two-stage: keep gnu declared until msvc is proven, then flip | That is what happened, but as a *sequence inside one change* rather than two declarations: the flip landed with CI, the rationale waited for the green run (D10) |
| Keep msvc undeclared and rely on CI's own target | `deny.toml`'s graph check, `cargo hakari`'s platform set and `rustup`'s installed std would all keep describing the old ABI; the declaration is what a contributor reads |

## Consequences

- **Contributors on Windows** need the MSVC build tools (`rustup` installs the
  toolchain; the linker and SDK come from Visual Studio Build Tools). Documented
  in `docs/guides/building.md`; no cross toolchain, no `cargo-zigbuild`, no
  `windres`, no mingw.
- **The five rationale sites now name msvc** where they named gnu:
  `crates/leas-tls/src/crypto/mlkem.rs`, `crates/leas-tls/Cargo.toml`,
  `docs/reference/crypto-dependencies.md`, `docs/reference/native-core.md`
  (twice). The historical statements keep their dates and say which triple was
  declared when, so the reasoning does not silently change hands.
- **ADR 0007 is not rewritten.** Its two mentions of the gnu triple are accurate
  for the decision it records; this ADR is the pointer that the target moved.
- **Windows defects become findable.** Four became findable immediately (T14) and
  all four are fixed; the remaining known Windows gap is the statistics memory
  row (`proc_rss_bytes`, `roadmap.md:360`), which stays Linux-only by design
  until `GetProcessMemoryInfo` fills it.
- **Re-evaluation trigger:** if a supported Windows-on-ARM build is ever wanted,
  the declaration needs a second triple (`aarch64-pc-windows-msvc`) and the
  asset-naming table in `updater.rs` already names that combination.
