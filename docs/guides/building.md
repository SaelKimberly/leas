# Building, prerequisites, and the fast path

What a clean machine needs, what it does not, and how to check that a build
proves something. It does not cover the release order (`publishing.md`) or the
quality gate's individual tools beyond the commands below. The measurements and
timings in this file were taken on 2026-10-13 against the portability change;
they are the numbers the toolchain printed.

## Prerequisites

| Need | Why | Notes |
| --- | --- | --- |
| `rustup` (or a system Rust at least the workspace `rust-version`, 1.99.1) | `rust-toolchain.toml` pins the `stable` channel, `rustfmt`/`clippy`, and three targets | `rustup show` installs what the file asks for |
| a C compiler (`build-essential`, `gcc`, or MSVC's `cl.exe`) | `ring`, `zstd-sys` and `libsqlite3-sys` compile C | verified: a clean build does its C work through `cc`/`cc1` |
| `git`, `curl`, `tar` | `just plugin-bins` fetches one prebuilt plugin and builds another | optional: only the plugin e2e rows need it |
| `just` | every documented task is a recipe | `cargo install --locked just` |
| `cargo-nextest` | the suite (`cargo nextest run --workspace`) | `cargo install --locked cargo-nextest` |
| `cargo-hakari`, `cargo-deny`, `cargo-machete`, `cargo-audit`, `cargo-outdated` | the `deps` half of the gate | `cargo install --locked …` |
| `python3` | regenerating the TLS fingerprint catalog (`crates/leas-tls/src/fingerprints/catalog/gen_specs.py`) | optional |

**Not required:** `protoc`. `crates/leas-core/build.rs` compiles the stats
`.proto` in-process with `protox::compile` and hands the `FileDescriptorSet` to
`prost_build`'s `compile_fds`, so neither contributors nor consumers of the
published crate need a protobuf compiler on `PATH`. (Before that change
`PROTOC=/bin/false` failed the build; it now passes.)

**Not required, but worth having:** `sccache`, `clang`, `mold`. See the fast path.

On Windows the extra prerequisite is **`nasm`**: `ring` assembles its perlasm
with it. `x86_64-pc-windows-msvc` is the declared target, so no mingw toolchain
is involved. `x86_64-pc-windows-gnu` is also installed as the local fallback
where `link.exe` is unavailable, but nothing in CI or the gate builds it.

## The fast path is opt-in: `just fast <cmd>`

The committed `.cargo/config.toml` is deliberately portable: `[build]
incremental = false` and nothing else. The speedups live in one recipe:

```sh
just fast cargo check -p leas-core
```

`just fast` exports `RUSTC_WRAPPER=sccache`, a molded `RUSTFLAGS`
(`-Clink-arg=-fuse-ld=mold -Ctarget-cpu=native`, applied only on Linux), and
the `LEAS_CORE_BIN_DIR` default. Two consequences matter:

- **`-Ctarget-cpu=native` is a machine-specific CPU baseline.** Never use it for
  an artifact meant to run elsewhere, and never in CI.
- **Benchmark numbers are comparable only under `just fast`.** `just bench`
  routes every `cargo criterion` call through it, as do the ignored perf labs
  (`cargo nextest run -p <crate> --features perf-lab --run-ignored all <name>`).
  A plain `cargo` build measures a different binary.

Arguments are word-split, so keep the command simple.

`just bench` runs the criterion targets; `just bench micro` skips the one that
needs real cores (`throughput` loads `$LEAS_CORE_BIN_DIR`). Results land in
`./.benchmarks`; `LEAS_BENCH_MB` defaults to 4 inside the recipe (the value
`crates/leas-native/benches/baseline.md` was captured at; the harness default is 64), and `all`
refuses to start when `$LEAS_CORE_BIN_DIR` has no `xray`/`sing-box`, because the
throughput rows would otherwise skip silently and exit 0.

## Host state can fake a green build

Three host-level sources override the repository, and none is visible in a
normal green build:

| Source | Effect |
| --- | --- |
| `CC` / `CXX` naming `sccache clang -fuse-ld=mold …` | every cc-rs C build goes through them; cargo config cannot override |
| a `~/.cargo/config.toml` (or any ancestor `.cargo/config.toml`) | cargo reads config from the CWD's ancestors as well as `$CARGO_HOME`, so `linker = "clang"`, `rustflags`, and `build.rustc-wrapper` from your home directory apply to every checkout beneath it, even with `HOME` and `CARGO_HOME` relocated |
| `PATH` | `just` and `cargo-nextest` may live outside the system directories; stripping `PATH` produces a fake portability failure |

To prove portability, build where none of that applies: a copy outside your home
tree, minimal environment.

```sh
mkdir -p /tmp/clean-clone && cd /path/to/leas \
  && git ls-files -z | tar --null -T - -cf - | tar -xf - -C /tmp/clean-clone
mkdir -p /tmp/clean-cargo && ln -sfn ~/.cargo/registry /tmp/clean-cargo/registry
cd /tmp/clean-clone
env -i PATH=/usr/bin:/bin:$HOME/.cargo/bin HOME=/tmp/clean-home TERM=dumb \
  CARGO_HOME=/tmp/clean-cargo CARGO_TARGET_DIR=/tmp/clean-target \
  cargo build --workspace --all-targets -v 2>&1 | tee /tmp/clean.log
grep -cE 'sccache|-fuse-ld=mold|target-cpu=native|linker=clang' /tmp/clean.log  # 0
```

A cold run takes minutes (no sccache). The flag count must be zero and no
`-C linker=` may appear; that is the claim "this repository builds on a machine
that is not mine".

## The gate

```sh
just quality-gate            # everything, verbose, all checks run even on failure
just quality-gate code       # fmt-check, clippy (all targets/features), nextest
just quality-gate deps       # hakari-check, deny, machete, outdated, audit
just quality-gate-ci code    # what CI runs: minimal output, stops at first failure
```

`code` runs `cargo fmt --all --check`, `cargo clippy --workspace --all-targets
--all-features -- -D warnings`, and `cargo nextest run` (the `ci` mode uses the
`ci` profile). `deps` runs `cargo hakari generate --diff`, `cargo hakari
manage-deps --dry-run`, `cargo hakari verify`, `cargo deny check bans licenses
sources`, `cargo machete --with-metadata`, `cargo outdated` (informational,
`--exit-code 0`), and `cargo audit`.

## CI

`.github/workflows/ci.yml` has three jobs; `stable-drift.yml` adds a weekly one.

| Job | Environment | Runs |
| --- | --- | --- |
| `code-linux` | `ubuntu-24.04` with the gate **inside an `ubuntu:22.04` container** | `just quality-gate-ci code`, then `cargo build --release -p leas` and the GLIBC floor assertion |
| `code-windows` | `windows-2022`, `nasm` installed, rustup toolchain cached | `just quality-gate-ci code` |
| `deps` | `ubuntu-24.04`, host | `just quality-gate-ci deps` |
| `stable-drift` | same container as `code-linux`, Mondays at 06:00 UTC | `rustup update stable` then `just quality-gate-ci code` |

The container is not ceremony: **glibc is forward-compatible only**, so a binary
linked against the runner's 2.39 will not start on a 2.35 machine. The floor the
project develops against is 2.35 (the reference box is Linux Mint 21.3,
`Ubuntu GLIBC 2.35-0ubuntu3.15`). Check any binary:

```sh
objdump -T target/release/leas | grep -o 'GLIBC_[0-9.]*' | sort -uV | tail -1
# must not exceed GLIBC_2.35; the release assertion in ci.yml fails above it
```

The build on 2026-10-13 reported `GLIBC_2.34`.

No job invokes `just fast`, for the CPU-baseline reason above. `deps` stays on
the host because its inputs (`deny.toml [graph] targets`, `.config/hakari.toml`
platforms, the registry) are host-independent.

`rust-toolchain.toml` floats on `stable`, so a new release can redden the
`-D warnings` gate with no commit behind it. That is what the weekly job is for:
its only job is the newest stable, container and all, so a toolchain drift cannot
mask the floor question.
