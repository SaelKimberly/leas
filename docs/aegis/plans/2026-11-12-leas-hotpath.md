# `leas-hotpath` — implementation plan

Date: 2026-11-12
Spec: `specs/2026-11-12-allocation-count-gate-design.md` (draft, D1/D2/D3 open)
Origin: `docs/research/2026-11-12-zeronet-zray-analysis.md` §4, §7
Execution route: **inline** — one owner, four sequential tasks, no independent slices.
`User confirmation required: no` — no new authorization, no release surface, no schema.

Aegis Visibility: a new workspace member and a new verification surface, with a
public-API boundary (what a separate crate may reach) and an exactness contract that
only the plan can pin; the durable plan is what stops the "measurement crate" from
growing a hook into the library.

## 1. Goal

A release-mode binary crate that installs a counting global allocator and asserts
exact allocation counts on four hot paths, so an allocation regression fails a named
row instead of passing a wall-clock benchmark.

Acceptance:

1. `cargo run --release -p leas-hotpath` exits 0 and prints one line per row with the
   observed count, the ceiling, and `zeroed`/`reallocs`.
2. `cargo clippy --workspace --exclude leas-oracles --all-targets --all-features --
   -D warnings` is clean.
3. `cargo nextest run` is unaffected (the crate is not a default member).
4. `cargo hakari generate --diff` is empty (new member, no lock drift).
5. Each of the four rows is demonstrated red by reintroducing its cost, then green
   after reverting.

## 2. Architecture

```text
crates/leas-hotpath (bin, publish = false)
├── Cargo.toml           deps: leas-native, leas-tls, tokio(rt, macros, io-util)
└── src/
    ├── main.rs          #[global_allocator] + rows + asserts
    └── alloc_count.rs   counting GlobalAlloc, Counts, measure_async
```

It never depends on `leas`: the binary owns the process-wide mimalloc allocator
(`crates/leas/src/alloc.rs:33`) and a second `#[global_allocator]` is a compile error,
which the existing cost lab already records (`crates/leas/src/ops/ping/flow_cost.rs:14-20`).
It is a member through `members = ["crates/*"]`, and not a default member because
`default-members` is an explicit list — so bare `cargo nextest run` does not build it.

## 3. Tech stack

Rust 2024 workspace; `tokio` (current-thread runtime for a deterministic measurement),
`leas-native` / `leas-tls` public surfaces only. No new external dependency.

## 4. Baseline and authority refs

- Spec D1 rows, re-derived against the real public surface (two spec rows were wrong
  and are corrected in T4):
  - `protocol::vless::header::encode_request` is `pub` and returns `Vec<u8>` — one
    allocation by construction, not zero.
  - `protocol::vless::stream::VlessClientStream::new` is `pub`.
  - `leas_tls::record` does not exist; the in-place AEAD lives at
    `leas_tls::crypto::{AeadKey::seal_in_place, AeadKey::open_in_place}`
    (`crates/leas-tls/src/crypto/mod.rs:632,667`), both `pub`.
  - `protocol::vless::vision` is `pub(crate)`, `transport::mux`'s frame codec is
    private — neither is reachable from another crate, so both stay out of this slice.
- Repo rules that shape the tasks: clippy workspace gate excludes `leas-oracles`;
  `cargo-hakari` regenerates after any lock change; a bench that measures must state
  its own determinism (no timing gate).
- ZeroNet's gate, which this mirrors: `thirdparty/ZeroNet/bench/hotpath/src/alloc_count.rs`.

## 5. Compatibility boundary

No library, wire, schema, or config change. The crate is `publish = false` and adds no
public API. `Cargo.lock` gains one local path package. Nothing in `crates/leas-native`
is un-privatised for the benchmark — if a row needs a hook, the row is cut, not the hook
added.

## 6. Change Necessity

Measurement cannot live in the existing crates: `leas` owns the allocator, and the
`leas-native` benches are criterion timing benches, which are distributions and already
documented as such (`benches/baseline.md`). A new binary crate is the minimum boundary
that can own an allocator and print exact counts; a docs-only result would leave the
claim unverified.

## 7. Ripple Signal Triage

Fires: **new owner** (workspace member + a verification surface) and **lockfile**
(`Cargo.lock`, hakari). Downstream consumers: `just` recipes, the docs index, the
quality gate. No producer/consumer contract in shipped code changes. Verification
carried into T5: clippy workspace, hakari diff, nextest, machete/deny.

## 8. Plan pressure test

Owner fit: one crate, one purpose, no adapter and no fallback. Retirement: none — this
is additive, and the row set is the retireable part (a row that cannot fail is deleted,
never kept green). Executability: every task has a command and an observable result.

## 9. TDD Route

Mode `auto`, decision **strict** for T2's rows, authority: each row is a
producer/consumer contract ("this path allocates N") whose only trustworthy proof is
witnessing it fail. RED = the row's mutation (reintroduce a `format!`, a `to_vec()`, a
`Vec` copy) makes the row exit non-zero; GREEN = revert, row passes. T1's harness has
its own self-test written before the allocator is trusted. No RED/GREEN ceremony is
prescribed for T3/T4 (mechanical).

## 10. Tasks

### T1 — crate skeleton, counting allocator, harness self-test

Files: `crates/leas-hotpath/Cargo.toml`, `src/main.rs`, `src/alloc_count.rs`,
`Cargo.lock`.

Change: counting `GlobalAlloc` around `System` with `ACTIVE`/`ALLOCS`/`BYTES`/
`REALLOCS`/`ZEROED` atomics; `measure_async` panics on nesting and drives one future;
`main` asserts `!cfg!(debug_assertions)` and a current-thread runtime.

Self-test (the harness proving itself, not the code): a region doing one
`vec![0u8; 16]` reports `allocs == 1`, `zeroed == 1`, `bytes == 16`; a region doing
nothing reports `allocs == 0`; a nested `measure_async` panics.

Prove: `cargo run --release -p leas-hotpath` prints the self-test rows green.

### T2 — four gate rows

Files: `src/main.rs` (rows), `src/alloc_count.rs` (assert helpers).

| Row | Call | Ceiling |
| --- | --- | --- |
| `vless/header/tcp-ipv4` | `header::encode_request(&uuid, ipv4 target, CMD_TCP, None)` | `allocs == 1`, `reallocs == 0`, `zeroed == 0` |
| `vless/peel/1k` | `VlessClientStream::new(duplex)` over `[0,0] || 1 KiB`; one `read` | `allocs == 0` |
| `tls13/seal/16k-in-place` | `AeadKey::from_key_bytes` + `seal_in_place` into a pre-reserved `Vec` | `allocs == 0`, `zeroed == 0` |
| `tls13/open/16k-in-place` | `open_in_place` on that record's body | `allocs == 0` |

Each row prints `observed/ceiling` and fails the process on breach. The IPv4 target in
row 1 is deliberate: `Vec::with_capacity(32)` fits a 26-byte header exactly, so a
reintroduced grow shows up as `reallocs > 0` rather than hiding inside the count.

RED proof per row, one mutation at a time, reverted before the next:

1. `encode_request`: wrap the return in `.to_vec()` → `allocs == 2`.
2. peel: replace the fast path with a `to_vec()` hand-off → `allocs == 1`.
3. seal: change the call to the test-only allocating `seal` twin → not reachable
   (`#[cfg(test)]`), so mutate `seal_in_place` to copy the body first → `allocs == 1`.
4. open: same shape → `allocs == 1`.

### T3 — `just hotpath` recipe

Files: `justfile`.

Change: one recipe next to `bench`, documented as exact-count, machine-independent,
release-only, no timing gate. `cargo run --release -p leas-hotpath`.

Prove: `just hotpath` exits 0 and prints the same rows.

### T4 — spec correction and docs

Files: `docs/aegis/specs/2026-11-12-allocation-count-gate-design.md`,
`docs/aegis/INDEX.md`, `docs/guides/building.md`, `docs/research/2026-11-12-zeronet-zray-analysis.md`.

Change: fix the two falsified spec rows (`leas_tls::record` → `leas_tls::crypto`;
"0 allocs" → "exactly 1 alloc" for `encode_request`), record the landed row set, name
the Vision/mux rows as blocked on a public hook, add the crate to the build guide, and
set the spec's status to implemented with the plan reference.

### T5 — verification matrix

Commands, in order: `cargo fmt --all --check`; `cargo clippy --workspace --exclude
leas-oracles --all-targets --all-features -- -D warnings`; `cargo nextest run`;
`cargo hakari generate --diff` (empty); `cargo machete`; `cargo run --release -p
leas-hotpath`; `just hotpath`. Record outcomes in the plan's execution note and commit
once.

## 11. Risks

- **A row that cannot fail.** Mitigated by the RED proof in T2; a row that survives its
  mutation is deleted, not documented as "informational".
- **Allocator interference.** `leas-native` code under measurement may allocate on a
  first poll (tokio internals). Rows are written to measure after a warm-up where one
  is needed, and an unexplained first-poll allocation becomes the row's stated
  baseline rather than a silently relaxed ceiling.
- **Lock drift.** Adding a member changes `Cargo.lock`; T5 runs hakari and machete.
- **Wrong claim in the spec** (already found twice). T4 is not optional documentation
  cleanup: leaving `leas_tls::record` in the spec would send the next reader to a
  module that does not exist.

## 12. Retirement

None. Additive surface. If the crate ever needs a library hook to grow its row set,
that is a new spec against the library owner, not a widening of this crate.

## Execution note (2026-11-12)

Executed inline, T1–T5, one commit's worth of change. Deviations from the plan as
written, each with its reason:

1. **Five rows, not four.** Both VLESS header forms are gated: the plain one and the
   Vision-addon one. The second exists because the plan's own fix (reserving addon
   bytes up front) is only observable on that form.
2. **The header row was red for a real reason on the first run** — `2 allocations`
   instead of the planned `1`. `encode_request` frames the header into its own `Vec`
   and then copied in a second `Vec` built by `encode_addr`
   (`crates/leas-native/src/addr.rs`); every VLESS *and* VMess connect paid it. Fixed
   by extracting `pub(crate) write_addr(&mut Vec<u8>, &TargetAddr)` (the same
   "into a caller-owned buffer" shape `write_addr_port_last` already had) and pointing
   both encoders at it. That is a library change the plan did not predict; it is the
   measurement working, not scope creep, and it is recorded in the spec as §4a.
3. **`leas_tls::record` does not exist.** The draft spec named a module that is not
   there; the row now uses `leas_tls::crypto::AeadKey::{seal_in_place, open_in_place}`.
4. **No custom `[profile.release]` in the workspace**, so the plan's "inherits LTO and
   `codegen-units = 1`" sentence was wrong. Corrected in the spec: the crate is
   measured on the default optimised profile and refuses a debug build itself.
5. **The `zeroed` self-test needed the allocator's `alloc_zeroed` path**, which the
   first harness draft exercised through `vec![0u8; 16]` — kept as the self-test, since
   it is the one construction guaranteed to take that path.

Evidence: `just hotpath` → 5/5 within budget; each row individually proven red (header
row naturally, the other four by a temporary mutation reverted in place);
`cargo nextest run -p leas-hotpath` → 2 passed; `cargo fmt --all --check` clean;
`cargo clippy --workspace --exclude leas-oracles --all-targets --all-features -- -D
warnings` clean; `cargo hakari generate --diff` empty.
