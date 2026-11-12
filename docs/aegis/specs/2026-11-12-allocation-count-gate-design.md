# Allocation-count gate — Design Spec Brief

Date: 2026-11-12
Status: **implemented 2026-11-12** — plan `plans/2026-11-12-leas-hotpath.md`.
Origin: `thirdparty/ZeroNet` @ `29e7a95` audit, `docs/research/2026-11-12-zeronet-zray-analysis.md` §4, §7.
Owner gap: no spec owns a deterministic cost gate. `2026-11-10-memory-reduction-design.md`
owns the allocator itself; `2026-11-05-ferrox-derived-verification-gates-design.md`
owns byte oracles. Neither gates allocation counts.

---

## 1. Why this exists

leas currently has no way to assert what a hot path allocates. The existing cost lab
records the constraint verbatim:

> Allocation COUNTS are not available in-process: this crate installs the
> process-wide `#[global_allocator]` (`src/alloc.rs`, mimalloc), and a second one is
> a compile error.

— `crates/leas/src/ops/ping/flow_cost.rs:14-20`

That is true **inside the `leas` binary**. It is not true for a separate bench crate
that depends on `leas-native` / `leas-tls` and never links `leas`: such a crate owns
its allocator, so it can install a counting one and state exact numbers.

ZeroNet does exactly this and gates on the counts, not on time:

> Wall-clock times are printed too, as context only. They are not gated on: a
> duration on a shared runner is a distribution, not a fact.

— `bench/hotpath/src/main.rs:18-22`

The counting allocator reports `allocs`, `reallocs`, `bytes`, and `zeroed`
separately, because a `vec![0u8; n]` whose bytes are then overwritten costs a memset
the allocation count alone cannot see (`alloc_count.rs:20-30`).

## 2. Scope

One new workspace crate, `crates/leas-hotpath`, with two halves:

1. `alloc_count.rs` — the counting `GlobalAlloc` and a `measure_async` helper that
   measures exactly one future and refuses nesting.
2. `main.rs` — gate rows over `leas-native` / `leas-tls` **public** surfaces:
   framing and record paths that can be driven without a socket.

The crate must not depend on `leas` (the binary), by construction: linking it would
put two `#[global_allocator]`s in one binary.

**Out of scope:**

- **The relay copy path.** `inbound::outbound::relay` / `copy_half` are `pub(crate)`;
  measuring them needs either a public test hook or a trait change. Named as the
  next slice, not this one.
- **Traffic-shape gating** (`bench/shape`'s packet-size classifier features). It
  needs a framing harness that turns writes into packets; a separate spec.
- **CI wiring** beyond a decision in D2.

## 3. The shape

```rust
pub async fn measure_async<F: Future<Output = R>, R>(body: F) -> (R, Counts);
pub struct Counts { pub allocs: usize, pub reallocs: usize, pub bytes: usize, pub zeroed: usize }
```

Rules, all of which are correctness conditions on the measurement rather than style:

- counting is off unless a measurement is active, so harness bookkeeping never lands
  in a row;
- one future measured at a time; a nested `measure_async` panics;
- the measured future runs on a current-thread runtime, so a work-stealing scheduler
  cannot move half the measurement to another allocator-carrying thread;
- rows are `assert`-ed against a ceiling, and the harness prints the observed value
  next to the ceiling so a regression is legible before it fails.

Landed rows (each discriminates a consumer-visible cost; every ceiling was proven by
making the row fail — see §5):

| Row | Surface | Ceiling | Failure it catches |
| --- | --- | --- | --- |
| `vless/header/tcp-ipv4` | `protocol::vless::header::encode_request` (`pub`) | 1 alloc, 0 reallocs | a second buffer for the address, a `String`/`format!` per connect |
| `vless/header/tcp-ipv4-vision` | same, with the 18-byte flow addon | 1 alloc, 0 reallocs | a header that reallocs on the Vision path |
| `vless/peel/1k` | `protocol::vless::stream::VlessClientStream` (`pub`) | 0 allocs | a scratch `Vec` per read in the peel |
| `tls13/seal/16k-in-place` | `leas_tls::crypto::AeadKey::seal_in_place` (`pub`) | 0 allocs, 0 zeroed | a record path that copies the body |
| `tls13/open/16k-in-place` | `leas_tls::crypto::AeadKey::open_in_place` (`pub`) | 0 allocs | a record path that copies before opening |

Two corrections the implementation forced, both recorded because the draft was wrong:

- `leas_tls::record` does not exist. The in-place AEAD is
  `leas_tls::crypto::{AeadKey::seal_in_place, AeadKey::open_in_place}`
  (`crates/leas-tls/src/crypto/mod.rs:632,667`).
- `encode_request` returns a `Vec` by construction, so its row cannot claim zero. The
  row's real budget is **one** allocation; that is what makes a second one visible.

Three closed modules cannot be reached from another crate and are therefore **not**
measured: `protocol::vless::vision` (`pub(crate)` at `protocol/vless/mod.rs:22`), the
mux frame codec (`transport::mux` frame functions are private), and
`inbound::outbound::relay`. None gets a `#[doc(hidden)]` un-privatisation for a
benchmark; a real hook is the next slice's decision.

## 4. Compatibility boundary

- New crate only; no wire change. It adds no *public* item to the library: the one
  helper the fix needed (`addr::write_addr`) is `pub(crate)`.
- `members = ["crates/*"]` makes the crate a member; `default-members` is an
  explicit list, so a bare `cargo nextest run` does not build it. It is
  `publish = false` and clippy-clean, because the authoritative lint gate runs
  `--workspace --exclude leas-oracles`.
- The workspace declares no custom `[profile.release]`, so the crate is measured on
  the default optimised profile. It refuses a debug build itself: a debug build
  measures debug code, and the `cfg!(debug_assertions)` guard returns a failure
  rather than printing a misleading green.

## 4a. What the gate found on its first run

`vless/header/tcp-ipv4` came up **red at 2 allocations**: `encode_request` built the
header into its own `Vec` and then copied in a second `Vec` from `encode_addr`
(`crates/leas-native/src/addr.rs`). One allocation per VLESS *and* VMess connect was
pure waste. Fixed by adding `addr::write_addr(&mut Vec, &TargetAddr)` —
`pub(crate)`, the same "into a caller-owned buffer" shape the port-last family already
has — and pointing both request encoders at it. `encode_request` now also reserves the
flow-addon bytes up front, so a Vision connect does not realloc.

## 5. Verification

1. Harness self-tests (`cargo nextest run -p leas-hotpath`): one `vec![0u8; 16]`
   reports `allocs == 1, zeroed == 1, bytes == 16`; an empty region reports zeros.
2. Every row was shown red: the header row was red on the first run for the real
   defect; the other four were proven by a temporary mutation (a `to_vec()` in the
   seal, a copy in the open, a per-read `Vec` on the peel's fast path) that turned the
   named row red and was reverted.
3. Gates run: `cargo fmt --all --check`; `cargo clippy --workspace --exclude
   leas-oracles --all-targets --all-features -- -D warnings`; `cargo nextest run`;
   `cargo hakari generate --diff` (empty); `cargo run --release -p leas-hotpath`;
   `just hotpath`.

## 6. Decisions (settled at implementation)

- **D1 — what the first slice owns.** Five rows: both header forms, the peel, and the
  two record operations. No relay, no Vision codec, no mux — each needs a public hook,
  and a measurement concern does not get to shape the library's API.
- **D2 — where it runs.** A `just hotpath` recipe now; the CI job follows once the row
  set stops moving. Allocation counts are machine-independent, which is what makes the
  CI step viable at all.
- **D3 — ceiling vs exact.** Exact for every landed row: `1` for the header, `0` for
  the rest. No row needed a tokio-driven read that forced a range, so a range would
  only hide a regression.

## 7. Next slice, if it is ever funded

Relay and Vision rows need one of: a public measurement hook on `leas-native`, a
`#[cfg(feature = "bench-internals")]` surface, or moving the row into the crate's own
`benches/`. The last is the only one that does not widen the public API, and it is
blocked because a criterion bench cannot replace the process allocator. Re-open with an
ADR if the value justifies it.
