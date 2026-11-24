# Writer retry budget and batched resolution writes

Date: 2026-11-24
Source: [`docs/research/2026-11-24-log-and-failure-audit.md`](../../research/2026-11-24-log-and-failure-audit.md) G2 (two of its four actions).

## Scoped findings

- **G2a — a writer's total wait is unbounded.** `retry_on_busy` retries on the
  error path only, so an operation that keeps colliding spends `attempts` ×
  (5 s busy ceiling + backoff) before it fails: 5–8 attempts is 25–40 s per
  operation, and the window measured 455 statements ≥ 1 s and 21
  retry-exhausted operations. The audit asks to "cap the total budget per
  operation and fail the *operation* (not the process)".
- **G2b — resolution writes are one transaction per endpoint.** The window
  logged `UPDATE endpoints SET resolved_at = ?` once per endpoint at 12:06;
  the enrichment flush (`ops/events.rs`) loops `update_endpoint_resolution`
  in one spawned task, so 65 k endpoints × (open + update + address replace +
  rank refresh + commit) is the import's write volume against the same
  single-writer WAL that the plan query needs. The 2026-11-20 F4
  recommendation (fold the resolved-at and `endpoint_ip` writes into one
  chunked transaction) is still open.

Out of scope, with reasons:

- **G2c (move the bulk reband off the hot path)** — `reband_all` already runs
  at startup (`state.rs`) and `reband_expired` at purge; no import path calls
  it. Nothing to move.
- **G9 / G2d (pool-wait vs exec split, in-flight heartbeat)** — needs a
  clock the toasty driver does not expose and a lab run to read; it is an
  instrumentation project of its own, and the audit's numbers cannot be
  re-verified from this repo.
- **G7's direct-fallback retry** — changes fetch routing semantics (a source
  URL is a credential-bearing control channel); it needs a user-visible
  decision, not a default.

## Steps

1. **G2a** — `retry_on_busy` gains a total budget
   (`BUSY_RETRY_BUDGET` = 15 s — three full 5 s busy ceilings — with a
   `tokio::time::Instant` from the first attempt). A busy error past the
   budget returns immediately instead of laddering.
   `retry_on_busy_within(op, attempts, budget)` is the seam the test uses;
   every caller keeps `retry_on_busy`.
2. **G2b** — `Database::update_endpoint_resolutions(rows)` writes a batch of
   `(EndpointId, Vec<IpAddr>, i64)` in ONE transaction per 64-row chunk
   (`resolved_at`, `endpoint_ip::replace`, one `endpoint_rank::refresh` for
   the chunk's ids, commit) under the same `retry_on_busy`. A failing chunk
   is logged and skipped — the per-endpoint loop it replaces isolated
   failures per endpoint — and an error is returned once the batch finishes:
   the first BUSY error if any chunk hit one (so the ladder retries the batch),
   else the first error. The single-endpoint method stays for its other callers.
3. **Caller** — the `ops/events.rs` flush task collects its batch and makes
   one call per pass instead of one per endpoint.

## Verification

- `a_zero_budget_spends_no_retry` (new, `retry.rs`) — with the budget
  exhausted at the first attempt, a busy op is called ONCE, where the old
  ladder called it `attempts + 1` times. The existing
  `retries_serialization_failures_then_succeeds` and `gives_up_after_attempts`
  pin that a normal budget still retries.
- `resolution_batch_writes_every_endpoint` (new) — three endpoints in one
  call: each gets its `resolved_at`, its address set (key order, not answer
  order), and the empty batch is a no-op.
- `resolution_batch_keeps_stored_countries` (new) — the bulk path must not
  regress the per-endpoint carry-over (`1.1.1.1` keeps `US`, the new address
  starts `None`), which only `endpoint_ip::replace` provides.
- `resolution_batch_moves_the_rank_out_of_the_dns_band` (new) — bin 15
  (DNS-unresolved) → 12 (untested): the stored rank key follows the address
  set, so deleting the batch's `refresh` reds it.
- `resolution_batch_spans_the_chunk_size` (new) — 65 endpoints: the tail
  chunk's stamp AND address set land.
- Focused runs only (the user's constraint): `cargo nextest run -p leas-db
  'resolution_batch' 'retry::tests' 'update_endpoint_resolution'`,
  `cargo nextest run -p leas 'ops::events'`, `cargo clippy -p leas-db` and
  `-p leas -p leas-native` with `--all-targets --all-features -D warnings`,
  `cargo fmt --check`.

The failing-chunk branch has no injectable fault (turso does not enforce the
`belongs_to` FK and no statement there can be made to fail from a test), so
it is covered by inspection, not a test.

## Outcome

Executed 2026-11-24. Main review (`G2Review`) raised one correctness fix and
three nits, all applied: the budget docs no longer claim write-behind re-stages
the resolution write (it is a bare spawned task; the TTL gate re-resolves on
the next pass), the budget is 15 s rather than one busy ceiling per attempt,
a failing chunk no longer aborts the rest of the batch, and the rank movement
is asserted. Round 2 corrected the TTL wording (the session gate re-resolves,
not the persisted stamp), a stale 30 s in the index row, the chunk comment's
refresh count, the flush's failure log, and the mermaid sequence. Round 3
found that returning an earlier non-busy error skipped the busy retry for the
rest of the batch; a busy error now wins. `docs/reference/database.md` lists
both writers and the batch in the rank-refresh table and query map.
