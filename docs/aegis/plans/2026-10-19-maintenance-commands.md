# Plan: Maintenance Commands — Mass DNS Retry + Smart Endpoints Compact

Date: 2026-10-19. Status: approved design, ready for implementation.

## Goal

Two manual maintenance commands for the leas TUI:

1. **Mass DNS retry** — re-resolve every DNS endpoint with an empty address set
   (`is_dns() && resolved_ips.is_empty()`), force-bypassing TTL, reusing the
   existing enrich pipeline. Purgatory included.
2. **Smart Endpoints Compact** — merge duplicate endpoints that are provably
   the same server, with an actions-log audit entry (no undo by design;
   apply-directly UX was the user's explicit choice).

## Architecture & decisions (approved)

- **Pair criterion** (blocker fix): a pair merges only when ALL hold:
  same `endpoint.port` AND shared `protocol_id` (canonical config identity,
  `identity.rs` — host-independent, so it only NARROWS) AND **`endpoint_ip`
  overlap** (one endpoint's resolved set ∩ the other's address/literal).
  Config equality alone can never identify a server (one UUID across a
  provider fleet). Unresolved↔unresolved pairs have no IP evidence → never
  merge.
- **Survivor**: DNS host over IP-literal; else lower endpoint id (older).
- **Link collision** (same `protocol_id` on both): better evidence wins —
  measured latency > untested, lower delay bin; absorbed side's
  `purge_reason` does NOT propagate (verdicts are pair-scoped,
  `ops/purge.rs` taxonomy).
- **Fan-out**: absorbed `endpoint_ip` rows move to survivor (deduped),
  `endpoint_groups` membership moves (collision: `last_seen_at` = max,
  survivor's `sort_order`), absorbed `endpoint_rank` deleted,
  survivor rank **recomputed** (`rank_of_row` + representative-link
  re-selection — invariant pinned by `models_toasty.rs:973-1008` tests).
  `Endpoint::ports` unioned. Absorbed `last_source` +
  `manual_protocol_override` dropped.
- **Write-behind safety**: flush `WriteBehind`, then DRAIN pending `LinkSpec`
  patches for absorbed endpoint ids (new discard API — staged patch flushing
  after the delete would hit an FK error and retry forever), then merge.
- **Live connections**: absorbed endpoint with a live connection is skipped
  this run and reported.
- **Compact trigger**: manual command only, apply directly, one actions-log
  entry per run listing every merge (absorbed id/host → survivor id/host,
  links moved vs collided, skipped list).
- **DNS retry**: DB rows (not state cache) are the target source; `force=true`
  through `should_resolve`; same permits/timeouts/seed as normal enrich;
  failure re-stamps `resolved_at` as today; report attempted/resolved counts.
  No auto-compact afterwards.

## Baseline refs

- `docs/reference/database.md` (schema, invariants), `docs/reference/database-manual-sql.md` (raw-SQL cause rule), `docs/reference/ordering-law.md`, `docs/guides/tui-manual.md` (keybindings), `docs/architecture/decisions.md`.

## TDD Route

auto → **strict** for the `leas-db` merge transaction (persistence, destructive,
regression signal; tests beside code + `tests/integration.rs` per repo rules)
→ **light** for op/UI wiring (existing spawn/dispatch patterns, smoke via
`tui-test`).

## Tasks

1. **`leas-db` merge engine** — `crates/leas-db/src/merge.rs` (new owner file,
   `impl Database`), re-exported from `lib.rs`.
   `pub async fn merge_endpoints(&self, survivor: EndpointId, absorbed:
   EndpointId) -> Result<MergeReport>`; one transaction. Typed path first;
   FK re-keying (`UPDATE links/endpoint_ip/endpoint_groups SET endpoint_id`)
   via toasty patch if expressive, else raw SQL WITH recorded cause appended
   to `docs/reference/database-manual-sql.md`. Ports union; group collision
   max(`last_seen_at`); delete absorbed endpoint + rank rows; recompute
   survivor rank via the `endpoint_rank.rs` persistence path. STRICT: rstest
   table tests — survivor rule (DNS/IP, DNS/DNS, IP/IP), link-collision
   evidence rule + no purge propagation, ip/group fan-out + dedup, ports
   union, rank recompute, absorbed-only protocol link re-key.
2. **`WriteBehind` discard** — `crates/leas-db/src/write_behind.rs`: pub
   `drain_for_endpoints(&self, ids: &[i64])` (or take), used by compact;
   unit test: staged patch for absorbed id is gone after drain, flush after
   merge is a no-op for it.
3. **`ops/compact.rs`** — scan (`protocol_id → [endpoint_id]` from loaded
   rows), pair filter (port + shared protocol + ip overlap), survivor pick,
   live-connection skip (AppState connection state), flush+drain, merge per
   pair, re-load rows into state, actions-log entry, `CoreEvent::CompactFinished`
   (types.rs). Light: unit-test the pure pair/survivor selection fn; smoke the
   command via TUI.
4. **Mass DNS retry entry** — `ops/enrich.rs`: pub entry reusing the enrich
   target pipeline with `force=true`, targets from DB rows where
   `is_dns() && resolved_ips.is_empty()`; report via actions log +
   `CoreEvent` variant. Light.
5. **UI wiring** — keybindings/screen hooks next to the existing maintenance
   surface (exact site per `docs/guides/tui-manual.md` + dispatch search:
   spawn + `CoreEvent` pattern, types.rs:486). Smoke via tui-test.
6. **Docs + gate** — tui-manual entries for both commands; recorded raw-SQL
   cause if task 1 needed it; `just quality-gate code`.

## Compatibility boundary

No schema bump (`user_version` untouched — no new columns/tables). New
`CoreEvent` variants are additive. No import-path change. No public API
outside the two new op entries + db merge/discard methods.

## Verification

`cargo nextest run --workspace`; merge tests prove behavior at the DB seam;
op-level tests exercise both commands end-to-end on a seeded temp database
(scan → merge → actions-log report). Plainly stated: keystroke-to-command
execution in the live TUI is NOT automated — the menu dispatch is a literal
string match on `SpeedTestMenuItem` labels, covered by the same-op tests, and
the repo has no TUI driver harness (the `tui-test` MCP cannot launch the
binary). The full suite's Summary line is the gate.

## Risks / retirement

- Residual: byte-identical config + port + shared CDN anycast IP across two
  origins → wrong merge, no undo. Accepted by user (apply-directly).
- Nothing retired: host+port import dedup stays (compact is the layer above).

## Execution route

inline (shared owner `leas-db` transaction + sequential deps between tasks
1→3). Fallback: task 3/4/5 could fan out after task 1/2 land.
