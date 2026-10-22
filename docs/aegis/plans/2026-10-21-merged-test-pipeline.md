# Plan: One Probe, Two Measurements — the merged test pipeline

- **Spec:** `docs/aegis/specs/2026-10-21-merged-test-pipeline-design.md` (approved 2026-10-21)
- **ADRs:** `docs/aegis/adr/0015-merged-test-pipeline.md`, `docs/aegis/adr/0016-latency-columns-and-auth-flag.md`, `docs/aegis/adr/0006-purge-evidence.md` (2026-10-21 amendment)
- **Goal:** one probe per link produces the transport span, the Auth flag and the real span; one concurrency limit, one progress bar, two delays per row.
- **Baseline refs:** `docs/reference/ordering-law.md` (§2 band law), `docs/reference/database.md` (`profile_stats`), `docs/reference/database-manual-sql.md` (raw-SQL cause rule), `docs/reference/native-core.md` (probe contract), `docs/guides/tui-manual.md` (grid + menu), ADR 0004 (the real-ping engine), ADR 0006 (purge evidence), ADR 0012 (the migration cursor).
- **Compatibility:** schema `18 → 19` with a real migration (the crate's first); the `Latency` model's shape changes (crate-internal); `fast_ping_concurrency` leaves the config (ignored, not an error); the `error_kind` and `PurgeReason` CHECK lists are untouched; the ordering law's bands are unchanged.

**TDD Route:** auto → **strict**. Authority: the repo's test convention (tests beside the code, `rstest` tables for near-identical cases) + the change's signals — persistence, a migration, a schema/contract change, a shared ordering law, and consumer-visible ordering. RED first for every behaviour change; the mechanical column re-pointing is a rename sweep with the existing suite as the gate.

**Change Necessity:** docs/config cannot produce two delays per row (the schema holds one), cannot merge two probes into one (the pipeline dials twice), and cannot retire the fast bar (the UI renders two phases). Minimum code boundary: `leas-db`'s `Latency` model + `schema/`, `leas-native`'s `probe.rs`, `leas`'s `ops/ping.rs` + `ops/ping_native.rs` + `ops/events.rs` + `ui/profiles.rs` + `ui/actions_log.rs` + `ui/mod.rs` + `leas-config`'s `app_config.rs`.

**Ripple Signal Triage — fires on four signals.**
1. **Schema + persistence:** `profile_stats` gains two columns, loses one; every raw-SQL site naming `latency_delay` is a consumer (26 sites / 6 files).
2. **Contract:** the `Latency` type's shape is consumed across `leas-db` → `leas` (`models_toasty.rs`, `endpoint_rank.rs`, `profiles_query.rs`, `database.rs`, `merge.rs`, `export.rs`, `write_behind.rs`, and `leas`'s `ops/events.rs`, `ops/enrich.rs`, `ui/profiles.rs`).
3. **Both producer and consumer:** the probe writes the delays; the ranking law, the page projection, the export and the panel read them.
4. **Retirement:** the `Latency` enum and the `latency` discriminator are **removed**, not deprecated. No compat path, no shim, no fallback column.

Canonical owners (no new owner is created): the schema is `leas-db/src/schema/`; the measurement model is `leas-db/src/models_toasty.rs`; the probe is `leas-native/src/probe.rs`; the probe policy is `leas/src/ops/ping_native.rs`; the batch pipeline is `leas/src/ops/ping.rs`; the result application is `leas/src/ops/events.rs`; the grid is `leas/src/ui/profiles.rs`.

**Coordination:** no sibling agent is running on these crates. `git status` is clean apart from this plan's own docs.

---

## Slice S1 — the schema (the migration framework + the latency reshape)

**Why S1 is first:** the probe and the worker both write the new columns; without the shape in place, every later slice carries two latency shapes at once.

### T1.1 — RED: the migration framework's contract

New: `crates/leas-db/src/schema/steps.rs` (the step list — the crate's **first**).

- `Step` enum: `Sql(&'static [&'static str])` (additive DDL/DML, applied in place) and `Rebuild` (reserved for identity re-keys, per ADR 0012 D-C — **not used** by this change).
- `pub const STEPS: &[Step]` — step 19 is the only entry.
- `schema::migrate`'s `other =>` arm becomes: `0 < cursor < LATEST` → apply the steps after `cursor` in order, in ONE transaction, advancing the cursor in the same transaction; anything else stays `IncompatibleSchema(other)`.

RED tests in `crates/leas-db/tests/schema_migrate.rs`:
- a version-18 database opens, migrates to 19, and its rows read back with the same numbers (`'real'` → `latency_real_delay`; `'fast'` → `latency_fast_delay`);
- a version-19 database opens and **reopens** without re-running the RENAME or the DROP (the non-idempotency trap — a second open must not fail);
- an unknown cursor is still `IncompatibleSchema`;
- the step list is applied in order and the cursor advances in the same transaction (a failing step leaves the cursor where it was).

### T1.2 — the schema change

`crates/leas-db/src/models_toasty.rs`:

```rust
/// The per-link measurements. A STRUCT embed (not an enum): the enum's
/// discriminator made the two delays mutually exclusive, and the merged
/// probe produces both in one pass.
///
/// `auth` is a plain `Option<i64>` — the four states are a Rust-side enum
/// (`AuthState`), because a toasty ENUM embed emits `TEXT` + a CHECK list,
/// and a CHECK cannot be altered afterwards.
#[derive(Debug, Clone, PartialEq, Eq, toasty::Embed)]
pub struct Latency {
    pub real_delay: Option<i32>,
    pub fast_delay: Option<i32>,
    pub ip: Option<String>,
    pub auth: Option<i64>,
}
```

- `AuthState` enum in the same module: `Ok | Failed | NotApplicable | Unknown`, with `as_i64` / `from_i64` (`NULL` = never observed). **No toasty enum embed** — the CHECK would make a future state a table rebuild.
- `ProfileStats.latency: Option<Latency>` stays the field name; the **columns** change (`latency_real_delay`, `latency_fast_delay`, `latency_ip`, `latency_auth`).

`crates/leas-db/src/schema/ddl.rs`: the migration's statements (ADR 0016 decision 2), in this order:

```sql
ALTER TABLE profile_stats RENAME COLUMN latency_delay TO latency_real_delay;
ALTER TABLE profile_stats ADD COLUMN latency_fast_delay INTEGER;
ALTER TABLE profile_stats ADD COLUMN latency_auth INTEGER;
UPDATE profile_stats SET latency_fast_delay = latency_real_delay WHERE latency = 'fast';
ALTER TABLE profile_stats DROP COLUMN latency;
```

(the data step runs **before** the DROP, so a `'fast'` row's number survives). The step lives in the **step list**, NOT in `ensure_raw_ddl` — `ensure_raw_ddl` re-runs on every open and tolerates only "duplicate column"; `RENAME`/`DROP` are not idempotent and are safe only because the cursor gates them.

`crates/leas-db/src/database.rs`: `SCHEMA_VERSION: 18 → 19`.

### T1.3 — the consumer sweep (the 26 sites)

Every reader/writer of the old shape becomes the new shape. **No behaviour change in this task** — the values must read back identically.

| file | site | change |
|---|---|---|
| `leas-db/src/database.rs` | `LINK_UPSERT_PREFIX` (`:661`), the latency literal writer (`:682-689`), the `ON CONFLICT` clause (`:741`) | write the four columns; the discriminator's slot is gone |
| `leas-db/src/profiles_query.rs` | `PAGE_PROJECTION` (`:805-807`), the decoder (`:1015-1044`) | project `latency_real_delay`, `latency_fast_delay`, `latency_ip`; the decoder builds the struct (the `latency` discriminator's slot is gone) |
| `leas-db/src/endpoint_rank.rs` | `RankLink::new` (`:132-136`), the refresh projection (`:1079`), the decoder (`:1111-1119`) | `(measured, delay)` = `(Some(true), real_delay)` if a real delay exists, else `(Some(false), fast_delay)` if one does, else `(None, i32::MAX)` — **the real delay wins the band**, which is what the old exclusivity guaranteed |
| `leas-db/src/merge.rs` | the collision writer (`:275-309`) | carry both delays + ip + auth |
| `leas-db/src/export.rs` | the projection (`:213`) + the decoder (`:251-258`) | carry the four columns |
| `leas-db/src/models_toasty.rs` | `link_test_key` (`:761-765`), `select_best_measured_link`, `sort_links_by_test_priority` | same real-wins rule as the rank |
| `leas-db/src/write_behind.rs` | the RESULT column set | carries the four columns |
| `leas-db/src/schema/mod.rs` | the stability seed (`:193-199`) | `WHERE latency = 'real'` → `WHERE latency_real_delay IS NOT NULL`; the seed's **stamp key** (`STABILITY_SEEDED_KEY`) must change, because its key names a column that no longer exists — the new key is `stability_seeded_v2`, so an old database re-seeds once |
| `leas/src/ops/events.rs` | `apply_test_result` (`:181-190`) | `TestType::RealPing` writes `real_delay` + `ip`; `TestType::TcpPing` writes `fast_delay` |
| `leas/src/ops/enrich.rs` | the exit-IP collector (`:906`) | reads `latency.ip` |
| `leas/src/ui/profiles.rs` | the Test cell (`:539-543`), the Exit cell (`:992-994`, `:1066-1072`), the expanded panel (`:1039`) | read the struct's fields |
| `leas/src/ops/profiles.rs` | `link_latency_delay` (`:2100`) | reads the typed row |
| `leas-native/examples/probe_replay.rs` | the diagnostic query (`:8`) | reads the new columns |

Test fixtures that name the old columns: `leas-db/tests/{partitioned_writers,schema_migrate,profiles_query,integration}.rs`, `leas/src/ops/{compact,connect,ping,profiles}.rs` (the `Latency::Fast { .. }` / `Latency::Real { .. }` constructions).

**Verification:** `cargo nextest run -p leas-db` green; `cargo nextest run -p leas` green; the values are identical to the pre-S1 shape (a real row's delay is in `latency_real_delay`; a fast row's in `latency_fast_delay`; the rank band for every fixture is unchanged).

### T1.4 — S1 docs (the slice owns them)

- `docs/reference/database.md` — the `profile_stats` mermaid block: the four columns replace `TEXT latency` + `INTEGER latency_delay`.
- `docs/reference/glossary.md` — the `Latency` entry names the struct embed.
- `docs/reference/database-manual-sql.md` — the raw-SQL table: the stability seed's predicate and the DDL list.

**NOT touched in S1:** `docs/reference/ordering-law.md` (the band law does not move until S3) and `docs/guides/tui-manual.md` (the grid does not change until S3).

**S1 acceptance:** a version-18 database opens, migrates, and reads back with the same numbers; a version-19 database opens and **reopens** unchanged; a foreign version still reports `IncompatibleSchema`; the rank band of every existing fixture is unchanged.

---

## Slice S2 — the merged probe

**Owner:** `leas-native/src/probe.rs` (the primitive) + `leas/src/ops/ping_native.rs` (the policy).

### T2.1 — RED: the per-stage budget and the transport span

`crates/leas-native/src/probe.rs`:
- `ProbeResponse` gains `transport_span: Option<Duration>` — the time to establish the endpoint's transport (stage 1), `None` when stage 1 did not complete.
- `ProbeRequest` gains `transport_timeout: Duration` (the stage-1 budget) alongside the existing `timeout` (the stage-2+3 budget). The two are **independent**, not a split of one total (spec D12).

RED tests:
- a peer that accepts the TCP connection and never answers the TLS handshake → the error is a **stage-2** timeout, and the response carries the transport span (the peer answered in stage 1);
- a peer that refuses the connection → no transport span, a **stage-1** failure;
- the stage-1 deadline bounds the dial alone (`transport_timeout`), and the stage-2 budget bounds the rest (`timeout`) — two independent deadlines, each asserted against a peer that stalls in its own stage.

### T2.2 — the probe's three stages

`crates/leas-native/src/probe.rs` — `fetch` becomes three stages:

1. **TRANSPORT** — dial the proxy server's socket, bounded by `transport_timeout`. The span is measured from the dial's start to the socket's establishment. This is the Fast metric (spec D2). For a QUIC-family protocol the "transport" is the QUIC handshake (quinn's `connect`), so the span includes the QUIC + TLS handshakes — the caveat is recorded in spec D2.
2. **PROTOCOL** — TLS/REALITY + the protocol handshake + the auth ack. The Auth flag comes from here: the family's ack is read if it has one (VLESS/VMess response header, SS2022 salt echo, hysteria2 h3 status 233), and `n-a` for a family with no ack (Trojan, SS-AEAD) or a row the engine cannot serve.
3. **PROBE** — the target TLS + the HTTP request + the response head. The real span is measured from the **probe's** start (stage 2's end) to the response head, so the real number and the fast number do not overlap.

The Auth flag's four states:
- `ok` — the ack arrived;
- `failed` — **positive** rejection evidence only (an EOF during the peel, an auth error, a framing error);
- `n-a` — the family has no ack, or the engine cannot serve the row;
- `unknown` — the ack is possible but was not observed in time (a lazy sing-box server + a slow target).

**The three outcomes (spec D1) and what each writes:**

| outcome | Fast | Auth | Real | marker |
|---|---|---|---|---|
| **measured** | the transport span | ok / failed / unknown | the real span | — |
| **transport-only** (the engine cannot serve this config) | the transport span | n-a | — | `not testable by the native engine: …` (today's marker, unchanged) |
| **not measurable** (the transport failed) | — | — | — | `[fast]` (the transport failure) |

The "not measurable" outcome is today's `hard_fast` rule: a transport failure
retires the row's real half, because the probe cannot pass where the dial did
not (`classify_fast_failure` → `hard` → `hard_fast`, `ops/ping.rs:1890-1912`).
It is kept, not re-invented.

**The `unknown` case is the one that must not be silently `failed`** — a false `failed` is a persisted false negative.

### T2.3 — one connection for both destinations (the mux handover)

`crates/leas/src/ops/ping_native.rs`:
- the latency probe and the exit-IP fetch share ONE proxy connection when the row is **mux**: `MuxClient::open_session` opens a second session on the live tunnel (the engine already has this — `leas-native/src/protocol/vless/mod.rs:337`). The IP fetch then costs **zero** extra handshakes.
- a non-mux row reopens for the IP fetch (unavoidable: a tunnel is bound to one target).

RED test (the decisive one): a mux row's IP fetch opens a second **session**, and the probe's own connection counter shows **one** handshake for both destinations. The counter is the evidence — the claim "one connection" is not observable otherwise.

### T2.4 — the exit-IP policy becomes a separate phase

`crates/leas/src/ops/ping_native.rs`:
- `real_ping` returns the transport span + the Auth flag + the real span, and **no longer** calls `fetch_ip_info` inline.
- the exit-IP fetch becomes a separate callable (`fetch_exit_ip(params, provider)`) with the provider fallback chain and the existing retry policy, callable by the background worker and by the `Fill Exit IPs` command.
- the exit-IP failure **never** affects the probe's verdict (a missing IP is a missing fact, not a config failure).

### T2.5 — S2 docs

- `docs/reference/native-core.md` — the probe contract: the two independent budgets, the three stages, the one-connection shape, the Auth flag's states.

**S2 acceptance:** a mux row's exit IP arrives over the same connection (one handshake, counted); a TCP-ok / TLS-hang row reports a transport span **and** a real failure (not a total timeout); an unobserved ack is `unknown`, never `failed`.

---

## Slice S3 — the TestWorker + the TUI

### T3.1 — RED: the worker's endpoint grouping and the sibling barrier

`crates/leas/src/ops/ping.rs` (the existing test harness: `harness`, `plan_from_rows`, `fake_row`).

RED tests:
- **the walk's order is `PageSort::Test`, unchanged** — the plan the worker
  receives is in the decision-16 order (the working servers first), and an
  endpoint's links are **contiguous** in it (the walk sorts ENDPOINTS and each
  endpoint's links come back together — `plan_row_links` → `row.links`);
- **at group entry**, the barrier is consulted once: the endpoint **succeeded**
  → the **whole group is dropped** (no probe, no marker, no delay, no exit IP
  for any of its links); the endpoint did **not** succeed → the endpoint's
  **first** protocol (the one the law ranks best) is dispatched immediately and
  its **siblings are deferred** to the back of the queue;
- a **deferred sibling is probed** when it is reached — there is no second
  barrier check, so an endpoint whose first protocol failed still gets its
  other configs measured;
- **an in-flight sibling completes and records its full result** — the
  endpoint's success does **not** suppress it. There is **no cancel-on-winner
  path**: a sibling is dispatched either after the endpoint's verdict (the
  deferral) or via the bypass, and in both cases its result is recorded in
  full;
- **the bypass**: when the concurrency limit is **not reached**, a deferred
  sibling is dispatched immediately — and its result is a **FULL result of its
  own** (its own Fast delay, Auth flag, Real delay and exit IP). A bypassed
  sibling that **fails** writes its **own** failure marker;
- the fast-failed endpoint's remaining rows are dropped from the queue (the
  "Fast failed → skip the endpoint" rule);
- the queue is refilled from the incoming stream when it drains.

**The Fast span's key is (endpoint, transport class), not endpoint.** The
transport class comes from the protocol kind (TCP family / UDP / QUIC) — the
same dispatch the fast adapter registry already does
(`leas-core/src/ping/adapters/`). Today's fast probe dedups per
`(address, port)` and ignores the class, which is why the datagram-plugin case
needed a special-case refusal (`datagram_plugin_mode`, `ops/ping.rs:113-121`).
Under the merged probe, the span is measured by the link's **own** probe
(stage 1), so a probed link carries its own class's span; the class only
matters where a span is **copied** — to a skipped sibling (same class only) or
by the Fast Test's fan-out (one probe per class, fanned to that class's
links).

### T3.2 — the TestWorker and the barrier

`crates/leas/src/ops/ping.rs` — the batch pipeline becomes a scheduler:

- **the walk's order is UNCHANGED: `PageSort::Test`.** The plan is a
  `VecDeque<PlanLink>` filled from the existing walk — the same
  `PlanWalk::next_page`, the same frozen id list, the same `PageSort::Test`.
  The endpoint grouping the worker needs **already exists** (the walk sorts
  endpoints; each endpoint's links come back together), so **no new order and
  no new query is introduced**. The "working servers first" property is
  preserved exactly.
- **the group is contiguous**, so the worker reads the group and acts on it —
  **no queue mutation to find a sibling**.
- `succeeded: HashSet<EndpointId>` — the barrier: the endpoints whose real
  probe **succeeded**. It is consulted **once per group entry**. It is
  **run-local and tiny** — the measured real-success rate is 0.03%–1.7%, so a
  74k-endpoint run holds **tens** of ids (a few kilobytes), and a membership
  test is a hash of 8 bytes. **No bloom filter**: it would add a
  false-positive dimension to a set that can be tested exactly, for no
  measurable saving. **No new dependency** (`fastbloom` stays where it is —
  `leas-host-features` uses it for its whitelists; the pipeline does not).
- one semaphore (`real_ping_concurrency`); the `fast_sem` is retired with the
  Fast level's separate pipeline (spec D14).

**The walk's ORDER and MEMBERSHIP are both unchanged.** The scoped walk still
freezes its endpoint set before the first probe (the scope predicate reads
`rank_bin`, which the batch itself rewrites — `ops/ping.rs:1379-1405`). The
frozen list is the run's **plan**: nothing re-reads the scope mid-run, so an
endpoint that leaves the scope while the run is in progress is **still probed**
— the freeze exists to prevent an endpoint being **skipped** by an
offset-paged walk, not to prevent probing.

**The bypass is implicit and load-dependent.** It fires only when a slot is
free, and the queue is full for the whole main pass (the walk produces ~5,900
links/s against the probes' ~250 links/s — a ~23× gap), so in practice it fires
**only at the tail**, where fewer than 100 links remain. The measured set of
siblings therefore depends on the machine's speed. This is accepted: the
bypass's purpose is to keep the slots busy, and the tail is where idle slots
exist.

**The task scheduler's role.** `ops/scheduler.rs` owns the per-(protocol,
endpoint) gate ("at most one live task per link"). The merged probe keeps
using it: a link's task is still one live task, and the endpoint's siblings
are separate links with separate gates.

**`cancel_queued` is now the STOP path only.** There is no cancel-on-winner
path: a sibling is dispatched either after the endpoint's verdict (the
deferral) or via the bypass, and in both cases its result is recorded in full
— the endpoint's success does not suppress a sibling's measurement, because
the sibling's config is a different config and may route elsewhere. A sibling
already in flight when the endpoint's winner lands **completes and records its
full result**.

### T3.3 — the Fast Test (endpoint scope)

`crates/leas/src/ops/ping.rs` — the Fast Test is its own command with its own
scope, **not** a mode of the Real Test:

- it probes **one transport per (endpoint, transport class)** and fans the
  measured span to every link of that class (spec D7);
- it writes **only** the Fast delay and the transport-failure marker. It
  writes **no** real delay, **no** Auth flag and **no** exit IP — it never
  builds a tunnel;
- it **never clears** an existing config-class marker (a transport handshake
  proves nothing about the config — ADR 0006 decision 8), and it never earns a
  purge verdict;
- a row measured only by the Fast Test ranks in the **fast** bands (6–11),
  exactly as a fast-only measurement does today.

RED tests: the Fast Test writes a fast delay and nothing else; it leaves a
`[real]` marker in place; it does not clear a purge verdict; two links of the
same endpoint but different transport classes get their own spans.

### T3.4 — one limit, one bar, one menu

- `crates/leas-config/src/app_config.rs`: `fast_ping_concurrency` is **removed** from `SpeedTestConfig`; a config file that still carries it is ignored (the struct uses `#[serde(default)]` throughout, so an unknown key must not be an error) with one warning line at load.
- `crates/leas/src/ui/mod.rs`: the speed-test menu becomes `Fast Test` / `Real Test` (+ the four scopes on Real Test) and `Fill Exit IPs (Successful)`; the `Fast + Real Ping` entries are **removed** (the merge IS the Real Test).
- `crates/leas/src/ui/actions_log.rs`: one bar per run; the Fast bar is dropped. The Fast Test's own run renders a `Fast`-labelled bar.
- `crates/leas/src/ui/status_bar.rs`: the `F done/total · R done/total` pair becomes the merged run's single counter.
- `crates/leas/src/types.rs`: `BatchMeters` loses the `fast`/`real` split (one level's meters); the maintenance meters are untouched.

### T3.5 — the grid's Fast + Auth columns

`crates/leas/src/ui/profiles.rs`:
- `GRID_COLUMNS` gains `(Fast, 7)` before `(Real, 7)` and `(Auth, 3)` between them; the `Test` column is renamed `Real`; `Stab` keeps its adjacency to the Real column (the stab-alive spec requires it).
- the Fast cell: the transport span, coloured by the existing thresholds (`TEST_WARN_MS` 500 / `TEST_BAD_MS` 1000), or `[name]` when the DNS host never resolved.
- the Auth cell: the quad-state glyph (`✓` / `✗` / `·` / `?`).
- the Real cell: the real span, or the failure marker (`[real]`, `[fast]`, `[name]`, the purge labels, the `not testable` marker) — the markers live in the Real column, and the Fast column keeps its number (spec D17).
- the width-based drop order is re-derived for the two new columns; the 118-cell geometry is re-measured (`GRID_COLUMNS` is the one owner — `ui/profiles.rs:1207-1221`).

RED tests: the grid renders `Fast │ Auth │ Real`; a row with a fast delay and a real failure renders `[12ms] ✓ [err]`; a transport-only row renders its fast delay with `·`; an untested row renders blanks.

### T3.6 — the `Fill Exit IPs (Successful)` command

`crates/leas/src/ops/ping.rs`:
- its own scope (the Successful band), its own bar, its own rate limiter.
- it writes the exit IP + the live country flag + (where observed) the Fast delay and the error marker, and **never** `latency_real_delay` (spec D11).
- the country flag updates **live** — a new event or a re-render path (`ops/enrich.rs` re-reads persisted IPs at load, which is the reload path, not the live one).

### T3.7 — the ordering-law clause

`crates/leas-db/src/endpoint_rank.rs`: the band law's "is it real or fast?" predicate becomes "is `latency_real_delay` non-null?" — the **bands themselves do not move** (real 0–5, fast 6–11). `STAB_VERSION` does **not** change (the inputs to the ring did not change).

### T3.8 — S3 docs

- `docs/reference/ordering-law.md` — §2's predicate + a dated clause: the bands are unchanged, the Auth flag is not a band term.
- `docs/guides/tui-manual.md` — the grid columns (Fast/Auth/Real), the Speed Test menu, the progress text.

**S3 acceptance:** the Fast column shows a number beside a real failure; the endpoint's other links show the Fast delay and no real delay; a feed-wide run's throughput is **better** than today's two-phase pipeline on the same corpus; the Auth flag's distribution is measured (spec §8 item 1) and reported.

---

## Verification (whole plan)

| gate | command |
|---|---|
| unit + integration | `cargo nextest run --workspace` |
| lint | `cargo clippy --workspace --all-targets --all-features -- -D warnings` |
| format | `cargo fmt` |
| deps | `just quality-gate deps` |

**Smoke (required, real runtime — the TUI surface is the deliverable):**
1. `cargo run` against the workspace DB; `t` → the Speed Test menu shows the new items; the grid header shows `Fast │ Auth │ Real`.
2. `Real Test (Selected)` on one live row: the Fast cell, the Auth glyph and the Real cell fill; the Exit column fills from the mux handover or the reopen.
3. `Real Test (All Profiles)` over a scoped set: the bar advances; a row with a broken config shows `[12ms] ✗ [err]` — the transport span **beside** the failure, which today's pipeline cannot show.
4. `Fill Exit IPs (Successful)`: the Exit column fills; the Real delay does **not** change.
5. The Auth-flag distribution is counted and reported (spec §8 item 1) — this is the measurement that decides whether the flag stays.

**The throughput claim must be measured, not asserted:** run the old pipeline and the new one over the same corpus and report both. If the new pipeline is not faster on healthy rows, the merge's premise is wrong and the plan stops for review (spec §7's "slower on hanging servers" is an accepted cost; "not faster on healthy rows" is not).

### Smoke evidence (2026-10-22)

The TUI surface was verified against a REAL runtime (the `tui-test` harness, an
isolated `HOME` + `XDG_CONFIG_HOME`, a copy of the seeded fixture):

| step | result |
|---|---|
| the Speed Test menu | `Fast Test (Selected)` / `Real Test (Selected)` / `Speed Test (Selected)` / `UDP Test (Selected)` — separator — `Fast Test (All Profiles)` / `Real Test (All Profiles)` / `Real Test (Successful)` / `Real Test (New)` / `Real Test (Successful + New)` / `Real Test (Failed)` / `Fill Exit IPs (Successful)` — … The `Fast + Real Ping` entries are GONE. |
| the grid header | `Fast ↑  Auth Real` — the Fast column carries the sort arrow, Auth sits between it and Real. |
| a measured row | `[ 12 ]  ✓   [ 120]` — the transport span, the auth flag (ok) and the real span, side by side. |
| the decisive row (the transport answered, the config did not) | `[ 12 ]  ✗    [real]` — the transport span BESIDE the auth failure BESIDE the real-probe failure. The old single Test column could not show that pair. |
| a transport-only row | `[ 45 ]  ·` — the transport span and the n-a auth, no real span. |
| an unprobed row | blanks in Fast and Auth. |

**Not verified on screen (the fixture has no reachable server):** the live
`Real Test` filling the three cells from a real probe, the mux handover
counting one handshake, and `Fill Exit IPs` filling the Exit column. Those
need a real endpoint; the probe-level equivalents are pinned by the tests
(`the_transport_stage_has_its_own_budget`,
`a_mux_row_probes_over_one_connection`,
`a_failed_probe_still_reports_the_transport_span`).

**One acceptance item is OPEN, and the smoke does not close it:**

1. **The throughput measurement is not taken.** The clause above is the plan's
   own stop-for-review gate, and it stays open.

**T2.2's Auth flag producer LANDED after the smoke** (2026-10-22): the
protocol phase installs an auth-ack slot on the link context, the tunnel's own
read path reports into it (a VLESS response header IS the acceptance; an EOF
during the peel is POSITIVE rejection evidence; a non-vless peer makes the ack
NotApplicable), and the probe reports the observed state with its result.
`apply_test_result` persists it into `latency_auth`. Pinned by
`the_peel_reports_the_ack_into_its_slot` — the same fixture-data caveat that
applied to the screen capture does NOT apply to the producer any more.

**The throughput claim is still OPEN.** It needs the old and the new pipeline
over the same live corpus, and the corpus here has no reachable server. The
structural argument is one connection per link instead of two (the TCP ping is
gone) and one probe instead of a ping plus a probe — but a measurement is not
a claim, and this item stays open until one exists.

---

## Risks

| risk | mitigation |
|---|---|
| the Auth flag lands mostly `unknown` (sing-box's lazy ack) | spec §8 item 1 measures it; D9's revisit condition drops the flag if `failed` appears on rows that later succeed |
| the merged level is slower on hanging servers (10 s worst case vs 5 s) | accepted (spec D12) — the fast-failure retirement already skips most of them |
| the migration is the crate's first and its non-idempotent steps are one-shot | the cursor gates them (T1.1's reopen test is the guard) |
| the exit-IP fill cannot cover a large feed (~2,700 rows/hour on ip-api's free tier) | the provider fallback chain; the fill is a separate, resumable command |
| the grid gains two columns in a fixed-width layout | the drop order is re-derived in T3.5; the geometry is re-measured |

## Retirement

- The `Latency` **enum** and the `latency` **discriminator column** are **removed** (not deprecated) — no shim, no fallback column, no compat path.
- `fast_ping_concurrency` leaves the config, the settings UI and the settings form.
- The `Fast + Real Ping` menu entries and the Fast progress bar are removed.
- The exit-IP fetch is no longer inside the real probe.
- The `BatchMeters.fast` / `.real` split is retired with the two-phase pipeline.

## Execution route

**inline.** The three slices touch one crate boundary each in sequence, and S1's schema change is a consumer for every later slice — parallel subagents would collide on `leas-db` and on the `Latency` type. Slice-by-slice, one commit per slice, each verified before the next begins.

`User confirmation required: no` — the spec is approved and the plan is derived from it; the execution route is the agent's own decision.
