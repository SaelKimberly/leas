# Design: One Probe, Two Measurements — the merged test pipeline

- **Date:** 2026-10-21
- **Status:** approved (grilling interview, same day)
- **Owners:** `crates/leas/src/ops/ping.rs` (the worker), `crates/leas-native/src/probe.rs` (the probe), `crates/leas-db/src/models_toasty.rs` + `crates/leas-db/src/schema/` (the storage), `crates/leas/src/ui/profiles.rs` (the columns)
- **Amends:** `2026-09-17-batch-ping-pipeline-design.md` (the two-phase pipeline), `2026-09-14-native-ping-pipeline-design.md` (the probe), ADR 0004 (the real-ping engine), ADR 0006 (purge evidence), `docs/reference/ordering-law.md` (the band law)
- **Supersedes (the parts it replaces):** the `Latency` enum embed (`models_toasty.rs:248-263`), the two-level progress surface (`types::BatchMeters.fast` / `.real`)

## 1. Problem

The test pipeline measures a link twice, in two phases, with two verdicts, and
the two phases disagree about what a number means.

**The fast level** (`leas_core::FastPingManager`) opens a raw TCP / UDP / QUIC
socket to the endpoint's address and measures the transport span. It proves
the server's socket accepts a connection. It says nothing about the config: a
wrong UUID, a wrong password and a dead backend all read "reachable".

**The real level** (`ops::ping_native::real_ping`) builds the full native
tunnel and issues one HTTP request to `ping_url` over it, then **opens a
second tunnel** to fetch the exit IP. So a successful row costs **two proxy
handshakes**, and the documented throughput (~2.45 results/s at concurrency 5,
`ops/ping.rs:49-56`) is really ~5 handshakes/s.

The two phases are also sequential in substance: the real half is dispatched
from the fast half's settle (`ops/ping.rs:1871-1936`), and the fast half's
transport verdict is the only thing that can retire the real half early
(`classify_fast_failure` → `hard` → `hard_fast`).

Three consequences the user wants gone:

1. **One pass, two numbers.** A single probe should produce the transport
   span AND the real span, so the dataset is measured once, not twice.
2. **One limit, one bar.** `fast_ping_concurrency` (200) and
   `real_ping_concurrency` (100) are two knobs for one pipeline; the merged
   limit bounds the expensive stage, so it must be the real level's number.
3. **Two delays per row.** A row should carry the transport span AND the real
   span simultaneously — today's `Latency` embed cannot hold both (one shared
   `delay` column + an exclusive discriminator).

## 2. Evidence (code facts, verified 2026-10-21)

| fact | site |
|---|---|
| the fast level already dedups per `(address, port)` and fans the result to every link sharing it | `ops/ping.rs:2140-2200` |
| a hard fast failure already retires the real half — "if TCP fails, no Real Ping after" is **implemented** | `ops/ping.rs:1890-1912` (`classify_fast_failure` → `hard` → `hard_fast`) |
| the real probe's exit-IP fetch is a **second full tunnel**, not a request | `ops/ping_native.rs:216-235` (`probe_attempts` + `fetch_ip_info`, each a `probe::fetch` → `crate::connect`) |
| the whole attempt shares ONE deadline today | `leas-native/src/probe.rs:78-96` |
| 531 of 535 real-timeout rows on the 2026-09-21 run had a **sub-second fast latency** — the transport was alive; the timeout was spent later | `specs/2026-09-22-native-testability-improvement-design.md:463` |
| the `Latency` embed is ONE column (`latency_delay`) + an exclusive discriminator (`latency` = `'real'`/`'fast'`) | `models_toasty.rs:248-263` |
| the native engine serves 6 of 27 protocol kinds: VLESS, VMess, Trojan, Hysteria2, Shadowsocks, Shadowsocks2022 | `leas-native/src/capability.rs:46-57` |
| Trojan and SS(AEAD) have **no server ack** — silent handshakes | `leas-native/src/protocol/trojan/mod.rs:9` |
| VLESS/VMess ack after auth and before dispatch; the ack may arrive **lazily** (sing-box) | `thirdparty/Xray-core/proxy/vless/inbound/inbound.go:619`; `leas-native/src/protocol/vless/stream.rs:1-11` |
| hysteria2's ack is the h3 auth status 233 | `leas-native/src/protocol/hysteria2/quic.rs:244` |
| SS2022's ack echoes the request salt | `leas-native/src/protocol/ss/stream2022.rs:173` |
| `into_0rtt()` is called, but a fresh `rustls::ClientConfig` AND a fresh `quinn::Endpoint` are built per dial ⇒ the resumption store is always empty ⇒ **0-RTT never fires** | `leas-native/src/transport/quic.rs:170`; `leas-native/src/protocol/hysteria2/quic.rs:155-166` |
| the migration cursor has **no step list** — a cursor between 0 and 18 is `IncompatibleSchema` ⇒ a wipe | `leas-db/src/schema/mod.rs:155-160` |
| `ALTER TABLE … DROP COLUMN` works on this engine | `leas-db/tests/schema_migrate.rs:344-350` |
| `PurgeReason` is CHECK-frozen ("one nullable column and one CHECK list") | ADR 0006 decision 2 |

### 2.1 The premises that did NOT survive

The user's original framing contained four claims the code refutes. They are
recorded because the design would otherwise look unmotivated.

1. **"0-RTT could be immediately validated."** 0-RTT cannot fire (empty
   resumption store), and on a feed-wide run every endpoint is probed **once**,
   so there is no ticket to reuse. The only re-probe is the exit-IP fill, and
   there the mux rows already ride the **live connection** — strictly better
   than 0-RTT. **Out of scope** (D13).
2. **"For 0-RTT / QUIC protocols, Fast Ping should act like a Real Ping with no
   difference."** The gap is **authentication**, not latency:
   `QuicPingAdapter` measures a bare QUIC/TLS handshake with a permissive
   verifier and **no hysteria2 auth**, while the native engine *does* auth
   (`leas-native/src/protocol/hysteria2/mod.rs:75`).
3. **"Make every protocol handshake interruptible."** Trojan and Shadowsocks
   have **no ack** — there is nothing to interrupt at. The Auth flag is
   **not applicable** for those families and for every kind the engine cannot
   serve.
4. **"If TCP succeeds, immediately Real Ping on the established session."** A
   tunnel is **bound to one target** (the request headers carry the
   destination), so a truncated-handshake number and a full probe cannot both
   come from one connection for the TCP family. The merge therefore measures
   the transport span as a **stage** of the one probe, not as a separate
   connection.

## 3. Decisions

### D1 — One probe, one verdict; the failure class picks the marker

A link's test is ONE probe that produces the transport span, the Auth flag
and (where the engine can serve the row) the real span. A failure's **class**
decides the marker, so a row never carries two contradicting verdicts:

| outcome | Fast | Auth | Real | marker |
|---|---|---|---|---|
| **measured** | transport span | ok / failed / unknown | real span | — |
| **transport-only** (the engine cannot serve this config) | transport span | n-a | — | `not testable by the native engine: …` (today's marker, unchanged) |
| **not measurable** (the transport failed) | — | — | — | `[fast]` marker (transport failure) |

The `not testable` marker stays a **STATUS** that outranks a delay in the Test
cell (`ui/profiles.rs:608-663`), exactly as today.

### D2 — The Fast metric is the transport span (one unit everywhere)

The Fast number is the time for the endpoint's IP+port to accept a transport
(TCP connect / UDP / QUIC handshake). It is the **same unit** whether it was
written by a Fast Test (endpoint scope) or as stage 1 of a Real Test (link
scope), so the column is comparable across every kind.

Rejected: the protocol-handshake span (it has **no ack** for Trojan/SS, and
21 of 27 kinds have no native handshake at all — so that metric would drop
coverage rather than add it).

**The one honest caveat on "one unit".** The metric is *the time to establish
the endpoint's transport*, and the transports differ in what that costs: a
TCP endpoint's span is the connect (no crypto), while a QUIC endpoint's span
is the UDP round trip **plus the QUIC handshake plus the TLS handshake**
(`QuicPingAdapter`, `leas-core/src/ping/adapters/quic.rs:29-66`). The two
numbers are therefore **not comparable in absolute terms** — a QUIC endpoint
inherently measures tens of milliseconds more. This is already true today
(today's fast probe dispatches the same adapters), so the merge does not
introduce it; the merge's contribution is that the number is now measured
**the same way** in the Fast Test and as stage 1 of the Real Test, so the two
writers of the column agree.

### D3 — The Auth flag is a quad-state success flag, not a metric

| state | meaning | glyph |
|---|---|---|
| `ok` | the ack arrived — the server accepted this config | `✓` |
| `failed` | **positive** rejection evidence (EOF during the peel, an auth error, a framing error) | `✗` |
| `n-a` | the family has no ack (Trojan, SS-AEAD), or the engine cannot serve the row | `·` |
| `unknown` | the ack is possible but was not observed in time (a lazy sing-box server + a slow target) | `?` |

`failed` requires positive evidence, because an unobserved ack is not a
rejection: sing-box writes the VLESS response header **lazily** (only before
the first application-data write — `leas-native/src/protocol/vless/stream.rs:1-11`),
so a slow target means the ack never arrives. Recording that as "failed"
would persist a false negative indistinguishable from a wrong UUID.

The flag is stored as an integer column (`NULL` = never observed, 1 = ok,
2 = failed, 3 = n-a, 4 = unknown) so the four states survive a restart and the
TUI can render them without re-deriving anything.

**The mechanism matters here, so it is named.** A toasty **enum** embed
emits `TEXT` with a `CHECK (col IN (...))` on SQLite/Turso
(`toasty-core-0.11.0/src/schema/db/ty_enum.rs:5`), and a `CHECK` on a column
cannot be altered afterwards (SQLite forbids changing one; a new variant means
a table rebuild). A toasty **struct** embed flattens its fields into plain
columns with no CHECK. So the auth flag MUST be a plain `Option<i64>` field
inside the struct embed, with the four states as a **Rust-side enum** in
`leas-db` (one `as_i64` / `from_i64` pair) — the `stab_mask` / `stab_len`
precedent, which is already two plain integers. A toasty enum embed for the
auth states would put a CHECK on the column, and the first state that needs
adding later would cost a `profile_stats` rebuild.

### D4 — The storage: the `Latency` enum becomes a struct embed

```
profile_stats.latency             DROPPED  (the discriminator)
profile_stats.latency_real_delay  RENAMED from latency_delay
profile_stats.latency_fast_delay  NEW
profile_stats.latency_ip          kept    (the exit IP)
profile_stats.latency_auth        NEW
```

A toasty **struct** embed flattens into prefixed columns
(`toasty-macros-0.11.0/src/lib.rs:848-870`), so `latency: Latency` with

```rust
pub struct Latency {
    pub real_delay: Option<i32>,
    pub fast_delay: Option<i32>,
    pub ip: Option<String>,
    pub auth: Option<i64>,
}
```

produces exactly the four columns above and **no discriminator** — the enum's
discriminator was what made the two delays mutually exclusive.

`latency_ip` stays inside the embed: it is the exit IP of the **real**
measurement, and it is written by the exit-IP worker, not by the probe.

### D5 — The schema change is a migration, and the migration machinery is built for it

The crate has never had a step list (`schema/mod.rs:155-160`: *"There are none
yet"*). ADR 0012 D-C already decided the cursor semantics — "a supported older
version applies the pending steps; only an UNKNOWN cursor wipes" — so slice 1
builds the **first** real step list and the cursor's `18 → 19` arm.

**Migration 19** (one transaction, the cursor advances in the same
transaction):

```
ALTER TABLE profile_stats RENAME COLUMN latency_delay TO latency_real_delay;
ALTER TABLE profile_stats ADD COLUMN latency_fast_delay INTEGER;
ALTER TABLE profile_stats ADD COLUMN latency_auth INTEGER;
UPDATE profile_stats SET latency_fast_delay = latency_real_delay WHERE latency = 'fast';
ALTER TABLE profile_stats DROP COLUMN latency;
PRAGMA user_version = 19;
```

**Why the non-idempotent statements are safe here** (this is the trap the
review raised): `ensure_raw_ddl` re-runs *idempotent* `ADD COLUMN`s on every
open and tolerates exactly one error string ("duplicate column",
`schema/ddl.rs:92-94`). `RENAME COLUMN` and `DROP COLUMN` are **not**
idempotent — they error with "no such column" / "no such column: latency" on a
second application. They are safe **only because the cursor gates them**: the
step list is applied when `cursor < 19`, and the cursor becomes 19 in the same
transaction that applies the step. A database at 19 never re-runs them. The
step list must therefore NOT be folded into `ensure_raw_ddl`.

Rejected: `ADD latency_real_delay` + `UPDATE` + keep `latency_delay` as a
vestigial column (anti-entropy violation — a second spelling of one fact).

The data step moves the old fast rows' delay into the fast column **before**
the discriminator is dropped, so a `'fast'` row's number is not lost.

**No CHECK list is added.** The `latency_auth` column is a plain integer and
the `error_kind` / `purge_reason` CHECK lists are untouched, so the
`profile_stats` table is **not** rebuilt. (The `latency` discriminator's own
CHECK — if the engine emitted one for the enum — disappears with the column;
the discriminator's values were `'real'`/`'fast'`/`''`, and nothing outside
the crate reads them.)

### D6 — The ordering law re-derives, and the Auth flag joins it

`docs/reference/ordering-law.md` §2's band law:

| condition | bin |
|---|---|
| purged | 16 |
| DNS unresolved | 15 |
| fast error marker | 14 |
| real error marker, no real success in the ring | 13 |
| **a real delay is present** | real delay bin 0–5 |
| **only a fast delay is present** | fast delay bin 6–11 |
| no delay | 12 |

The discriminator is gone, so "is this a real or a fast measurement?" becomes
"**is `latency_real_delay` non-null?**". A row can now carry both; the real
one wins the band (unchanged semantics: *"a real measurement outranks a fast
one of any delay"*).

The **Auth flag does not enter the band law**: it is a status, not a
measurement, and no band has room for a third axis. It is a **TUI** fact
(a column between Fast and Real) and a **purge** input only if D9 changes.

### D7 — The Fast probe is (endpoint, transport-class)-scoped and fans out

One transport probe per **(endpoint, transport class)**; the measured span is
written to every link of that endpoint that needs that class. The transport
class comes from the protocol kind (TCP family / UDP / QUIC) — the same
dispatch the fast adapter registry already does (`leas-core/src/ping/adapters/`).

This is today's fan-out semantics (`ops/ping.rs:2140-2200`) made
transport-aware: today one TCP probe covers a (address, port) even when a
sibling link is QUIC, which is why the datagram-plugin case needed a
special-case refusal (`datagram_plugin_mode`, `ops/ping.rs:113-121`).

### D8 — The Real probe is link-scoped; the endpoint's other links get the Fast delay only

When the endpoint's real test succeeds on protocol P, the endpoint's other
links (protocol Q) are **skipped**: they receive the **Fast** delay (a shared
transport fact) and **no** real delay, **no** marker and **no** exit IP.

**Scope of the skip.** The skip applies to the links of the **same endpoint**
that the run has not yet probed — it is not a claim that protocol Q is bad.
A link whose own probe already ran keeps its own result. And because the
dedup is decided **per endpoint per run**, a later run probes the endpoint's
other protocols again if the scope selects them: the dedup is a per-run
economy, not a persisted verdict about the sibling.

This is today's endpoint-dedup semantics verbatim
(`ops/ping.rs:1966-1976`, the `completed_endpoints` branch), and it is
required for correctness, not tidiness: the exit IP of protocol P is **not**
protocol Q's exit IP (the endpoint's own comment says so —
`ops/ping.rs:2645`: *"their exit IPs may differ"*).

Consequence: a multi-protocol endpoint's row shows a Real delay only if its
**representative** link (the ordering law's argmin) is the tested one.

### D9 — An auth rejection earns NO purge verdict

A wrong UUID / password is recorded as the **Auth flag = failed** plus a
`[real]` marker; the row **stays in Active**. No `FailureEvidence` arm and no
`PurgeReason` variant are added.

Rationale: the signal is only *positive* for hysteria2 (an explicit non-233 h3
status), and even there a non-233 may be the server's **masquerade** page
answering a non-hysteria request — a hijacked IP, not a wrong credential. For
VLESS/VMess, "the connection ended before the ack" is indistinguishable from a
crash or a middlebox kill. And a false positive **deletes a working profile**
("Remove Bad Servers").

`PurgeReason` is CHECK-frozen (ADR 0006 decision 2), so a new variant would
force a `profile_stats` table rebuild; the cost is not worth it while the
signal is ambiguous.

**Revisit condition**: measure the Auth-flag distribution per server family in
slice 3. If `failed` is observed on rows that later succeed, the flag is
unsound and must be dropped. If it is observed overwhelmingly on
never-succeeding rows, a typed `FailureEvidence::AuthRejected` + a
`PurgeReason` variant becomes worth the rebuild.

### D10 — The exit IP is a separate background phase, with a live-connection handover

The probe writes the real span; the **exit-IP worker** fetches the exit IP
separately, with the provider fallback chain (`leas-config/src/ip_provider.rs`)
and the existing retry policy.

**Mux rows hand the live connection over.** For a VLESS-mux row the IP fetch
opens a **second session on the same proxy connection**
(`MuxClient::open_session`), so the row costs **one** handshake for both
destinations. Non-mux rows reopen (one extra handshake — unavoidable, because
a tunnel is bound to one target).

The exit-IP phase is **rate-limited by the provider** (ip-api's free tier is
~45 req/min ⇒ ~2,700 rows/hour) and never blocks the probe's throughput.

### D11 — The exit-IP command never rewrites the Real delay

`Fill Exit IPs (Successful)` re-tests the links of the Successful band
against the IP-API and writes: the exit IP, the country (live), and — where the
re-test observed them — the Fast delay and the error marker. It **never**
writes `latency_real_delay`: that number belongs to gstatic's
`generate_204`, and an IP-API measurement is a different destination.

Consequence: the Real delay and the exit IP are **independently-aged facts in
one row**. The TUI must not imply they are one measurement (the Exit column
and the Real column are separate cells, which is already true).

### D12 — Per-stage budgets

| stage | budget | measured |
|---|---|---|
| transport (dial to host:port) | `speed_test.tcp_timeout_secs` (5 s default) | the Fast span |
| protocol (TLS + handshake + auth) + probe (tunnel + target TLS + request) | `speed_test.real_ping_timeout_secs` (5 s default), **in full** | the Auth flag + the Real span |

The budgets are **independent**, not a split of one total: a row's worst case
is 10 s (was 5 s). The reason is D2 — the transport span must never be
truncated by the protocol stage's budget, which is the whole point of
measuring it separately.

Consequence: a TCP-ok / TLS-hanging server occupies its slot twice as long,
so the merged level's throughput on hanging servers is **lower** than today's
single-deadline pipeline. This is the accepted cost of separating the two
measurements.

### D13 — 0-RTT is out of scope

See §2.1 item 1. The live-connection handover (D10) already covers the only
re-probe in the design, and it dominates 0-RTT (zero extra RTT, no ticket, no
early-data rejection path).

### D14 — One concurrency limit, inheriting the real level's value

`speed_test.real_ping_concurrency` (default 100) is the **only** limit. The
merged limit bounds native handshakes — the expensive stage — so the fast
level's 200 was never a meaningful ceiling for it.

`speed_test.fast_ping_concurrency` is **retired**: removed from the config
struct, from the settings UI and from the settings form. A config file that
still carries it is ignored with one warning line (an unknown key must not be
an error — the config is deserialized with `#[serde(default)]` throughout).

### D15 — The TestWorker: the walk's order is kept; the group is gated at entry

> **Corrected 2026-10-21 (user ruling).** This decision previously proposed
> streaming the rows **sorted by endpoint**, replacing `PageSort::Test`. That
> was wrong on two counts, and the correction is recorded here rather than
> silently overwritten — the rejected alternative is in §9.

The worker is a **scheduler**, not a sequential processor, and it keeps
**`PageSort::Test`** as the walk's order.

**Why `PageSort::Test` stays.** It is the decision-16 law's order — the
**working servers first**. The walk reads the endpoint ids once, in that
order, and the run probes them in that order, so a feed-wide run finds the
servers that actually work **first**. On a 74k-endpoint feed at the measured
real-level throughput, that ordering is worth more than any parallelism
tweak. A result-independent order (by endpoint id) would have been *stable*,
but stable is not the property that matters: **"the working servers, first"**
is.

**The endpoint grouping already exists.** `PageSort::Test` sorts **endpoints**
(`order_terms`, `profiles_query.rs:372-385`: `band, rank_bin, rank_stab,
rank_weight, rank_domain, rank_sub_domain, rank_addr, endpoint_id`), and each
endpoint's links come back together (`plan_row_links` → `row.links`, "sorted by
test priority", `models_toasty.rs:657`). So an endpoint's protocols are
**contiguous in the plan** already — the grouping the worker needs is free, and
no new order is required.

**The rules:**

1. **The endpoint's group is contiguous in the plan**, so the worker never
   mutates the queue to find a sibling: it reads the group, consults the
   barrier **once at group entry**, and acts.
2. **At group entry**, the barrier is asked whether the endpoint already
   **succeeded**:
   - **succeeded** → the whole group is **dropped** (no probe, no marker, no
     delay, no exit IP for any of its links);
   - **not succeeded** → the endpoint's **FIRST** protocol (the one the law
     ranks best, `row.links[0]`) is **dispatched immediately**, and its
     **siblings are deferred to the back** of the queue.
3. **The deferred siblings are probed when they are reached** — a different
   protocol config may work where the first did not. There is **no second
   barrier check**: a sibling that was deferred is probed.
4. **The bypass.** When the concurrency limit is **not reached**, a deferred
   sibling may be dispatched **immediately** instead of waiting. Its result is
   a **FULL result of its own** — its own Fast delay, Auth flag, Real delay and
   exit IP — because a sibling's config may route through a different exit
   (the code says so: *"their exit IPs may differ"*, `ops/ping.rs:2645`). A
   bypassed sibling that **fails** therefore carries its own failure marker,
   which today's endpoint-dedup never produces.
5. **The bypass is implicit and load-dependent.** It fires only when a slot is
   free, and the queue is full for the whole main pass (the walk produces
   ~5,900 links/s against the probes' ~250 links/s — a 23× gap), so in practice
   it fires **only at the tail**, where fewer than 100 links remain. The set of
   measured siblings therefore depends on the machine's speed. Accepted: the
   bypass's purpose is to keep the slots busy, and the tail is where idle
   slots exist.

**The barrier is a plain `HashSet<EndpointId>`** of the endpoints whose real
probe **succeeded** — consulted once per group entry.

No bloom filter. The set is **run-local and tiny**: the measured real-success
rate is 0.03%–1.7% (1 of 3,380 / 9 of 996 / 75 of 4,423), so a 74k-endpoint
run holds **tens** of ids — a few kilobytes, and a membership test is a hash
of 8 bytes. A bloom filter would add a false-positive dimension to a set that
is already small enough to test exactly, for no measurable saving. (A bloom
filter WAS considered and rejected: `fastbloom` is already in the dependency
graph via `leas-host-features`, so the cost was low — but the benefit was
zero, and the false-positive question is not worth asking about a set of 20.)

**There is no cancel-on-winner path.** Under these rules a sibling is
dispatched either after the endpoint's verdict (the deferral) or via the
bypass — and in **both** cases its result is recorded in full. A sibling
already in flight when the endpoint's winner lands **completes and records its
full result**: the endpoint's success does **not** suppress it, because the
sibling's config is a different config and may route elsewhere. The only
remaining `cancel_queued` consumer is the batch **STOP** path.

**The tier may move under the walk.** A sibling's own result can make it the
endpoint's new representative, so the endpoint's stored tier moves **mid-run**
while the walk's order is a frozen snapshot. This is the law working, not
breaking: the walk's order and the tier are already different objects (the
walk orders ENDPOINTS by the endpoint key; the tier is the representative
LINK's `rank_bin`), and any real probe can already change the
representative. The siblings raise the **rate**, not the class.

**The frozen plan is the run's plan.** The scope predicates select endpoints at
**plan time**; nothing re-reads them mid-run. An endpoint that leaves the
scope while the run is in progress is **still probed** — the freeze exists to
prevent an endpoint being **skipped** by an offset-paged walk (the 2026-09-17
bug), not to prevent probing.

### D16 — The menu, the bars and the single-row path

The speed-test menu becomes:

```
Fast Test (Selected)          Real Test (Selected)
Speed Test (Selected)         UDP Test (Selected)
──────────────────────────────
Fast Test (All Profiles)          <- endpoint scope, transport only
Real Test (All Profiles)          <- link scope, transport + auth + real
Real Test (Successful)
Real Test (New)
Real Test (Successful + New)
Real Test (Failed)
Fill Exit IPs (Successful)        <- its own scope, its own bar
──────────────────────────────
Remove Bad Servers / Retry Failed DNS Lookups / Compact Duplicate Endpoints
```

`Fast + Real Ping` disappears: the merge **is** the Real Test now.

**One progress bar per run.** The Fast bar is dropped (the Fast Test has its
own bar, labelled `Fast`).

`Real Test (Selected)` is the merged probe, and it waits for the exit IP
inline (the user is watching one row). `Fast Test (Selected)` stays the cheap
transport-only probe.

### D17 — The Profiles grid: a Fast column and an Auth column

```
… Protocol │ Fast │ Auth │ Real │ Stab │ Out │ Exit …
```

- **Fast** — the transport span, coloured by the existing thresholds
  (`TEST_WARN_MS` 500 / `TEST_BAD_MS` 1000), or `[name]` when the DNS host
  could not be resolved (there is no transport measurement at all).
- **Auth** — the quad-state glyph (`✓` / `✗` / `·` / `?`).
- **Real** — the real span, **or the failure marker**: `[real]`, `[fast]`,
  `[name]`, the purge labels, or the `not testable` marker.

The **markers live in the Real column**; the Fast column keeps its number. A
row reads `[12ms] ✓ [err]` — *the transport was alive, the config was not*.
That is the information the merged probe exists to produce.

The grid's width-based drop order (`Exit`, `Out`, `White`, `Stab`) is
re-derived for the two new columns, and the 118-cell geometry is re-measured.

### D18 — Three slices, each shippable

| slice | content | acceptance |
|---|---|---|
| **S1 — schema** | the migration step list + the cursor's `18 → 19` arm; the `Latency` struct embed; the four columns; the data step; the discriminator's drop; every raw-SQL site that names `latency_delay` re-pointed (26 sites / 6 files) | a version-18 database opens, migrates, and reads back with the same numbers; a version-19 database opens unchanged; a foreign version still reports `IncompatibleSchema` |
| **S2 — probe** | the merged probe (one connection, both destinations for mux); the per-stage budgets; the transport span measured separately; the Auth flag; the three outcomes (D1); the live-connection handover | a VLESS-mux row's exit IP arrives over the same connection (one handshake, countable by the probe's own connection count); a TCP-ok / TLS-hang row reports a Fast span **and** a real failure, not a total timeout |
| **S3 — worker + TUI** | the TestWorker (D15); the one merged limit (D14); the one bar; the menu (D16); the Fast + Auth columns (D17); the ordering-law clause (D6); the exit-IP command (D11) | the Fast column shows a number beside a real failure; the endpoint's other links show the Fast delay and no real delay; a feed-wide run's throughput is **better** than today's two-phase pipeline on the same corpus |

### D18.1 The reference docs are updated BY THE SLICE THAT CHANGES THEM

The reference set (`docs/reference/`, `docs/guides/tui-manual.md`) describes
**shipped** architecture, so it is not edited when the design is approved —
only when the code that backs it lands. Each doc is therefore a task of the
slice that owns the change, and no slice may leave the set self-contradictory:

| doc | what it says today | owning slice | what changes |
|---|---|---|---|
| `reference/ordering-law.md` | §2's band law, read off `latency` = `'real'`/`'fast'` | **S3** (the band law does not move in S1 — only the columns do) | §2's "is it real or fast?" predicate becomes "is `latency_real_delay` non-null?"; a dated clause records that the bands are unchanged and that the Auth flag is not a band term |
| `reference/database.md` | the `profile_stats` mermaid block: `TEXT latency` + `INTEGER latency_delay` | **S1** | the block becomes the four columns; the discriminator's row goes |
| `reference/glossary.md` | `Latency` = the enum embed; `Fast Ping` = the transport probe | **S1** (`Latency`), **S3** (`Fast Ping` → `Fast Test`) | the `Latency` entry names the struct embed; the `Fast Ping` entry names the merged pass |
| `reference/database-manual-sql.md` | the raw-SQL table, including the stability seed's `WHERE latency='real'` | **S1** | the seed's predicate becomes `WHERE latency_real_delay IS NOT NULL`; the row's DDL list gains the new columns |
| `reference/native-core.md` | the probe contract (the attempt deadline, the two-tunnel exit-IP fetch) | **S2** | the per-stage budgets and the one-connection shape |
| `guides/tui-manual.md` | the grid columns, the Speed Test menu, the progress text | **S3** | the Fast + Auth columns, the new menu, the one bar |

**Why this table exists:** a pending marker in one doc and silence in the
others leaves the reference set describing two different schemas at once —
which is worse than describing either one alone, because a reader cannot tell
which is current.

## 4. Data flow

```
                    ┌──────────────────────────────────────────┐
  DB (PageSort::Test)│  TestWorker                              │
  ───────────────►  │  queue: VecDeque<Link>  (groups contiguous)│
                    │  succeeded: HashSet<EndpointId>           │
                    └───────────────┬──────────────────────────┘
                                    │ group entry -> barrier:
                                    │   succeeded -> drop the group
                                    │   else -> probe links[0],
                                    │           defer the siblings
                                    ▼
                    ┌──────────────────────────────────────────┐
                    │  probe (one connection)                  │
                    │  stage 1 TRANSPORT  ──► Fast span        │
                    │  stage 2 PROTOCOL   ──► Auth flag         │
                    │  stage 3 PROBE      ──► Real span         │
                    └───────────────┬──────────────────────────┘
                                    │ success -> the endpoint id
                                    │          joins `succeeded`
                                    ▼
                    ┌──────────────────────────────────────────┐
                    │  exit-IP worker (background, rate-limited)│
                    │  mux rows: 2nd session on the SAME conn   │
                    │  others:   reopen                        │
                    └───────────────┬──────────────────────────┘
                                    ▼
                    profile_stats: real_delay, fast_delay, ip, auth
```

## 5. Error handling

| failure | class | Fast | Auth | Real | marker |
|---|---|---|---|---|---|
| the transport refused / timed out / no route / DNS | transport | — | — | — | `[fast]` |
| the transport answered, the engine cannot serve the row | capability | span | n-a | — | `not testable …` |
| the protocol handshake was refused (positive evidence) | protocol | span | failed | — | `[real]` |
| the ack was not observed in time | timeout | span | unknown | — | `[real]` |
| the tunnel died / the framing failed | protocol | span | unknown | — | `[real]` |
| the target answered a non-2xx | http | span | ok | — | `[real]` |
| success | — | span | ok | span | — |

A **transport failure retires the row's real half** (today's `hard_fast`
rule, kept — D1's "not measurable" outcome is its product).

The **exit-IP failure never affects the probe's verdict**: a missing exit IP
is a missing fact, not a failure of the config.

## 6. Compatibility boundary

- **No public API change** outside `leas-db`'s existing `pub fn`s (the
  `Latency` type's shape changes — it is a crate-internal model).
- **The schema moves 18 → 19** with a real migration (the first one this
  crate has ever run). A version-18 database migrates in place; a foreign
  version still wipes (ADR 0012's rule).
- **The config file** loses `fast_ping_concurrency` (ignored, not an error).
- **The `error_kind` CHECK is untouched** — `ProfileErr::Fast` / `Real` /
  `Name` stay the only marker kinds (a new kind would be a wipe, ADR 0004
  alternative 3).
- **`PurgeReason` is untouched** (D9).
- The ordering law's bands are unchanged in number and meaning (D6).

## 7. Risks

| risk | evidence | mitigation |
|---|---|---|
| the Auth flag lands mostly `unknown` (sing-box's lazy ack + a slow target) | `leas-native/src/protocol/vless/stream.rs:1-11` | measure the distribution in S3; D9's revisit condition |
| the exit-IP fill cannot cover a large feed | ip-api's free tier ~45 req/min ⇒ ~2,700 rows/hour | the provider fallback chain; the fill is a separate, resumable command |
| the real delay and the exit IP become independently-aged facts in one row | D11 | separate TUI cells; the Exit column is never presented as part of the Real measurement |
| the merged level is **slower** on hanging servers (10 s worst case vs 5 s) | D12 | accepted: the transport span is the measurement that separates "alive" from "dead"; the fast-failure retirement already skips most of them |
| the write amplification of the Fast Test (N links per endpoint probe) | 1.85 links/endpoint on the 2026-09-17 feed | the fan-out is one probe, N staged writes (the write-behind already batches) |
| the grid gains two columns and the 118-cell geometry is fixed | `ui/profiles.rs:1207-1221` | the drop order is re-derived; `Stab` keeps its adjacency to the Real column |
| the Auth flag's `failed` state is a false positive on a middlebox kill | D9 | marker-only: no purge verdict, so a false positive costs a marker, not a deletion |

## 8. Evidence still needed (measure, do not assume)

1. The Auth-flag distribution per server family (xray vs sing-box) — decides
   whether the flag is worth its column at all, and whether D9's revisit
   condition fires.
2. The mux coverage of the real feed — decides how many rows get the
   zero-extra-RTT exit-IP path.
3. The throughput delta of the per-stage budget on hanging servers (the
   accepted cost in D12, quantified).
4. The exit-IP fill's coverage rate against the provider's ceiling.
5. The Auth flag's `unknown` rate on a fast target (a cheap proxy ⇒ a fast
   ack) — the difference between a useful column and a mostly-`?` column.

## 9. Rejected alternatives

| alternative | why rejected |
|---|---|
| keep two semaphores and two phases | the user rejected it; it does not merge anything |
| the fast number = the protocol-handshake span | no ack for Trojan/SS; 21/27 kinds have no native handshake — coverage drops |
| two rows per endpoint (one fast, one real) | doubles the rows and the writes; the error marker's ownership becomes ambiguous |
| the fast delay stored at the endpoint level | a new schema surface for a value that is per (endpoint, class); the write amplification is the same |
| `ADD latency_real_delay` + keep `latency_delay` | a vestigial second spelling of one fact |
| `Step::Rebuild` for the latency reshape | the data migrates (a copy), so an in-place step suffices; `Rebuild` is reserved for identity re-keys (ADR 0012 D-C) |
| the exit IP rides the probe's tunnel | a tunnel is bound to one target; only a mux session (or a second connection) can reach a second destination |
| an auth rejection earns a purge verdict | D9: the signal is ambiguous, and `PurgeReason` is CHECK-frozen |
| 0-RTT via a per-server QUIC session cache | D13: it cannot fire on a feed-wide run, and the live connection already covers the only re-probe |
| the Fast Test writes no verdict (transport-only, no marker) | D1: the transport failure IS the row's verdict at that level, and `remove_failed_servers` needs it |
| **stream the rows sorted by endpoint, replacing `PageSort::Test`** | **REJECTED by the user (2026-10-21).** A result-independent order is *stable*, but stable is not the property that matters: `PageSort::Test` puts the **working servers first**, which is what a feed-wide run wants. It also was **unnecessary**: the walk sorts ENDPOINTS and each endpoint's links come back together, so the endpoint grouping the worker needs already exists for free. The original proposal would have cost a sort and lost the ordering property, for nothing |
| the endpoint's siblings are dispatched in parallel during the main pass | the walk's front would advance 3× slower on a multi-protocol endpoint (three slots on E1 before E2 is reached) — the "working servers first" property would hold only for each endpoint's best link, not for the walk's front |
| the deferred siblings are skipped unconditionally | an endpoint whose first protocol has a broken config would never have its other protocols tried — a working vless row beside a broken trojan row on the same host is never measured |
| the scope is re-checked before each probe | the run would probe LESS than it planned; the freeze exists to guarantee that a scoped run probes everything it planned |
| the bloom filter decides alone (the HashSet is a rare-path audit) | a false positive would skip a **working** endpoint's siblings — their real delay and exit IP would never be measured. Superseded by the ruling below: there is no bloom at all |
| **a bloom filter over the success set** (user ruling 2026-10-21: **no bloom at all**) | the set is **tiny and run-local**: the measured real-success rate is 0.03%–1.7%, so a 74k-endpoint run holds **tens** of ids — a few kilobytes, and a membership test is a hash of 8 bytes. A bloom filter adds a false-positive dimension to a set that can be tested exactly, for no measurable saving. (`fastbloom` was already in the dependency graph via `leas-host-features`, so the cost was low — but the benefit was zero.) |
| **the deferred siblings are skipped unconditionally** (i.e. the whole group is dropped whenever the endpoint's verdict is known) | an endpoint whose FIRST protocol has a broken config would never have its other protocols tried — a working vless row beside a broken trojan row on the same host is never measured. The group is dropped only when the endpoint **succeeded**; otherwise the siblings are deferred and **probed** |
| **cancel the siblings when the endpoint's winner lands** | there is no cancel-on-winner path left: a sibling is dispatched either after the endpoint's verdict (the deferral) or via the bypass, and in **both** cases its result is recorded in full — a sibling's config is a different config and may route elsewhere. Only the batch **STOP** path cancels |

### 9.1 The Fast Test's verdict, precisely

The Fast Test (endpoint scope) writes **only** the transport span and the
transport-failure marker. It writes **no** real delay, **no** Auth flag and
**no** exit IP — it never builds a tunnel. A row measured by the Fast Test
therefore carries a Fast delay and an empty Auth/Real, and it ranks in the
**fast** bands (6–11), exactly as a fast-only measurement does today.

Two consequences worth stating, because they are the difference between the
Fast Test and the Real Test:

- The Fast Test **does not clear an existing error marker**. A row that a
  Real Test marked `[real]` keeps that marker after a Fast Test, because a
  transport handshake proves nothing about the config — the same rule the
  purge policy already follows ("a TCP/UDP handshake cannot clear a verdict",
  ADR 0006 decision 8). The Fast Test may *replace* a transport-class marker
  with a fresh transport verdict, but it never touches a config-class one.

  The corollary is the purge policy's own: the Fast Test's own transport
  failure **cannot** clear a verdict either (ADR 0006 decision 8 names the
  TCP/UDP handshake explicitly). So a Fast Test neither sets nor clears a
  purge verdict — only a real probe (or a speed test) can.
- The Fast Test **never earns a purge verdict** (no evidence, by definition).
