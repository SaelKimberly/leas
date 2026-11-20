# The failure pair (`error_stage` / `error_cause`): why every row is NULL, and what it would buy

Second part of the 2026-11-19/20 run analysis. Companion to
[`2026-11-20-log-review-real-test.md`](2026-11-20-log-review-real-test.md)
(timeline) and [`2026-11-19-real-test-funnel.md`](2026-11-19-real-test-funnel.md)
(outcome funnel). This one reads the database: the schema-22 typed failure
pair, the columns that do carry data, and what the pair would add once it is
actually written.

Snapshot: copy of `~/.config/leas/data.db` + `-wal` taken 2026-11-20 at
07:29 UTC (after the log export ended at 06:46). `PRAGMA user_version` = **22**;
24 columns in `profile_stats`; both pair triggers present
(`profile_stats_pair_ins/upd`). 66 191 endpoints, **124 391 links**, 78 154
protocols.

## 1. Headline

| Fact | Value |
| --- | ---: |
| Links (`profile_stats` rows) | 124 391 |
| Rows carrying an error marker | 124 341 |
| Rows with `error_stage` / `error_cause` | **0** |
| Error rows updated after 04:46 UTC today (last 2.5 h) | 107 906 |

The pair is **never written**. Not "written sparsely", not "NULL for legacy
rows": every failure row in this snapshot, including 107 906 rows written
after the schema-22 migration, has both columns NULL. The columns, the enum
model, the mapping function, the CHECK triggers and the read paths all exist;
the writer does not bind them.

## 2. The bug: the raw SQL writer never learned the two columns

The pair is computed correctly and then dropped at the SQL layer.

1. `failure_pair` (`crates/leas/src/ops/ping_native.rs:80`) maps
   `ProbeClass` + `transport_failed` + evidence to `(FailureStage,
   FailureCause)`. Both result paths pass it: `ping.rs:435` (single probe) and
   `ping.rs:2926` (batch), as `Some(pair)`.
2. `apply_test_result` stores it: `events.rs:225-230` builds `ErrorInfo { kind,
   text, stage: failure.map(..), cause: failure.map(..) }`.
3. `ErrorInfo` (`crates/leas-db/src/models_toasty.rs:221`) is an embed with
   `stage`/`cause` as `Option<FailureStage>`/`Option<FailureCause>`.
4. **The writer loses it.** All link writes go through one shared raw
   statement: `LINK_UPSERT_PREFIX` (`crates/leas-db/src/database.rs:732`)
   lists 22 columns and stops at `stab_mask, stab_len`; `link_values_sql`
   (`:744`) emits the matching 22 values. Both writers use it —
   `database.rs:876` (bulk upsert) and `:1428` (patch writer) — so
   `error_stage`/`error_cause` are neither inserted nor updated.

Why the test suite did not catch it: the only pair test
(`events.rs:1477`, `the_failure_pair_is_persisted_and_a_success_clears_it`)
asserts on the in-memory `ProfileStats` **struct**. It proves the mapping
reaches the model, not that the model reaches SQLite. A test that writes one
row through the shared writer and reads it back would have failed on day one.

Consequence: `ps.error_stage`/`ps.error_cause` in `profiles_query.rs:941`,
`export.rs:234` and the UI all read a column nothing produces, so the typed
taxonomy the spec (`2026-11-19-probe-truth`, S1) introduced is silently absent
from every report — including this one. It also kills a shipped UI state:
`ui/profiles.rs:606-612` renders the `[dest]` label ("the server is up, the
exit is not") only when `latency_auth == Ok` **and**
`error.stage == Target`; with the stage always NULL the label can never
appear, even on the 86 rows whose ack was observed as Ok.

## 3. What the pair is, exactly

It is a **closed projection of two facts we already have**: the engine's
`ProbeClass` and the `transport_failed` flag. The mapping
(`ping_native.rs:80-128`):

| ProbeClass | condition | stage | cause |
| --- | --- | --- | --- |
| Dns | | Dial | Nxdomain |
| Refused | | Dial | Refused |
| NoRoute / Unreachable | | Dial | NoRoute |
| Dial | | Dial | Io |
| **Timeout** | `transport_failed` | **Dial** | Timeout |
| **Timeout** | not `transport_failed` | **Target** | Timeout |
| Tls | | Transport | Alert |
| Reality | | Transport | Config |
| Transport | `HttpRejected` evidence | Transport | Status |
| Transport | otherwise | Transport | Framing |
| Protocol | `CredentialsRejected` / `ConfigDefect` | Protocol | Config |
| Protocol | otherwise | Protocol | Framing |
| Http | | Target | Status |
| Config | | Protocol | Config |
| Io / Other | `transport_failed` | Dial | Io |
| Io / Other | otherwise | Target | Io |

So the pair adds exactly two things over `error_text`: a **queryable
vocabulary** (no regex, stable across message wording) and, for `Timeout`, the
**Dial-vs-Target split**, which the text cannot express. Everything else is a
coarser restatement of the prose.

That split is not small. This snapshot's failures:

| class (from `error_text`) | kind | rows |
| --- | --- | ---: |
| `timeout on probe transport` (transport never came up) | fast | 40 919 |
| `timeout on probe attempt` (tunnel formed, destination silent) | real | 25 448 |
| `ws: HTTP error` (403/409/500/530) | real | 9 745 |
| TLS alert | real | 7 769 |
| REALITY fell back to the real certificate | real | 3 543 |
| `TLS error: I/O error: transport error: ws: HTTP …` | real | 3 261 |
| other transport errors | real | 3 235 |
| `CertNotValidForName` | real | 1 917 |
| other TLS | real | 1 870 |
| tunnel closed during the target handshake | real | 1 099 |
| `TLS error: I/O error: vless response … not a VLESS` | real | 592 |
| `CertificateExpired` | real | 143 |
| `server dial failed: … failed to lookup …` | fast | 24 026 |

(The table is not exhaustive: 774 real rows fall in none of these classes,
and the 50 rows with no marker at all are excluded.)

66 367 timeouts (53 % of all 124 341 failure rows). The pair would not tell us
*which* of the 25 448 real timeouts died at the dial and which at the target —
that depends on `transport_failed`, which is computed and then discarded. It is
also why the funnel document had to classify its 13 buckets with a ladder of
`LIKE` patterns.

## 4. A second defect: the mapping mislabels the TLS-wrapped inner failures

`ProbeFailure::from_engine` (`ping_native.rs:200-224`) classifies the **outer**
`NativeError`. When TLS wraps an underlying transport/protocol failure —
rendered `TLS error: I/O error: transport error: ws: HTTP error: 409 …` — the
class is `Tls`, so the pair says **(Transport, Alert)** even though the cause
is an HTTP status or a framing error. The same file already fixed the
analogous case for `TunnelClosed` (the comment at `:218-222`: "not `Tls`,
which is what the engine's `TlsError::Io` wrap used to produce"); the generic
`TlsError::Io(Transport(…))` wrap was not.

Rows that would be mislabelled on the day the writer is fixed:

| `TLS error: I/O error: …` inner failure | rows | pair would say | truth |
| --- | ---: | --- | --- |
| `transport error: ws: HTTP error …` | 3 261 | Transport/Alert | Transport/Status |
| `vless response version … not a VLESS` | 592 | Transport/Alert | Protocol/Framing |
| `early eof` | 497 | Transport/Alert | Transport/Framing |
| `Connection reset by peer` | 300 | Transport/Alert | Transport/Io |
| `invalid or unsupported config` | 192 | Transport/Alert | Protocol/Config |
| `transport error: ws: Watchdog …` | 186 | Transport/Alert | Transport/Framing |
| `transport error: grpc …` | 137 | Transport/Alert | Transport/Framing |
| `transport error: ws: I/O …` | 27 | Transport/Alert | Transport/Io |
| `protocol ss error: AEAD …` | 4 | Transport/Alert | Protocol/Framing |
| `vmess response header …` | 3 | Transport/Alert | Protocol/Framing |

≈5 200 rows. The type is lost one layer earlier than the classifier: the
server handshake maps every non-special `TlsError` to `NativeError::Tls(String)`
in `security/mod.rs:251` (`map_tls_err`), so the inner `NativeError` the record
layer boxed into `TlsError::Io` becomes text there. Fix at that owner — when the
`io::Error` downcasts to a `NativeError`, return it instead of the string; the
classifier and `evidence()` then read the real stage for free. Verify the bridge
that builds that `io::Error` actually boxes the typed error
(`io::Error::other(native)`, not `…to_string()`): if it formats, keep the type
there first, in the same change. The target leg (`probe.rs:617`) deliberately
keeps the plain variant: a target-side failure proves nothing about the config.

## 5. What the database can already tell us (no pair needed)

### 5.1 Transport × outcome

Real-probe failures, joined to `protocols`:

| class | transport | rows |
| --- | --- | ---: |
| timeout | ws | 16 340 |
| ws HTTP status | ws | 9 745 |
| TLS alert | ws | 5 873 |
| timeout | tcp | 5 004 |
| ws status under TLS wrap | ws | 3 261 |
| REALITY fallback | tcp | 2 514 |
| timeout | grpc | 1 677 |
| TLS cert-name | x_http | 935 |
| tunnel closed | tcp | 631 |
| REALITY fallback | grpc | 589 |

Every large `ws` class is dominated by two shapes: the front answered an HTTP
status (13 006 rows) or nothing answered at all (16 340 timeouts). That is a
front-policy question, not a client-code question — the pair groups it, it
does not answer it.

### 5.2 Protocol × outcome

The same class ladder, per `proto_kind` (real probes):

| class | proto_kind | rows |
| --- | --- | ---: |
| timeout | vless | 24 205 |
| ws HTTP status | vless | 7 971 |
| TLS alert | vless | 6 113 |
| REALITY fallback | vless | 3 543 |
| other transport error | vless | 3 206 |
| ws status under TLS wrap | vless | 3 163 |
| other TLS I/O | vless | 1 872 |
| TLS cert-name | vless | 1 823 |
| ws HTTP status | vmess | 1 612 |
| TLS alert | trojan | 991 |

The feed is VLESS-heavy, so raw counts say little; the within-protocol ratio
is the readable number: vless timeouts 24 205 of 54 008 real failures (45 %),
vmess ws statuses 1 612 of 2 852 (57 %), trojan TLS alerts 991 of 2 127
(47 %). The pair would not change any of that either — it is a denominator
problem, not a taxonomy one.

### 5.3 `latency_auth` — an observed ack that is almost never observed

`AuthState` stores 1 = Ok, 2 = Failed, 3 = NotApplicable, 4 = Unknown
(`models_toasty.rs:414-443`). Among the 59 396 real failures:

| state | rows | share |
| --- | ---: | ---: |
| Unknown | 56 685 | 95.4 % |
| NotApplicable | 2 382 | 4.0 % |
| Ok | 86 | 0.14 % |
| Failed | **0** | 0 |
| NULL | 243 | 0.4 % |

Zero positive rejections and 86 accepted-configs across the whole run. The
observation point is the tunnel's first read, which on a failed target
handshake never happens — so the column reports "could not observe" for
almost every failure. The funnel document's "partial credit" idea (§5.8,
"111 auth-ok links") has no population to stand on: the signal is there, but
only for the handful of probes that fail *after* the ack is read.

### 5.4 `error_kind = 'name'` is dead vocabulary

The schema, the UI (`ui/details.rs:381`, `ui/profiles.rs:575`) and the rank
builder (`endpoint_rank.rs:237`) all know `ProfileErr::Name`, and the CHECK
allows it. **No writer produces it**: DNS failures are written as
`error_kind='fast'` with `server dial failed: <host>: failed to lookup …`
(24 026 rows). The funnel document's bucket 02 therefore had to select on
`error_kind='fast' AND error_text LIKE '%lookup address%'` — prose, not the
kind.

### 5.5 Purge verdict vs class

| class | purge verdict | rows |
| --- | --- | ---: |
| ws HTTP status | transport_rejected | 5 689 |
| ws HTTP status | origin_unreachable | 885 |
| ws HTTP status | none | 6 432 |
| REALITY fallback | reality_fallback | 3 407 |
| REALITY fallback | none | 136 |

The purge verdict already carries a typed cause for a subset; the pair would
overlap it. They must agree (both derive from `FailureEvidence`), so a
post-fix consistency query is a free regression check: every
`reality_fallback` row should read `(Transport, Config)` and every
`certificate_mismatch` row should read `(Transport, Alert)` — the triplet
name-mismatch / expired / pin-mismatch all collapse into `Alert` by design,
so the pair is the coarse group and `purge_reason` the finer one there.

## 6. What we could fix or improve, ranked

1. **Write the pair (P0).** Add `error_stage, error_cause` to
   `LINK_UPSERT_PREFIX`, `link_values_sql` and the `ON CONFLICT … SET`
   action of the RESULT group, both writers. Compact's merge is a **second**
   writer of the same columns (`merge.rs::overwrite_link_fields` copies the
   error text onto the survivor) and must copy the pair with it, or a merge
   leaves a text that disagrees with its stage. Add a test that inserts one row
   through `Database::upsert_links` (not just `apply_test_result`) and reads
   the pair back. One row proves it: the bug is total, not partial.
2. **Unwrap the TLS I/O passthrough before classifying (P0, same change).**
   Otherwise ~5 200 rows get a wrong cause on the first run and the report
   that finally has data is wrong. Mirror the `TunnelClosed` fix, with
   `#[rstest]` cases for `TlsError::Io(Transport(HttpRejected))`,
   `Io(Protocol(..))` and `Io(Transport(Framing))`.
3. **Decide `error_kind='name'` (P1).** Either write it from the DNS-failure
   path so `[name]`, bucket 02 and the rank stop reading prose, or drop it
   from the CHECK in the next rebuild. A value nothing writes but four
   readers branch on is a trap for the next reader.
4. **Settle the auth ack (P2).** 0 `Failed` and 95.4 % `Unknown` mean the
   column cannot support the four-state display it was added for. Either
   accept it as "best effort" (document that `Unknown` dominates) or move the
   observation earlier (xray writes the VLESS response header eagerly;
   sing-box lazily, so `Unknown` stays honest there). Do not add UI weight on
   top of a signal with 86 samples.
5. **CHECK the pair's values (P2, next rebuild only).** The triggers enforce
   both-or-none, not membership. The typed enum conversion is the only
   writer today, but this is a raw-SQL table where any future writer can
   store arbitrary text. Add the enum's snake_case spellings —
   `stage IN ('dial','transport','protocol','target')`,
   `cause IN ('timeout','refused','no_route','nxdomain','alert','status','framing','config','io')`
   — when the table is next rebuilt; a schema bump for this alone is not worth
   it.
6. **Do not backfill.** The `transport_failed` flag is gone from history, so
   the Timeout split cannot be reconstructed; recomputing the rest from
   `error_text` would re-introduce exactly the regex the pair exists to
   remove. NULL already means "class unknown" in the model
   (`models_toasty.rs:221-228`); the migration sets it for every pre-22 row
   on purpose (`schema/ddl.rs:207`). Let the next run fill it.
7. **Switch reporting to the pair, keep the prose.** The funnel document's
   `CASE` ladder of 13 `LIKE` patterns is the status quo the pair replaces.
   After the fix, run both and compare: every disagreement is either a
   mapping bug (#2) or a missing class. Keep `error_text` for the detail
   column — the pair is an index, and this snapshot shows it is coarser than
   the text (cert-name vs cert-expired both collapse to `Alert`; the
   `purge_reason` column is the finer one there).

## 7. What the pair would let us ask

- **Of the 25 448 real timeouts, how many died at the dial and how many at
  the target?** Today: unknowable from the DB. That single number decides
  whether the dominant cohort is "server dead" or "server fine, destination
  filtered" — and the funnel document's recommendation 1 (re-probe at low
  concurrency) is precisely the experiment this column replaces.
- **Did a client change move rows between stages across runs?** `Dial →
  Target` migration on a protocol family is evidence a handshake fix worked,
  without reading a single message.
- **Is the ws front rejecting configs (Status) or failing to frame
  (Framing)?** The text answers it per row; only the pair answers it per
  cohort without a regex. In this snapshot the status side is 13 006 rows
  (9 745 direct ws statuses + 3 261 TLS-wrapped), the genuine framing side is
  small (439 `ws: WebSocket protocol error`), and the "expected 101/200"
  rows (2 714) are status evidence too — so the pair's `Framing` bucket is
  thin, and the prose remains the detail column.
- **Do ingest changes reduce `Protocol/Config`?** The one class where the
  client is definitively at fault and a fix is provable.

## 8. Method and limits

```sh
mkdir -p /tmp/dbc && cp ~/.config/leas/data.db ~/.config/leas/data.db-wal /tmp/dbc/
~/.turso/tursodb /tmp/dbc/data.db "<query>"      # production engine, read-only copy
```

- One snapshot, taken after the log export; the app was still running, so
  this is the last writer's state, not the funnel-run state (link count
  124 391 vs the funnel document's 120 405). The error slot is one per link
  and the later run overwrote many of them — do not compare bucket counts
  across the two documents link-for-link.
- The class column in §3 and the cross-tabs use `error_text LIKE`, i.e. the
  status quo the pair replaces; they describe what is stored today, not a
  proposed query shape.
- Cross-tabs join `protocols`; a link whose protocol row was purged would
  drop out of the join. The join counts sum to less than the row counts
  above, and that gap is exactly that case.
- No code was changed for this study.
