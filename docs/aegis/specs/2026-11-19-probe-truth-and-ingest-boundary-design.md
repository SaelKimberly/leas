# Probe truth and the ingest boundary — Design Spec

Date: 2026-11-19
Status: **implemented 2026-11-19** (all ten items; see the plan for per-item evidence). Draft v2 was the grilled decision set.
Origin: [`docs/research/2026-11-19-real-test-funnel.md`](../../research/2026-11-19-real-test-funnel.md)
(§5 recommendations, §3.1 policy, §3.2 inventory, §3.4 flow experiment), the user's
deprecation rule recorded as [ADR 0018](../adr/0018-deprecation-grounds.md), and the grilling
session of 2026-11-19 whose answers are folded in below (§9).

Owners touched: `leas-config` (ingest gate, settings, IP providers), `leas-db` (schema 22,
rank refresh, write paths), `leas-native` (`capability`, probe retry policy), `leas` (batch
scheduler, events, UI cells), `leas-oracles` (calibration + SOCKS5 rows).

Evidence basis and limits, stated once: the report's numbers are one snapshot of one DB
(2026-11-19, 120 405 links), source reads of the three pinned oracles, and one dial
experiment (29 links) plus its implied-TLS cross-check (6 targets, xray 1.7.5 and sing-box
1.13.13). No item below is implemented; every "where" pointer was read at this commit, none
was executed.

---

## 1. Why this exists

The run measured **14 links** whose tunnel completed a target handshake out of 120 405, and
the reason is not only dead servers. From the report:

- **63 697 links never got a TCP connection or a name**; 18 of 28 sampled flow targets did
  not resolve at all. A timeout is recorded identically to a refusal, so "dead" and
  "filtered" are one row.
- **23 778 links** opened the tunnel and then timed out at the *target* handshake. The only
  successful stage is the one with the least budget: successes span 226–5 394 ms against a
  5 s cap.
- **52.7 % of all rows** are timeouts; the report cannot say which are measurements and
  which are the client's own contention (`retries` run **concurrently**, `ping_native.rs:465-575`,
  so in-flight = concurrency × attempts).
- **11.6 % of failures** carry a purge verdict. Everything else stays live and is re-probed,
  because the class survives only as capped, localized `error_text`.
- **752 links** are "engine cannot test", of which the report grades 548 as *not configs*
  (490 stale markers over invalid values, 58 `ss://null:null` placeholders), 51 gate-only
  (SOCKS5), 148 accepted by at least one oracle, 5 defects.
- **102 endpoints** (336 links) carry a `[name]` marker on a host that resolves — the retry
  resolves hosts but never clears the marker and never re-probes.
- **27 of 29 non-vision-flow links** are invalid configs (flow without a TLS layer); none of
  the 29 is alive (§3.4), and the implied-TLS cross-check rescued none of the reachable
  targets.

So the problem class is **measurement truth**: the pipeline stores one boolean and one
sentence for a four-stage probe, cannot separate *server dead* from *not measured*, and lets
the ranking treat both the same. The secondary class is **ingest boundary**: shapes that no
core can dial enter the store and then consume probe budget and display space forever.

## 2. Governing rule

ADR 0018 (accepted 2026-11-19) is the authority: a variant is deprecated only for measured
absence from the sources or an evidenced upstream finding of harm; a peer's refusal is never
a ground; invalid ≠ deprecated; stored invalid rows take a verdict and Purgatory retires them.
This spec enforces that rule and adds nothing to it.

## 3. Scope

| # | Item | Class | Schema |
| --- | --- | --- | --- |
| S1 | Persist `error_stage` × `error_cause` | measurement | **schema 22** |
| S2 | Sequential confirm-retry, severity-ordered failure, ring sampling on confirmation only, in-flight cap | measurement | — |
| S3 | One stage-aware second observation; Cloudflare-trace fallback that also yields the exit IP/country | measurement | — |
| S4 | Name failure is a retry state: resolved ⇒ clear marker + rank refresh | measurement/ranking | — |
| S5 | Ingest boundary (drop structural impossibility) + `config_invalid` DATA step for stored rows | ingest/policy | — (data step) |
| S6 | Exit-IP coverage and server-count reporting | statistics | — |
| S7 | `[dest]` in the Profiles cell | display | — |
| S8 | SOCKS5: oracle row + gate flip in one change | capability | — |
| S9 | Oracle calibration sample, after S1 | evidence | — |
| S10 | Refresh stale untestable markers without a dial | capability | — |

Non-goals (explicit):

- Implementing `xtls-rprx-direct`/`-origin`. No live instance exists to prove against
  (report §3.4) and no safety ground to retire them (§3.3, ADR 0018 D-A).
- Normalising a non-vision flow to plain, and **implying** TLS/REALITY for a flow-only config:
  tested 2026-11-19. xray 1.7.5 with implied TLS: 6/6 fail (plain and direct). sing-box
  1.13.13, TLS on, flow omitted: 5/6 fail; the same targets with `flow=vision`: 6/6 fail.
  Reality is unreconstructable (25 of 27 rows carry no `pbk`). The decisive control also
  holds: **none of the 14 links that ever succeeded has an empty security layer** — 12 carry
  no flow but all are `tls`/`reality`, 2 are `vision` + `reality`. A working plain-TCP VLESS
  has never been observed in this corpus, so "missing security ⇒ TLS" is consistent with the
  data yet still rescues nothing here. The shape is dropped at ingest, not rewritten.
- Retiring ws/gRPC/HTTPUpgrade transports or SS stream ciphers (ADR 0018 D-F).
- Any change to the ordering law's key. S4 uses the existing bin law; it does not modify it.
- A UI redesign. S7 is one token.

## 4. Design per item

### S1 — Persist stage and cause

**Contract.** `profile_stats` gains two nullable columns:

- `error_stage` ∈ `dial | transport | protocol | target`;
- `error_cause` ∈ `timeout | refused | no_route | nxdomain | alert | status | framing | config`.

Both are written on every probe failure and cleared on success; a table CHECK enforces
`(error_stage IS NULL) = (failure_cause IS NULL)` — a cause without a stage is meaningless.
`error_text` stays (operator diagnosis; the untestable-marker machinery reads its prefix);
`error_kind` stays frozen (`real`/`fast`/`name` — a new value is a wipe).

Stage comes from where the probe failed, cause from the existing typed `ProbeClass`
(`ping_native.rs`) plus the call site: `Timeout` at the dial ⇒ `dial/timeout`; at the target
⇒ `target/timeout`; `CredentialsRejected` ⇒ `protocol/config`… the mapping table is one
`match`/rstest pair, not a new detector.

**Where.** Model `leas-db/src/models_toasty.rs`; DDL `schema/ddl.rs` (`profile_stats_v22`
rebuild, the shape schema 21 used — `ddl.rs:178-190`); cursor `SCHEMA_VERSION` 22 with one
`schema/steps.rs` entry (stamp and step in one transaction, ADR 0012 D-C); writer
`leas/src/ops/events.rs` `apply_test_result`; projection `leas-db/src/profiles_query.rs`.

**Why columns and not a prefix.** Reports must be computable without a regex over English
prose, and `cap_error_text` truncates (`events.rs:93-110`). The untestable prefix exists only
because the CHECK is frozen — a constraint, not a pattern.

**Migration.** Existing rows get `NULL`; no backfill (guessing from prose is the defect).

**Test.** rstest table (ProbeClass × call site) → (`stage`, `cause`), one row per arm; success
clears both; untestable marker leaves both NULL; the CHECK rejects cause-without-stage;
migration fixture: a v21 file opens at 22 with NULL pairs and unchanged `error_kind`.

**Risk.** A rebuild of the 120 k-row table. Mitigation: schema-21 pattern, one transaction,
fixture test, nullable columns so no backfill can fail.

### S2 — Sequential confirm-retry; the ring samples only on confirmation

**Contract.**
1. Attempts are **sequential**: one attempt; if it fails without positive evidence
   (`CredentialsRejected`, cert-class, `HttpRejected` 4xx), exactly one confirm observation
   follows (its target chosen by S3's rule). Classification is computed after both.
2. **No ring sample until the second observation agrees.** A single failure never samples 0,
   whatever its stage. Agreement = same `(stage, cause)` twice, or the fallback target
   failing the same way.
3. The persisted failure is the **most informative**, not the last to finish: severity
   `config/reality > credentials > cert > status > framing > alert > timeout > dial_*`, ties
   to the earlier observation.
4. In-flight tunnels are bounded by `real_ping_concurrency` in total (`ping.rs:642`'s claim),
   not by `concurrency × attempts`.

**Where.** `ping_native.rs:465-575` (`probe_attempts`): the `JoinSet` fan-out becomes a loop;
`last_error` becomes `best_failure` with the severity comparison; the ring write moves to the
caller (`ping.rs` `after_fast_settle` / real-result path), which sees both observations.
`sample_stability` (`ping.rs:2251-2253`) gains the "confirmed" predicate.

**Test.** Pair table on the severity ladder ("later timeout does not overwrite earlier
credentials rejection"); attempt count per class; a single timeout writes no ring sample and
leaves `stab_len` unchanged; two agreeing timeouts sample 0 once; a counting dialer proves
peak in-flight ≤ semaphore.

**Risk.** Every failing real-phase link now costs a second observation: ~24 k failures × 5 s
at concurrency 100 ≈ +20 min per run. Accepted (Q6); the fast phase still retires hard dial
failures before the real phase (`ping.rs:2221-2255`).

### S3 — One stage-aware second observation; Cloudflare trace

**Contract.**
1. The single extra observation (S2's confirm) is spent by stage: `stage=target` ⇒ the
   **fallback target**; `stage=dial|transport` ⇒ the same target. Never two extra dials.
2. The fallback is `https://www.cloudflare.com/cdn-cgi/trace` (verified 2026-11-19: 200,
   221 B, `ip=`, `loc=`, `ts=`), fetched with GET and parsed as `key=value` lines.
3. A fallback success yields the exit IP and country **from the body** — no separate provider
   call on that path. The primary path keeps the configured `ip_provider`.
4. `leas-config` gains `IpProvider::CloudflareTrace`, selectable for general IP+country tests,
   using the same parser (one parser, two consumers).

**Where.** `leas-config` `speed_test` (new `probe_fallback_url` with a serde default; the
`IpProvider` enum); `ping_native.rs` (`ProbeMethod::Get` + bounded body read for the fallback
probe; `ip_info` formatting from `ip=`/`loc=`); `ping.rs` the stage-aware choice.

**Test.** Table (first outcome, second outcome) → success/class, including: primary timeout +
fallback 200 ⇒ success, exit IP from the body; primary 403 + fallback timeout ⇒
`target/timeout` (the target's answer is not the config's answer); body missing `ip=` ⇒
success, no IP, no retry. Trace parser table: normal body, CRLF, truncated body, junk.

**Risk.** A second GET shape in the hot path (body read bounded, e.g. 1 KiB) and a new
provider that changes the settings surface. Both are small; the parser is table-tested.

### S4 — A name failure is a retry state

**Contract.** A successful DNS lookup clears the endpoint's name-class markers and refreshes
its ordering keys: the link lands in **bin 12 (untested)**, the endpoint in `New`
(`rank_proven = 0 AND rank_bin = 12`, `profiles_query.rs:96-105`). `band` is untouched. Only
name-class markers clear; a `real` marker, a measurement and a purge verdict stay.

**Where.** `enrich.rs:496-513` (the `Ok(ips)` arm) writes `error = NULL` on name-class rows
of that endpoint, then `refresh_endpoint_ranks` — the shape `clear_expired_errors`
(`profiles.rs:33-70`) already uses.

**Test.** DB: two links on one endpoint (name marker + real marker) — resolve clears the
first only; `rank_bin = 12`, `band` unchanged, `New` selects it; a purged row stays bin 16.

**Precondition (user-owned inspection, 2026-11-19).** The resolver is being audited for mass
lookups. Facts this item relies on:

| Knob | Value | Where |
| --- | --- | --- |
| hickory `ResolverOpts` | `timeout = 500 ms`, `RoundRobin`, rest default | `leas-dns/src/lib.rs:24-29` |
| resolver instance | one process-wide, from the DNSCrypt/DoH list (cached 168 h) | `leas-dns/src/lib.rs:333-341` |
| per-lookup budget | `DNS_LOOKUP_TIMEOUT = 8 s` | `enrich.rs:51` |
| fan-out bound | `RESOLVE_SEM = 64` | `enrich.rs:300-308` |
| per-host dedup | `lookup_key` waiter sets | `enrich.rs:376`, `:430` |
| trigger policy | `Routine` TTL-gated · `Maintenance` TTL-bypassed · `Forced` unbounded | `enrich.rs:310-329` |

Two facts make the audit worth doing: all 12 913 name failures carry one message with zero
rows of any other resolver text, and a manual retry still finds 20–30 resolutions per run. If
the audit finds permanent and temporary answers conflated, S1's cause set gains `nxdomain` vs
a temporary class and S4's hook may need to fire on the temporary one only.

**Risk.** A resolver answer is not a server: bin 12 says "not tested", the cell must render
blank, not a delay.

### S5 — The ingest boundary

**Contract.**
1. `SsConfig.method` must resolve through the native method set (`null`, `telegram-id-…` are
   not ciphers). Home: `validate_ss_config` (`import_export.rs:157-185`), which already drops
   three shapes; the list moves to `leas-proto` (`ss_method_support.rs` owns the cipher facts)
   so parser, gate and codec read one set.
2. A non-empty `flow` requires `security` `tls` or `reality`. New `validate_vless_shape` beside
   it, same `ImportError::Validation` shape, reason naming the flow.
3. `flow = "none"` normalises to *absent* at parse (the `normalize_vless_encryption`
   precedent) — an alias, not a variant.
4. Stored rows that violate (1)/(2) — 85 flow/vision rows + 58 `null`-method rows — get
   `purge_reason = 'config_invalid'` through a marker-gated DATA step
   (`app_meta.flow_without_tls_purged`, no cursor bump; `rekey.rs:25-64` shape) plus a rank
   refresh. Purgatory's 7-day TTL retires them.
5. **No implied TLS/REALITY.** Tested 2026-11-19 and rejected (report §3.4 cross-check): the probe
   does not invent a layer the feed did not send.
6. The *insecure* class stays empty (ADR 0018 D-E); `parsing.reject_insecure` remains the
   hook, and no inventory variant qualifies.

**Tests.** Method: `null` rejected, `aes-256-cfb` accepted, `2022-blake3-…` accepted. Flow:
`direct` + no security rejected, + `tls` accepted, + `reality` accepted, `flow=none` stored
absent, empty untouched. Data step: the 143 rows end at bin 16 with `config_invalid`; valid
TLS-bearing `direct-udp443` rows untouched; second open is a no-op.

**Risk.** A live feed may carry a flow-bearing config whose server accepts plain VLESS; the
rule refuses it at import (grilled Q4: accept). The import log names the refusal and counts
it.

### S6 — Exit IP coverage; servers, not links

**Contract.** Every real success records the exit IP — from the trace body on the fallback
path, from the provider on the primary path; a provider failure never fails the probe. The
statistics surface reports **distinct exit IPs** beside link counts.

**Where.** `ping_native.rs` result handling + `ip_provider`; Details pane aggregates.

**Test.** Success + provider 200 ⇒ IP; success + provider timeout ⇒ success, no IP, no retry
storm; two links, same exit IP ⇒ one distinct.

### S7 — `[dest]`

**Contract.** The Test cell shows `[dest]` when `latency_auth = ok` and `failure_stage =
target` — the server took the config, the destination did not answer. Bracketed like the other
status markers (`[real]`/`[fast]`/`[name]`), so it cannot be read as a verdict (those are
bare: `mitm`, `cert`, `cfg`, `http`, `cred`). Everything else unchanged.

**Where.** `ui/profiles.rs` `compute_test_cell` / `test_cell_content`, one fact added to
`RealCellFacts`, one table test.

**Token constraints (a test, not taste).** The token must be ≤ 4 characters, bracketed (the
bracketed form is the *status* vocabulary — `[real]`, `[fast]`, `[name]` — while verdicts are
bare: `mitm`, `cert`, `cfg`, `http`, `cred`), and distinct from every existing token so neither
the cell parser nor an operator can confuse the two layers. `[dest]` satisfies all three; the
table test asserts the cell never emits `[dest]` for a `config`-class failure and never emits a
bare `dest`.

**Risk.** Vocabulary grows by one token; `[dest]` must not be emitted when the failure is
`config`-class.

### S8 — SOCKS5, one change

**Contract.** Add the oracle row (`leas-oracles`: a SOCKS5 server from a pinned core + native
client, TCP CONNECT), flip `kind_supported` to admit `Socks` (`capability.rs:67-78`), drop the
entry from `non_native_kinds_unsupported` (`:1216-1240`) — in the same change so the flip
cites green evidence. 51 links become measurable.

**Risk.** Untested code becomes reachable. The oracle row is the mitigation; if it is red the
whole change waits, and the 51 links stay parked.

### S9 — Oracle calibration, after S1

**Contract.** `leas-oracles` harness: 200 links per `(stage, cause)` stratum, dialled by the
pinned cores as clients; prints an agreement matrix. Dev-only, `#[ignore]`d, no shipping
dependency. Its output goes into the closing note (and a research note if it reopens a class).

### S10 — Refresh stale untestable markers without a dial

**Contract.** Before the walk, `run_batch` re-runs the config-aware capability gate for links
whose `error_text` starts with `UNTESTABLE_PREFIX`, rewriting or clearing the marker. Today
the gate runs only in the real phase (`ping.rs:2659`) and the real phase is dispatched only
after a fast dial produced a transport (`ping.rs:2213-2255`), so a row whose fast dial fails
keeps an older build's marker forever — 490 rows prove it.

**Test.** Legacy text + now-supported config ⇒ cleared; invalid value ⇒ current text;
supported row ⇒ no write.

**Risk.** Cost bounded by distinct protocols, paid once per batch — the reason the gate was
kept out of plan time (`ping.rs:2236-2237`).

## 5. Data and schema impact

| Change | Cursor | Step |
| --- | --- | --- |
| `profile_stats.failure_stage` + `error_cause` + pair CHECK | 21 → 22 | table rebuild, one `schema/steps.rs` entry |
| Invalid flow/method rows → `config_invalid` (143) | none | marker-gated DATA step (`app_meta`) |
| `speed_test.probe_fallback_url`, `IpProvider::CloudflareTrace` | none | serde default + enum variant |
| Everything else | none | — |

Rank refresh is owed by the S5 data step and by S4's resolve hook; both use
`refresh_endpoint_ranks`, never a hand-written key.

## 6. Test obligations

- Every table-shaped item is one `#[rstest]` table with named `#[case]` rows.
- No source-text, mock-echo or length-grew assertions; each row distinguishes a
  consumer-visible behaviour (a stored pair, a chosen failure, a bin, a glyph).
- Oracle rows (S8) must be green before the gate flips; S9 runs on the pinned cores.
- `just quality-gate code` is the exit gate; schema items also run the v21 fixture migration.

## 7. Sequencing

| Stage | Items | Why |
| --- | --- | --- |
| S0 | ADR 0018 (done) | the rule governs S5 |
| S1 | S1, S2 | the pair is S9's stratum key; S2 is the same file and the same test table |
| S2 | S3, S10 | both reduce false negatives without schema |
| S3 | S4, S5 | ranking + ingest; the S5 data step needs the refresh path S4 exercises |
| S4 | S6, S7 | statistics and display on typed facts |
| S5 | S8, S9 | capability flip + calibration |

## 8. Risks

1. **Schema rebuild on the hottest table** — schema-21 pattern, one transaction, fixture test,
   nullable pair.
2. **Probe wall time** — one extra observation per failing link (~+20 min/run); no further
   increase (Q6). The fast phase keeps retiring hard dial failures early.
3. **Ranking surprise from S4** — a resolved host jumps ahead of untested rows; that is the
   intent, and bin 12 is the law's own state.
4. **S5 drops rows a user might want** — named at import; stored rows go to Purgatory, not
   oblivion.
5. **S8 unlocks untested code** — the oracle row lands in the same change.

## 9. Decisions and open items

Grilled 2026-11-19 (each answer is now binding for this spec):

| # | Question | Decision |
| --- | --- | --- |
| 1 | Value | Both, staged as written: S1 first, calibration as its input |
| 2 | S1 shape | `error_stage` × `error_cause` (two orthogonal enums) |
| 3 | Ring sampling | No sample until the second observation agrees |
| 4 | Ingest gate | Drop structural impossibility only; no implied TLS |
| 5 | Inference placement | Nowhere — the cross-check rescued nothing |
| 6 | Second observation | One dial, stage-aware (fallback target vs same target) |
| 7 | Stored invalid rows | DATA step → `config_invalid` → Purgatory |
| 8 | Rule's home | ADR 0018 |
| 9 | SOCKS5 | Oracle row + gate flip in one change |
| 10 | Fallback target | Cloudflare trace, also a curated IP provider |
| 11 | Calibration | In scope, after S1 |
| 12 | Cell label | `[dest]` |
| 13 | Acceptance | Property gates the merge; the alive number is reported |

Remaining open item: **the resolver audit** (Q8 above, S4's precondition). If it finds
permanent and temporary answers conflated, S1's causes gain `nxdomain` vs a temporary class
before the column ships.

## 10. Acceptance

- **Gate (deterministic):** after one full run plus the DATA step,
  `SELECT count(*) FROM profile_stats WHERE error = 1 AND error_stage IS NULL` is 0; every
  purge verdict carries a shape; the funnel is one `GROUP BY error_stage, error_cause`;
  the v21 fixture migrates; S8's oracle row is green.
- **Reported (not a gate):** alive endpoints after one run at the new budget, against the 7-link
  baseline — recorded in the closing note, and a flat number triggers a follow-up investigation
  rather than a revert.

## 11. References

- `docs/research/2026-11-19-real-test-funnel.md` — §2 funnel, §3.1 policy, §3.2 inventory,
  §3.3 removal rationale, §3.4 flow experiment, §4 defects, §5 recommendations.
- `docs/aegis/adr/0018-deprecation-grounds.md` — the rule S5 enforces.
- `docs/reference/ordering-law.md` §2 (bins), §6 (resolution band, scopes);
  `docs/reference/database.md` (cursor, `profile_stats`).
- Code: `ping_native.rs:465-575`; `ping.rs:2213-2255`, `:2659`; `profiles.rs:33-70`;
  `enrich.rs:496-513`; `capability.rs:67-140`; `import_export.rs:157-185`; `rekey.rs:25-64`.
- `thirdparty/{Xray-core,sing-box,mihomo}` — the oracle facts the report quotes.
