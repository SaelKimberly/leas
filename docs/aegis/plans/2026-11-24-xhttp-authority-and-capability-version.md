# xhttp h2 `:authority` and stale capability verdicts — implementation

## Goal

Two audit findings with code-level evidence (§D1/G1, §D4/G5):

1. **G1** — every xhttp-over-h2 request sends `Host` but no `:authority`:
   `build_request` emits an origin-form URI and `h2`'s `Pseudo::request`
   fills `:authority` from the URI only (`h2-0.4.20/src/frame/headers.rs:597-600`).
   All 501 `421 Misdirected Request` rows are `vless/x_http/tls`; the h1 xhttp
   rows have none.
2. **G5** — a persisted `not testable by the native engine: …` verdict is
   never invalidated when native support grows. 27 SS-2022 multi-user rows and
   5 VLESS rows keep reporting a gap the engine no longer has.

Outcome: an h2 xhttp request carries the config host as `:authority`, and a
capability upgrade clears the persisted untestable verdicts once through an
`app_meta` marker; a still-unsupported row re-stamps from `support_reason` at
its next plan, before any probe dials.

## Architecture / ownership

| Concern | Owner |
| --- | --- |
| h2 request target shape | `leas-native::transport::xhttp::build_request` (one builder for h1/h2/h3) |
| "Which HTTP version does this row use" | `leas-native::transport::xhttp::http_version` (existing dispatch table) |
| Capability revision | `leas-native::capability::SUPPORT_REVISION` (bumped by the same edit that changes `NATIVE_KINDS` / `support_reason`) |
| Persisted marker discriminator | `leas_db::UNTESTABLE_PREFIX` (one const; `ops::ping` re-exports it) |
| One-time stored-row clear | `leas-db::Database::clear_stale_capability_verdicts(version)`, called from `main` after `Database::open` |

No schema change: `app_meta.capability_version` is a DATA step. No new crate,
no identity (`sig`) change.

## Tech stack

Rust 2024; `http`/`h2`/`hyper` already in the xhttp transport; `leas-db` raw
SQL is the existing marker pattern (`purge_invalid_shapes_once`).

## Baseline / authority refs

- `docs/research/2026-11-24-log-and-failure-audit.md` §5 D1/D4, §11 G1/G5.
- `thirdparty/Xray-core/transport/internet/splithttp/dialer.go` (request URL
  carries the config host; Go's h2 derives `:authority` from it).
- `thirdparty/mihomo/transport/xhttp/client.go:110-127` (same: `url.URL{Host}`).
- `h2-0.4.20/src/frame/headers.rs:561-600` (`Pseudo::request` reads the URI).
- `crates/leas-db/src/database.rs::purge_invalid_shapes_once` (marker shape).

## Compatibility boundary

- h1 requests keep origin-form (`GET /path HTTP/1.1`); only the h2 arm changes.
- h3 already rewrites to an absolute URI; the builder's h2 branch leaves the
  version-3 arm untouched.
- Stored configs, `sig`, and h1 wire bytes are unchanged.
- The capability clear drops only `error_text` values with the untestable
  prefix; a probe failure, a purge verdict and a clean row are untouched.

## TDD route

- Mode: `auto`. Decision: **strict** (wire contract + persistence marker).
- Authority: audit findings + repository test conventions.
- Test posture: RED tests first in both crates, then GREEN, then the gate.

## Tasks

### T1 — RED: h2 request target carries the authority

File: `crates/leas-native/src/transport/xhttp.rs` (tests module).

Add two cases against `build_request` with the existing `ctx_mode` helper:

- h2 ctx (`security = {"tls": {}}` → `http_version == "2"`): the URI scheme is
  `https`, `authority() == Some("example.com")`, `path_and_query()` is the
  configured path.
- h1 ctx (no security): `authority()` is `None`, URI is the origin-form path.

Run `cargo nextest run -p leas-native xhttp` → new cases FAIL.

### T2 — GREEN: absolute URI when the dispatch table says h2

File: same.

In `build_request`, after `request_target`, prepend `{scheme}://{host}` when
`http_version(ctx.security()) == "2"`. Keep the `Host` header (Go sends both
the URL host and, for h2, the engine maps it to `:authority`; xray sets
`requestURL.Host`). The scheme is already computed for the Referer.

Tests pass; h1/h3 behavior unchanged.

### T3 — RED: stale capability verdicts

File: `crates/leas-db/src/database.rs` (tests module), beside
`invalid_shapes_are_retired_once`.

Seed one DB with three links: (a) `error_kind='real'`, `error_text='not
testable by the native engine: old gap'`, `purge_reason=NULL`; (b) the same
text but `purge_reason='config_invalid'`; (c) an ordinary `real` failure text.
Call `clear_stale_capability_verdicts(1)` → assert (a) columns NULL, (b)/(c)
intact, marker `capability_version = '1'`. Seed a new (a)-shaped row, call
again → untouched (marker gate). Run → FAIL (method absent).

### T4 — GREEN: marker step and the shared prefix

Files: `crates/leas-db/src/lib.rs`, `crates/leas-db/src/database.rs`,
`crates/leas-native/src/capability.rs`, `crates/leas/src/ops/ping.rs`,
`crates/leas/src/main.rs`.

- `pub const UNTESTABLE_PREFIX` in `leas-db` (top level, documented as the
  persisted discriminator); `ops::ping` re-exports it and keeps
  `untestable_marker_text`.
- `capability::SUPPORT_REVISION: i64 = 1` with a doc: bump in the same change
  as any `NATIVE_KINDS`/`support_reason` move.
- `clear_stale_capability_verdicts(version)`: marker-gated (`capability_version`
  ≥ version returns); `SELECT DISTINCT endpoint_id` from the marker predicate;
  chunked `UPDATE … SET error = NULL, error_kind = NULL, error_text = NULL,
  error_stage = NULL, error_cause = NULL, updated_at = now WHERE endpoint_id IN
  (…) AND error_kind = 'real' AND error_text LIKE '<prefix>%' AND purge_reason
  IS NULL`; `refresh_endpoint_ranks` for the touched endpoints; stamp the
  marker even when no row matches.
- `main.rs` after `Database::open`: run it with `SUPPORT_REVISION`, warning on
  failure (boot must not die on a maintenance step, same as the invalid-shape
  purge).

T3 passes; full suite green.

### T5 — Verification and record

- `just quality-gate code` (fmt, workspace clippy `-D warnings`, nextest).
- Migration on a copy of the audit snapshot: count `not testable` rows before
  and after the step; the count goes to zero for live rows and the marker is
  stamped; a second open does not re-clear.
- Reviewer round; fix until no findings.
- Update `AGENTS.md` (xhttp h2 authority; `capability_version` DATA step) and
  the Aegis INDEX row; fill this plan's Outcome.

## Risks / non-goals

- The capability revision is a manual constant: a support change that forgets
  to bump it leaves the old verdicts (the failure mode the marker fixes). The
  doc comment is the guard; no code can detect a semantic support change.
- G5 does not change probe planning: a clean row is what makes the next Real
  Test re-evaluate it.
- No change to the 409/403/500/530 analysis, the h1 statuses, or the purge
  verdicts.

## Outcome

Executed 2026-11-24.

- **G1** — `build_request` emits `https://{host}{path_and_query}` when
  `http_version == "2"`; h1 stays origin-form and h3 keeps its own rewrite.
  `stream_one_h2_full_duplex` now asserts the server-side URI
  (`scheme = https`, `authority = localhost`): RED before (`None`/`None`),
  GREEN after. `h1_request_target_keeps_origin_form` pins the h1 half.
- **G5** — `Database::clear_stale_capability_verdicts(SUPPORT_REVISION)` clears
  live rows whose text starts with `leas_db::UNTESTABLE_PREFIX`, refreshes the
  touched endpoint ranks and stamps `app_meta.capability_version`; a purge
  verdict and an ordinary failure stay, and the same revision does not
  re-clear. Snapshot copy evidence: **154** live markers → **0**, 74 512 other
  real failures untouched, marker `1`, second call a no-op.
- Cost accepted: the clear is revision-wide, so a still-unsupported row
  (TUIC/WireGuard/Hysteria1/…) loses its marker for one plan cycle and gets it
  back from `support_reason` before any probe — no probe is spent on it.
- Gate: fmt, workspace clippy `-D warnings`, nextest — pass (3/3).
