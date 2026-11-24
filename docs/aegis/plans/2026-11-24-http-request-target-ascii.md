# HTTP request targets and transport hosts: ASCII-safe dial — implementation

## Goal

Two findings from the 2026-11-24 audit (§D2, §D3):

1. **G3** — `http::Uri` rejects a space in the configured path, so 890 window
   rows die as `transport/config: invalid uri character`: 800 on a non-ASCII or
   markup **authority** (host) and 90 on a space in the **path**. A path that
   is only non-ASCII is accepted but sent as raw UTF-8, a `#` silently truncates
   the request target, and an invalid `%` escape passes through.
2. **G4** — the transport `host`/`authority` (the HTTP `Host` and h2
   `:authority` value) is never validated at ingestion: 1,008 window rows
   carry a non-ASCII host and 2 carry Markdown/HTML punctuation. Every retest
   pays a probe slot for a request line no HTTP implementation can send.

Outcome: a configured path is always emitted as a valid ASCII request target
(percent-encoded like Go's `url.EscapedPath`), and an unrepresentable
transport host is refused at ingestion and retired once from an existing DB as
`config_invalid`.

## Architecture / ownership

| Concern | Owner |
| --- | --- |
| Path → ASCII request target | one helper in `leas-native::transport`, used by ws/httpupgrade/xhttp/v2rayhttp |
| "Which transport carries a Host" | `leas_proto::proto_spec::TransportConfig::host()` (one match, beside `uri_path_mut`) |
| "Is this shape undialable" | `leas_proto::proto_spec::is_undialable_shape` (DB step) + `leas-config::import_export::validate_host` (ingest) |
| One-time stored-row verdict | `leas-db::database::purge_invalid_shapes_once`, marker version bump |

No new crate. No schema change (the purge is an `app_meta` DATA step, not DDL).
Identity (`sig`) is untouched: the path is encoded at request-build time, not
in the stored config, and the host gate rejects without rewriting.

## Tech stack

Rust 2024 workspace; `http`/`h2`/`hyper` as already used by the transports;
`idna` is not part of this change (non-ASCII hosts are refused, not converted —
see the audit §D3: 288/311 convert but the sampled endpoints are decoys).

## Baseline / authority refs

- `docs/research/2026-11-24-log-and-failure-audit.md` §5 D2/D3, §11 G3/G4.
- `thirdparty/Xray-core/transport/internet/websocket/dialer.go` (URI from the
  endpoint, `Host` header separate; Go `url.EscapedPath` semantics).
- `thirdparty/sing-box/transport/v2rayhttpupgrade/client.go` (`requestURL.Host`
  = server, `Host:` header = config host).
- `thirdparty/mihomo/transport/xhttp/client.go:110-127` (absolute URL with
  `cfg.Host`; the precedent `v2rayhttp.rs` already states).
- `crates/leas-native/src/transport/v2rayhttp.rs:60-85` — the in-tree comment
  that a bare-path URI yields no `:authority`; this plan applies the same
  discipline to the request target, not the authority (G1 is out of scope).

## Compatibility boundary

- Wire: a non-ASCII path becomes `%XX` instead of raw UTF-8; a space becomes
  `%20`; `#` becomes `%23` instead of truncating; a valid existing `%HH` is
  preserved (no double-encode). This matches Go and browsers.
- Ingest: configs with a non-ASCII/control/markup transport host are refused as
  host-validation errors; they were never dialable on any HTTP stack.
- Existing DB: the one-time purge marks those rows `config_invalid`; rows stay
  in place (Purgatory TTL retires them), no deletion, no re-key.
- Stored config and identity bytes are unchanged, so no `IDENTITY_VERSION`
  bump and no rekey step.

## TDD Route

- Mode: `auto` (no explicit user TDD request).
- Decision: **strict**.
- Authority: Aegis auto rule — behavior and producer/consumer boundary change
  (stored verdicts + wire bytes), plus a persistence verdict.
- Posture: write the failing tests first (encoder table, ws/xhttp request
  target, gate accept/reject table, DB purge fixture), then implement; keep
  the full suites green.

## Tasks

### T1 — request-target encoder (RED → GREEN)

Files: `crates/leas-native/src/transport/mod.rs`.

- Add `pub(crate) fn request_target(path: &str) -> Cow<'_, str>`:
  - Borrowed when every byte is allowed and every `%` starts a valid `%HH`.
  - Allowed ASCII: alphanumeric plus `-._~!$&'()*+,/:;=?@[]`; `%` only as a
    valid escape. Everything else (space, control, `#`, `"`, `<`, `>`, `\`,
    `^`, `` ` ``, `{`, `|`, `}`, non-ASCII) → uppercase `%XX` per UTF-8 byte.
  - Preserve an existing valid `%HH` verbatim; an invalid `%` becomes `%25`.
- Tests (table): ASCII path borrows (no allocation); space; a Unicode path
  (`/?ed=Telegram🇨🇳+@WangCai2`); `#`; invalid `%zz`; valid `%2F` preserved;
  every output parses as `http::uri::PathAndQuery`.

### T2 — wire the encoder into every request builder (RED → GREEN)

Files: `transport/ws.rs`, `transport/httpupgrade.rs`, `transport/xhttp.rs`,
`transport/v2rayhttp.rs`.

- ws: encode `cfg.path` before `ws://{host}{path}`; the early-data request
  inherits it. The plugin twin (`transport/v2ray/ws.rs::plugin_ws_request`)
  has the same builder and is encoded too (the shared plugin path corpus carries
  non-ASCII paths).
- httpupgrade: extract a pure `upgrade_request(cfg)` (or encode inline at the
  single builder) and `.uri(request_target(&path))`.
- xhttp: encode the final `url_path` in `build_request`, and the base path in
  the `Referer`; h3 reuses the already-encoded request target.
- v2rayhttp: `.path_and_query(&request_target(&path))`.
- Tests:
  - `ws_request` with `path = "/?ed=2560 PuLaFreeBOT"` returns an ASCII
    `path_and_query` (`%20`), Host unchanged; a Unicode path yields `%XX`.
  - xhttp `build_request` with a Unicode/space path is ASCII and the `Referer`
    is a valid header value.
  - httpupgrade request builder exposes the same encoded target.

### T3 — transport-host predicate in `leas-proto` (RED → GREEN)

Files: `crates/leas-proto/src/proto_spec/common.rs`,
`crates/leas-proto/src/proto_spec/mod.rs`.

- `TransportConfig::host()` → `Option<&str>`: `Ws/Http/HttpUpgrade/XHttp.host`,
  `Grpc.authority`, else `None`.
- `pub fn transport_host_unrepresentable(config: &ProtocolConfig) -> bool`:
  any `host()` value with a byte outside Go's `ValidHostHeader` table (alnum
  plus `!$%&'()*+,;=-._~:[]`) is invalid — the reference's own ceiling, so a
  decoy host carrying a sub-delim is not a false positive.
  Empty stays valid **because the transports implement the fallback**: a
  `?host=` share link stores `Some("")`, and all five Host consumers now use
  `transport::host_or`, which treats empty as unset (the reference grammars'
  meaning). Rejecting empty would drop rows the references dial.
- `is_undialable_shape` returns true when that predicate fires.
- Tests: the two audit hosts (`</code>speedtunnel…`, `` `rb24`.`ir` ``),
  a Persian host, a space host, and a good `host:443` / empty host.

### T4 — ingestion gate (RED → GREEN)

Files: `crates/leas-config/src/import_export.rs`.

- At the top of `validate_host`, before the endpoint early-return, reject
  `transport_host_unrepresentable` as
  `ImportError::Validation("transport host is not an ASCII host".into())` —
  the category the subscription summary already counts as `host validation`.
- rstest table through `parse_share_url`:
  - ws host `RFDJCK.سیسی.wOrLd` → refused;
  - ws host `</code>speedtunnel<code><br/><br/>` → refused;
  - ws host `example.com:443` → imports;
  - ws path `/?ed=2560 PuLaFreeBOT` → **imports** (path is encoded at dial);
  - grpc authority non-ASCII → refused.

### T5 — one-time stored-row verdict (RED → GREEN)

Files: `crates/leas-db/src/database.rs`.

- `const SHAPE_MARKER_VERSION: i64 = 2`; skip only when the marker is `>= 2`,
  stamp `2`. Key name unchanged, so no schema/rekey work.
- Extend `invalid_shapes_are_retired_once`: add a bad-host VLESS ws row
  (`config_invalid`) and a space-path VLESS ws row (`None`); keep the existing
  flow/SS rows; seed the marker at **1** (an existing DB) so the version bump
  is what runs the scan, and assert the second open observes value `"2"`.
- The step reads stored JSON and calls the same predicate — no second rule.

### T6 — verification and delivery

- `cargo nextest run -p leas-proto -p leas-config -p leas-native -p leas-db`
  (targeted first, then the four-crate suite).
- `cargo clippy --workspace --exclude leas-oracles --all-targets --all-features -- -D warnings`
- `cargo fmt` (check)
- Offline census on the audit snapshot: run the new predicate over stored
  configs and confirm the 890 `invalid uri character` rows split into
  ~798 host-rejected + ~90 path-now-dialable; confirm the 2 markup hosts are
  caught and no space-path row is (`config_invalid` count should rise by
  ~1,000, not 2,010).
- Record the executed plan status in `docs/aegis/INDEX.md`.

## Repair / retirement

- Repair track: none — the encoder is the single path; no fallback keeps the
  old raw-UTF-8/space behaviour.
- Retirement: the inline `format!`/`.uri(&path)` constructions in the four
  transports are replaced; no second encoding helper.

## Verification (acceptance)

- A configured space/Unicode path produces a valid ASCII request target on the
  wire (`ws_request`/xhttp/h2 builders), and a valid `%HH` is not doubled.
- A non-ASCII/control/markup transport host cannot be imported, and an old
  stored row gets `config_invalid` on the next open exactly once.
- A space-path config still imports and is planned (the fix is not a blanket
  path rejection).
- Full four-crate suites + workspace clippy green.

## Risks

- A server that matched the previous raw UTF-8 path would see `%XX` now; raw
  UTF-8 in an HTTP request target is non-standard, and Go/Xray/browsers encode.
  Accepted.
- `#` in a path was silently truncating; it now travels encoded and may reach a
  path the old client never requested. Intended.
- The DB step re-scans once on the next open for every user (JSON parse per
  row); it is marker-gated and was already part of the open path.
- Non-ASCII **SNI** is out of scope (the audit's IDNA note); no behaviour
  change there.

## Self-review record

- Scope matches §D2/§D3 only; G1 (`:authority`), G5 (capability version) and
  the relay/DNS findings are not touched.
- One owner per rule: encoder, host accessor, predicate, ingest gate, marker.
- No placeholders; every task names files, tests, and the command that proves
  it.
- Identity/compat: stored bytes unchanged; only wire and verdicts change.

## Outcome (2026-11-24)

- **Delivered.** `request_target` (Borrowed on ASCII, `%XX` otherwise) is used
  by ws (including the plugin twin), httpupgrade, xhttp (request + Referer),
  and v2rayhttp; the space/`#`/raw-UTF-8 failure class cannot be built any more.
- **Ingest.** `validate_host` refuses an unrepresentable transport host with a
  `transport host …` message; subscription summaries now count it as
  `host_validation` (test pins both counters). `is_undialable_shape` carries the
  same predicate to the DB step, whose marker is now version **2** so an
  existing v1 DB re-scans once.
- **Empty host.** The review found that `Some("")` had no fallback; the fix is
  `transport::host_or` at all five Host consumers (ws, plugin ws, httpupgrade,
  xhttp, v2rayhttp), not rejection — the references treat empty as unset.
- **Review correction.** The first predicate used `[A-Za-z0-9._:[]-]`, which
  dropped representable decoys (`foo~bar`, `a!b`); it now uses Go's
  `ValidHostHeader` set. `@` stays refused (Go refuses it; the Rust authority
  parser would accept it as userinfo).
- **Census on the audit snapshot** (read-only copy): of the 890 rows whose
  stored error was `invalid uri character`, the new predicate marks **801** as
  `config_invalid` (host) and leaves **89** dialable (the space/non-ASCII path
  rows that the encoder now covers). The 2,010-row class splits as predicted:
  hosts are rejected, paths are fixed.
- **Verification.** `just quality-gate code` 3/3 (fmt, clippy `-D warnings`,
  2 965 passed / 12 skipped); the DB test observes the v1→v2 re-scan and the
  marker; a second reviewer round returned no findings.
