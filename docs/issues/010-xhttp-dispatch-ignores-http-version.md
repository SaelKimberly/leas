# 010 — xhttp dispatches h1/h2 by TLS presence, not by its own `http_version()` table

- **Location:** `crates/leas-native/src/transport/xhttp.rs:902-925` (`connect`),
  `:119-160` (`http_version`), `:992`, `:1070` (the h1 arm's second dial)
- **Severity:** medium
- **Status:** theory
- **Domain:** native-transport

## Hypothesis

`xhttp::http_version()` is the documented mirror of xray's
`decideHTTPVersion` (`xhttp.rs:119-160`) and returns `"1.1"` for a TLS row
whose single explicit ALPN is `http/1.1`:

| condition | version |
|---|---|
| reality config present | `"2"` |
| no TLS config | `"1.1"` |
| TLS, exactly one ALPN `"http/1.1"` | `"1.1"` |
| TLS, exactly one ALPN `"h3"` | `"3"` |
| TLS, exactly one other ALPN | `"2"` |
| TLS, zero or 2+ ALPNs | `"2"` |

`connect()` never calls it. The mode dispatch branches on `ctx.is_tls()`
alone, so every TLS row goes to the `h2` arm:

```rust
match xhttp_mode(ctx)? {
    "stream-one" => { if ctx.is_tls() { stream_one_h2(..) } else { stream_one_h1(..) } }
    "stream-up"  => { if ctx.is_tls() { stream_up_h2(..)  } else { stream_up_h1(..)  } }
    _            => { if ctx.is_tls() { packet_up_h2(..)  } else { packet_up_h1(..)  } }
}
```

For a TLS row with `alpn=http/1.1`, `LinkContext::alpn_vec` advertises exactly
`["http/1.1"]` (`context.rs:237-268` — an explicit `alpn` token wins over the
transport-implied `h2`), the TLS handshake therefore negotiates HTTP/1.1, and
`h2_client_with` then sends the h2 preface over an h1 session. The server
answers 400 / closes, `h2::client::handshake` fails, and the row is recorded as
a **transport** failure — although nothing about the server is wrong and xray
connects to it. That is the wrong verdict class: the shape is servable, so it
must be **served** (the h1-over-TLS arm below) or refused at the dial with a
named capability error — not retired. ADR 0018 D-F keeps any shape a pinned
oracle serves (`docs/aegis/adr/0018-deprecation-grounds.md` D-F), and
`is_undialable_shape` is explicitly not a deprecation list
(`crates/leas-proto/src/proto_spec/mod.rs:20-26`), so ingestion refusal is the
wrong tool here even though it would be the cheapest.

The `http_version` table has exactly one production consumer — the h3
self-contained predicate (`transport/mod.rs:60`) — plus the two pool guards
(`xhttp.rs:202`, `:235`); the h1/h2 choice ignores it. The unit test at
`xhttp.rs:1814-1834` pins the table but not the dispatch, which is why the two
can disagree silently.

## Why a one-line dispatch fix is not enough

The h1 arms are plaintext by construction: `packet_up_h1` and `stream_up_h1`
open the upload connection with `crate::transport::tcp::connect(ctx, None)`
(`:992`, `:1070`) — a raw TCP dial that never runs `security::wrap`. That is
correct only because the arm is reachable only when `is_tls()` is false. An h1
arm that is reachable under TLS must dial **and** secure its second connection
(`chain.rs:75-96::secured_upgraded` is how the first one does it), otherwise
the upload half of the tunnel would be cleartext.

So the fix is two-part:

1. Dispatch on `http_version()` (which already folds in reality and the ALPN
   fallback), not on `is_tls()`.
2. Add the h1-over-TLS arm: the second connection goes through
   `tcp::connect` + `security::wrap` before `h1_client` (stream-one needs no
   second dial).

If (2) is out of scope for now, the honest interim step is a dial-time
`capability` refusal — `capability::support_reason` is the layer that already
answers "can this engine dial this row" with a named reason
(`crates/leas-native/src/capability.rs:118`) — so the failure reads as an
unsupported shape instead of a dead server. It must remain a dial refusal: ADR 0018 D-F
keeps the shape alive for as long as a pinned oracle serves it, so nothing may
mark the stored row `config_invalid`.

## Evidence

- `xhttp.rs:902-925` — the dispatch, `is_tls()` in all three arms.
- `xhttp.rs:119-160` — the table and its `dialer.go` provenance.
- `context.rs:237-268` — explicit `alpn` wins; the transport-implied default is
  `h2` for xhttp ("xhttp falls back to HTTP/1.1 only when there is no TLS at
  all" — which is the assumption this issue contradicts).
- `xhttp.rs:202` / `:235` — pooling does check `http_version() == "2"`, so the
  pool cannot mask the mis-dispatch; it only means the mismatched session is
  never reused.
- `v2rayhttp.rs:1-16` records the analogous gap as knowingly deferred ("the
  sing-box no-TLS h1 arm ... deferred"), i.e. the reverse combination is
  already a known hole; this is the same hole on the TLS side, except it is
  mis-dispatched rather than refused.

## Reproducer (not run — needs the oracle crate)

A hermetic unit test cannot reach this: the decision is in `connect`, which
needs a stream. The discriminating case belongs in `leas-oracles`: an xray
`xhttp` inbound with `alpn: ["http/1.1"]` and a client row carrying
`alpn=http/1.1`. Expected today: the dial fails at the h2 preface. A cheaper
static check that would have caught it: assert `connect`'s arm selection equals
`http_version()` for every row shape in the existing `http_version` table test
(`xhttp.rs:1814`).

## Fix sketch

- Replace the three `is_tls()` branches with a single
  `match http_version(ctx.security())` → `"1.1" | "2" | "3"` (h3 still routes
  through `connect_quic` before this function).
- `packet_up_h1`/`stream_up_h1`: take the already-secured first stream's
  context and build the second connection through
  `tcp::connect(ctx, None)` + `security::wrap(ctx, ..)` when `is_tls()`; keep
  the raw dial for the plaintext case.
- Until then: refuse at dial through `capability::support_reason` (a named
  unsupported-shape reason), never at ingestion — ADR 0018 D-F keeps the shape while a pinned
  core serves it.

## Related

- **006:** a neighbouring visibility question in the neighbouring pool — 006 is
  a carrier built by the build gate's 1 s fallback that is never registered;
  here `register` runs after the h2 handshake but before the xhttp GET, so a
  failed fresh session leaves its sender pooled (`xhttp.rs:1012`, `:1086`; only
  `connect_pooled` calls `forget`).
- **004:** both are "a config field reaches the plan, then is dropped before the
  wire" — there the mux cap, here the ALPN-derived version.
