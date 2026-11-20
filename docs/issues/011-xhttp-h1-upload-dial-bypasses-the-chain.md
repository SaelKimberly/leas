# 011 — The plaintext xhttp h1 arm dials its upload connection straight to the server, bypassing a chain

- **Location:** `crates/leas-native/src/transport/xhttp.rs:992`
  (`packet_up_h1`), `:1070` (`stream_up_h1`), `:199-232` (`pooled`/`register`
  `direct_hop` guard for contrast)
- **Severity:** low
- **Status:** theory
- **Domain:** native-transport

## Hypothesis

xhttp picks its h1 arms when there is no TLS (`xhttp.rs:902-925`). Those arms
need a SECOND connection — h1 cannot multiplex the upload onto the GET
connection — and they open it with

```rust
let post_stream = crate::transport::tcp::connect(ctx, None).await?;
```

`tcp::connect(ctx, None)` ignores any base and dials `ctx.params.server`
itself (`tcp.rs:8-14`: `base` is the identity path, `None` means "dial").
When the xhttp row is not the first hop of a chain, `xhttp::connect` receives
the earlier hop's tunnel as `stream` and correctly runs the GET over it — then
sends every upload byte on a fresh direct TCP connection to the same server,
bypassing the chain.

Two consequences, in audit order:

1. **Routing leak.** The upload half leaves from the client's own address to
   the server the user asked to reach only through the chain (that server —
   and any observer of the last leg — sees the client directly).
2. **Split tunnel.** Download rides the chain, upload does not; a server that
   authenticates or rate-limits by source address sees two different peers for
   one session.

The codebase already treats exactly this shape as forbidden for the h2 pool:
`register` refuses a non-first hop (`xhttp.rs:233-238`, "Only a DIRECT first
hop may be pooled: a later hop's bytes traverse the earlier proxy, so leasing
it for a direct row would route through that chain"). The h1 second dial has
no such guard, so the rule is enforced on the pool and not on the dial.

Reachability: a chain (`base: Some`) whose later hop is a plaintext
`xhttp` `h1` row. A TLS xhttp row cannot hit it today — see 010, which routes
every TLS row to the h2 arm.

## Evidence

- `xhttp.rs:982-1008`, `:1061-1082` — both h1 arms call
  `tcp::connect(ctx, None)` after `h1_client(stream)` used the chained stream.
- `tcp.rs:8-14` — `base: Some` is a passthrough; `None` dials.
- `chain.rs:75-96::secured_upgraded` — the chain's one dial+security+upgrade
  path; the second dial bypasses all three.
- `xhttp.rs:233-238` and `chain.rs:208-213` — the same rule stated twice: the
  h2 pool refuses a later hop in `register`, and the chain refuses to consult
  the pool when `base.is_some()`. The h1 second dial is the one direct
  connection neither guard covers.
- The h3 arm cannot hit it: `transport::connect` refuses `base.is_some()` for
  the self-contained QUIC dial (`mod.rs:35-42`).

## Fix sketch

Smallest correct change: refuse the combination instead of leaking.
`xhttp::connect` does not receive the base (its signature is `connect(ctx,
stream)`), but `LinkContext::direct_hop` carries the same fact — the chain sets
it from `base.is_none()` (`chain.rs:205`) and the h2 pool already keys its own
guard on it (`xhttp.rs:233-238`). So the guard belongs at the top of each h1
arm:

```rust
if !ctx.direct_hop {
    return Err(NativeError::Config(
        "xhttp h1 needs a second connection for uploads and cannot ride a chain".into(),
    ));
}
```

Put the same predicate in `capability::support_reason` so the row reads as an
unsupported shape at dial rather than as a broken server.

The alternative — giving the second dial the base — needs an h1 client that
multiplexes two requests over one upgraded tunnel, which is a different
transport, not a fix.

## Related

- **010:** the same three arms; the dispatch bug hides this one (a TLS row
  never reaches the h1 arm), so fixing 010 makes this reachable under TLS too.
  Whichever lands second must carry the guard.
- **006:** both are "a second connection the pool/gate opened is not
  accounted for by the layer above".
