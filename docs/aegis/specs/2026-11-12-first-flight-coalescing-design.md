# First-flight coalescing — Design Spec Brief

Date: 2026-11-12
Status: **implemented 2026-11-12** — plan `plans/2026-11-12-first-flight-coalescing.md`.
Origin: `thirdparty/ZeroNet` @ `29e7a95` audit, `docs/research/2026-11-12-zeronet-zray-analysis.md` §2, §7.
Owner gap: no spec owns what a protocol connect writes before the first payload.

---

## 1. Why this exists

Every protocol connect ends by writing its request header as its own `write_all`:

| Protocol | Site |
| --- | --- |
| VLESS plain | `protocol/vless/mod.rs:126` |
| VLESS + Vision | header `:191`, then camouflage frame `:204` |
| VLESS UDP | `:317` |
| VLESS mlkem | `:105` |
| Trojan | `protocol/trojan/mod.rs:92`, `:545` |
| VMess | `protocol/vmess/mod.rs:88`, `:104` |

On a TLS or REALITY carrier that is a small record of a recognisable size, and with
`TCP_NODELAY` a small packet, before the application says anything — the exact shape
a classifier fingerprints. On the Vision path it is **two** such writes (header,
then the empty camouflage frame) before the first padded frame.

ZeroNet solves it with one shared wrapper: the header is withheld and leaves in the
same carrier write as the application's first bytes, so one record, one packet, one
less thing to recognise (`zero-protocol/src/first_flight.rs:1-40`). Their Vision
codec does the same internally: the header waits in `pending_write` and leaves with
the first padded frame (`zero-protocol/src/vision.rs:7-21`).

## 2. Scope

A writer wrapper in `leas-native`, applied at the protocol connect sites listed
above, plus the Vision hand-off.

**Out of scope:** server-side response headers (leas is a client), the mux session's
own framing decisions, and any change to what the header *contains*.

## 3. The shape

```rust
pub(crate) struct FirstFlight<S> { /* inner, pending: Vec<u8>, written, released, wait */ }
```

Rules:

1. The header is always the first bytes on the carrier, exactly once, and nothing the
   caller wrote is reordered or lost.
2. On the first `poll_write`, the header is prepended to the caller's bytes, up to a
   `FIRST_FLIGHT_MAX` cap (16 KiB). Bytes past the cap stay with the caller.
3. A protocol that lets the **server** speak first (SSH, SMTP) would deadlock if the
   header waited for a write that never comes. A **read flushes the header first**,
   before it may hand up read data, so the carrier never carries read data ahead of
   the request header. (ZeroNet arms a 100 ms timer instead; a read-triggered flush
   needs no timer and no extra future, and is what the implementation does.) Closing
   the write side without a write sends it too.
4. The per-write `timeouts::PROTOCOL` guard is **removed, not moved**: `connect` no
   longer writes, so nothing at that point can stall. The outer bound is the relay's
   `TUNNEL_READ` idle deadline, which fails the tunnel when neither direction moves a
   byte for 30 s. This is where the plan overrode this draft.

Vision needs one extra step rather than the generic wrapper: `connect_vision_over`
currently writes header, then camouflage, then wraps in `VisionStream`
(`protocol/vless/mod.rs:191-221`). Hand both byte runs to the codec as its initial
pending write, so the first carrier write is `header | camo | first padded frame`.

## 4. Compatibility boundary

- No wire-content change: the same bytes in the same order, one write instead of two.
  A reader of the carrier cannot tell.
- No schema, config, or API change.
- Interaction to respect, not change: `VlessClientStream::with_ack_slot` peels the
  response header and fires the ACK slot (`protocol/vless/mod.rs:219-221`). The
  wrapper sits **below** it, on the carrier, so the peel still sees the response
  first.
- Interaction to respect: mux writes its `New` frame as the first post-header write,
  so coalescing is a straight win there. Both mux connects are wired (`plain` and
  `Vision`, the latter with `header || camo` as the preamble); the UDP connect paths
  are the declared exception.

## 5. Verification

1. Byte-level test: for VLESS plain, Vision, Trojan and VMess, drive a duplex carrier
   and assert the first write observed at the carrier equals
   `header || first-payload` (Vision: `header || camo || first-frame`), and that a
   second write does not repeat the header.
2. Server-first test: a peer that only reads and never writes; the client's first read
   must flush the header ahead of the greeting it consumes.
3. No-write-close test: dropping the writer without a write releases the header.
4. `leas-oracles` e2e rows for VLESS/Trojan/VMess against the pinned real cores still
   pass, which is the interop proof that the coalesced first flight is accepted.

## 6. Decisions (settled at implementation)

- **D1 — one wrapper.** `protocol::first_flight::HeaderFirst`, used under the response
  peel by VLESS (plain, Vision, mlkem), Trojan and VMess — including VMess's UDP
  handshake, which shares the same function. Vision needed no internal change: its
  first padded frame is the first write, so the preamble joins it.
- **D2 — no wait at all.** A read flushes the header instead of a timer
  (`a_read_flushes_the_header_before_read_data`). The 100 ms ZeroNet value is recorded
  here as the alternative that was rejected: it delays the server-first case by 100 ms
  and needs a future per connection.
- **D3 — 16 KiB cap.** Bounds the one copy; a larger first write reports only the
  copied prefix as written and the caller's `write_all` continues with the rest.
