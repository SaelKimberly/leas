# Subscription failure logging + relay idle cap

Date: 2026-11-24
Source: [`docs/research/2026-11-24-log-and-failure-audit.md`](../../research/2026-11-24-log-and-failure-audit.md) G6, G7 (logging half), G8.

## Scoped findings

- **G8** — one network failure is logged twice: `HTTP fetch failed: …`
  (`stream_import.rs`) and `Subscription update failed: …` (the event line in
  `events.rs`). 72 error lines for ~36 events in the window.
- **G7a** — a body read failure on a subscription (`error decoding response
  body`) names neither the source nor how many bytes had been read; the
  operator cannot tell which feed needs a longer/retry budget.
- **G6** — `RELAY_IDLE` (60 s) reaped 2 985 sessions in the window, 2 930 of
  them after carrying traffic (947.8 MB): Google push
  (`mtalk.google.com:5228`, 964), Telegram web (276), GitHub alive (196).

Out of scope (noted, deliberately not done here): G7's direct-fallback retry
(changes fetch routing semantics; needs its own evidence), G2/G9 (DB
instrumentation), G10–G12 (oracle labs / taxonomy). The retry-direct idea also
needs a re-plan of the route when the tunnel is the thing being tested.

## Steps

1. **G6** — raise `timeouts::RELAY_IDLE` 60 s → 90 s; update the AGENTS relay
   bullet with the new value and the 2026-11-24 reap evidence.
2. **G7a** — `HttpSource` carries its `source_label` (scheme + host + path,
   query/fragment dropped, capped 96 chars) and the bytes served so far; a
   body-read error reads `body read failed for <source> after <n> bytes: <e>`.
   The decoder error path (undecodable body) gains the same byte count.
3. **G8** — drop the source-level `tracing::error!` on a send failure; the
   pipeline's `DB upsert INCOMPLETE` / event line is the single owner of the
   failure text (`ended_early` already carries it).

## Verification

- `source_label_keeps_origin_and_path_without_query` (new) — a token query is
  dropped, origin + path kept, the cap is char-safe.
- `a_truncated_body_names_the_source_and_served_bytes` (new) — end to end: a
  body cut short propagates `for <origin+path>` and `after <n> bytes`.
- `a_blocked_write_fires_while_the_shared_stamp_moves` (new) — the injectable
  `relay_with_cap` seam; drives `copy_half` alone so only the write stall can
  fire. `a_stalled_reader_ends_the_write_half` asserts the tunnel ends.
- `cargo nextest run -p leas --lib 'stream_import::tests'`,
  `cargo nextest run -p leas-native 'inbound::outbound::tests'`,
  `just quality-gate code`.

## Outcome

Executed 2026-11-24.

- **G6** — `RELAY_IDLE` is 90 s; the AGENTS relay bullet cites the 2026-11-24
  reap evidence. `Idle` now carries the cap and `relay_with_cap` is the test
  seam (`relay` passes `RELAY_IDLE`), so a timeout test no longer has to
  virtual-time past the shipped value. New
  `a_blocked_write_fires_while_the_shared_stamp_moves` drives `copy_half`
  alone: the shared read timer is never polled, so only the write stall can
  end it (the old integration test depended on poll order once both halves
  stalled on the same stamp; it now asserts the tunnel ends, with either
  bound).
- **G7a** — `HttpSource` keeps `source_label` (origin + path, query/fragment
  dropped, 96-char cap) and the served byte count; a chunk error reads
  `body read failed for <source> after <n> bytes: <e>`, and the decoder error
  line gained the same byte count. Tests: `source_label_keeps_…` (label
  hygiene) and `a_truncated_body_names_the_source_and_served_bytes` (an
  end-to-end short body asserts the propagated text).
- **G8** — the source-level `HTTP fetch failed` error line and the
  `HTTP client build failed` line are gone; the pipeline `INCOMPLETE` line and
  the `Subscription update failed` event own the text (`ended_early` still
  carries it, so nothing is lost).
- `cargo nextest run -p leas --lib 'ops::stream_import'`: 14/14.

