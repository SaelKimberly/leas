# The Sniffer table builds a row for every host on every frame, then the widget paints ~20

- **Domain:** ui-render (pane-1 `Sniffer`)
- **Severity:** low
- **Status:** theory (render scope proven from the code; the cost measured outside the repo)
- **Location:** `crates/leas/src/ui/sniffer.rs:188-234` (`render_table`, the row build at `:202-215`)
- **Found in:** iteration 9

## Hypothesis

`render_table` maps the whole `snapshot.hosts` list into `Row`s — five `String`
allocations and one `Row` per host — and then hands all of them to the widget,
which paints only the rows the current offset and the pane height select. The
cost is therefore O(hosts) per draw against a ~20-row window, re-paid on every
redraw while the tab is open, and the host list is capped at 1000
(`crates/leas-native/src/telemetry.rs:196-198`).

## Evidence

```rust
// sniffer.rs:202-215
let rows: Vec<Row> = snapshot
    .hosts
    .iter()
    .map(|host| {
        Row::new([
            Cell::from(host.host.to_string()),
            outbound_cell(host.outbound.as_deref(), theme),
            Cell::from(format_bytes(saturating_i64(host.down))),
            Cell::from(format_bytes(saturating_i64(host.up))),
            Cell::from(host.conns.to_string()),
            Cell::from(host.failed.to_string()),
        ])
    })
    .collect();
```

Six cells per host, `outbound_cell` returning a `'static` line (no allocation),
the other five allocating a `String` each — `host.to_string()`,
`format_bytes(..)` twice, `conns.to_string()`, `failed.to_string()`.

The widget does not need them. `ratatui-widgets-0.3.2/src/table.rs:846-884`
(`render_rows`) computes `visible_rows(state, area)` and iterates
`.skip(start_index).take(end_index - start_index)`; `visible_rows`
(`:998-1031`) walks only until the area height is filled plus at most one
partial row. The column widths come from the constraints alone
(`get_column_widths`, `:1041-1068`, a `Layout::horizontal` over `self.widths`),
never from cell content, so nothing downstream reads an off-screen row —
except `column_count()` (`:1070-1077`), which reads `.cells.len()` per row (a
length, not the text) and is kept at 6 by the header anyway.

Measured outside the repo (`rustc -O`, best of 20 runs). The probe builds six
`String`s per host — one more than the repo's five, because it allocates the
static `"→"` cell and substitutes `index`/`"0"` for `conns`/`failed`, and it
omits `Cell`/`Row` construction — so both rows are an upper bound on the real
per-host cost, not a like-for-like measurement:

| hosts | Strings built | probe time |
|---|---|---|
| 200 | 1,200 | 58 µs |
| 1,000 | 6,000 | 180 µs |

So at the 1000-host cap a draw spends ~180 µs and 6,000 allocations to paint
~20 rows (`~120` Strings). Draws happen on every input event and on every core
event (`ui/mod.rs:374`, `events_seen`), and the native core publishes a
`SnifferSample` once a second (`ops/native_connect.rs:138-141`), so the tab
re-pays this at ≥1 Hz while connected and once per keystroke.

## Why it matters

This is the pane a user leaves open to watch a live session, which is exactly
when the host table is largest. The waste is bounded (1000 rows) and it is not
the dominant cost of a frame, so the severity is low — but it is pure: the
allocation count grows with the session while the painted area does not, and
the fix is a slice.

## Reproducer

The row build is a pure function of the host list, so the reproducer is the
probe above (kept outside the repo; no source change). In-repo, the proof that
the widget ignores off-screen rows is the ratatui source cited — plus the
existing `TestBackend` tests (`sniffer.rs:283-386`) which show a 20-row pane
rendering three rows from a three-host snapshot.

A test that discriminates the fix: build a snapshot of 100 hosts with distinct
host names, render a 20-row pane at offset 0, then assert the rendered text
contains host 0 and **not** host 50 — this passes today (the widget clips) and
so does not by itself bound the allocation. The allocation bound is the hot-path
gate's job (`crates/leas-hotpath`), not a `#[test]`.

## Fix options

1. **Slice before mapping, and reset the offset.** Take the window the widget
   will paint and give it a zero offset:
   `let start = scroll_offset(len); let visible = area.height.saturating_sub(1) as usize;`
   then map `snapshot.hosts[start..(start + visible + 1).min(len)]` and build the
   `TableState` **without** `with_offset`. The `+1` keeps the partial row
   `visible_rows` includes. Two traps:
   - `area.height` counts the header row, which the widget splits off before
     `visible_rows` (`table.rs:775-777`), so `visible` is one too large — the
     slice is capped by `len` anyway.
   - **the offset must become 0.** The widget applies `state.offset` to
     whatever rows it is handed (`start = state.offset.min(last_row)`, `:998`,
     then `.skip(start_index)`, `:865-866`), so a sliced list plus offset 1
     drops the first visible host, and offset 900 on a 20-row slice paints one
     row. The slice is only behaviour-preserving together with the reset.

   Widths are unchanged either way — they come from the constraints, not the
   cells (`:1041-1068`), and the header still renders from its own cells.
2. **Reuse one `Vec<Row>` allocation across frames.** A `Rc<Vec<Row>>` cache
   keyed on the snapshot is *not* worth it: the snapshot is a fresh box every
   second and the rows borrow nothing, so the cache would rebuild anyway.

Note the interaction with [023](023-sniffer-scroll-clamps-to-the-last-host-not-the-last-page.md):
once the slice exists, the `len - 1` clamp makes the last page **one row**
(`hosts[len-1..len]`), so `End` shows a single host instead of the last page —
023 must land with or before this one.

## Verification

`End` on a 100-host table must still show the last page (023), and the pane
must render identically for every scroll position — same columns, same glyphs,
same header — with the row vector now at most `pane height + 1` long. The
existing three-host test must stay green unchanged.

## Related

- [023](023-sniffer-scroll-clamps-to-the-last-host-not-the-last-page.md) — the
  clamp this slice depends on.
- [022](022-dns-failure-mark-sweeps-the-whole-deferral-map.md) — the same
  "work proportional to the whole collection on a hot path" shape, one layer
  down (the DNS deferral map's sweep).
