# The Sniffer's scroll clamps to the *last host*, not the last *page*, so `End` leaves a one-row pane

- **Domain:** ui-render (pane-1 `Sniffer`)
- **Severity:** low
- **Status:** theory (proven from the scroll arithmetic and the widget's own windowing code)
- **Location:** `crates/leas/src/ui/sniffer.rs:41-44` (`scroll_offset`), `:255-272` (`handle_key`), `:232` (`with_offset`)
- **Found in:** iteration 9

## Hypothesis

The host table's scroll offset is bounded by `len - 1` instead of `len -
visible_rows`. With more hosts than the pane can show, `End` (and `PageDown`
near the end) parks the window on the final host, so the pane renders **one**
host row and leaves the rest of the table blank — for as long as the user
stays there, and through every subsequent redraw.

## Evidence

The bound is written in two places, both `len - 1`:

```rust
// sniffer.rs:41-44
fn scroll_offset(len: usize) -> usize {
    let max = len.saturating_sub(1);
    SCROLL.fetch_min(max, Ordering::Relaxed).min(max)
}
```

```rust
// sniffer.rs:268, :271 — End, then the same clamp
KeyCode::End => usize::MAX,
…
SCROLL.store(next.min(len.saturating_sub(1)), Ordering::Relaxed);
```

`ratatui` does not rescue an over-scrolled offset: `Table::visible_rows`
(`ratatui-widgets-0.3.2/src/table.rs:998-1025`) takes
`start = state.offset.min(last_row)` and then walks forward only as far as the
area height allows — it never backs `start` up to fill the window unless a
*selected* row is off screen (`:1008-1013`, and this table sets no selection).
`render_rows` (`:856-884`) then iterates `.skip(start).take(end - start)`, so
`offset = len - 1` renders exactly one row, and `buf` keeps whatever the
previous frame left in the other rows only until the terminal repaints —
which is the blank interior.

The same wrong bound also applies when the host table shrinks: the map evicts
past `HOST_TABLE_CAP = 1000` (`crates/leas-native/src/telemetry.rs:196-198`),
and `scroll_offset` re-clamps a previously valid offset down to `len - 1`
rather than to a still-full page.

## Why it matters

The pane is the only per-host view of a live native session, and its own key
handler advertises `End`/`PageDown` (`:255-272`). Pressing `End` on a
browser-sized session (hundreds of hosts) produces a nearly empty pane that
looks like "the session has one host"; `PageDown` from `len - PAGE_ROWS - 1`
lands in the same state. Recovery is one `PageUp` (`:265`, which moves a whole
page) or `Home`, but nothing on screen says so.

## Reproducer

Not a code-mutation reproducer: the arithmetic is total. Read the two call
sites above and `ratatui-widgets-0.3.2/src/table.rs:998-1025`; then, in a
`TestBackend` of height 20 with 100 hosts, `handle_key(End)` →
`scroll_offset(100) = 99` → `visible_rows` returns `(99, 100)` → one row
painted.

A `#[test]` that pins the fix (fails today, passes after):

```rust
#[test]
fn end_fills_the_window_at_the_last_page() {
    let len = 100;
    let visible = 19; // pane height minus the header
    assert_eq!(scroll_at_end(len, visible), len - visible);
}
```

## Fix options

1. **Clamp against the visible row count.** Record the **data-row** height the
   render pass last used in an `AtomicUsize` beside `SCROLL` (the module
   already owns its offset this way, `:33-44`), and clamp `End`/`PageDown` and
   the render clamp to `len.saturating_sub(visible)`. The height to record is
   the rows area, not `area.height`: the widget splits the header off before
   `visible_rows` (`table.rs:775-777`), so recording the pane height clamps one
   row short — `End` would paint hosts `len-visible ..= len-1` and never the
   last host. That is exactly the test helper's 19 of 20 in the reproducer
   above.
2. **Compute the bound from the terminal height.** `state.term_height` is
   already tracked by the shell (`ui/mod.rs:366`) but it is the *terminal*
   height, not the pane's, so this only works if the pane's share is a pure
   function of it — it is not (pane-2 shares the row, and the tab header takes
   one line). Listed to record that the easy-looking source is the wrong one.

A `TableState` selection does **not** substitute for either: `visible_rows`
only pulls `start` back when the selected row is *past* `end`
(`table.rs:1015-1023`), and at `offset = len - 1` the selected last row is
already the only visible one, so nothing moves.

## Verification

After the fix, `End` on a 100-host table in a 20-row pane must show hosts
`82..=100` (the last page), and `PageDown` from row 80 must land on the same
page, not on row 99. Both are `TestBackend` assertions on `screen_text`, the
shape the file's existing tests already use (`sniffer.rs:283-386`).

## Related

- [024](024-sniffer-table-builds-every-host-row-per-frame.md) — the same
  `render_table`, one function up: it builds a row for *every* host while the
  widget paints only the window this offset selects. Fixing 024 by slicing the
  host list makes the correct clamp here load-bearing: a slice taken from this
  `len - 1` offset holds exactly **one** host (`len-1..len`), so `End` would
  paint a one-row table until the clamp is fixed. (The header is unaffected
  either way — it is rendered from the header cells at `table.rs:777`.)
