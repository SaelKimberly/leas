# Settings & Sources: informative, narrow-safe, consistent

Date: 2026-11-12
Status: approved design (sections §1–§3 approved via review rounds; §2 amended
with the `○`-at-default marker; §3 amended with Routing Rules UX)

## Goal

Three user-facing goals:

1. The Settings popup is more informative and user-friendly: per-field
   descriptions, defaults, reset, richer markers, selector positions, dirty
   counts.
2. The popup looks right on screens narrower than 120 columns: adaptive bands,
   truncation that never hides the cursor or the error, a too-small guard.
3. Subscriptions become a first-class pane-1 tab ("Sources") with a
   table-like, human-readable layout; the Settings popup loses its
   Subscriptions branch.
4. Consistent field-widget styling across settings, routing, and group forms;
   Routing Rules gets its UX pass.

## Non-goals

- No restart-required (`⟳`) or `+` explicit-override markers (no metadata for
  restart effect exists).
- No unit suffixes or `0 → auto` display (needs a per-key unit table; later).
- No mouse support changes.
- No persistence/schema changes. `r` reset writes a form value; saving works
  exactly as today through `apply_settings_fields`.

## §1 Sources tab (pane 1)

### Model changes

- `types.rs`: `Pane1Tab` gains `Sources`, ordered `Profiles · Sniffer ·
  Sources · Logs` (`prev`/`next` unchanged).
- `types.rs`: new `AppMode::Sources` (list state: selection index) and
  `AppMode::GroupForm { group_id: Option<String>, fields, focus_index,
  form_errors, snapshot }` overlay mode. `GroupList`/`GroupForm` variants leave
  `SplitRightPane`; `SettingsSection::Subscriptions` leaves the section enum.
- `SETTINGS_TREE` loses the Subscriptions leaf (Advanced drops to 2 leaves).
- `g`/`G` on Profiles switches to the Sources tab (was: open Settings at
  Subscriptions).

### `ui/sources.rs` (new)

- `DataTable` (existing widget) with columns, left to right:
  `Name` · `Enabled` (`✓`/`✗`) · `Status` (error reason verbatim, error color
  on failure) · `Last Updated` · `Endpoints` (count per group) · `URL`
  (truncated `…`).
- Narrow handling: threshold-based column shedding right-to-left (URL first),
  xrat `table.rs` pattern; no column ever renders half-drawn.
- Keys, unchanged semantics: `a` add (opens `GroupForm` empty), `e` edit,
  `d` delete (`y` confirm), `u` update all groups, `Space` toggle enabled mask,
  `↑↓` navigate. `Esc` does nothing (tab, not modal).
- `ops/subscriptions.rs`: handlers move off `AppMode::Settings` matching to the
  new modes; `start_add_group`/`start_edit_group`/`confirm_*` gain the new mode
  shapes. The import pipeline (HTTP + Telegram crawl, watermarks, route gate)
  is untouched.

### Removals

- `crates/leas/src/ui/settings.rs`: `GroupListItem`, `render_group_list_inner`,
  `handle_group_list_key`, `handle_group_form_key`, group-form field defs,
  subscriptions branches in `form_field_defs_for_section` /
  `render_right_pane` / `value_display` callers.
- Settings help/status/counter code paths for the group panes.
- `status_bar.rs`: settings hints lose group-list/group-form segments; Sources
  tab gets its own pane-1 hint segment.
- `ui/mod.rs`: help rows (`?`) gain the Sources tab rows; `render_pane1` and
  the pane-1 tab bar gain `Sources`.
- `docs/guides/tui-manual.md`: Subscriptions content moves from the Settings
  section to a new `### Sources (pane 1)` entry.

## §2 Defaults, reset, descriptions, markers

### Field metadata

- `form_field_defs` entries become `(key, label, field_type, description)`;
  `description` is one authored line per field (what it does + when it takes
  effect), xrat `settings_screen` style.
- New `FieldMeta` helpers in `crates/leas/src/ops/settings.rs` (or a sibling
  `field_meta.rs`):
  - `default_fields(state, section) -> Vec<(String, String)>` built from
    `leas_config`'s `Default` impls of the matching sub-structs, formatted by
    the same code path `build_settings_fields` uses.
  - A test asserts field-by-field equality between `default_fields` and
    `build_settings_fields` over a fresh `AppConfig::default()`, so reset and
    load cannot drift.
- Help band gains a `Default` row (value or `—`).

### Reset

- `r` on a focused form field writes the field's default into the form buffer
  (dirty `*` until saved). No section-wide reset. Esc guard and `Ctrl+S`
  unchanged.
- Hint surfaces (input bar edit mode, footer hints) gain `[r] Default`.

### Markers

- `provenance_marker` becomes three-valued, precedence `*` > `○` > `·`:
  - `*` unsaved edit (differs from snapshot) — warning tint on the value.
  - `○` saved value equals the field default — dimmed.
  - `·` saved, differs from default — current neutral look.
- Legend text updates: `· saved   ○ at default   * unsaved   › selected`.

## §3 Visual polish

### Popup frame

- Border stays **squared** (plain `Block`, user decision 2026-11-12).
- Width cap raises `clamp(w-4, 50, 110)` → `clamp(w-4, 50, 118)`.
- Too-small guard: below ~12 rows or ~40 columns the popup renders a centered
  `Terminal too small for settings (40x12 needed)` in the error color and
  nothing else (zellij `settings_screen.rs` pattern).

### Narrow mode (popup width < 90)

- Idle input bar collapses to a borderless 1-row hint; active filter/edit keep
  the bordered 3-row bar.
- Help band collapses to 1–2 rows: `Field · Type · Current` (and `Default`)
  on one line, full value wrapped; the wide layout keeps the current
  `Field/Type/Accepts/Current/Default/Keys` rows.
- Split switches from proportional (30%/35%) to `left = 18` fixed — 18 is the
  safe minimum: longest leaf "Routing Rules" (13) + marker (2) + indent (3) —
  and `render_sections` truncates names with `…` below that floor.

### Width-aware rendering (bug fix, affects today's build)

- New truncation/padding helpers using display width (grapheme/`unicode-width`),
  not `char` count: `{label:<label_w$}` padding and the `GroupListItem`-style
  pop-truncation both misalign rows on non-ASCII text today.
- `fit_value(text, width)`: reserves one column for `…`, reserves the focused
  cursor cell — `█` is always visible; long values read fully in the help
  band's `Current` row (wrapped).
- Form errors: inline `⚠` renders only when the whole row fits; the status
  band always carries the first error (both surfaces, user decision).

### Informative touches

- `Values` title: `Values · i/n · k unsaved`.
- Selectors render `‹ 2/5 · liberty ›` (position + option).
- Group headers show leaf counts (`▾ Routing · 3`).
- Idle input bar hint drops (borderless) as above.

### Token polish (no theme additions; all tokens exist)

- Bool `✓` success / `✗` hint color; selector brackets accent, focused value
  bold; dirty value carries the warning tint (with `*`); focused pane title
  accent-bold; saved-notice colors unchanged.

### Consistent field widgets

- One shared `render_field_row` (label column, marker, value display, focused
  cursor `█`, inline error `⚠`) replaces:
  - the settings form's hand-drawn spans (`render_form_with_area`),
  - the routing form's `ratatui_cheese::Input` rows
    (`render_routing_form_inner`, which also loses its bottom help line —
    the modal border owns keys).
- Type-level colors and cursor behavior identical across all three forms.

### Routing Rules UX

Observed on a live run at 120x40 and 80x24
([scenario record](../../guides/tui/2026-11-12-154049-scenario-routing-rules-audit.md)):
the list renders one blank row per rule (`ListItem::height` is 1; the gap
comes from the widget), rule rows overrun the popup's right border at 80
columns, the header hint clips mid-word with no `…`, the footer hint
advertises `[a] Add [e] Edit [d] Delete` in `ruleset: default` where those
keys are silently dead, the help band wastes 6 of 8 rows, and the 14-field
routing form has no scroll (tail fields unreachable while focus can Tab into
them).

Root cause of the border overrun, verified in code: `RoutingRuleItem::render`
builds the row as `format!(" {:>2} {} {:<30} {} ", …)` — a fixed 30-column
target cell plus fixed number/type/outbound columns (~45+ columns minimum)
— and paints it with `buf.set_string` clamped to nothing. Below ~45 inner
columns the row paints past the pane and erases its border; `{: <30}` pads
but never truncates, so a long targets blob overruns at any width. The group
list's own render (pop-truncate on `unicode_width`) is the in-repo precedent
for the fix.

- Header becomes a controls row: `D ‹dataset› · C ‹country› · M ‹ruleset›`
  with accent-bold values (same bracket idiom as selectors), plus a summary
  `12 rules · 2 off`.
- List columns reworked: `#` · `Outbound` (colored: `block` error, `proxy`
  accent, `direct` neutral, `off` dimmed) · `Targets` (first entries, then
  `+k more`) · `Matcher` (domain_matcher / ports / network summary). The
  opaque `r#type` number leaves the row.
- One rule per row — no blank gap rows; lines clamp to the pane's inner
  width (never paint over the border).
- `ruleset: default` dims the list rows — the read-only state becomes
  visible — and the footer hint set switches to the read-only variants; an
  ignored edit key (`a`/`e`/`d` in default mode) sets a status-band notice:
  `default is read-only — [M] switch to custom`.
- The routing form scrolls with the shared keep-focus-visible window; it
  loses its bottom help line (the modal border owns keys).
- Disabled (`off`) rows keep the dimmed + `off` rendering.

## Testing

Unit/integration rows beside the code (`settings.rs` test mods, `sources.rs`):
- value truncation keeps the cursor visible at any width;
- display-width padding/truncation with non-ASCII labels and values;
- narrow-mode band collapse and fixed-left split;
- too-small guard renders the guard line and nothing else;
- `default_fields == build_settings_fields` on a fresh config (drift guard);
- `r` writes the default and flips the dirty marker; `○` marker precedence
  `* > ○ > ·`;
- dirty-count in the `Values` title;
- Sources tab: column shedding thresholds, enabled toggle, add/edit/delete
  flows through the new modes (moved, not new, tests — same expectations at
  the new mode entry points);
- routing list rows clamp to the pane's inner width and render one row per
  rule (no blank gap rows);
- an ignored edit key in `ruleset: default` produces the status-band notice.

## Verification

`cargo nextest run -p leas` for the crate; workspace clippy per AGENTS.md
(`cargo clippy --workspace --exclude leas-oracles ... -D warnings`); manual
TUI check of the popup at 120/100/80/60/40-column terminals and the Sources
tab flows (add/edit/delete/update/toggle).
