# Pane TUI Redesign & Profiles Columns — Design Spec

| Field | Value |
|---|---|
| Date | 2026-10-15 |
| Status | proposed — awaiting user review |
| Kind | spec |
| Supersedes | — |
| Inputs | user directives (2026-10-15, four messages); `thirdparty/matryoshka` (Python/Textual), `thirdparty/xrat` (Rust), `thirdparty/Bushuray-tui` (Go/bubbletea) read as references; current-state reads: `crates/leas/src/ui/mod.rs` (`render` 982-1091, `handle_key` Tab/BackTab 676-699), `crates/leas/src/types.rs:184-206` (`Tab`), `crates/leas/src/ui/profiles.rs` (16-col table, 999-1060), `crates/leas/src/ui/actions_log.rs`, `statistics.rs`, `native_activity.rs`, `logs.rs`, `settings.rs` |

## 1. Summary

Two coupled changes to the app shell:

1. **Shell.** Replace the 6-tab / single-content-area layout with **two framed panes**: pane 1 (top) with tabs `[Profiles]` / `Logs`; pane 2 (bottom) with tabs `Details` / `Metrics`. Settings stops being a tab and becomes a **popup overlay** over both panes. Statistics, Native Activity and the Actions Log dissolve as screens and are absorbed: Actions Log → pane 2 `Details`; Statistics + Native Activity + traffic counters → pane 2 `Metrics`.
2. **Profiles table.** Seven column changes: Address split into Address+Port; row number replaced by 8-char hex link id; inbound/outbound country flags become dedicated 2-char columns; all decorative brackets and glyph arrows removed; `Feat` renamed `White` with `SNI`/`CIDR`/`SNI+CIDR` text tokens; over-long DNS subdomains left-truncated with `...` keeping the domain; per-column colouring.

Shell and table land together or in that order; the table work is independent of the pane work and can ship first.

## 2. Goal / Non-goals / Acceptance

**Goal.** One screen answers "what can I connect to, what is happening, how is traffic moving" without tab-hopping; the settings surface is a popup with xrat-grade per-field feedback; every Profiles column carries meaning without ornament.

**Non-goals.** No protocol/DB/config behaviour change. No new dependency. No rename of persisted fields (`current_tab` is in-memory only). No change to the Logs data source, the ping pipeline, or enrichment.

**Acceptance (machine-checked).**

| # | Criterion | Proved by |
|---|---|---|
| A1 | `Tab` enum, `Tab::ALL`, `render_tabs` deleted; no `current_tab` reference remains in `crates/leas/src` | `grep` gate in plan |
| A2 | Pane focus cycles with `Tab`/`BackTab` and jumps with `1`/`2`; focused pane border = accent, unfocused = muted | `tui-test` scenario `pane-shell` |
| A3 | Pane-tab cycle `[`/`]` works with either pane focused; active tab renders `[Name]` accent-bold, others muted | scenario + screenshot |
| A4 | `,` opens Settings popup over both panes; `Esc` closes; unsaved changes prompt `y/n` discard | scenario `settings-popup` |
| A5 | Metrics tab shows traffic totals, sys stats and native connection ring in one scrollable pane with a visible `rows visible/total` counter | scenario `pane2-metrics` |
| A6 | Pane 2 height adjustable per tab: `Alt+↑/↓` resizes (pane 2 focused), clamped 3…terminal/2; default Details 8, Metrics 14; value survives within session | scenario `pane2-resize` |
| A7 | Profiles column cells match §7 exactly and no row-render cell emits a bracket or `▶/▾` glyph | gate = grep scoped to the column-cell builders in `ui/profiles.rs` (the row/cell construction fns), not the whole file — `data_table.rs` may legitimately use brackets elsewhere; plus scenario `profiles-columns` |
| A8 | `White` column shows `SNI`/`CIDR`/`SNI+CIDR`/`—`, width 9 (longest token intact, no abbreviation) | scenario `profiles-columns` case |
| A9 | Over-long subdomain: `sub….example.com` shape (3 dots then full domain) in Address cell | unit test on the truncate helper |
| A10 | Full gate green: `cargo clippy --workspace --all-targets --all-features -- -D warnings`, `cargo nextest run --workspace`, all existing `tui-test` scenarios + new ones | verification step |

## 3. Locked decisions

| ID | Decision | Why |
|---|---|---|
| D1 | Render is **base panes + overlay stack**: `render()` draws the pane shell, then walks an ordered list of popup renderers (confirm → speed-test menu → export chain → add/edit form → import/batch → settings popup → help). No `is_form_mode` branch threading | Advisory (turns_ago=2) accepted: today's `render()` already special-cases ~7 overlays (`ui/mod.rs:999-1080`); migrating each as a bespoke branch would reproduce the sprawl inside the new shell. xrat's `view/render.rs:14-27` is the same shape (base body + sequential modal renders) |
| D2 | Keymap scope: **app-level** = `Tab`/`BackTab` (pane focus), `1`/`2` (focus pane N), `[`/`]` (cycle focused pane's tabs), `,` (settings), `F1` (compact), `q`/`Ctrl+c` (quit). **Pane-1 Profiles-scoped** = all existing profile keys. **Pane-1 Logs-scoped** = `c`/`t`/`v`/scroll/copy. **Pane-2-scoped** = scroll keys, `Alt+↑/↓` resize | Advisory (turns_ago=3) accepted. Verified free in current `handle_key`: `1`, `2`, `[`, `]`, `,` (grep `crates/leas/src/ui/mod.rs`, zero hits); `Alt+↑/↓` free (grep: zero `KeyModifiers::ALT` sites in the crate; taken: `Ctrl+↑/↓` = move_profile, `Ctrl+Shift+S` = copy share URL, `Shift+↑` = Logs selection anchor) |
| D3 | Pane 2 height: **per-tab default + user resize + position counter**. Defaults Details 8, Metrics 14; `Alt+↑/↓` (pane 2 focused) steps ±2, clamp [3, terminal_h/2]; counter `first-last/total` in the pane title. Session-only, not persisted | Advisory (nit) accepted. Per-tab default alone fails A5's ring (2000-row trace); a resize without default leaves the first run cramped; persistence adds config churn for a transient preference. Key verified collision-free by grep: **no `KeyModifiers::ALT` site exists in `crates/leas/src`**; taken combos are `Ctrl+↑/↓` (profile reorder, `ui/mod.rs:727-737`), `Ctrl+Shift+S` (copy share URL, `ui/mod.rs:914-916`), `Shift+↑` (Logs selection anchor, `ui/logs.rs:305-308`) — Alt alone needs no guard |
| D4 | Screen homes: Statistics + Native Activity → pane 2 `Metrics` sections; Actions Log → pane 2 `Details`; Logs → pane 1 tab; Settings → popup; Export/Import/Add/Edit stay overlay forms | Advisory (turns_ago=5/7) accepted — one explicit home each, nothing implicit |
| D5 | Settings popup = centered, width `clamp(term_w-4, 50, 110)`, height `clamp(term_h-2, 20, 40)`, keeps the split tree+form internally (xrat `modals/settings.rs:7-12`, 96-108) | matches the "popup like xrat" directive; our 14-section tree fits the modal's two-pane interior |
| D6 | Tab-bar style mirrors xrat `log_title` (`view/configs/log.rs:417-436`): pane index `1:`/`2:` accent-bold, active tab `[Name]` accent-bold, inactive plain muted, labels inline in the pane's border title | the "bracketed bold highlight" and "accurate frames" directives; one line, no separate tab strip row |
| D7 | Pane frames: full `Block::borders(ALL)`, border = accent when focused, muted otherwise (xrat `theme.rs::border_style(focused)`); our resolved via opaline `accent.primary` vs `text.muted` | same directive; focus is readable in monochrome |
| D8 | Profiles column set per §7: `status 2, ID 8, Flag 5, Address flex, Port 6, White 9, Protocol 24, Test 6, Out 5, Exit 14` — 10 columns | user directives; drops 5 decorative cells, adds 2 real columns (Port, ISO-in-flag) net −3 columns. `White` is 9, not 8, because the user-named token `SNI+CIDR` is 9 cells — abbreviating to `SN+CIDR` would break the user's chosen vocabulary |
| D14 | **Flags normalized** (user ruling 2026-10-15): inbound and outbound flags render as `<flag emoji>-<ISO>` (e.g. `🇳🇱-NL`) directly before the Address and Exit values — the standalone ISO column is removed, ISO rides the flag. Fallback when the terminal lacks flag-emoji capability: bare `<ISO>` (2 cells). Unknown country = `—` | one idiom for both flag positions, no second column for a code the flag already carries |
| D9 | Hex id = `format!("{link_id:08x}")` of the endpoint's **representative link** (user ruling 2026-10-15) — the same `EndpointRow::representative_link_index` argmin the Test cell describes (`profiles.rs` doc on `compute_test_cell`), so ID and Test cell always name one link. Lowercase zero-padded 8, the existing panel convention (`profiles.rs:919`); `leas://{id:x}` (`ops/events.rs:17`) stays share-URL-only | "like it was done for logs" directive; one row = one link identity, no skew between cells |
| D10 | Multi-select `*` mirrors `index_cell`'s law **exactly** (equal-width invariant, test 1762-1768): the marker *replaces* the id, exactly as today's marker replaces the number. ID cell = either the full 8-hex `{link_id:08x}` or `*`, both padded to 8 — id simply not shown on multi-selected rows. Status column stays 2 cells for its glyph — advisory ×-check: no room for `*`+glyph there | the marker must survive the column change without widening the row |
| D11 | Expandable affordance (user ruling 2026-10-15): **bold `+` / `-`** prefix in the Address cell — `+` when collapsed, `-` when expanded. Not an arrow; one accent-bold cell prefixing the host | user directive wipes `▶/▾`; a 1-cell bold glyph survives colour-blindness and monochrome themes, unlike the underline-only proposal (D11 prior draft) |
| D12 | Per-column colour map in §7 (protocol accent, Test threshold green/yellow/red per existing delay thresholds, White secondary, id/port muted, flags uncoloured emoji) | "each column colored, similar to xrat" directive; xrat maps `latency_style`/`series_style` per cell (`theme.rs`) |
| D13 | **Profiles sort stays fixed**: no user sort cycle, deliberately, to avoid database contention (user ruling 2026-10-15). The page request is `PageRequest { sort: PageSort::Test, ascending: true }` (`ops/profiles.rs:103-104`); the table's arrow is a static `DataTable::sort_column` (`profiles.rs:996-997`, currently `Some(11)` = the Test column in the 16-col layout). **No `SortColumn` enum or sort state exists in the crate** (grep-verified) — the architecture doc's `AppState.sort_column` is stale | Advisories accepted; keeps the column redesign truthful: the arrow must point at the real ordering, never imply an interaction that was disabled on purpose |

## 4. Reference-client findings (carried from the comparison)

| Client | Finding (evidence) | Disposition in this spec |
|---|---|---|
| xrat | 4-panel dashboard with focus cycling, leader-key chords, per-field settings help/default/source/legend, stale test scope, bulk delete/purge/restore scoped ops, QR share, rotation, CLI+daemon | adopted: popup settings interior, focus model, scoped bulk ops (later slice), `[ ]`-style pane tabs; deferred: chords, rotation; rejected: daemon/CLI (architecture) |
| matryoshka | chained gateways GW1→GW2 with per-stage latency, security score column, latency history sparkline, custom test-URL columns, favorites/rename, Ctrl+P command palette, theme cycling | later slices (favorites/rename, security score); out of scope here |
| Bushuray-tui | mouse click zones, warning bar with severity+TTL, group tabs | later slices |
| leas today | 6 tabs, single content area + 8-row actions panel; 16-column table with brackets/flags; settings = tab with 3-tuple field defs (no help/default/source) | superseded by this spec |

## 5. Current-state inventory (evidence)

- `Tab` enum with 6 variants (`types.rs:184-206`); `Tab::ALL` cycled by `Tab`/`BackTab` at `ui/mod.rs:676-699`; dispatch at `ui/mod.rs:1048-1055, 1081-1088`; `render_tabs` at 1282-1310.
- `render()` (`ui/mod.rs:982-1091`): chunks = tabs(1) / content(Min 3) / actions(FULL_PANEL_HEIGHT=8 or 1 or overlay) / status(1). Overlay branches: small-terminal overlay, `is_form_mode` set, export-chain, speed-test menu, generic non-List modes, per-Tab dispatch — seven paths threading through the tab logic.
- Profile table: 16 columns, 118 fixed cells, decorative brackets `][`, `]=>{`, `}=>` and tree glyphs `▶/▾` (`profiles.rs:999-1060`). **Sort is fixed by design** (user ruling 2026-10-15: database contention): `PageRequest { sort: PageSort::Test, ascending: true }` (`ops/profiles.rs:103-104`); no `SortColumn` enum or sort state exists in the crate (grep-verified; the architecture doc's `AppState.sort_column` is stale); `DataTable` draws a static arrow via hardcoded `sort_column = Some(11)` + `Ascending` (`profiles.rs:996-997`, column 11 = Test).
- Latency thresholds are named constants `TEST_WARN_MS = 500` / `TEST_BAD_MS = 1000` (`profiles.rs:395-396`) — the colour map cites these, not xrat's 150/400.
- Actions Log full/compact renderers (`actions_log.rs:57-59`); Statistics (`statistics.rs:10`); Native Activity (`native_activity.rs:46`) — each a full screen today.
- Settings: `SettingsMode::Split` + `SplitRightPane::{Form,RoutingList,RoutingForm,UpdateForm,GroupList,GroupForm}` (`ui/settings.rs:229-353`); field defs are `(key,label,field_type)` 3-tuples (`:475-501`); form render `render_form_with_area` (`:634-712`).

## 6. New shell spec

```
┌─ 1: [Profiles]  Logs ──────────────┐
│ <pane-1 content: table or logs>    │  Min(6), border accent iff focused
├─ 2: Details  [Metrics] ────────────┤
│ <actions log | traffic+sys+native> │  height: per-tab default, resizable
└─ status bar ───────────────────────┘
```

- Overlay stack (D1) order: `Confirmation → SpeedTestMenu → ExportScope/Destination/Path → AddServer/EditServer → ImportUrl/BatchImport → Settings(,) → Help(?)`. Each renders over the full pane area; only the top-most consumes keys.
- Pane key routing: profiles keys only when pane 1 focused **and** tab = Profiles; logs keys only when tab = Logs; pane 2 scroll/resize when pane 2 focused. Overlay keys take precedence over pane routing (existing handler order preserves this: modals checked first).
- Small terminals (<20 rows): pane 2 collapses to the 1-row compact bar (existing `actions_compact` mechanism); the `<20` overlay-fullscreen branch is deleted (it double-renders the actions panel as the whole screen).
- `F1` toggles compact pane 2 as today.

## 7. Profiles column spec

| # | Header | Width | Content | Align | Colour (token) | Sort key |
|---|---|---|---|---|---|---|
| 1 | *(none)* | 2 | connection status glyph (multi-select `*` lives in the ID cell, D10) | left | success/error/default | no |
| 2 | `ID` | 8 | `{link_id:08x}` (D9); multi-selected rows print `*` instead of the id, both padded to 8 (D10) | left | `text.muted` | no |
| 3 | `Flag` | 5 | `<flag emoji>-<ISO>` before Address (e.g. `🇳🇱-NL`); fallback `<ISO>` = 2 when no flag-emoji capability (D14) | left | none (emoji) | no |
| 4 | `Address` | flex (≥13) | expandable endpoints: bold `+`/`-` prefix (D11) then host; DNS names whose subdomain overflows → `sub….domain.tld` (§8) | left | `text.secondary` | no |
| 5 | `Port` | 6 | port number | right | `text.muted` | no |
| 6 | `White` | 9 | `SNI` / `CIDR` / `SNI+CIDR` / `—` (user-named tokens; 9 = width of the longest) | left | `text.secondary`; `—` = `text.muted` | no |
| 7 | `Protocol` | 24 | `protocol/transport/security`, centered | center | `accent.primary` when security=`reality`, else `text.secondary` | no |
| 8 | `Test` | 6 | `[ 12 ]` thresholds green <`TEST_WARN_MS`(500) / yellow ≥ / red ≥`TEST_BAD_MS`(1000) (`profiles.rs:395-396`); `[real]`/`[fast]`/`[name]` markers keep meanings | center | latency thresholds (existing) | no (fixed) |
| 9 | `Out` | 5 | `<flag emoji>-<ISO>` before Exit; fallback `<ISO>` = 2 (D14) | left | none (emoji) | no |
| 10 | `Exit` | 14 | exit IP of active link, `—` none | left | `text.secondary` | no |

Removed vs today: tree `▶/▾` cell, `#` number, brackets `[ ][ ]=>( }=>`, endpoint-level `Type` cell (already merged), separate `Feat` 4-wide glyph cells, separate `Country` flag+ISO cell — the ISO folds into the flag prefix (D14), so no standalone ISO column remains. **Capability detection** (new helper, Phase 5): `<flag>-<ISO>` needs regional-indicator emoji; when the terminal cannot render them (non-UTF-8 locale, dumb term, `NO_EMOJI`/`LEAS_NO_FLAGS` escape hatch, or a width probe showing tofu) fall back to bare `<ISO>`. One pure `fn flag_cell(iso: Option<&str>) -> String` owns the branch; unit tests pin both forms. **Sort arrow**: `DataTable` indices are 0-based and §7 rows are 1-indexed, so the old `Some(11)` (Test, 12th cell) becomes `Some(7)` (Test, 8th row). It stays a fixed `Ascending` pointing at the real `PageRequest { sort: PageSort::Test, ascending: true }` — never wired to an interaction, since sorting is disabled (D13). The old arrow was truthful only by coincidence (two independent hardcodes that matched); the new column index must come from **one shared constant derived from the page request's sort field**, not a second literal. `PageSort` lives in `leas-db` (`crates/leas-db/src/profiles_query.rs`, `PageRequest.sort` + `order_terms`) and has no UI cycle; hex ID is deliberately outside any future sort.

Header style: one owner — `table.header` token, bold. Empty value = single `—` glyph everywhere (one empty-value glyph rule).

## 8. Address truncation rule

DNS names (`host_type == Dns`): if rendered width > column, keep the registrable domain (last two labels) intact and elide the subdomain's tail: `verylongsubdomain….example.com`. Exactly `…` may consume ≤3 cells; never elide the domain or TLD. IP literals and overflowed hosts: plain right-truncate `192.0.2.…`. Helper = pure fn `truncate_host(host, width) -> String`, unit-tested (A9).

## 9. Advisory resolutions

| Advisory (age) | Verdict | Where it landed |
|---|---|---|
| overlay-stack collapse (2) | **accepted** | D1, §6 |
| keymap scope/collision check (3) | **accepted** | D2 (collisions verified: `1`,`2`,`[`,`]`,`,`,`Ctrl+Shift+↑/↓` all free) |
| read render() body; explicit homes (5) | **accepted** | §5 inventory; D4 homes |
| decide screen homes before keymap (7) | **accepted** | D4 before D2 in decision order; homes drive the keymap |
| pane-2 height mechanism (nit, new) | **accepted** | D3 |
| SVG mock grid defect: no hex IDs, `○`/`*` overlap at x=18 | **accepted** — mocks re-emitted as files with the §7 grid (status 2 / ID 8 / Flag 5 …), row 2 shows `*` alone in the ID cell | `2026-10-15-pane-tui-design.svg`, `2026-10-15-settings-popup-design.svg` |
| flag normalization (user ruling) | **accepted** | D14, §7 rows 3/9, `flag_cell` helper task |

## 10. Relation to the 2026-10-14 tui-polish spec (supersession map)

The tui-polish spec (`2026-10-14-tui-polish-and-theming-design.md`) is partially landed: **P1 theme foundation is in** (`AppState.theme: opaline::Theme` in `state.rs`, `ui/theme.rs` token helpers — verified by read). Its open items (P2 hint owner, P3 per-frame size, P4 density, P5 docs) are re-scoped by this spec, not silently broken:

| tui-polish item | Disposition |
|---|---|
| D5 `hints_for(&AppState)` one owner, hints keyed per screen state | **kept, re-keyed**: hints now key pane-1/pane-2/popup state; the `[Tab] Next tab` sequences change to pane-focus/tab-cycle semantics (D2). The stated-empty-state fixes (A4/A5 classes) still land |
| D6 per-frame size, delete `<20` overlay (`ui/mod.rs:964-969`), `F1` = height-only | **kept, merged**: overlay branch is deleted as part of D1's overlay stack; `F1` toggles the pane-2 compact bar; height defaults/resize per D3 replace the fixed `panel_rows = 8` |
| A5 "`Esc` out of Settings returns to the Profiles tab" | **restated**: Settings is a popup; `Esc` closes it back to the previously focused pane/tab. The tui-polish scenario assertion is updated, not deleted |
| §5.4 density: `#`-header alignment, one empty glyph, panel border vs scrollbar | **kept** (empty `—` glyph is adopted in §7); `#` alignment is moot — the column is replaced by hex ID (D9) |
| §5.3 80-col drop list naming `Country`/`Outbound`/`Feat` | **re-derived** from the new §7 table in Phase 5 (columns renamed/split; drop priority re-decided on the new set) |
| D8 manual restatement (tree UI, theme table) | **deferred to Phase 6** of this spec, which rewrites the manual for the pane shell anyway |

## 11. Risks

| Risk | Mitigation |
|---|---|
| Overlay stack changes key precedence for every existing popup | one handler branch `if let Some(top) = state.overlay_stack.last()`; per-popup key fns stay as-is; scenario matrix re-runs all existing overlays |
| Sort-arrow re-index after the column change | Task: derive the arrow index from the page request's sort field (`PageSort::Test`, `ops/profiles.rs:103-104`), one shared constant — Phase 5 re-derives `Some(11)`→`Some(7)` and deletes the second literal |
| Bold `+`/`-` affordance reads as decorative | scenario `profiles-columns` asserts the prefix on an expandable row; `+`/`-` semantics match the `→`/`←` keys (collapse/expand) |
| Metrics pane 2000-row ring render cost | window-then-format already used by `native_activity.rs`; keep — render only the visible slice |
| Manual rewrite is large | Phase 6 owns it: tui-manual.md sections for panes, popups, columns |

## 12. Phase sequence (plan will expand)

| Phase | Work |
|---|---|
| 1 | Overlay stack render refactor (D1) — mechanical, behaviour-preserving; proves the new render shape before any state change |
| 2 | Pane state + shell + keymap (D2, D6, D7) — `Tab` deleted, pane enums + focus added |
| 3 | Settings popup (D5) with dirty-track + Esc discard |
| 4 | Pane 2: tab bar + Details (actions_log) + Metrics (merge statistics + native_activity + counters), resize (D3) |
| 5 | Profiles columns (§7) + truncation (§8) + colour map + `flag_cell` capability helper (D14) + sort-arrow shared constant (`Some(11)`→`Some(7)`) |
| 6 | Manual + INDEX/doc updates |
