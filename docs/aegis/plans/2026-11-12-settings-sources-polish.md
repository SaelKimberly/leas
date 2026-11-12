# Settings & Sources Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans
> to implement this plan task-by-task (native execution — chosen by the user,
> who asked for plan and implementation in one go). Steps use checkbox
> (`- [ ]`) syntax for tracking.

**Goal:** Make the Settings popup informative and narrow-safe (defaults,
reset, descriptions, adaptive bands, width-correct rendering), move
Subscriptions out of Settings into a pane-1 "Sources" table tab, and rework
the Routing Rules UX.

**Architecture:** One width-aware text-fitting module feeds a single shared
field-row renderer used by every form in the popup. Field metadata collapses
into one static per-section table that both the value builder and the form
defs read, killing the existing SpeedTest defs/builder drift. Subscriptions
becomes a pane-1 tab (`Pane1Tab::Sources`) with group state in `AppState`;
the group form becomes an `AppMode::GroupForm` screen (same pattern as
AddServer). Routing Rules drops the `List` widget for manual rows with
display-width budgeting.

**Tech Stack:** ratatui 0.30, crossterm 0.29, ratatui_cheese (DataTable),
unicode-width, leas-config (serde defaults).

**Spec:** `docs/aegis/specs/2026-11-12-settings-sources-polish-design.md`

## Global Constraints

- `#![forbid(unsafe_code)]` stays; no new dependencies.
- Every hand-written crate opts into `[lints] workspace = true` — new module
  inherits from the crate.
- Tests live beside code in `crates/leas/src/ui/` test mods; `thiserror` for
  error types (none new here).
- Suite command: `cargo nextest run -p leas <filter>`; authoritative lint:
  `cargo clippy --workspace --exclude leas-oracles --all-targets
  --all-features -- -D warnings`.
- No persistence/schema changes: `r` reset and the `○` marker are render/form
  concerns; saving flows through the unchanged `apply_settings_fields`.
- Border corners stay squared (plain `Block`) — user decision 2026-11-12.
- Session-only state is reset on entry points (`enter_settings`, tab entry),
  never resumed stale.

## Review Focus

1. **Non-ASCII values/labels** (subscription names, CJK, emoji) — every new
   pad/truncate must measure display width, not `char` count. Pinned by the
   `textfit` tests in Task 1.
2. **The cursor must never leave the screen** — a focused text value longer
   than its column keeps `█` visible. Pinned in Task 2.
3. **Defs/builder drift** — SpeedTest today shows wrong label/value pairs from
   `speed_test_url` onward (builder has `error_ttl_hours`, defs do not).
   Pinned by the key-equality test in Task 3.
4. **Reset must not invent values** — `r` writes exactly what a fresh config
   would load; pinned by the defaults-equality test in Task 3.
5. **Routing rows must never paint over a border** — clamped to the pane's
   inner width at every width. Pinned in Task 8.

---

### Task 1: Width-aware text helpers (`ui/textfit.rs`)

**Files:**
- Create: `crates/leas/src/ui/textfit.rs`
- Modify: `crates/leas/src/ui/mod.rs` (add `pub mod textfit;`)
- Test: same file, `#[cfg(test)] mod tests`

**Interfaces:**
- Produces: `pub fn width(s: &str) -> usize` (display width),
  `pub fn pad(s: &str, width: usize) -> String` (pad or truncate to exactly
  `width` display cells, truncation ends with `…`),
  `pub fn truncate(s: &str, width: usize) -> String` (at most `width` cells,
  one cell reserved for `…` only when truncation happens),
  `pub fn truncate_keep_tail(s: &str, width: usize, tail_cells: usize) -> String`
  (keeps the LAST `tail_cells` cells — the cursor cell — truncating the head;
  used so a focused value's `█` always renders).

- [ ] **Step 1: Write the failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pad_measures_display_width_not_chars() {
        // "配置" is 2 chars but 4 cells.
        assert_eq!(width("配置"), 4);
        assert_eq!(pad("ab", 5), "ab   ");
        assert_eq!(pad("配置xyz", 6), "配置xy"); // 6 cells exactly, no room for …
    }

    #[test]
    fn truncate_reserves_the_ellipsis_cell() {
        assert_eq!(truncate("abcdef", 6), "abcdef");
        assert_eq!(truncate("abcdefg", 6), "abcde…");
        assert_eq!(truncate("配置配置", 5), "配置…"); // 4 + 1 = 5 cells
        assert_eq!(truncate("", 0), "");
        assert_eq!(truncate("ab", 1), "…");
    }

    #[test]
    fn keep_tail_keeps_the_cursor_visible() {
        // 6-cell budget, 1 tail cell: the cursor survives at the right edge.
        assert_eq!(truncate_keep_tail("abcdefg", 6, 1), "…def █");
        // Short value untouched.
        assert_eq!(truncate_keep_tail("ab", 6, 1), "ab    ");
    }
}
```

(Adjust the `pad`-with-ellipsis expectation to the function's contract you
implement; the tests above are the contract — implement to them.)

- [ ] **Step 2: Run to verify failure** — `cargo nextest run -p leas textfit`
  → FAIL (module missing).

- [ ] **Step 3: Implement.** Walk `UnicodeSegmentation::graphemes` (dep exists
  transitively via ratatui; if not importable, walk chars with
  `unicode_width::UnicodeWidthChar`), accumulate display cells; on overflow
  drop back one cell for `…`. `truncate_keep_tail` renders `…` + as many
  leading cells as fit, then pads the remainder — callers append the cursor
  span themselves (it is NOT part of the string; the test string above is the
  cell budget the caller then fills with `value + █`).

- [ ] **Step 4: Run to pass** — `cargo nextest run -p leas textfit`.

- [ ] **Step 5: Commit** — `git commit -m "feat(ui): display-width text fitting helpers"`.

### Task 2: Shared field-row renderer + token polish

**Files:**
- Modify: `crates/leas/src/ui/settings.rs` (`render_form_with_area`,
  `value_display`, `provenance_marker` signature stays; row building moves to
  a new `fn render_field_row(...)`)
- Test: existing `mod tests` in the same file.

**Interfaces:**
- Produces: `fn render_field_row(frame, Rect, theme, params: FieldRowParams)`
  where `FieldRowParams { label: &str, value: &str, field_type: &str,
  focused: bool, dirty: bool, at_default: bool, error: Option<&str>,
  marker_col_style... }` — one row: `›`/space + marker + padded label +
  value (+ `█` when focused + inline `⚠` only when the whole row fits).
  `render_form_with_area` becomes a loop over `render_field_row`.

- [ ] **Step 1: Tests first** (in `mod tests`):

```rust
#[test]
fn bool_value_colors_split_by_truth() {
    // Contract: value_display("Boolean","true") == "✓", styled success;
    // "false" == "✗", styled hint. Assert through the style helper, not text.
    let theme = crate::ui::theme::load("dracula").unwrap();
    assert_eq!(value_style_for("Boolean", "true", false), ThemeStyles::success(&theme));
    assert_eq!(value_style_for("Boolean", "false", false), ThemeStyles::hint(&theme));
}

#[test]
fn dirty_value_carries_warning_tint() {
    let theme = crate::ui::theme::load("dracula").unwrap();
    assert_eq!(value_style_for("Text", "x", true), ThemeStyles::warning(&theme));
}
```

- [ ] **Step 2: Run** — `cargo nextest run -p leas field_row` → FAIL.

- [ ] **Step 3: Implement:**
  - `fn value_style_for(field_type, value, dirty) -> Style`: dirty → warning;
    Boolean true → success; Boolean false → hint; Select focused →
    `footer_value` + BOLD; else current focused/unfocused styles.
  - `value_display` Select branch becomes:
    `‹ {i}/{n} · {value} ›` where `i` is the current option's 0-based
    position (+1), `n` the option count; an unknown stored value renders
    position 1.
  - Label padding: `textfit::pad(label, label_w)` replaces
    `format!("{label:<label_w$}")`.
  - Value rendering: budget = `area.width - (marker 2 + label_w + 2)`;
    unfocused → `textfit::truncate(value, budget)`; focused →
    `textfit::truncate_keep_tail(value, budget, 1)` then append `█`.
  - Inline error: only when `2 + label_w + 2 + value_cells + 3 + width(err)`
    ≤ area.width; else skip (status band repeats it — Task 4 keeps that).
  - Group headers in `render_sections`: `▾ {name} · {n}` / `▸ {name} · {n}`
    with `n = SETTINGS_TREE[group].items.len()`.

- [ ] **Step 4: Run** — pass.

- [ ] **Step 5: Commit** — `feat(ui): shared field row, type-level value colors, selector position`.

### Task 3: Field metadata — one table, defaults, `r` reset, `○` marker

**Files:**
- Modify: `crates/leas/src/ui/settings.rs` (`form_field_defs_for_section`,
  `handle_form_key`, `help_content`, `provenance_marker` callers),
  `crates/leas/src/ops/settings.rs` (`build_settings_fields` refactor,
  `default_fields`, `build_right_pane`),
  `crates/leas/src/state.rs` (`settings_form_defaults: Option<Vec<(String,
  String)>>`, default `None`, reset in `enter_settings`),
  `crates/leas/src/types.rs` (no change to `SettingsSection` here —
  Subscriptions removal is Task 7).
- Test: `crates/leas/src/ops/settings.rs` `mod tests`, settings.rs tests.

**Interfaces:**
- Produces: `pub async fn default_fields(state: &AppState, section) ->
  Vec<(String, String)>` — what a fresh install would load
  (`AppConfig::default()` for config-backed sections; the empty-DB branch for
  `Dns`; `""` for `RouteProbes`).
  `AppState.settings_form_defaults` set by `build_right_pane` for `Form`
  panes alongside `settings_form_snapshot`.
  `handle_form_key` `KeyCode::Char('r')` with no modifiers (and `!` CTRL):
  `fields[focus_index].1 = defaults[focus_index].1.clone()` (bounds-checked),
  no save.

- [ ] **Step 1: Failing test — defaults equal a fresh load (drift + reset
  ground truth):**

```rust
#[tokio::test]
async fn default_fields_equal_build_over_a_fresh_config() {
    let state = test_state_with(AppConfig::default()).await; // existing test helper pattern
    for section in [
        SettingsSection::Gui, SettingsSection::Inbound, SettingsSection::SystemProxy,
        SettingsSection::Tun, SettingsSection::Mux, SettingsSection::SpeedTest,
        SettingsSection::Logging,
    ] {
        let built = build_settings_fields(&state, section).await;
        let defaults = default_fields(&state, section).await;
        assert_eq!(built.len(), defaults.len(), "{section}");
        assert_eq!(built, defaults, "{section}: reset must write what a fresh config loads");
    }
}
```

- [ ] **Step 2: Failing test — defs keys match builder keys (kills the
  SpeedTest drift):**

```rust
#[test]
fn every_section_def_matches_the_builder_key_order() {
    for section in [/* all config-backed sections + RouteProbes */] {
        let def_keys: Vec<_> = form_field_defs_for_section(section).iter().map(|f| f.key).collect();
        // Mirror of the builder's vec! keys, asserted pairwise:
        let built = test_build_order(section); // see step 5
        assert_eq!(def_keys, built, "{section}: defs and builder drifted");
    }
}
```

- [ ] **Step 3: Run** — both FAIL (SpeedTest mismatches: defs list 18 keys,
  builder builds 19; defs missing `error_ttl_hours`).

- [ ] **Step 4: Refactor to one table.** Replace
  `form_field_defs_for_section`'s `(&str,&str,&str)` triples with:

```rust
pub(crate) struct FieldDef {
    pub key: &'static str,
    pub label: &'static str,
    pub ftype: &'static str,
    pub description: &'static str,
}
```

  One `const` table per section; `build_settings_fields` walks the same table
  so key order cannot drift again (the per-field value expression stays in a
  `match key` inside the builder loop; the table only owns order/labels/
  types/descriptions). Add the missing `error_ttl_hours` def
  (`"Error TTL Hours"`, `"Number"`, position after `dns_failure_defer_secs`).

- [ ] **Step 5: Author the 56 descriptions** (one line each; `&'static str` in
  the table). Content, section by section:

  - Gui: `language` "UI language"; `theme` "Colour theme, applied live on save"; `refresh_interval` "How often the feed re-queries the DB".
  - Inbound: `socks_port` "Local SOCKS5 listen port"; `http_port` "Local HTTP listen port, empty = off"; `mixed_port` "Local mixed (SOCKS+HTTP) port, empty = off"; `listen` "Bind address for the local inbound"; `sniffing` "Sniff destination domains for routing".
  - SystemProxy: `enabled` "Set the OS proxy to leas's inbound"; `http_port` "OS proxy HTTP port"; `socks_port` "OS proxy SOCKS port"; `bypass` "Hosts the OS proxy must not capture".
  - Tun: `enabled` "TUN device capture (needs privileges)"; `interface_name` "TUN interface name"; `mtu` "TUN interface MTU, empty = default".
  - Mux: `enabled` "Multiplex links over one connection"; `concurrency` "Streams per connection, empty = auto"; `protocol` "Mux protocol the core speaks"; `max_connections` "Connection pool cap"; `min_streams` "Min streams before a new connection"; `max_streams` "Max streams per connection"; `padding` "Pad mux frames"; `fragment_enabled` "Split TLS ClientHello into fragments"; `fragment_packets` "Fragment sizes, e.g. 10-20,30-50"; `fragment_length` "Fragment byte lengths"; `fragment_interval` "Delay between fragments (ms)".
  - SpeedTest: `ping_url` "URL the real probe fetches"; `ip_provider` "Service that reports the exit IP"; `tcp_timeout_secs` "Transport stage timeout"; `real_ping_timeout_secs` "Real probe timeout"; `real_ping_retries` "Retries per real probe"; `real_ping_concurrency` "Parallel real probes"; `real_ping_test_all_protocols` "Probe every link of an endpoint, not the best"; `task_queue_limit` "Queued-test cap, 0 = unlimited"; `dns_failure_defer_secs` "Window a DNS failure defers a re-test"; `error_ttl_hours` "Hours a failure marker stays believable, empty = never"; `speed_test_url` "File downloaded for the speed test"; `speed_test_concurrency` "Parallel speed tests"; `speed_test_retries` "Retries per speed test"; `speed_test_min_duration` "Min run length per download"; `speed_test_min_bytes` "Min bytes per download"; `speed_test_max_duration` "Max run length per download"; `geoip_mode` "GeoIP artifact format"; `geo_auto_update` "Re-download geo artifacts on a timer"; `geo_update_interval` "Geo artifact re-download interval (hours)".
  - Logging: `log_ttl_secs` "How long core logs stay stored"; `log_to_file` "Also write core logs to a file"; `log_file_path` "Log file path".
  - RouteProbes: `probes` "Hostnames that must resolve for the routing probe".
  - Dns: `servers` "DNS servers the core queries (comma-sep)"; `hosts` "Static host mappings (comma-sep)"; `query_strategy` "A/AAAA preference"; `disable_cache` "Disable the core's DNS cache"; `disable_fallback` "Disable fallback servers"; `client_ip` "Reported client IP for EDNS"; `cache_ttl_secs` "TUI DNS cache TTL, empty = 300".

- [ ] **Step 6: Implement `default_fields`** in `ops/settings.rs`:

```rust
pub async fn default_fields(state: &AppState, section: SettingsSection) -> Vec<(String, String)> {
    match section {
        SettingsSection::Dns => vec![ // the fresh-DB branch, byte-for-byte
            ("servers".into(), String::new()), ("hosts".into(), String::new()),
            ("query_strategy".into(), String::new()), ("disable_cache".into(), String::new()),
            ("disable_fallback".into(), String::new()), ("client_ip".into(), String::new()),
            ("cache_ttl_secs".into(), String::new()),
        ],
        SettingsSection::RouteProbes => vec![("probes".into(), String::new())],
        _ => {
            let fresh = leas_config::AppConfig::default();
            build_config_fields(&fresh, section) // extracted formatting, shared with build_settings_fields
        }
    }
}
```

  `build_settings_fields` becomes `build_config_fields(&state.config,
  section)` (sync, private) plus the DB wrappers it already had; SpeedTest's
  geo fields read `fresh.geo.*` — note `build_config_fields` must stay one
  function so reset and load share formatting.

- [ ] **Step 7: `r` in `handle_form_key`:**

```rust
KeyCode::Char('r') if !key.modifiers.contains(KeyModifiers::CONTROL) => {
    let default = state
        .settings_form_defaults
        .as_ref()
        .and_then(|d| d.get(*focus_index).map(|(_, v)| v.clone()));
    if let Some(v) = default
        && let Some((_, val)) = fields.get_mut(*focus_index)
    {
        *val = v;
        *state.settings_notice = None; // a reset is not a save
    }
}
```

  (fit the borrow shape of the existing match — extract `fields,
  focus_index` the way the handler already does.) Footer hint gains
  `[r] Default` in the Form segment of `status_bar::settings_hints`.

- [ ] **Step 8: `○` marker.** `build_right_pane` sets
  `state.settings_form_defaults = Some(default_fields(state, section).await)`
  for `Form` panes (and `None` otherwise; `enter_settings` resets it).
  `render_form_with_area` receives `defaults: Option<&Vec<(String,String)>>`
  and computes:

```rust
let marker = if base != current { '*' }
    else if defaults.and_then(|d| d.get(index)).is_some_and(|(_, v)| v == current) { '○' }
    else { '·' };
```

  Marker styles: `*` warning, `○` hint (dimmed), `·` hint. Legend in
  `help_content` becomes `· saved   ○ at default   * unsaved   › selected`.

- [ ] **Step 9: Help band gains `Default`** row: `row("Default",
  value_display(ftype, default_value))` after `Current`; narrow mode renders
  `Field · Type · Current` (+ `· Default`) on one line (Task 4 wires the
  band, this task supplies the data via a `help_content` variant flag).

- [ ] **Step 10: Tests for `r` + `○`:**

```rust
#[tokio::test]
async fn r_writes_the_default_and_flips_dirty() { /* set field to a non-default,
    press r, assert value == defaults value and snapshot still differs */ }

#[test]
fn marker_precedence_is_star_then_circle_then_dot() { /* current != snapshot → '*';
    == snapshot && == default → '○'; else '·' */ }
```

- [ ] **Step 11: Run crate tests, commit** — `feat(settings): field metadata, defaults, r-reset, at-default marker`.

### Task 4: Popup frame + narrow mode + too-small guard

**Files:**
- Modify: `crates/leas/src/ui/mod.rs` (`render_overlay` Settings arm),
  `crates/leas/src/ui/settings.rs` (`render`, `render_input_bar`,
  `render_help`, `render_sections`).
- Test: `ui/mod.rs` overlay tests + settings.rs tests.

**Interfaces:**
- Produces: `settings::render` handles `area.width < 40 || area.height < 12`
  by rendering only a centered `Terminal too small for settings (40x12
  needed)` error line. Narrow mode = `popup.width < 90`.

- [ ] **Step 1: Tests first** (`ui/mod.rs` `overlay_tests` + settings tests):

```rust
#[tokio::test]
async fn settings_popup_caps_at_118() {
    // 140-wide area → popup width 118 (was 110).
}

#[tokio::test]
async fn tiny_area_renders_only_the_guard_line() {
    // area 30x10 → screen contains "Terminal too small for settings" and no
    // "Sections" band.
}

#[tokio::test]
async fn narrow_mode_collapses_idle_bar_and_help() {
    // popup width 70: idle input bar is borderless 1 row ("Press / to filter
    // settings" without a border box), help band 2 rows.
}
```

- [ ] **Step 2: Run** — FAIL.

- [ ] **Step 3: Implement:**
  - `ui/mod.rs`: `clamp(50, 110)` → `clamp(50, 118)`; in `settings::render`,
    guard first (centered Paragraph, `ThemeStyles::error`), then bands.
  - `render()` layout: `bar_rows = if narrow && idle { 1 } else { 3 }`;
    idle = `!settings_search.active && no focused text field`. Borderless
    bar: render the hint Paragraph directly (no Block).
  - `help_rows`: narrow → `2`; wide → `10.min(...)` as today. Narrow help
    line: `Field {label} · {type} · {current}`; when `current` exceeds the
    line, wrap to the 2nd row (`textfit::truncate`, no `Wrap` widget needed).
  - Split: `left_w = if rows[1].width < 90 { 18 } else { percentage as today }`;
    `render_sections` truncates leaf/group names with `textfit::truncate` to
    `left_w - 4`.
  - `render_right_pane` Form title: ` Values · i/n · k unsaved ` where
    `k = fields.iter().zip(snapshot).filter(|(cur, snap)| cur != snap).count()`
    (omitted when 0; ` Values ` below width 18 as today).
  - `footer_hints`: narrow popup (< 80) uses short spellings — `[Tab]`→`⇥`,
    `[Ctrl+S]`→`^S`, `[Ctrl+W]`→`^W`, `[Shift+Tab]`→`⇤` in the hint strings
    of `status_bar::settings_hints` via a `compact: bool` parameter threaded
    from `footer_hints(state, popup_width)`.

- [ ] **Step 4: Run** — pass; run the full popup test mod.

- [ ] **Step 5: Commit** — `feat(ui): settings popup narrow mode, 118 cap, too-small guard`.

### Task 5: Sources tab — types, state, routing, render

**Files:**
- Modify: `crates/leas/src/types.rs` (`Pane1Tab` gains `Sources` between
  `Sniffer` and `Logs`; `AppMode` gains `GroupForm { group_id: Option<String>,
  fields: Vec<(String,String)>, focus_index: usize, form_errors:
  HashMap<String,String> }`), `crates/leas/src/state.rs`
  (`sources_selected: usize`, `sources_selected_mask: Vec<bool>` — reset on
  entering the tab), `crates/leas/src/ui/mod.rs` (tab bar, `render_pane1`,
  `is_screen_mode`, key routing, `g` handler, help rows),
  `crates/leas/src/ui/status_bar.rs` (pane-1 Sources hint segment).
- Create: `crates/leas/src/ui/sources.rs`.
- Test: `ui/sources.rs` tests, `ui/mod.rs` tests.

**Interfaces:**
- Produces: `Pane1Tab::Sources` (prev/next include it — Profiles · Sniffer ·
  Sources · Logs). `ui::sources::render(frame, area, state)`,
  `ui::sources::handle_key(state, key)` (list keys), `ui::sources::
  render_group_form(frame, area, state)`, `ui::sources::
  handle_group_form_key(state, key)` (called from the AppMode::GroupForm
  route). `ops::subscriptions::start_add_group/start_edit_group` write
  `AppMode::GroupForm`; `confirm_add_group/confirm_edit_group` read it and
  return to `AppMode::List` (the tab stays selected).

- [ ] **Step 1: Types + state.** `Pane1Tab` order and `prev`/`next` updates;
  `AppState` fields with defaults; the existing `g|G` handler
  (`ui/mod.rs:1276`) becomes `state.pane1_tab = Pane1Tab::Sources;
  state.focused_pane = FocusedPane::Pane1;` (no settings popup).

- [ ] **Step 2: Key routing.** In the pane-1 key router next to the Sniffer/
  Logs blocks:

```rust
if matches!(state.pane1_tab, crate::Pane1Tab::Sources)
    && matches!(state.focused_pane, crate::FocusedPane::Pane1)
    && matches!(state.mode, crate::AppMode::List)
{
    crate::ui::sources::handle_key(state, key).await;
    return;
}
```

  `is_screen_mode` gains `AppMode::GroupForm { .. }`; the full-screen render
  match calls `sources::render_group_form`; the mode's key dispatch calls
  `sources::handle_group_form_key` (Tab/Shift+Tab/Up/Down/Backspace/Enter
  save via `ops::subscriptions::confirm_add_group`/`confirm_edit_group`/
  Esc cancel back to `AppMode::List` — port the bodies of the two removed
  `handle_group_*` functions, changing only the mode shapes).

- [ ] **Step 3: Sources table.** Columns and shedding thresholds
  (`area.width` of pane-1 content):

| Width | Columns shown |
|---|---|
| ≥ 100 | Name · Enabled · Status · Last Updated · Endpoints · URL |
| 80–99 | Name · Enabled · Status · Endpoints · URL |
| 60–79 | Name · Enabled · Status · URL |
| < 60 | Name · Enabled · URL |

  - `Endpoints` = `state.db` group member count is not loaded per group;
    derive from `state.endpoints` (each `EndpointRow` carries its group ids —
    count `row.groups` matches; if the row model exposes no group list, use
    the loaded `state.groups` membership already available in
    `EndpointRow.groups`; verify at implementation time and if neither
    exists, count from `state.endpoints` by matching `group_id` in the
    endpoint's `groups` field — never a per-row DB query).
  - Rendering: `DataTable` (crates/leas/src/ui/widgets/data_table.rs) with
    `ColumnWidth` per shed set; cells: Enabled `✓` success / `✗` hint;
    Status error text in `ThemeStyles::error`; URL truncated with
    `textfit::truncate`.
  - Keys: `↑↓` move (`sources_selected` clamp), `Space` toggles
    `sources_selected_mask[i]`, `a` → `start_add_group`, `e` →
    `start_edit_group(groups[selected].id)`, `d` → set `state.confirmation`
    for the selected group id (reuse the existing delete-confirmation flow),
    `u` → `update_all_subscriptions(state)`. `Esc` does nothing.
  - Header row (pane title): ` Sources · n/N ` counter like other tabs.

- [ ] **Step 4: Tests:**

```rust
#[tokio::test]
async fn sources_columns_shed_by_width_thresholds() { /* 60/80/100 width table
    renders the documented column sets, URL last to go, none half-drawn */ }

#[tokio::test]
async fn add_edit_delete_flows_through_group_form_mode() { /* a → GroupForm
    fields default; Enter saves and returns to List with the group present;
    e edits the selected; d with confirmation deletes */ }
```

- [ ] **Step 5: Run** — `cargo nextest run -p leas sources`.

- [ ] **Step 6: Commit** — `feat(ui): Sources pane-1 tab for subscription groups`.

### Task 6: Remove Subscriptions from Settings

**Files:**
- Modify: `crates/leas/src/types.rs` (drop `SettingsSection::Subscriptions`,
  `SplitRightPane::GroupList`/`GroupForm`), `crates/leas/src/ui/settings.rs`
  (drop `GroupListItem`, `render_group_list_inner`, `handle_group_list_key`,
  `handle_group_form_key`, the Subscriptions branch of
  `form_field_defs_for_section`, the `GroupList`/`GroupForm` arms of
  `render_right_pane`, `handle_split_key` pane_type 5/6, `search_available`),
  `crates/leas/src/ops/settings.rs` (`build_settings_fields`,
  `apply_settings_fields`, `build_right_pane` Subscriptions arms),
  `crates/leas/src/ops/subscriptions.rs` (mode matches → `AppMode::GroupForm`),
  `crates/leas/src/ui/status_bar.rs` (`settings_hints` GroupList/GroupForm
  segments, `status_bar_section_label`).
- Test: existing mods updated (delete group-pane tests that only pinned the
  old location; keep behavior tests re-homed in Task 5).

**Steps:**
- [ ] **Step 1:** Grep `Subscriptions` and `GroupList|GroupForm` across
  `crates/leas/src` — every hit is either a moved (Task 5) or deleted arm.
  `SETTINGS_TREE` Advanced group drops the leaf (9 leaves in 4 groups).
- [ ] **Step 2:** Delete the listed symbols; fix every match arm the compiler
  flags (no `unreachable!`, no TODO).
- [ ] **Step 3:** `cargo nextest run -p leas` green; clippy workspace clean.
- [ ] **Step 4: Commit** — `refactor(ui): subscriptions leave the settings popup`.

### Task 7: Routing Rules rework

**Files:**
- Modify: `crates/leas/src/ui/settings.rs` (`render_routing_list_inner`,
  `render_routing_form_inner`, `handle_routing_list_key`,
  `guard_read_only`), `crates/leas/src/ui/status_bar.rs`
  (`settings_hints` RoutingList arm).
- Test: settings.rs tests.

**Interfaces:**
- Produces: manual row rendering (the `List` widget goes away) with the
  columns `#` · `Outbound` · `Targets` · `Matcher`; a scrollable form using
  `render_field_row`.

- [ ] **Step 1: Tests first:**

```rust
#[test]
fn routing_rows_clamp_to_the_inner_width() { /* 58-col inner: every rendered
    line's display width <= inner width; the row keeps … on targets */ }

#[test]
fn ignored_edit_key_in_default_mode_sets_the_notice() { /* press a with
    ruleset default → state.settings_notice == Some("default is read-only —
    [M] switch to custom") */ }

#[test]
fn routing_form_scrolls_to_the_focused_field() { /* focus index 13 on a
    10-row pane → first visible row index >= 4, last field rendered */ }
```

- [ ] **Step 2: Header controls row.** Replace the two text lines with:

```
 D ‹loyalsoldier› · C ‹ru› · M ‹default›            10 rules · 2 off
 [D] dataset  [C] country  [M] mode   shipped table — [M] to edit
```

  Values accent-bold (`ThemeStyles::container_title`), keys hint-colored;
  `off` count = `rules.iter().filter(disabled).count()`; the second line
  truncated with `textfit::truncate` (never mid-word past the border).

- [ ] **Step 3: Manual rows.** Per rule, one line:

```
  1  block   geosite:win-spy, geosite:category-…      match: domain
```

  - `Outbound` cell colored: `block` → `ThemeStyles::error`, `proxy` →
    `ThemeStyles::container_title`, `direct` → `ThemeStyles::footer_value`,
    `off`/disabled row → whole line DIM (`ThemeStyles::hint`).
  - `Targets`: `domains`+`ips` first entries until the budget, then `+k
    more` (k = remaining count).
  - `Matcher`: `domain_matcher` value, else `ports` (`:80,443`), else
    `network`, else `—`.
  - `r#type` leaves the row.
  - Row window: keep the selected row visible (same scroll math as
    `render_form_with_area`).
  - `ruleset: default` (mode != Custom): every row DIM.

- [ ] **Step 4: Mode-aware hints + notice.** `guard_read_only` sets
  `state.settings_notice = Some("default is read-only — [M] switch to
  custom".into())` (keep the log line too). `status_bar::settings_hints`
  RoutingList arm:

```rust
let ro = state.ruleset_mode() != leas_config::RulesetMode::Custom;
if ro { " [↑/↓] Nav  [D]ataset  [C]ountry  [M]ode  [Ctrl+W] Sections  [Esc] Back " }
else  { " [↑/↓] Nav  [a] Add  [e] Edit  [d] Delete  [Ctrl+↑↓] Reorder  [Ctrl+W] Sections  [Esc] Back " }
```

- [ ] **Step 5: Form → shared renderer + scroll.** `render_routing_form_inner`
  becomes the `render_field_row` loop over `ROUTING_FIELD_DEFS` (labels from
  the defs; values comma-joined as today; `> (empty)` dropped — the marker
  `—` convention applies), with the same visible-window math as
  `render_form_with_area` (`start = focused_row.saturating_sub(height - 1)`).
  The bottom help line is deleted (modal border owns keys).

- [ ] **Step 6: Run** — pass; commit `feat(ui): routing rules header, columns, scroll, read-only notice`.

### Task 8: Manual + verification

**Files:**
- Modify: `docs/guides/tui-manual.md` (Settings section: bands, markers incl.
  `○`, `r` key, defaults row, narrow behavior, 118 cap, 9-leaf tree;
  Subscriptions content moves to a new `### Sources (pane 1)` entry; Routing
  Rules description matches the new header/columns).

**Steps:**
- [ ] **Step 1:** Manual edits as listed; keep the existing voice and table
  shapes.
- [ ] **Step 2:** Full gates:

```bash
cargo nextest run -p leas
cargo clippy --workspace --exclude leas-oracles --all-targets --all-features -- -D warnings
cargo fmt
```

- [ ] **Step 3:** Re-run the TUI audit scenario
  (`docs/guides/tui/2026-11-12-154049-scenario-routing-rules-audit.md`,
  fixture home recreated fresh): E5 still shows the read-only state but now
  with the status notice; P1–P9 verifications (no border overrun, one row per
  rule, no dead-column, form scrolls). Record the re-run as a new dated
  scenario doc appended to `docs/guides/tui/` and refresh `INDEX.md`.
- [ ] **Step 4: Commit** — `docs: tui manual for Sources tab and settings polish` + scenario re-run.

## Self-review

- Spec coverage: §1 → Tasks 5+6; §2 → Task 3 (+`○`); §3 frame/narrow → Task 4;
  §3 width helpers → Task 1; §3 shared widgets → Tasks 2+7; §3 routing →
  Task 7; testing/manual → Task 8. No gap.
- Placeholders: none — every code step carries real code or an exact symbol
  list; the descriptions table is authored inline.
- Type consistency: `FieldDef { key, label, ftype, description }` used by
  Tasks 3+7; `textfit::*` used by Tasks 2, 4, 5, 7; `AppMode::GroupForm`
  used by Tasks 5+6; `settings_form_defaults` by Task 3 (+4's dirty count
  uses `settings_form_snapshot`, unchanged).
- Review Focus → tests: (1) Task 1 tests, (2) Task 1 `truncate_keep_tail` +
  Task 2 renderer, (3) Task 3 Step 2, (4) Task 3 Step 1, (5) Task 7 Step 1.
