---
name: settings-xrat-parity
description: leas Settings popup — the four-band xrat-parity reskin: filter bar, Sections n/N list, Values i/n rows with provenance markers, Help box, status band, and hints in the modal border
app: leas 0.1.0 (debug build, target/debug/leas)
tags: [settings, popup, filter, markers, help, resize]
---

# Scenario: settings-xrat-parity

| Field | Value |
|---|---|
| Run at | 2026-10-16 09:30:00 +0500 |
| App under test | leas 0.1.0, debug binary `target/debug/leas`, md5 `fe4f62aa9f584fa6a8b5a2f89851cbe5` — **every frame in the linked transcript is from this build**, captured in one session after the last source change; frames from earlier binaries were removed rather than carried over |
| Launch command | `env TERM=xterm-256color LC_ALL=C XDG_CONFIG_HOME=/home/user/.cache/leas-tui/settings-parity/config target/debug/leas` |
| Session / mode / size | `default` / buffer, 120x40 for E1-E9, then **relaunched** at 54x24 for E10 (the 80x24 pass in E7 was captured on the previous binary and is re-run as part of that row's check) |
| Harness | mcp-tui-test (buffer mode, pyte) |
| Evidence | [2026-10-16-093000-scenario-settings-xrat-parity-transcript.md](2026-10-16-093000-scenario-settings-xrat-parity-transcript.md) |

## Purpose and scope

Asserts the Settings popup's new surface: the four bands, the two counters, the filter
lifecycle (open → filter → cancel), the provenance marker after an edit, the help box
following the cursor, the hints living in the modal border, and the layout at 80x24.

Does not cover: saving a section for real (the discard path is exercised instead), the
routing/updates sub-panes, or colour beyond the modal-surface cells asserted in E9.
The 2026-10-14 `settings-forms` transcript predates this reskin and is superseded **for the
Settings surface**; its non-surface observations (field focus, save, `q` behaviour) remain
historical.

## Environment and fixtures

```bash
R=/home/user/.cache/leas-tui/settings-parity
rm -rf "$R" && mkdir -p "$R/config/leas"
cp docs/guides/tui/fixtures/config.json "$R/config/leas/"
cp docs/guides/tui/fixtures/seeded/data.db "$R/config/leas/"   # 7 endpoints, synthetic
```

## Expected behaviour (written before the run)

| ID | Step | Expected observation (exact text where asserted) |
|---|---|---|
| E1 | `,` at 120x40 | popup ` Settings `; bands in order: `┌ Search ┐` with `Press / to filter settings`, ` Sections · 2/20 ` next to ` Select a section `, `┌ Help ┐`, no status band; footer hints inside the bottom border `[↑↓] Navigate  [←→] Collapse  [/] Filter  [Enter] Open  [Ctrl+W] Form  [Esc] Close`; the app status bar shows ` Settings` and **no** hint set |
| E2 | `/dns` | ` Filter ` title, body `dns█`, sections reduced to `▾ Routing` + `›    DNS`, counter ` Sections · 2/2 `, footer becomes `[type] Filter  [Enter] Apply  [Ctrl+U] Clear  [Esc] Cancel` |
| E3 | `Esc` | the query clears: title back to ` Search `, body back to the placeholder |
| E4 | `↓`x12 then `Enter` | DNS opens: bar ` Edit Servers (JSON) · Text `, ` Values · 1/7 `, rows `›· Servers (JSON)          —█`, ` · Disable Cache           ✗`, ` · Disable Fallback        ✗`, help `Help · DNS` with `Field Servers (JSON)`, `Type Text`, `Accepts free text`, `Current —`, `Keys · saved   * unsaved   › selected` |
| E5 | type `1.1.1.1` | row becomes `›* Servers (JSON)          1.1.1.1█`, popup title becomes ` Settings * ` |
| E6 | `Tab` | ` Values · 2/7 `, the focus ring moves to `Hosts (JSON)`, the help box's `Field`/`Current` follow it |
| E7 | resize `80x24` | sections list scrolls to keep the selection visible (`Mux … DNS`), the `*` row stays visible, the footer drops from the left with a leading `…` and keeps `[Esc] Back` |
| E8 | `Esc` (from a dirty form) | the app-level ` Confirm ` overlay appears above the popup with ` Discard unsaved settings? (y/N) `, and the status bar switches to `[y] Confirm  [n/Esc] Cancel` |
| E9 | `get_cell_style` inside the popup, a section row and the help overlay | every one reports `bg=default` — the app background, no modal fill (D13/A11); text colours are the theme's (`f8f8f2` selected, `7c7f8f` group headers) |
| E10 | open Settings at `54x24` (the popup's minimum width) with Core Settings selected | all four bands and the footer render; `┌ Sections ────┐` drops the counter instead of clipping `2/20`; every label keeps a separating space at the 15-column value column (`Sing-Box Path —`, `Skip Cert Verify ✗`); the footer drops from the left and keeps `[Esc] Close` |
| E11 | `Tab` in Sections, then `Tab` again | focus moves to the Values pane and back; the popup stays open, and the Sections border changes muted → accent (`6272a4` → `bd93f9`) |
| E12 | `,` on a fresh launch | the Values pane is **already** `Values · 1/5` (Core Settings' fields) — there is no empty state (R1) |
| E13 | one `down` | counter `2/20` → `3/20` (exactly one row) AND the pane becomes Protocol Core's `Values · 1/22` — the section loads on move (R1/A13) |
| E14 | `←` then `→` then `→` | `←` collapses Core (`Sections · 1/18`, `› ▸ Core` carries the highlight); the first `→` expands it (`2/20`, `▾ Core`); the second `→` moves focus to Values (footer becomes the field hint set) (R4/A15) |
| E15 | `→`, `down`, `Space` in Protocol Core | VMess advances `Auto` → the next option, marker flips to `*`; one `←` on a selector wraps past its last option back to the first (R2) |
| E16 | `/gui` | sections narrow to the GUI group and the Values pane becomes GUI Settings' three fields — the filter does **not** filter fields (A16) |
| E17 | `→`, `down`, `Space`, `Ctrl+S` on GUI Settings | Theme reads the slug the app is **currently** running (`< dracula >` on a stock fixture, `< catppuccin-mocha >` after the E17 save persisted one), advances to the next slug, and `Ctrl+S` saves: the marker returns to `·` and the group-header colour changes with the new theme (`7c7f8f` → `cba6f7` for catppuccin-mocha). Persistence is checked by relaunching: the next launch reads the new slug (R2/R3/A14) |
| E18 | `/sub` | the Subscriptions row reads `      Default … never …` — one gutter, `never` in full, and the pane's right border intact (R5) |

## Observed

All eighteen rows (E1-E18) were captured from **one** build — `target/debug/leas`, md5 in the
header — in a single session, after the last source change; the transcript holds every frame
and no frame is carried over from an earlier binary. Deviations found while running, each
fixed in the same slice and re-captured:

1. The filter-miss case needed a status line; `settings_status` now reports
   `No settings match "<query>" — [Ctrl+U] clear  [Esc] cancel`.
2. At 80x14 the verbatim popup height (`clamp(area-2, 20, 40)`) exceeded the screen and
   clipped the frame's own border; the rect is now clamped to the live area and the help
   band yields its rows first, so the two lists keep their viewport.
3. At the 50-column minimum the pane title was clipped mid-counter (`┌ Sections · 2/┐`);
   the counter is now dropped below 18 columns instead of being cut.
4. `Tab` in the Sections pane silently closed the popup — nothing on screen said so. It now
   moves focus to the Values pane, and `Tab` from an empty Values pane comes back, which is
   what the `[Tab] Sections` hint promises.
5. **The popup's background was the reported defect.** It filled with `bg.surface`, which is
   not an opaline token, so `Theme::color` substituted `OpalineColor::FALLBACK` — neutral grey
   `#808080` — over the entire modal. Removed: modals now share the app background, as the
   reference does (D13). A token audit across the workspace found no other unknown token.

## Harness notes

- Single-key calls are exact (`down` moves exactly one row). Sending a **list** of keys in
  one call over-delivers — `send_special_keys([down]*6)` moved eight rows — so the script
  below sends one key per call. `Esc` must go through `send_special_keys(["escape"])`:
  the raw `\u001b` byte is swallowed and the keypress silently becomes the next `Enter`.
- The scenario asserts outcomes, not presence: the filter's row-count delta (E2), `*` vs `·`
  across an edit and a save (E5/E17), `—` on empty fields and `✗` on false booleans (E4),
  the discard confirmation (E8), and the section-loads-on-move coupling (E13).

## Scenario script

```python
# one key per call: a list of keys over-delivers (see Harness notes)
launch("env TERM=xterm-256color LC_ALL=C XDG_CONFIG_HOME=/home/user/.cache/leas-tui/settings-parity/config target/debug/leas",
       mode="buffer", dimensions="120x40", timeout=60)
send(",")
expect("Values · 1/5")          # E12: the pane is never empty
expect("Sections · 2/20")
line(2)                          # Search bar
line(5)                          # Sections · 2/20 / Values · 1/5
line(38)                         # footer hints in the modal border
send("/dns")
expect("Sections · 2/2")         # E2: filter narrows sections
send_special("escape")
expect("Press / to filter settings")   # E3: cancel clears the query
for _ in range(12):
    send_special("down")                # E13: one row per press, pane follows
expect("Values · 7/7")                  # DNS has 7 fields -> selection reached it
send_special("enter")
expect("Values · 1/7")
send("1.1.1.1")
expect("Settings *")             # E5: unsaved edit marks the popup
send_special("tab")
expect("Values · 2/7")           # E6: help follows the cursor
resize("80x24")
expect("Sections · 12/20")       # E7: list scrolls, footer drops from the left
send_special("escape")
expect("Discard unsaved settings?")     # E8
# R1-R5 rows
send_special("left")
expect("Sections · 1/18")        # E14: collapsed group carries the highlight
send_special("right"); expect("Sections · 2/20")
send_special("right"); expect("Space] Advance")   # focus moved to the fields
send_special("down"); send(" ")
expect("*")                      # E15: selector advanced, marked unsaved
send("/gui")
expect("Values · 1/3")           # E16: filter does not filter fields
```
