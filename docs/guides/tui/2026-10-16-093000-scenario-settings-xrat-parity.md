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
| App under test | leas 0.1.0, debug binary `target/debug/leas` (md5 `09ec04ef927c94d6c32e8adc420d1bd1` before the final hint-text edit; re-verified live after it) |
| Launch command | `env TERM=xterm-256color LC_ALL=C XDG_CONFIG_HOME=/home/user/.cache/leas-tui/settings-parity/config target/debug/leas` |
| Session / mode / size | `default` / buffer / 120x40, then resized to 80x24 |
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
| E10 | launch at `54x24` (the popup's minimum width) | all four bands and the footer still render; pane titles drop the counter (`┌ Sections ────┐`, not a clipped `Sections · 2/`); the footer drops from the left with `…` and keeps `[Esc] Close` |
| E11 | `Tab` in Sections, then `Tab` again | focus moves to the Values pane and back; the popup stays open, and the Sections border changes muted → accent (`6272a4` → `bd93f9`) |

## Observed

All eleven expectations held (E9-E11 were added after the run once the surface report
arrived, and re-run against the same fixture). Deviations found while running and fixed in
the same slice:

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

## Scenario script

```python
launch("env TERM=xterm-256color LC_ALL=C XDG_CONFIG_HOME=/home/user/.cache/leas-tui/settings-parity/config target/debug/leas",
       mode="buffer", dimensions="120x40", timeout=60)
send(",")
expect("Sections · 2/20")
line(2)   # Search bar
line(5)   # Sections · 2/20 / Select a section
line(39)  # footer hints in the border
send("/dns")
expect("Sections · 2/2")
send_special("escape")
expect("Press / to filter settings")
send_special("down", times=12)
send_special("enter")
expect("Values · 1/7")
send("1.1.1.1")
expect("Settings *")
send_special("tab")
expect("Values · 2/7")
resize("80x24")
expect("Sections · 12/20")
send_special("escape")
expect("Discard unsaved settings?")
```
