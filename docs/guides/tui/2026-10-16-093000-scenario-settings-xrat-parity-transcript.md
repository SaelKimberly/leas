# Transcript: settings-xrat-parity

Raw captures for
[2026-10-16-093000-scenario-settings-xrat-parity.md](2026-10-16-093000-scenario-settings-xrat-parity.md).

**Binary: `target/debug/leas` md5 `fe4f62aa9f584fa6a8b5a2f89851cbe5`.** Every frame below was captured
from that build, in sessions started after the last source change; no frame is carried over from
an earlier binary.

Fixture: `/home/user/.cache/leas-tui/settings-parity` (7 synthetic endpoints). Session
`default`, buffer mode, 120x40 unless a heading says otherwise. One key per call (see
Harness notes).

## E5 / E8 — an unsaved edit, then the discard confirmation (120x40)

```
│ ┌ Sections · 2/20 ────────────┐ ┌ Values · 1/5 ──────────────────────────────────────────────────────────┐ │
│ │  ▾ Core                     │ │›* Xray Path               1.1.1.1█                                     │ │
│ │›    Core Settings           │ │ · Sing-Box Path           —                                            │ │
│ │     Protocol Core           │ │ · Log Level               < warning >                                  │ │
│ │  ▾ Connection               │ │ · Skip Cert Verify        ✗                                            │ │
│ │     Inbound                 │ │ · Clash Mixin (JSON/YAML) —                                            │ │
│ │  ▾ GUI                      │ │  ╭ Confirm ──────────────────────────╮                                 │ │
│ │     GUI Settings            │ │  │  Discard unsaved settings? (y/N)  │                                 │ │
```

`Esc` on a dirty form asks before discarding; the status bar switches to `[y] Confirm  [n/Esc] Cancel`.

## E7 — the same state at 80x24 (live resize)

```
┌ 1: [Profiles]  Logs ─────────────────────────────────────────────────────────┐
│ ┌ Settings * ──────────────────────────────────────────────────────────────┐ │
│ │ ┌ Edit Xray Path · Text ───────────────────────────────────────────────┐ │ │
│ │ │type to change · [Backspace] erase · [Tab] next field                 │ │ │
│ │ └──────────────────────────────────────────────────────────────────────┘ │ │
│ │ ┌ Sections · 2/20 ──────┐ ┌ Values · 1/5 ──────────────────────────────┐ │ │
│ │ │  ▾ Core               │ │›* Xray Path               1.1.1.1█         │ │ │
│ │ │›    Core Settings     │ │ · Sing-Box Path           —                │ │ │
│ │ │     Protocol Core     │ │ · Log Level               < warning >      │ │ │
│ │ │  ▾ Connection         │ │ · Skip Cert Verify        ✗                │ │ │
│ │ │     Inbound     ╭ Confirm ──────────────────────────╮                │ │ │
│ │ └─────────────────│  Discard unsaved settings? (y/N)  │────────────────┘ │ │
│ │ ┌ Help · Core ────│                                   │────────────────┐ │ │
│ │ │Field    Xray Pat│                                   │                │ │ │
└─│ │Type     Text    ╰───────────────────────────────────╯                │ │─┘
┌ │ │Accepts  free text                                                    │ │─┐
│ │ │Current  1.1.1.1                                                      │ │ │
│ │ │Keys     · saved   * unsaved   › selected                             │ │ │
│ └──────────────────────────────────────────────────────────────────────┘ │ │
└─└──────────────… [Space] Advance [Ctrl+S] Save [Ctrl+W] Sections [Esc] Back┘─┘
 Settings > Core Disconnected                       [y] Confirm  [n/Esc] Cancel
```

The popup stays framed, the sections list scrolls to keep the selection visible, the `*` row
stays visible, and the footer drops from the left (`…`) while keeping `[Esc] Back`.

## E1 / E12 — `,` on a fresh launch: the Values pane is never empty

```
┌ Settings ──────────────────────────────────────────────────────────────────────────────────────────────────┐
│ ┌ Search ────────────────────────────────────────────────────────────────────────────────────────────────┐ │
│ │Press / to filter settings                                                                              │ │
│ └────────────────────────────────────────────────────────────────────────────────────────────────────────┘ │
│ ┌ Sections · 2/20 ────────────┐ ┌ Values · 1/5 ──────────────────────────────────────────────────────────┐ │
│ │  ▾ Core                     │ │›· Xray Path               —█                                           │ │
│ │›    Core Settings           │ │ · Sing-Box Path           —                                            │ │
│ │     Protocol Core           │ │ · Log Level               < warning >                                  │ │
│ │  ▾ Connection               │ │ · Skip Cert Verify        ✗                                            │ │
│ │     Inbound                 │ │ · Clash Mixin (JSON/YAML) —                                            │ │
│ │     System Proxy            │ │                                                                        │ │
│ │     TUN                     │ │                                                                        │ │
│ │     Mux                     │ │                                                                        │ │
│ │  ▾ Routing                  │ │                                                                        │ │
│ │     Routing Rules           │ │                                                                        │ │
│ │     Probe Hosts             │ │                                                                        │ │
│ │     DNS                     │ │                                                                        │ │
│ │  ▾ GUI                      │ │                                                                        │ │
│ │     GUI Settings            │ │                                                                        │ │
│ │  ▾ Advanced                 │ │                                                                        │ │
│ │     Statistics              │ │                                                                        │ │
│ │     Updates                 │ │                                                                        │ │
│ │     Speed Test              │ │                                                                        │ │
│ │     Logging                 │ │                                                                        │ │
│ │     Subscriptions           │ │                                                                        │ │
│ ┌ Help · Core ───────────────────────────────────────────────────────────────────────────────────────────┐ │
│ │Field    Xray Path                                                                                      │ │
│ │Type     Text                                                                                           │ │
│ │Accepts  free text                                                                                      │ │
│ │Current  —                                                                                              │ │
│ │Keys     · saved   * unsaved   › selected                                                               │ │
└──────────────────────────── [↑↓] Navigate  [←] Collapse  [→] Fields  [/] Filter  [Enter] Open  [Esc] Close ┘
 Settings > Core Disconnected
```

`Values · 1/5` on open — no empty state (R1). `—` on empty fields, `✗` on a false boolean,
`< warning >` on a selector, `·` = saved.

## E13 — one `down`: exactly one row, and the pane follows

```
│ ┌ Sections · 3/20 ────────────┐ ┌ Values · 1/22 ─────────────────────────────────────────────────────────┐ │
│ │  ▾ Core                     │ │›· VMess                   < Auto >█                                    │ │
│ │     Core Settings           │ │ · VLESS                   < Auto >                                     │ │
│ │›    Protocol Core           │ │ · Shadowsocks             < Auto >                                     │ │
```

## E14 — `←` collapses (the header carries the highlight), `→` expands, `→` then moves focus

```
│ ┌ Sections · 1/18 ────────────┐ ┌ Values · 1/22 ─────────────────────────────────────────────────────────┐ │
│ │› ▸ Core                     │ │›· VMess                   < Auto >█                                    │ │
│ │  ▾ Connection               │ │ · VLESS                   < Auto >                                     │ │
```

After the two `→` presses the footer is the field set:

```
└────└────────────────────── [Tab/Shift+Tab] Field  [Space] Advance  [Ctrl+S] Save  [Ctrl+W] Sections  [Esc] Back ┘────┘
```

## E15 — a selector advances, steps back, and wraps

```
Space   : ›* VMess   < Auto >█     →  ›* VMess   < SingBox >█
←       :                            →  ›* VMess   < Xray >█
←       :                            →  ›* VMess   < Auto >█
←       :                            →  ›* VMess   < SingBox >█      (wrap past the first option)
```

## E16 / E17 — `/gui` narrows sections only; the theme selector saves and repaints

```
│ ┌ Sections · 2/2 ─────────────┐ ┌ Values · 1/3 ──────────────────────────────────────────────────────────┐ │
│ │  ▾ GUI                      │ │›· Language                < en >█                                      │ │
│ │›    GUI Settings            │ │ · Theme                   < catppuccin-mocha >                         │ │
│ │                             │ │ · Refresh Interval        5s                                           │ │
```

All three fields are listed while the filter is live (`Values · 1/3`): the filter narrows the
section list only. Theme is a selector bound to `config.theme_name`; `Space` + `Ctrl+S` wrote
the new slug, reloaded the theme and persisted it — this run's first launch started on
`dracula`, and the next one starts on `catppuccin-mocha`.

## E9 — modal surface: one background everywhere

```
get_cell_style inside the popup (6,20)   : fg=default bg=default
get_cell_style a section row (8,8)        : fg=f8f8f2  bg=default   (selected row)
get_cell_style a group header (9,12)      : fg=7c7f8f  bg=default
get_cell_style inside the help overlay   : fg=7c7f8f  bg=default
```

Before the D13 fix the popup reported `bg=808080` (opaline's `OpalineColor::FALLBACK`, the
grey that the non-existent `bg.surface` token resolved to) and the dialogs `bg=44475a`
(`bg.elevated`). Both fills are gone.

## E10 — popup minimum width, 54x24 (Core Settings open, no filter)

```
┌ 1: [Profiles]  Logs ───────────────────────────────┐
│ ┌ Settings ──────────────────────────────────────┐ │
│ │ ┌ Search ────────────────────────────────────┐ │ │
│ │ │Press / to filter settings                  │ │ │
│ │ └────────────────────────────────────────────┘ │ │
│ │ ┌ Sections ────┐ ┌ Values · 1/5 ─────────────┐ │ │
│ │ │  ▾ Core      │ │›· Xray Path    —█         │ │ │
│ │ │›    Core Sett│ │ · Sing-Box Path —         │ │ │
│ │ │     Protocol │ │ · Log Level    < warning >│ │ │
│ │ │  ▾ Connection│ │ · Skip Cert Verify ✗      │ │ │
│ │ │     Inbound  │ │ · Clash Mixin (JSON/YAML) │ │ │
│ │ └──────────────┘ └───────────────────────────┘ │ │
│ │ ┌ Help · Core ───────────────────────────────┐ │ │
│ │ │Field    Xray Path                          │ │ │
│ │ │Type     Text                               │ │ │
│ │ │Accepts  free text                          │ │ │
│ │ └────────────────────────────────────────────┘ │ │
└───────────… [/] Filter [Enter] Open [Esc] Close┘─┘
 Settings > Core Disconnected
```

Three things this row asserts, all visible above:

- `Sections` **drops its counter** rather than clipping `2/20` into `2/` at 16 columns.
- Every label keeps a separating space at the 15-column value column: `Sing-Box Path —`,
  `Skip Cert Verify ✗`, and the 22-character `Clash Mixin (JSON/YAML)` gets its space and its
  value is simply cut by the pane edge — a truncation, not the `Sing-Box Path—` collision the
  pre-fix build rendered.
- The footer drops from the left (`… [/] Filter [Enter] Open [Esc] Close`) and keeps
  `[Esc] Close`.

## Harness notes

- One key per call. `send_special_keys(["down"] * 6)` moved **eight** rows; a single call moves
  exactly one (E13).
- `Esc` must use `send_special_keys(["escape"])`: a raw `\u001b` is swallowed and the press
  turns into the following `Enter`, which reads as a filter that "did not cancel".
