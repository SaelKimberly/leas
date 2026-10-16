# Transcript: settings-xrat-parity

Raw captures from the run described in
[2026-10-16-093000-scenario-settings-xrat-parity.md](2026-10-16-093000-scenario-settings-xrat-parity.md).
Session `default`, buffer mode, 120x40 then 80x24. Fixture:
`/home/user/.cache/leas-tui/settings-parity` (7 synthetic endpoints).

## Step 1 — `,` at 120x40 (E1)

```
┌ 1: [Profiles]  Logs ─────────────────────────────────────────────────────────────────────────────────────────────────┐
│ Vie┌ Settings ──────────────────────────────────────────────────────────────────────────────────────────────────┐    │
│    │ ┌ Search ────────────────────────────────────────────────────────────────────────────────────────────────┐ │    │
│    │ │Press / to filter settings                                                                              │ │    │
│    │ └────────────────────────────────────────────────────────────────────────────────────────────────────────┘ │    │
│    │ ┌ Sections · 2/20 ────────────┐ ┌ Select a section ──────────────────────────────────────────────────────┐ │    │
│    │ │  ▾ Core                     │ │                                                                        │ │    │
│    │ │›    Core Settings           │ │                                                                        │ │    │
│    │ │     Protocol Core           │ │                                                                        │ │    │
│    │ │  ▾ Connection               │ │                                                                        │ │    │
│    │ │     Inbound                 │ │                                                                        │ │    │
│    │ │     System Proxy            │ │                                                                        │ │    │
│    │ │     TUN                     │ │                                                                        │ │    │
│    │ │     Mux                     │ │                                                                        │ │    │
│    │ │  ▾ Routing                  │ │                                                                        │ │    │
│    │ │     Routing Rules           │ │                                                                        │ │    │
│    │ │     Probe Hosts             │ │                                                                        │ │    │
│    │ │     DNS                     │ │                                                                        │ │    │
│    │ │  ▾ GUI                      │ │                                                                        │ │    │
│    │ │     GUI Settings            │ │                                                                        │ │    │
│    │ │  ▾ Advanced                 │ │                                                                        │ │    │
│    │ │     Statistics              │ │                                                                        │ │    │
│    │ │     Updates                 │ │                                                                        │ │    │
│    │ │     Speed Test              │ │                                                                        │ │    │
│    │ │     Logging                 │ │                                                                        │ │    │
│    │ │     Subscriptions           │ │                                                                        │ │    │
│    │ └─────────────────────────────┘ └────────────────────────────────────────────────────────────────────────┘ │    │
│    │ ┌ Help ──────────────────────────────────────────────────────────────────────────────────────────────────┐ │    │
│ Ser│ │Pick a section on the left, then edit its fields on the right.                                          │ │    │
│    │ └────────────────────────────────────────────────────────────────────────────────────────────────────────┘ │    │
└────└──────────────────────── [↑↓] Navigate  [←→] Collapse  [/] Filter  [Enter] Open  [Ctrl+W] Form  [Esc] Close ┘────┘
 Settings Disconnected
```

## Step 2 — `/dns` (E2), region rows 1-7

```
│ Vie┌ Settings ──────────────────────────────────────────────────────────────────────────────────────────────────┐    │
│    │ ┌ Filter ────────────────────────────────────────────────────────────────────────────────────────────────┐ │    │
│    │ │dns█                                                                                                    │ │    │
│    │ └────────────────────────────────────────────────────────────────────────────────────────────────────────┘ │    │
│    │ ┌ Sections · 2/2 ─────────────┐ ┌ Select a section ──────────────────────────────────────────────────────┐ │    │
│    │ │  ▾ Routing                  │ │                                                                        │ │    │
│    │ │›    DNS                     │ │                                                                        │ │    │
```

## Step 3 — `Esc` (E3), region rows 2-3

```
│    │ ┌ Search ────────────────────────────────────────────────────────────────────────────────────────────────┐ │    │
│    │ │Press / to filter settings                                                                              │ │    │
```

## Step 4 — `↓`x12, `Enter` (E4), region rows 1-23

```
│ Vie┌ Settings ──────────────────────────────────────────────────────────────────────────────────────────────────┐    │
│    │ ┌ Edit Servers (JSON) · Text ────────────────────────────────────────────────────────────────────────────┐ │    │
│    │ │type to change · [Backspace] erase · [Tab] next field                                                   │ │    │
│    │ └────────────────────────────────────────────────────────────────────────────────────────────────────────┘ │    │
│    │ ┌ Sections · 12/20 ───────────┐ ┌ Values · 1/7 ──────────────────────────────────────────────────────────┐ │    │
│    │ │  ▾ Core                     │ │›· Servers (JSON)          —█                                           │ │    │
│    │ │     Core Settings           │ │ · Hosts (JSON)            —                                            │ │    │
│    │ │     Protocol Core           │ │ · Query Strategy          —                                            │ │    │
│    │ │  ▾ Connection               │ │ · Disable Cache           ✗                                            │ │    │
│    │ │     Inbound                 │ │ · Disable Fallback        ✗                                            │ │    │
│    │ │     System Proxy            │ │ · Client IP               —                                            │ │    │
│    │ │     TUN                     │ │ · DNS Cache TTL (secs)    —                                            │ │    │
│    │ │     Mux                     │ │                                                                        │ │    │
│    │ │  ▾ Routing                  │ │                                                                        │ │    │
│    │ │     Routing Rules           │ │                                                                        │ │    │
│    │ │     Probe Hosts             │ │                                                                        │ │    │
│    │ │›    DNS                     │ │                                                                        │ │    │
```

(The help box, the status band and the footer were asserted in the same capture; the full
frame at this state is reproduced in step 6 below, which is the same screen one `Tab` later.)

## Step 5 — type `1.1.1.1` (E5), region rows 5-25

```
│    │ ┌ Sections · 12/20 ───────────┐ ┌ Values · 1/7 ──────────────────────────────────────────────────────────┐ │    │
│    │ │  ▾ Core                     │ │›* Servers (JSON)          1.1.1.1█                                     │ │    │
│    │ │     Core Settings           │ │ · Hosts (JSON)            —                                            │ │    │
│    │ │     Protocol Core           │ │ · Query Strategy          —                                            │ │    │
```

Popup title at this point: `│ Vie┌ Settings * ───…───┐    │`.

## Step 6 — `Tab`, then resize 80x24 (E6/E7)

```
┌ 1: [Profiles]  Logs ─────────────────────────────────────────────────────────┐
│ ┌ Settings * ──────────────────────────────────────────────────────────────┐ │
│ │ ┌ Edit Hosts (JSON) · Text ────────────────────────────────────────────┐ │ │
│ │ │type to change · [Backspace] erase · [Tab] next field                 │ │ │
│ │ └──────────────────────────────────────────────────────────────────────┘ │ │
│ │ ┌ Sections · 12/20 ─────┐ ┌ Values · 2/7 ──────────────────────────────┐ │ │
│ │ │     Mux               │ │ * Servers (JSON)          1.1.1.1          │ │ │
│ │ │  ▾ Routing            │ │›· Hosts (JSON)            —█               │ │ │
│ │ │     Routing Rules     │ │ · Query Strategy          —                │ │ │
│ │ │     Probe Hosts       │ │ · Disable Cache           ✗                │ │ │
│ │ │›    DNS               │ │ · Disable Fallback        ✗                │ │ │
│ │ └───────────────────────┘ └────────────────────────────────────────────┘ │ │
│ │ ┌ Help · DNS ──────────────────────────────────────────────────────────┐ │ │
│ │ │Field    Hosts (JSON)                                                 │ │ │
│ │ │Type     Text                                                         │ │ │
│ │ │Accepts  free text                                                    │ │ │
│ │ │Current  —                                                            │ │ │
│ │ │Keys     · saved   * unsaved   › selected                             │ │ │
│ │ └──────────────────────────────────────────────────────────────────────┘ │ │
└─└───────────────────────────… [←→] Cycle [Enter] Save [/] Filter [Esc] Back┘─┘
 Settings > DNS Disconnected
```

## Step 7 — `Esc` from the dirty form (E8)

```
│    │ │                             │ │  ╭ Confirm ──────────────────────────╮                                 │ │  █ │
│    │ │                             │ │  │  Discard unsaved settings? (y/N)  │                                 │ │  █ │
│    │ │                             │ │  ╰───────────────────────────────────╯                                 │ │  █ │
 Settings > DNS Disconnected                                                                [y] Confirm  [n/Esc] Cancel
```

## Step 8 — modal surface (E9), `get_cell_style` after the D13 fix

```
Style at (6, 20):  char=' ' fg=default bg=default     # inside the popup
Style at (8, 41):  char=' ' fg=default bg=default     # a section row
Style at (8, 8):   char=' ' fg=f8f8f2 bg=default     # selected row text
Style at (9, 12):  char='C' fg=7c7f8f bg=default     # group header text
```

The popup, the app canvas and the help overlay all report `bg=default` — one background,
borders only. Before the fix the popup reported `bg=808080` (opaline's
`OpalineColor::FALLBACK`, the grey that `bg.surface` resolved to), and the help overlay
reported `bg=44475a` (`bg.elevated`). Both fills are gone.

## Step 9 — popup minimum width (E10), 54x24

```
│ ┌ Settings ──────────────────────────────────────┐ │
│ │ ┌ Search ────────────────────────────────────┐ │ │
│ │ │Press / to filter settings                  │ │ │
│ │ └────────────────────────────────────────────┘ │ │
│ │ ┌ Sections ────┐ ┌ Select a section ─────────┐ │ │
│ │ │  ▾ Core      │ │                           │ │ │
│ │ │›    Core Sett│ │                           │ │ │
│ │ │     Protocol │ │                           │ │ │
│ │ └──────────────┘ └───────────────────────────┘ │ │
└─└─────────… [Enter] Open [Tab] Fields [Esc] Close┘─┘
```

No clipped counter, footer keeps its tail, popup fits the live area.

## Step 10 — `Tab` focus round-trip (E11)

```
Style at (5, 4): fg=6272a4   # Sections border while the Values pane has focus (muted)
Style at (5, 5): fg=bd93f9   # Sections border after Tab brings focus back (accent)
```

## Not covered by this transcript

- The save notice band (`Saved Core`) and the filter-miss line
  (`No settings match "zzzz" — [Ctrl+U] clear  [Esc] cancel`) were captured during
  development and are covered by the unit tests plus the two behaviours above.
