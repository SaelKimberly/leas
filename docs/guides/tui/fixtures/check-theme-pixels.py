#!/usr/bin/env python3
"""Prove which theme each screenshot actually shows, by sampling pixels.

Why this exists: a vision reader described `colour-light-canvas-profiles.png` as "bright fuchsia/pink
against the dark terminal background" — i.e. Dracula on a dark canvas. The pixels say otherwise, and
the pixels are authoritative: the app paints no background of its own, so the canvas colour comes
from `MCP_TUI_TEST_BG` and the chrome fills come from the theme.

Measured (cell centre, 120x40 grid):

    colour-light-canvas-profiles.png  canvas #eff1f5  status #ccd0da  -> Latte on a light canvas
    colour-light-canvas-profiles.png  status #ccd0da -> latte; canvas #eff1f5 = a light canvas
    colour-light-canvas-confirm.png   status #ccd0da -> latte; canvas #eff1f5 = a light canvas
    colour-light-confirm.png          status #ccd0da -> latte; canvas #000000 = the harness default
    colour-dark-profiles.png          status #44475a -> dracula; canvas #000000 = the harness default

So both `colour-light-canvas-*` frames are genuine light-theme witnesses, and the E13 frames are the
light theme rendered on a dark canvas — which is why a reader found the hint strip legible there.

Latte: base #eff1f5, selection/surface #ccd0da, accent #1e66f5, text #4c4f69.
Dracula: base #282a36, selection #44475a, accent #bd93f9, text #f8f8f2.
"""

from PIL import Image

BASE = "/home/user/oss/xray-tui/docs/guides/tui/artifacts/"
FILES = [
    "colour-light-canvas-profiles.png",
    "colour-light-canvas-confirm.png",
    "colour-light-confirm.png",
    "colour-dark-profiles.png",
]
THEMES = {
    "latte": {"base": (0xEF, 0xF1, 0xF5), "surface": (0xCC, 0xD0, 0xDA), "accent": (0x1E, 0x66, 0xF5)},
    "dracula": {"base": (0x28, 0x2A, 0x36), "surface": (0x44, 0x47, 0x5A), "accent": (0xBD, 0x93, 0xF9)},
}


def dist(a, b):
    return sum((x - y) ** 2 for x, y in zip(a, b)) ** 0.5


def hexes(c):
    return "#%02x%02x%02x" % c


for name in FILES:
    img = Image.open(BASE + name).convert("RGB")
    w, h = img.size
    cw, ch = w / 120, h / 40

    def cell(row, col, inset=0.5):
        return img.getpixel((int((col + inset) * cw), int((row + inset) * ch)))

    canvas, status = cell(0, 118), cell(39, 110)
    # Theme identity comes from the chrome the theme paints (the status-bar fill); the canvas is
    # whatever MCP_TUI_TEST_BG set, and (0,0,0) is the harness default, not a theme colour.
    theme = min(THEMES, key=lambda k: dist(status, THEMES[k]["surface"]))
    if canvas == (0, 0, 0):
        canvas_desc = "the harness default (black)"
    else:
        canvas_theme = min(THEMES, key=lambda k: dist(canvas, THEMES[k]["base"]))
        canvas_desc = f"a light canvas ({canvas_theme} base)"
    print(f"{name}: status {hexes(status)} -> {theme}; canvas {hexes(canvas)} = {canvas_desc}")
