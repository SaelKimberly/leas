#!/usr/bin/env python3
"""Re-render the light-theme screenshots on a light canvas.

Why this exists: leas paints no background of its own (every cell is `bg=default`), so a
`screenshot` canvas IS the terminal's background. The harness defaults (`MCP_TUI_TEST_BG`/
`MCP_TUI_TEST_FG`) are dark, so a light-theme frame rendered without these exports shows a light
theme on a dark canvas — the light-theme contrast bug in the status bar cannot be seen on it, and a
walkthrough can pass while shipping an unreadable hint row.

Catppuccin Latte's own base/text (`#eff1f5` / `#4c4f69`, the constants from ratatui-themes 0.3.0)
reproduce a light terminal. Both variables are read per render (`_render.default_colors()`), so
exporting them in the shell that launches the runner is equivalent to setting them here.

Used by `2026-10-14-144700-scenario-colour-focus-audit.md`; the pair it writes is cited by that
scenario's P3 and by the colour review's finding 1.

    MCP_TUI_TEST_BG=eff1f5 MCP_TUI_TEST_FG=4c4f69 \
      uv run --project /home/user/oss/mcp-tui-test python ~/.cache/leas-tui/lightcanvas.py
"""

import asyncio
import os

import os as _os

# Fixture and artifact paths, relative to the repository root.
CONFIG = "/home/user/.cache/leas-tui/colour-light/config"
BINARY = "/home/user/oss/xray-tui/target/debug/leas"
ARTIFACTS = "/home/user/oss/xray-tui/docs/guides/tui/artifacts"

# Catppuccin Latte: base + text.
CANVAS_BG = "eff1f5"
CANVAS_FG = "4c4f69"

os.environ.setdefault("MCP_TUI_TEST_BG", CANVAS_BG)
os.environ.setdefault("MCP_TUI_TEST_FG", CANVAS_FG)

from mcp_tui_test._server import mcp  # noqa: E402

CMD = f"env -u NO_COLOR TERM=xterm-256color LC_ALL=C XDG_CONFIG_HOME={CONFIG} {BINARY}"


async def main():
    await mcp.call_tool("launch_tui", {"command": CMD, "session_id": "light", "mode": "buffer",
                                       "dimensions": "120x40", "timeout": 40})
    await mcp.call_tool("expect_text", {"pattern": "rows 1-7 of 7", "session_id": "light", "timeout": 20})
    r = await mcp.call_tool("screenshot", {"session_id": "light",
                                           "path": f"{ARTIFACTS}/colour-light-canvas-profiles.png"})
    print(r.content[0].text)
    await mcp.call_tool("send_keys", {"keys": "d", "session_id": "light", "delay": 0.6})
    await mcp.call_tool("expect_text", {"pattern": "Confirm", "session_id": "light", "timeout": 5})
    r = await mcp.call_tool("screenshot", {"session_id": "light",
                                           "path": f"{ARTIFACTS}/colour-light-canvas-confirm.png"})
    print(r.content[0].text)
    await mcp.call_tool("close_session", {"session_id": "light"})


asyncio.run(main())
