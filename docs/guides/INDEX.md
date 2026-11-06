# guides/

Task-oriented instructions. Architecture and reference material live in
`../architecture/` and `../reference/`.

| Entry | What it covers |
| --- | --- |
| [tui-manual.md](tui-manual.md) | Driving the interface: shell and panes, screens, status bar, one keybinding table per context, workflows, theme roles, and writing a tui-test scenario |
| [building.md](building.md) | Prerequisites (no `protoc`), the opt-in `just fast` path and its perf caveat, host state that fakes a green build, the `GLIBC_2.35` floor, the quality gate, and the CI jobs |
| [publishing.md](publishing.md) | Release order to crates.io with `cargo hakari publish`, the dependency edges behind it, and the leaf-crate offline packaging proof |
| [tui/](tui/INDEX.md) | TUI scenario documents and their transcripts: pre-registered expectations, replayable scripts, observed evidence, and the collected index |
