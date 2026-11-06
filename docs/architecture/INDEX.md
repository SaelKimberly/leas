# architecture/

How the system is put together: the crate graph, the process boundaries, the shared state and the flows that cross them. `decisions.md` records the choices; this page explains the shape they produce.

| File | Contents |
| --- | --- |
| `architecture.md` | Crate dependency graph, crate responsibilities, runtime boundaries, `AppState`/`CoreEvent`, TUI screen map, batch-ping flow, connect path |
| `decisions.md` | Durable design decisions, one line each, with a link to the page that owns the detail |
| `native-core-integration.md` | Design brief for the in-process native backend: why it exists, its seams, risks and work items; partly superseded by ADR 0004 and the shipped `ops/connect.rs` |
