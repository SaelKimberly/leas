# architecture/

How the system is put together.

| File | Contents |
| --- | --- |
| `architecture.md` | Crate dependency graph, crate responsibilities, `AppState`/`CoreEvent`, TUI screens, batch-ping flow |
| `decisions.md` | Durable design decisions (identity, schema policy, ordering, native core, transports, secrets) |
| `native-core-integration.md` | Design brief for the in-process native backend — **superseded in part** by ADR 0004 and the shipped `ops/connect.rs` selection |
