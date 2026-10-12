# leas — Agent Guide

**leas** is a feature-rich terminal client for modern VPN and proxy protocols. Top priority: compatibility with the mainstream server backends (Xray-core, sing-box), with a first-class TUI. `v2rayN` is one reference implementation, not a parity target.

This file is auto-detected project context: commands, structure, conventions. The wiki is [`docs/INDEX.md`](docs/INDEX.md); architecture decisions are [`docs/architecture/decisions.md`](docs/architecture/decisions.md).

## Package Manager & Toolchain
- Rust 2024 workspace; `cargo` only (no JS toolchain). Pinned in `rust-toolchain.toml`.
- Lint config: root `Cargo.toml` `[workspace.lints.clippy]`, opted in per crate. Format: `rustfmt.toml`.
- Root `[workspace.dependencies]` holds only deps used by 2+ crates or architecture-driving crates; single-crate deps live in that crate's own manifest.

## Commands
| Task | Command |
|------|---------|
| Run | `cargo run` |
| Release build | `cargo build --release` |
| One test | `cargo nextest run -p <crate> <filter>` |
| Full test suite | `cargo nextest run --workspace` |
| Lint (authoritative) | `cargo clippy --workspace --all-targets --all-features -- -D warnings` |
| Format | `cargo fmt` |
| Full gate (verbose) | `just quality-gate` |
| Full gate (CI, exit-code) | `just quality-gate-ci` |
| Gate: fmt + lint + test | `just quality-gate code` |
| Gate: deps only | `just quality-gate deps` |
| Benchmarks | `just bench` (`micro` needs no core binaries) |
| SIP003 plugin oracle bins | `just plugin-bins` |

`cargo clippy -p <crate>` is a TRAP: if the crate fails to compile, clippy never lints, so a clean grep proves nothing. Use the workspace form. A per-crate green is not evidence until `cargo nextest run --workspace` prints its Summary line.

## Tool Restrictions
- NEVER use `ast_edit` — it corrupts session state. Use `edit`.
- Search contents with `search`, never shell `grep`/`rg`/`awk`.
- Display files with `read`, never `cat`/`head`/`tail`/`ls`.

## Structure
- `crates/leas` — binary: `main.rs`, `state.rs` (`AppState`), `types.rs`, `ops/` (connect, ping, events, scheduler, profiles, enrich, subscriptions, settings, updates, export, stream_import, db_monitor, clipboard, native_connect, ping_native, purge), `ui/` (profiles, settings, logs, statistics, actions_log, native_activity, add_server, export, status_bar, theme, widgets).
- Other crates and their responsibilities: [`docs/architecture/architecture.md`](docs/architecture/architecture.md).

## Key Conventions
- Tests live beside code (unit) or in `tests/` (integration); `thiserror` for error types, `anyhow` for propagation.
- `#![forbid(unsafe_code)]` in `leas-tls` and `leas-native`; crypto standard is `ring` (plus `x25519-dalek`, RustCrypto `ml-kem`). Consult `docs/reference/crypto-dependencies.md` before adding a primitive.
- All DB access is async on `Database`; the typed path is the default, raw SQL needs a recorded cause in `docs/reference/database-manual-sql.md`.
- The schema cursor is `PRAGMA user_version` (`crate::schema`): a supported older version MIGRATES, an unknown one wipes. NEVER bump `SCHEMA_VERSION` for a change; an identity re-key is a DATA step, not a schema bump.
- `leas-hakari` is generated — regenerate with `cargo hakari` after any `Cargo.lock` change; never edit it by hand.
- `zeroize` on owned key buffers, and the `zeroize` FEATURE must stay listed on every crypto dep that touches keys — re-check after any crypto dep edit.

## External References
| Need | File |
|------|------|
| Wiki hub | `docs/INDEX.md` |
| Durable design decisions | `docs/architecture/decisions.md` |
| Architecture overview | `docs/architecture/architecture.md` |
| Native core + TLS engine (purpose, verification tiers, roadmap) | `docs/reference/native-core.md` |
| TUI screens, keybindings, workflows | `docs/guides/tui-manual.md` |
| Releasing to crates.io | `docs/guides/publishing.md` |
| Ordering law | `docs/reference/ordering-law.md` |
| DB schema, indexes, invariants | `docs/reference/database.md` |
| Raw-SQL sites and rules | `docs/reference/database-manual-sql.md` |
| Crypto sites and dependency advisories | `docs/reference/crypto-dependencies.md` |
| Protocol specs | `docs/reference/protocols.md`; Clash YAML: `docs/reference/clash.md` |
| Glossary | `docs/reference/glossary.md` |
| Aegis specs / plans / ADRs index | `docs/aegis/INDEX.md` |
| Reference repos (read-only) | `thirdparty/Xray-core`, `thirdparty/sing-box`, `thirdparty/v2rayN` |
