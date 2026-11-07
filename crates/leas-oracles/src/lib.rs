//! E2E oracles for `leas`: pinned real cores, config pairs, and process launch.
//!
//! This crate is a dev-only workspace member: it is excluded from
//! `default-members`, so ordinary `cargo build` / `test` / `nextest` / `run`
//! never build it. An explicit `-p leas-oracles` builds it and runs `build.rs`,
//! which fetches the pinned Xray-core and sing-box releases into
//! `OUT_DIR/core-bin` (SHA-256 verified). Set `LEAS_CORE_BIN_DIR` to use
//! already-installed binaries instead, or `LEAS_ORACLES_SKIP_DOWNLOAD=1` to
//! compile-check without network.
//!
//! `e2e` drives the native client against real server cores; `pins` is the
//! single source of truth for the versions, asset names and checksums.

#![forbid(unsafe_code)]

pub mod e2e;
pub mod oracle_adapters;
pub mod pins;
