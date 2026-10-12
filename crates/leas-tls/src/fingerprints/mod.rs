//! Flexible TLS fingerprint selection (see
//! `docs/superpowers/specs/2026-08-24-tls-fingerprint-design.md`).

pub mod builder;
pub mod catalog;
pub mod error;
pub mod query;
pub mod resolve;

pub use builder::{FingerprintBuilder, GreasePolicy};
pub use error::FingerprintError;
pub use query::{Browser, Device, Fingerprint, Os};
pub use resolve::Resolved;
pub use resolve::available_identities;
