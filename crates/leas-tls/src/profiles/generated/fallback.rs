//! Entries with no family template (the `ascending` fallback; no corpus entries yet)
//!
//! Emitter output (`gen_specs.py --emit`); do not edit by hand.
//! Regeneration is byte-deterministic (`--selftest` verifies the
//! committed files match a fresh render).

use super::GenEntry;

// No corpus entries for this family yet; the registry
// stays empty until the catalog grows one.
pub const GENERATED: &[GenEntry] = &[];
