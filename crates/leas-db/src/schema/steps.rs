//! The migration step list: the crate's FIRST real set of migration steps.
//!
//! Before this module, the cursor had exactly one behaviour per value: "the
//! schema is current" or "the file is not mine — wipe it". ADR 0012 D-C
//! decided the policy that a **supported older version applies the pending
//! steps** and only an **unknown** cursor wipes; this file is where those
//! steps live.
//!
//! # Why the statements are not idempotent
//!
//! `ensure_raw_ddl` re-runs *idempotent* `ADD COLUMN`s on every open and
//! tolerates exactly one error string ("duplicate column"). The steps here
//! include `RENAME COLUMN` and `DROP COLUMN`, which are **not** idempotent:
//! a second application fails with "no such column".
//!
//! That is safe **only because the cursor gates them**: a step is applied when
//! `cursor < step.version`, and the cursor advances **in the same transaction**
//! that applies the step. A database already at the step's version never
//! re-runs it. The steps must therefore NOT be folded into `ensure_raw_ddl` —
//! that path has no version to gate on and would re-run the RENAME on every
//! open.
//!
//! # The step kinds
//!
//! * [`StepKind::Sql`] — statements applied in place, in order. An additive or
//!   reshaping DDL/DML step: the data migrates by copy, so the table is not
//!   rebuilt.
//! * [`StepKind::Rebuild`] — reserved for an **identity re-key**, where the
//!   rows must be copied into a new table (ADR 0012 D-C: a re-key is a DATA
//!   step, not a schema bump). Unused so far; it exists so the first re-key
//!   does not have to invent the mechanism.

/// What a step does.
#[derive(Debug, Clone, Copy)]
pub enum StepKind {
    /// Statements applied in place, in order, inside the step's transaction.
    ///
    /// The statements are NOT idempotent — the cursor gates them.
    Sql(&'static [&'static str]),
    /// A table rebuild: the rows are copied into a new table and swapped in.
    /// Reserved for an identity re-key (ADR 0012 D-C).
    Rebuild,
}

/// One migration step: the version it produces and what it does.
#[derive(Debug, Clone, Copy)]
pub struct Step {
    /// The schema version the step produces. A cursor below it gets the step.
    pub version: i64,
    /// What the step does.
    pub kind: StepKind,
}

/// The migration steps, in version order.
///
/// Each entry's `version` is the version it produces, so the list is the
/// authority for "which versions exist" and the cursor's arm is the only
/// place that decides which of them to apply.
pub const STEPS: &[Step] = &[Step {
    version: 19,
    kind: StepKind::Sql(crate::schema::ddl::V19_LATENCY_RESHAPE),
}];

/// The steps a cursor at `cursor` must apply, in order.
///
/// `None` when the cursor is at or past the latest step (nothing to apply) or
/// when it names a version BELOW the first step — the pre-migration world
/// (versions 1..18 were unrelated schemas), which is not migratable.
#[must_use]
pub fn steps_after(cursor: i64) -> Option<&'static [Step]> {
    let first = STEPS[0].version;
    if cursor < first - 1 {
        // Below the first step's predecessor: an unknown, pre-migration
        // version. The caller reports it as incompatible.
        return None;
    }
    if cursor >= STEPS[STEPS.len() - 1].version {
        return None;
    }
    let mut i = 0;
    while i < STEPS.len() {
        if STEPS[i].version > cursor {
            break;
        }
        i += 1;
    }
    Some(&STEPS[i..])
}

/// The version a cursor at `cursor` REACHES after the pending steps are
/// applied: the last pending step's version, or `cursor` itself when no step
/// applies.
#[must_use]
pub fn version_after(cursor: i64) -> i64 {
    let mut version = cursor;
    for step in STEPS {
        if step.version > cursor {
            version = step.version;
        }
    }
    version
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_cursor_at_the_latest_has_no_steps() {
        assert!(steps_after(19).is_none());
    }

    #[test]
    fn a_cursor_below_the_first_step_gets_it() {
        let steps = steps_after(18).expect("the v19 step");
        assert_eq!(steps.len(), 1);
        assert_eq!(steps[0].version, 19);
    }

    #[test]
    fn a_pre_migration_cursor_is_not_migratable() {
        // 1..17 were unrelated pre-alpha schemas: not migratable, and the
        // cursor's arm reports them as incompatible (the wipe).
        assert!(steps_after(1).is_none());
        assert!(steps_after(17).is_none());
    }

    #[test]
    fn the_version_after_a_step_is_that_step() {
        assert_eq!(version_after(18), 19);
        assert_eq!(version_after(19), 19);
    }
}
