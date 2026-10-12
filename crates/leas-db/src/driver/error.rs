//! Classification of `turso` errors into Toasty errors.
//!
//! Vendored from `toasty-driver-turso` (local-only fork — see `mod.rs`).

use toasty_core::Error;
use turso::Error as TursoError;

/// Classifies a [`turso::Error`] into a Toasty [`Error`].
///
/// * `Busy` and `BusySnapshot` — what the engine returns when a
///   `BEGIN CONCURRENT` transaction conflicts on commit, or when a writer
///   would have blocked. Both are retryable; map to
///   [`Error::serialization_failure`]. This is the classification the
///   app's own `retry_on_busy` recognizes, so MVCC conflicts and WAL
///   lock waits retry instead of failing permanently.
/// * `Error(msg)` containing the substring `"conflict"` — the `turso`
///   crate sometimes surfaces MVCC commit conflicts on this generic
///   variant rather than as `Busy*`; treat it as retryable until upstream
///   normalizes the variant.
/// * `Readonly` — the database refused a write because the connection is
///   in read-only mode. Map to [`Error::read_only_transaction`].
/// * `IoError` — a low-level I/O fault on the storage layer. Map to
///   [`Error::connection_lost`] so the pool evicts the slot.
/// * Everything else carries an opaque message; map to
///   [`Error::driver_operation_failed`].
pub(super) fn classify_turso_error(err: TursoError) -> Error {
    match err {
        TursoError::Busy(msg) | TursoError::BusySnapshot(msg) => Error::serialization_failure(msg),
        // Case-INSENSITIVE on purpose. `turso_core` renders this class two ways —
        // `Write-write conflict` (lowercase) and `Conflict: {0}` (capital, from
        // its own `Conflict` variant) — and `turso_sdk_kit` funnels BOTH into
        // the catch-all `TursoError::Error(String)` with no dedicated arm. A
        // case-sensitive `contains` therefore missed the capital spelling, which
        // became `driver_operation_failed` → `is_busy_error` false → NEVER
        // retried, silently outside every retry budget.
        TursoError::Error(msg) if msg.to_ascii_lowercase().contains("conflict") => {
            Error::serialization_failure(msg)
        }
        TursoError::Readonly(msg) => Error::read_only_transaction(msg),
        TursoError::IoError(_, _) => Error::connection_lost(err),
        _ => Error::driver_operation_failed(err),
    }
}

#[cfg(test)]
mod tests {
    use super::classify_turso_error;
    use crate::DatabaseError;

    /// Contention MUST classify as a toasty serialization failure, because
    /// that is the only class the app's `retry_on_busy` retries. `Busy` /
    /// `BusySnapshot` are what the engine returns for an MVCC commit conflict
    /// or a WAL writer wait, and the `"conflict"` message is how the `turso`
    /// crate sometimes surfaces the same thing on the generic variant — any of
    /// them flattened to an opaque error would make a transient conflict a
    /// PERMANENT failure that re-stages the window instead of retrying it.
    #[test]
    fn contention_is_retryable_and_real_errors_are_not() {
        let retryable =
            |err| crate::is_busy_error(&DatabaseError::Toasty(classify_turso_error(err)));
        for err in [
            turso::Error::Busy("busy".to_string()),
            turso::Error::BusySnapshot("busy snapshot".to_string()),
            // Both spellings the engine actually emits, through the catch-all
            // `Error(String)` arm that `turso_sdk_kit` funnels them into.
            turso::Error::Error("write conflict".to_string()),
            turso::Error::Error("Conflict: another writer committed".to_string()),
            turso::Error::Error("Write-write conflict".to_string()),
        ] {
            assert!(retryable(err), "contention must classify as retryable");
        }
        assert!(
            !retryable(turso::Error::Error("no such table: nope".to_string())),
            "a genuine error is not retryable"
        );
    }
}
