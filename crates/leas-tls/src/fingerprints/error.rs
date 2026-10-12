//! Fingerprint selection/build errors.

/// Strict-resolution and builder failures.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FingerprintError {
    /// No resolution-table row satisfies the query.
    #[error(
        "unknown fingerprint combination `{query}`; available: {}",
        listing(available)
    )]
    Unknown {
        /// Rendered query (`chrome@133/windows/desktop` shape).
        query: String,
        /// Resolvable identity names, sorted.
        available: Vec<String>,
    },
    /// A builder override violates a base-spec invariant.
    #[error("invalid fingerprint override: {0}")]
    InvalidOverride(String),
}
/// Alternatives shown before the total-count suffix (design: error
/// message-bloat mitigation — the roster lists ~990 identities).
const ALTERNATIVES_CAP: usize = 8;

/// Renders the alternatives list capped at [`ALTERNATIVES_CAP`] entries,
/// with a `… and N more` suffix when more exist.
fn listing(available: &[String]) -> String {
    if available.len() <= ALTERNATIVES_CAP {
        return available.join(", ");
    }
    format!(
        "{}, … and {} more",
        available[..ALTERNATIVES_CAP].join(", "),
        available.len() - ALTERNATIVES_CAP
    )
}
