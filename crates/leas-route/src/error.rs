//! Routing engine error types.

use thiserror::Error;

/// Errors produced while parsing or evaluating routing rules.
#[derive(Debug, Error)]
pub enum RouteError {
    /// A rule failed to parse at the given index and field.
    #[error("rule {rule_index}: invalid {field}: {message}")]
    Parse {
        rule_index: usize,
        field: &'static str,
        message: String,
    },
    /// A rule uses an unsupported feature.
    #[error("unsupported routing feature: {0}")]
    Unsupported(&'static str),
    /// Domain resolution failed.
    #[error("resolve failed: {0}")]
    Resolve(String),
}
