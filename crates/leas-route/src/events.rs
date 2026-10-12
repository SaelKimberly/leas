//! Routing engine event stream.
//!
//! Emitted during configuration compilation and connection decisions.

use std::sync::Arc;

/// Events emitted by the routing engine during configuration compilation and
/// connection decisions.
///
/// String fields are `Arc<str>`: events are cloned/moved through channels
/// and into UI state, so the engine pays one allocation per distinct string
/// and every hand-off is a refcount bump.
#[derive(Debug, Clone)]
pub enum RouteEvent {
    /// A terminal routing decision was reached for a connection.
    DecisionApplied {
        /// Name of the matched rule; `None` when the default fell through.
        rule_name: Option<Arc<str>>,
        /// Target outbound tag for routed decisions, `None` otherwise.
        tag: Option<Arc<str>>,
        /// Sniffed TLS SNI host (`None` until Task 12 wires sniffing).
        sni: Option<Arc<str>>,
        /// Wall-clock time of the decision.
        at: jiff::Timestamp,
    },
    /// Non-fatal issue found while compiling the rule set.
    CompileWarning {
        /// Index into [`crate::ir::RuleSet::rules`].
        rule_index: usize,
        /// Human-readable description of the issue.
        message: String,
    },
    /// A DNS resolution completed for a host.
    Resolved {
        /// The hostname that was resolved.
        host: Arc<str>,
        /// All resolved addresses.
        ips: Vec<std::net::IpAddr>,
        /// Wall-clock time of the resolution.
        at: jiff::Timestamp,
    },
    /// A probe target stopped answering (first failure of a streak).
    NetworkBreakdown {
        /// The probe that failed.
        failed_probe: Arc<str>,
        /// Wall-clock time of the failure.
        at: jiff::Timestamp,
    },
    /// A previously failed probe answered again (streak reset).
    ProbeRecovered {
        /// The probe that recovered.
        probe: Arc<str>,
        /// Wall-clock time of the recovery.
        at: jiff::Timestamp,
    },
}
