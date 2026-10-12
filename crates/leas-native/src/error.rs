use std::time::Duration;

use leas_proto::proto_spec::ProtocolKind;

/// Errors from the native proxy core.
///
/// Every network step (dial, transport upgrade, security handshake, protocol
/// handshake, tunnel I/O) is wrapped in `tokio::time::timeout`; a deadline
/// expiry surfaces as [`NativeError::Timeout`].
#[derive(Debug, thiserror::Error)]
pub enum NativeError {
    #[error("invalid or unsupported config: {0}")]
    Config(String),
    #[error("server dial failed: {0}")]
    Dial(String),
    #[error("TLS error: {0}")]
    Tls(String),
    #[error("REALITY error: {0}")]
    Reality(String),
    /// The peer's certificate does not cover the configured server name.
    #[error("TLS error: {0}")]
    CertNotValidForName(String),
    /// The peer's certificate is expired (or not yet valid).
    #[error("TLS error: {0}")]
    CertExpired(String),
    /// The peer answered in cleartext instead of a TLS record.
    #[error("TLS error: {0}")]
    CleartextPeer(String),
    #[error("transport error: {0}")]
    Transport(String),
    /// The peer answered our own transport handshake with an HTTP status.
    /// `detail` is the message the [`Self::Transport`] arm carries.
    #[error("transport error: {detail}")]
    TransportRejected { detail: String, status: u16 },
    #[error("protocol {kind} error: {detail}")]
    Protocol { kind: ProtocolKind, detail: String },
    /// The stream UNDER a later phase ended before it answered.
    ///
    /// Distinct from [`Self::Tls`] because the class must name the stage that
    /// failed: when the target leg's TLS handshake reads an EOF from the tunnel
    /// beneath it, the tunnel ended — the proxy never delivered a protocol
    /// response. The engine's record layer reports that as `TlsError::Io`
    /// (`read_exact` over the tunnel), so without this variant the failure
    /// surfaces as `Tls` and a protocol-stage EOF is counted as a TLS problem
    /// (measured: 151 rows of the 2026-09-21 run).
    ///
    /// Proves nothing about the endpoint — `evidence()` is `None`, exactly as
    /// for [`Self::Tls`] — so this changes the reported CLASS, never a verdict.
    #[error("tunnel closed: {detail}")]
    TunnelClosed { detail: String },
    #[error("not implemented: {feature}")]
    NotImplemented { feature: String },
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("timeout on {step} (limit {limit:?})")]
    Timeout { step: &'static str, limit: Duration },
}

/// What a failure PROVES about the endpoint, when it points at a permanent
/// defect instead of a transient one (spec
/// `2026-09-17-purge-reason-design.md` §6).
///
/// Produced from the typed error where the failure happened — never parsed out
/// of a message, exactly as the probe classes are not. The TUI's purge policy
/// is the only consumer; this crate decides nothing about it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureEvidence {
    /// A REALITY handshake was answered by a real certificate.
    RealityFallback,
    /// The peer's certificate does not cover the configured server name.
    CertNotValidForName,
    /// The peer's certificate is expired.
    CertExpired,
    /// The peer answered in cleartext.
    CleartextPeer,
    /// The config as stored cannot dial.
    ConfigDefect,
    /// The peer's own answer to our handshake, when it is an HTTP status.
    HttpRejected(u16),
}

impl NativeError {
    /// What this failure proves, when it proves anything permanent. `None` is
    /// the default and the honest answer for a timeout, a dial failure, an I/O
    /// error, a framing error, or a client-side capability gap.
    #[must_use]
    pub const fn evidence(&self) -> Option<FailureEvidence> {
        match self {
            Self::Config(_) => Some(FailureEvidence::ConfigDefect),
            Self::Reality(_) => Some(FailureEvidence::RealityFallback),
            Self::CertNotValidForName(_) => Some(FailureEvidence::CertNotValidForName),
            Self::CertExpired(_) => Some(FailureEvidence::CertExpired),
            Self::CleartextPeer(_) => Some(FailureEvidence::CleartextPeer),
            Self::TransportRejected { status, .. } => Some(FailureEvidence::HttpRejected(*status)),
            Self::Dial(_)
            | Self::Tls(_)
            | Self::Transport(_)
            | Self::Protocol { .. }
            | Self::TunnelClosed { .. }
            | Self::NotImplemented { .. }
            | Self::Io(_)
            | Self::Timeout { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{FailureEvidence, NativeError};
    use std::time::Duration;

    /// Every variant's verdict, so a new arm cannot land without deciding
    /// whether it proves anything (spec §6). `None` is the honest answer for
    /// anything transient, local, or client-side.
    #[test]
    fn evidence_is_the_single_owner_of_what_a_failure_proves() {
        let cases: Vec<(NativeError, Option<FailureEvidence>)> = vec![
            (
                NativeError::Config("bad".into()),
                Some(FailureEvidence::ConfigDefect),
            ),
            (
                NativeError::Reality("real certificate".into()),
                Some(FailureEvidence::RealityFallback),
            ),
            (
                NativeError::CertNotValidForName("mismatch".into()),
                Some(FailureEvidence::CertNotValidForName),
            ),
            (
                NativeError::CertExpired("expired".into()),
                Some(FailureEvidence::CertExpired),
            ),
            (
                NativeError::CleartextPeer("\"HTTP/\"".into()),
                Some(FailureEvidence::CleartextPeer),
            ),
            (
                NativeError::TransportRejected {
                    detail: "ws handshake: HTTP error: 403 Forbidden".into(),
                    status: 403,
                },
                Some(FailureEvidence::HttpRejected(403)),
            ),
            (NativeError::Dial("refused".into()), None),
            (NativeError::Tls("alert 2 40".into()), None),
            (
                // The class changes, the verdict does not: a tunnel that ended
                // during a later phase proves nothing about the endpoint.
                NativeError::TunnelClosed {
                    detail: "the tunnel ended during the target handshake".into(),
                },
                None,
            ),
            (NativeError::Transport("ws framing".into()), None),
            (
                NativeError::NotImplemented {
                    feature: "vless encryption".into(),
                },
                None,
            ),
            (NativeError::Io(std::io::Error::other("reset")), None),
            (
                NativeError::Timeout {
                    step: "dial",
                    limit: Duration::from_secs(1),
                },
                None,
            ),
        ];
        for (err, expected) in cases {
            assert_eq!(err.evidence(), expected, "for {err}");
        }
    }

    /// The typed variants keep the message their plain-`Tls`/`Transport` twins
    /// produced, so no log or DB row changes shape.
    #[test]
    fn typed_variants_render_their_original_text() {
        assert_eq!(
            NativeError::CertNotValidForName("bad name".into()).to_string(),
            "TLS error: bad name"
        );
        assert_eq!(
            NativeError::TransportRejected {
                detail: "v2rayhttp: expected 200, got 404 Not Found".into(),
                status: 404,
            }
            .to_string(),
            "transport error: v2rayhttp: expected 200, got 404 Not Found"
        );
    }
}

/// Named deadline limits, applied around every network step.
pub mod timeouts {
    use std::time::Duration;

    pub const DIAL: Duration = Duration::from_secs(10);
    pub const TRANSPORT: Duration = Duration::from_secs(10);
    pub const SECURITY: Duration = Duration::from_secs(10);
    pub const PROTOCOL: Duration = Duration::from_secs(10);
    pub const TUNNEL_READ: Duration = Duration::from_secs(30);
}
