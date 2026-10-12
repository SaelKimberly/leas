//! The purge policy: which probe evidence moves a config to Purgatory.
//!
//! This module is the ONLY owner of that decision (spec
//! `2026-09-17-purge-reason-design.md` §6/§7). The engine reports typed
//! evidence ([`FailureEvidence`]) where the failure happened; the taxonomy —
//! which classes count, and which are plausibly transient — is product policy
//! and lives here, in one function, so a revision costs one function rather
//! than a schema change.

use leas_db::models::PurgeReason;
use leas_native::error::FailureEvidence;

/// The verdict a failed real probe's evidence earns, or `None` for
/// "inconclusive: probe it again later".
///
/// Deliberately NOT purging: every timeout, dial/DNS/refusal failure, TLS
/// alert, protocol framing failure, and the statuses `429`/`412`/`500`/`503`.
/// Each is either indistinguishable from a transient network condition or a
/// rate-limit/bot-management answer from the CDN, and none of them is a
/// statement the origin made about this config (spec §7).
///
/// `fp` is the link's TLS fingerprint as the CONFIG carries it (never the
/// `security_fp` column — no call site holds a `Protocol` row, and the row
/// label reads the column from the page projection; spec §5.3 records the
/// split and the agreement test it owes). When it is an approximation, the
/// probe dialled a shape the link did not ask for, so the failure is about a
/// config that was never tried and earns NO verdict.
///
/// Not `const` any more: the approximation check goes through the SAME
/// predicate the capability gate and the row label use
/// (`security::fingerprint::resolve_fingerprint`), and that predicate is not
/// `const`. Re-implementing the check inline to keep `const` would duplicate
/// the single decision point this rule exists to share.
#[must_use]
pub fn reason_for(evidence: FailureEvidence, fp: Option<&str>) -> Option<PurgeReason> {
    if leas_native::security::fingerprint::resolve_fingerprint(fp).1 {
        return None;
    }
    match evidence {
        FailureEvidence::RealityFallback => Some(PurgeReason::RealityFallback),
        FailureEvidence::CertNotValidForName => Some(PurgeReason::CertificateMismatch),
        FailureEvidence::CertExpired => Some(PurgeReason::CertificateExpired),
        FailureEvidence::CleartextPeer => Some(PurgeReason::NotTls),
        // The stored config cannot dial as written: no retry will change that.
        FailureEvidence::ConfigDefect => Some(PurgeReason::ConfigInvalid),
        FailureEvidence::HttpRejected(status) => match status {
            // The CDN could not reach the origin: the config's backend is gone.
            521 | 522 | 526 | 530 => Some(PurgeReason::OriginUnreachable),
            // The proxy's own answer to our exact request: the path or host is
            // wrong, or the server refuses this config.
            301 | 302 | 400 | 403 | 404 | 405 | 409 | 410 => Some(PurgeReason::TransportRejected),
            _ => None,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::reason_for;
    use leas_db::models::PurgeReason;
    use leas_native::error::FailureEvidence;

    /// A roster-mapped fingerprint: the probe dialled the shape the link asked
    /// for, so its failures are statements about the config.
    const HONOURED: Option<&str> = Some("chrome");

    #[test]
    fn every_typed_evidence_maps_to_its_reason() {
        let cases = [
            (
                FailureEvidence::RealityFallback,
                Some(PurgeReason::RealityFallback),
            ),
            (
                FailureEvidence::CertNotValidForName,
                Some(PurgeReason::CertificateMismatch),
            ),
            (
                FailureEvidence::CertExpired,
                Some(PurgeReason::CertificateExpired),
            ),
            (FailureEvidence::CleartextPeer, Some(PurgeReason::NotTls)),
            (
                FailureEvidence::ConfigDefect,
                Some(PurgeReason::ConfigInvalid),
            ),
        ];
        for (evidence, expected) in cases {
            assert_eq!(reason_for(evidence, HONOURED), expected, "for {evidence:?}");
        }
    }

    /// An approximated probe proves NOTHING about the config: the shape dialled
    /// is not the shape the link asked for, so a verdict would be about a config
    /// that was never tried. Every evidence variant, including the ones that
    /// otherwise purge permanently.
    #[test]
    fn an_approximated_probe_earns_no_verdict_at_all() {
        let approximated = ["qq", "android", "360", "hellochrome_120", "unknown-id"];
        for fp in approximated {
            for evidence in [
                FailureEvidence::RealityFallback,
                FailureEvidence::CertNotValidForName,
                FailureEvidence::CertExpired,
                FailureEvidence::CleartextPeer,
                FailureEvidence::ConfigDefect,
                FailureEvidence::HttpRejected(404),
                FailureEvidence::HttpRejected(521),
            ] {
                assert_eq!(
                    reason_for(evidence, Some(fp)),
                    None,
                    "{fp} + {evidence:?} must not purge"
                );
            }
        }
    }

    /// The three spellings of "no fingerprint requested" are NOT approximations:
    /// the engine default IS the shape they asked for, so their verdicts stand.
    #[test]
    fn no_fingerprint_requested_still_earns_a_verdict() {
        for fp in [None, Some(""), Some("unsafe")] {
            assert_eq!(
                reason_for(FailureEvidence::RealityFallback, fp),
                Some(PurgeReason::RealityFallback),
                "{fp:?} requested no fingerprint, so the default is the shape asked for"
            );
        }
    }

    #[test]
    fn the_origin_errors_are_their_own_reason() {
        for status in [521_u16, 522, 526, 530] {
            assert_eq!(
                reason_for(FailureEvidence::HttpRejected(status), HONOURED),
                Some(PurgeReason::OriginUnreachable),
                "status {status} means the CDN could not reach the origin"
            );
        }
    }

    #[test]
    fn the_proxy_refusing_our_request_is_evidence() {
        for status in [301_u16, 302, 400, 403, 404, 405, 409, 410] {
            assert_eq!(
                reason_for(FailureEvidence::HttpRejected(status), HONOURED),
                Some(PurgeReason::TransportRejected),
                "status {status} is the server's answer to our exact request"
            );
        }
    }

    /// The excluded classes are the point of the taxonomy: each is plausibly
    /// transient or aimed at the client, so a config must not be retired on it.
    #[test]
    fn transient_and_client_side_statuses_never_purge() {
        for status in [200_u16, 204, 412, 429, 500, 502, 503, 520, 525] {
            assert_eq!(
                reason_for(FailureEvidence::HttpRejected(status), HONOURED),
                None,
                "status {status} must not purge"
            );
        }
    }
}
