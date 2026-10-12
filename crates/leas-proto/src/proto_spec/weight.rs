//! The static config weight: a compiled prior for "which transport/security
//! stack is most likely to work today".
//!
//! This is a TASTE TABLE, not a measurement and not a cost model. It answers a
//! question measurement cannot yet answer: among links nothing has probed, which
//! stack should be tried first. Spec:
//! `docs/aegis/specs/2026-10-01-static-config-weight-design.md`.
//!
//! Three properties the rest of the feature depends on:
//!
//! * **Lexicographic, higher = better.** Declaration order IS precedence, so
//!   `security` decides unless two stacks tie on it exactly. That is why every
//!   area is authored as a COARSE BAND (0..=[`BAND_MAX`], 10): with finer values the
//!   lower three areas are read only on exact ties and the weight degenerates
//!   to "pick the best security". Coarse bands are a design constraint, not a
//!   convenience.
//! * **Exhaustive lookups.** [`security_score`], [`mimicry_score`] and
//!   [`transport_score`] are total `match`es with no `_` arm — on BOTH axes for
//!   the pair-valued [`mimicry_score`] — so a new [`TransportType`] /
//!   [`SecurityType`] variant is a COMPILE ERROR here rather than a silent zero
//!   that sinks every row of that shape to the bottom of the page. Same rule and
//!   same reason as `leas-native`'s `capability::transport_supported`.
//! * **Versioned.** The tables are code, so any edit silently invalidates every
//!   stored weight. Bump [`WEIGHT_VERSION`] when a cell changes; the DB layer
//!   compares it at open and recomputes the materialized keys on a mismatch.
//!
//! ## Deliberate omissions
//!
//! * **Protocol kind is not a dimension.** VLESS/VMess/Trojan over the same
//!   transport+security score identically: what a deep probe can distinguish is
//!   measurement's job, not this table's.
//! * **No sub-config facts.** Nothing here reads ws `path`, xhttp `mode` or kcp
//!   `header_type`; those live in the deferred `config` JSON, and a weight that
//!   needed them would force a decode on the write path. The function takes
//!   only the discriminators the DB already stores in scalar columns.

use crate::proto_spec::{SecurityType, TransportType};

/// Bump when ANY cell in the tables below changes.
///
/// The DB stores materialized `rank_weight` values per endpoint; without this
/// stamp an app upgrade would leave every row ordered by the previous release's
/// opinions, with nothing to indicate it.
pub const WEIGHT_VERSION: u32 = 1;

/// The weight, as four coarse bands in precedence order.
///
/// `#[repr(C)]` with `Ord` derived from the field order: the be-bytes packing
/// and the comparator then agree by construction (field 1 occupies the most
/// significant bytes), which is what lets SQL `ORDER BY` on the stored blob
/// match the Rust comparator without a second hand-written encoding.
///
/// Higher is better in every field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[repr(C)]
pub struct ConfigWeight {
    /// Which security the stack uses. The dominant band.
    pub security: u16,
    /// How hard the stack is to fingerprint for a DPI.
    pub mimicry: u16,
    /// Security-layer cost, inverted: a cheaper handshake scores higher.
    pub sec_cost: u16,
    /// Transport cost, inverted: a cheaper transport scores higher.
    pub transport_cost: u16,
}

/// The all-zero weight — "nothing known", and the SQL `NOT NULL` default.
///
/// It sorts below every real weight, so an un-refreshed endpoint lands at the
/// bottom of its tier rather than an arbitrary middle position.
pub const ZERO_WEIGHT: ConfigWeight = ConfigWeight {
    security: 0,
    mimicry: 0,
    sec_cost: 0,
    transport_cost: 0,
};

impl ConfigWeight {
    /// Pack as 8 big-endian bytes: field 1 first, so memcmp over the packed
    /// form is the lexicographic order with the top field most significant.
    #[must_use]
    pub const fn to_be_bytes(self) -> [u8; 8] {
        let [sec_hi, sec_lo] = self.security.to_be_bytes();
        let [mim_hi, mim_lo] = self.mimicry.to_be_bytes();
        let [cost_hi, cost_lo] = self.sec_cost.to_be_bytes();
        let [trn_hi, trn_lo] = self.transport_cost.to_be_bytes();
        [
            sec_hi, sec_lo, mim_hi, mim_lo, cost_hi, cost_lo, trn_hi, trn_lo,
        ]
    }

    /// Inverse of [`Self::to_be_bytes`].
    #[must_use]
    pub const fn from_be_bytes(bytes: [u8; 8]) -> Self {
        Self {
            security: u16::from_be_bytes([bytes[0], bytes[1]]),
            mimicry: u16::from_be_bytes([bytes[2], bytes[3]]),
            sec_cost: u16::from_be_bytes([bytes[4], bytes[5]]),
            transport_cost: u16::from_be_bytes([bytes[6], bytes[7]]),
        }
    }

    /// The SQLite blob literal for the packed form (`x'00ff…'`).
    ///
    /// The rank table's bulk statements inline their values (this engine bills
    /// ~0.8 ms per BOUND parameter, and the existing writes already inline
    /// integers), so the literal is what the write path needs.
    #[must_use]
    pub fn sql_literal(self) -> String {
        use std::fmt::Write as _;
        let mut literal = String::with_capacity(19);
        literal.push_str("x'");
        for byte in self.to_be_bytes() {
            let _ = write!(literal, "{byte:02x}");
        }
        literal.push('\'');
        literal
    }
}

/// The top of every band. The adjustments below are CLAMPED here, so a band's
/// value can never leave the coarse range the tables are authored in — an
/// unbounded `+1` would put the mimicry band above every cell in the security
/// band it is meant to refine.
const BAND_MAX: u16 = 10;

/// The weight for one link, from the discriminators alone.
///
/// `sni` and `fp` only adjust the MIMICRY band; they never change which
/// security is in use, so they cannot outrank it under the lexicographic order.
#[must_use]
pub fn weight_of(
    transport: TransportType,
    security: SecurityType,
    sni: Option<&str>,
    fp: Option<&str>,
) -> ConfigWeight {
    let mut mimicry = mimicry_score(transport, security);
    // A client-hello fingerprint only exists to look like a browser; with none
    // the hello is the engine's own. Only meaningful under TLS.
    if security != SecurityType::None && fp.is_some_and(|f| !f.is_empty()) {
        mimicry = mimicry.saturating_add(1).min(BAND_MAX);
    }
    // A TLS ClientHello with no SNI is conspicuous precisely because almost
    // every real TLS connection carries one.
    if security == SecurityType::Tls && sni.is_none_or(str::is_empty) {
        mimicry = mimicry.saturating_sub(1);
    }
    ConfigWeight {
        security: security_score(security),
        mimicry,
        sec_cost: sec_cost_score(security),
        transport_cost: transport_score(transport),
    }
}

/// Band 1 — which security is in use.
const fn security_score(security: SecurityType) -> u16 {
    match security {
        // Borrows the server's own certificate handshake: nothing for a DPI to
        // key on beyond "TLS that terminates successfully".
        SecurityType::Reality => 10,
        // Ordinary TLS: ubiquitous, and the fingerprint surface this project
        // exists to mitigate.
        SecurityType::Tls => 6,
        // The payload speaks its own protocol on port 443.
        SecurityType::None => 2,
    }
}

/// Band 2 — DPI detectability of the (transport, security) PAIR.
///
/// Total on BOTH axes on purpose: a new `TransportType` **or** `SecurityType`
/// must fail to compile here. An arm like `(Ws, _)` would still compile when a
/// security variant is added, silently reusing a transport-only score — the
/// exact silent gap this table exists to make impossible.
const fn mimicry_score(transport: TransportType, security: SecurityType) -> u16 {
    use SecurityType::{None as Plain, Reality, Tls};
    match (transport, security) {
        // REALITY over a bare stream is the shape it was designed for: the
        // handshake looks like a normal TLS visit to a borrowed site.
        (TransportType::Tcp, Reality) => 10,
        // HTTP/2-shaped framing is what the CDN-fronted CDNs emit.
        (TransportType::Grpc, Tls | Plain | Reality) => 8,
        // Both are an HTTP/2-shaped upgrade over the stream.
        (TransportType::HttpUpgrade | TransportType::XHttp, Tls | Plain | Reality) => 7,
        // WebSocket is the most-deployed tunnel transport, so the least
        // remarkable, but the HTTP upgrade is still recognisable.
        (TransportType::Ws, Tls | Plain | Reality) => 6,
        // QUIC's version negotiation and the TLS-in-QUIC handshake are loud, and
        // plain HTTP camouflage is a distinctive header shape.
        (TransportType::Quic | TransportType::Http, Tls | Plain | Reality) => 4,
        // mKCP ships its own header type and a fixed-cadence packet train.
        (TransportType::Kcp, Tls | Plain | Reality) => 2,
        // Raw TCP + TLS: the tunnel's framing is the only thing to see.
        (TransportType::Tcp, Tls | Plain) => 5,
    }
}

/// Band 3 — security-layer cost, inverted (higher = cheaper).
const fn sec_cost_score(security: SecurityType) -> u16 {
    match security {
        // No handshake at all: the cheapest possible security layer.
        SecurityType::None => 10,
        // One extra round trip plus the certificate exchange.
        SecurityType::Tls => 6,
        // The 9-step reality contract runs before anything else is sent.
        SecurityType::Reality => 3,
    }
}

/// Band 4 — transport cost, inverted (higher = cheaper).
const fn transport_score(transport: TransportType) -> u16 {
    match transport {
        TransportType::Tcp => 10,
        TransportType::Ws => 8,
        TransportType::HttpUpgrade | TransportType::Grpc => 7,
        TransportType::XHttp => 6,
        TransportType::Quic | TransportType::Http => 5,
        TransportType::Kcp => 3,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cmp::Ordering;

    fn all_pairs() -> Vec<(TransportType, SecurityType)> {
        const T: [TransportType; 8] = [
            TransportType::Tcp,
            TransportType::Ws,
            TransportType::Grpc,
            TransportType::Http,
            TransportType::Quic,
            TransportType::Kcp,
            TransportType::HttpUpgrade,
            TransportType::XHttp,
        ];
        const S: [SecurityType; 3] = [SecurityType::None, SecurityType::Tls, SecurityType::Reality];
        T.iter()
            .flat_map(|t| S.iter().map(move |s| (*t, *s)))
            .collect()
    }

    #[test]
    fn pack_round_trips_including_the_zero_weight() {
        for (t, s) in all_pairs() {
            let w = weight_of(t, s, Some("example.com"), Some("chrome_130"));
            assert_eq!(ConfigWeight::from_be_bytes(w.to_be_bytes()), w);
            assert_eq!(
                ConfigWeight::from_be_bytes(ZERO_WEIGHT.to_be_bytes()),
                ZERO_WEIGHT
            );
        }
    }

    /// The property the SQL `ORDER BY` depends on: memcmp over the packed bytes
    /// is exactly `Ord`. A field order or a packing regression fails HERE rather
    /// than as an inverted page.
    #[test]
    fn memcmp_order_of_packed_bytes_equals_ord() {
        let mut weights = vec![ZERO_WEIGHT];
        for (t, s) in all_pairs() {
            for sni in [Some("example.com"), None] {
                for fp in [Some("chrome_130"), None] {
                    weights.push(weight_of(t, s, sni, fp));
                }
            }
        }
        for a in &weights {
            for b in &weights {
                assert_eq!(
                    a.to_be_bytes().cmp(&b.to_be_bytes()),
                    a.cmp(b),
                    "packed order disagrees for {a:?} vs {b:?}"
                );
            }
        }
    }

    #[test]
    fn zero_weight_sorts_below_every_real_weight() {
        for (t, s) in all_pairs() {
            let w = weight_of(t, s, None, None);
            assert_eq!(
                ZERO_WEIGHT.cmp(&w),
                Ordering::Less,
                "{t}/{s} must beat zero"
            );
            assert!(w.to_be_bytes() > ZERO_WEIGHT.to_be_bytes());
        }
    }

    /// Lexicographic means band 1 decides. This pins the property the coarse-band
    /// design depends on: a better transport never rescues a weaker security.
    #[test]
    fn security_band_dominates_the_rest() {
        let weak = weight_of(TransportType::Kcp, SecurityType::None, None, None);
        let strong = weight_of(TransportType::Tcp, SecurityType::Reality, None, None);
        assert!(strong > weak);
        assert_eq!(
            ConfigWeight {
                transport_cost: u16::MAX,
                ..weak
            }
            .cmp(&strong),
            Ordering::Less,
            "a perfect transport band must not outrank a stronger security band"
        );
    }

    #[test]
    fn every_band_stays_inside_the_documented_coarse_range() {
        for (t, s) in all_pairs() {
            for sni in [Some("a.example"), None] {
                for fp in [Some("chrome_130"), None] {
                    let w = weight_of(t, s, sni, fp);
                    for (name, value) in [
                        ("security", w.security),
                        ("mimicry", w.mimicry),
                        ("sec_cost", w.sec_cost),
                        ("transport_cost", w.transport_cost),
                    ] {
                        assert!(
                            value <= BAND_MAX,
                            "{t}/{s} {name} band {value} exceeds BAND_MAX {BAND_MAX}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn a_fingerprint_only_lifts_mimicry_and_only_under_tls() {
        let plain = weight_of(
            TransportType::Tcp,
            SecurityType::Tls,
            Some("a.example"),
            None,
        );
        let fp = weight_of(
            TransportType::Tcp,
            SecurityType::Tls,
            Some("a.example"),
            Some("chrome"),
        );
        assert_eq!(fp.security, plain.security);
        assert!(fp.mimicry > plain.mimicry);

        let none_sec = weight_of(
            TransportType::Tcp,
            SecurityType::None,
            Some("a.example"),
            None,
        );
        let none_fp = weight_of(
            TransportType::Tcp,
            SecurityType::None,
            Some("a.example"),
            Some("chrome"),
        );
        assert_eq!(
            none_fp.mimicry, none_sec.mimicry,
            "no TLS, no fingerprint to spoof"
        );
    }

    #[test]
    fn a_tls_stack_without_sni_is_less_conspicuous_than_one_with() {
        let with = weight_of(
            TransportType::Tcp,
            SecurityType::Tls,
            Some("a.example"),
            None,
        );
        let without = weight_of(TransportType::Tcp, SecurityType::Tls, None, None);
        assert!(without.mimicry < with.mimicry);
        assert_eq!(
            without.security, with.security,
            "the band 1 verdict must not move"
        );
    }

    #[test]
    fn sql_literal_is_the_packed_bytes_in_hex() {
        let w = weight_of(TransportType::Tcp, SecurityType::Reality, None, None);
        assert_eq!(w.sql_literal(), format!("x'{}'", hex(&w.to_be_bytes())));
        assert_eq!(
            w.sql_literal().len(),
            19,
            "x' + 16 hex digits + closing quote"
        );
    }

    fn hex(bytes: &[u8]) -> String {
        use std::fmt::Write as _;
        let mut out = String::new();
        for byte in bytes {
            let _ = write!(out, "{byte:02x}");
        }
        out
    }
}
