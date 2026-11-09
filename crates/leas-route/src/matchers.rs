//! Compiled domain matchers and CIDR prefix sets.

use crate::addr::Cidr;
use crate::error::RouteError;
use daachorse::DoubleArrayAhoCorasick;
use memchr::memchr;
use rapidhash::RapidHashSet;
use regex::RegexSet;
use std::borrow::Cow;
use std::net::{IpAddr, Ipv6Addr};

/// Uncompiled set of domain matching rules.
#[derive(Debug, Clone, Default)]
pub struct DomainRulesSpec {
    /// Exact hostnames.
    pub exact: Vec<String>,
    /// Matched as parent domains (`sub.example.com` matches suffix `example.com`).
    pub suffix: Vec<String>,
    /// Substring keywords.
    pub keywords: Vec<String>,
    /// Regular expressions over the hostname.
    pub regexes: Vec<String>,
}

/// A [`DomainRulesSpec`] with no rules.
#[must_use]
pub fn empty_spec() -> DomainRulesSpec {
    DomainRulesSpec::default()
}

/// Compiled domain matcher: exact set, suffix set, keyword automaton, regex set.
pub struct CompiledDomain {
    // `rapidhash`'s `fast` state seeds itself from process entropy (minimal,
    // not zero, DoS resistance). The keys are config-built hostnames; the
    // attacker can only choose the probed host, never the stored set, so the
    // per-process random seed is the accepted trade — same boundary as the
    // telemetry maps.
    exact: RapidHashSet<String>,
    suffix: RapidHashSet<String>,
    // Boxed: daachorse's automaton is 168 bytes inline (vs aho-corasick's
    // 24-byte internal box), which alone pushed `ItemMatcher::Domain` over the
    // `large_size_differences_between_variants` gate.
    keywords: Box<DoubleArrayAhoCorasick<u32>>,
    /// Whether any keyword pattern exists: an empty automaton still costs a
    /// call per evaluation, and most rules carry no keywords.
    has_keywords: bool,
    regexes: RegexSet,
    /// Whether any regex pattern exists (see `has_keywords`).
    has_regexes: bool,
    n_rules: usize,
}

impl CompiledDomain {
    /// Compiles a spec into a matcher.
    ///
    /// # Errors
    /// Returns [`RouteError::Parse`] when any regex fails to compile or a
    /// suffix entry is empty.
    pub fn build(spec: &DomainRulesSpec) -> Result<Self, RouteError> {
        let lower_all = |xs: &[String]| xs.iter().map(|s| s.to_lowercase()).collect::<Vec<_>>();
        let exact = lower_all(&spec.exact).into_iter().collect();
        // Suffix entries are stored dot-prefixed: a small set scans them with
        // `ends_with` (the boundary check is the leading dot itself), and a
        // large set looks each dot-prefixed host tail up directly. Leading
        // dots on the input are trimmed; empty entries are rejected.
        let mut suffix = RapidHashSet::default();
        for s in lower_all(&spec.suffix) {
            let s = s.trim_start_matches('.');
            if s.is_empty() {
                return Err(RouteError::Parse {
                    rule_index: 0,
                    field: "suffix",
                    message: "empty suffix".to_owned(),
                });
            }
            suffix.insert(format!(".{s}"));
        }
        let keyword_pats = lower_all(&spec.keywords);
        let keywords = Box::new(DoubleArrayAhoCorasick::<u32>::new(&keyword_pats).map_err(
            |e| RouteError::Parse {
                rule_index: 0,
                field: "keyword",
                message: e.to_string(),
            },
        )?);
        let regex_pats = lower_all(&spec.regexes);
        let regexes = RegexSet::new(&regex_pats).map_err(|e| RouteError::Parse {
            rule_index: 0,
            field: "regex",
            message: format!("invalid pattern: {e}"),
        })?;
        Ok(Self {
            n_rules: spec.exact.len()
                + spec.suffix.len()
                + spec.keywords.len()
                + spec.regexes.len(),
            exact,
            suffix,
            has_keywords: !keyword_pats.is_empty(),
            keywords,
            has_regexes: !regex_pats.is_empty(),
            regexes,
        })
    }

    /// Whether `host` hits any rule (exact, suffix, keyword, or regex).
    #[must_use]
    pub fn matches_domain(&self, host: &str) -> bool {
        // Hosts arrive lowercase in the common case (SNI, both cores' config
        // producers), so only allocate when a case fold is actually needed.
        // The matcher sets are built with `to_lowercase`, so this must use the
        // same mapping — `to_ascii_lowercase` would diverge on non-ASCII.
        let lowered: Cow<'_, str> = if host.chars().any(char::is_uppercase) {
            Cow::Owned(host.to_lowercase())
        } else {
            Cow::Borrowed(host)
        };
        let host: &str = lowered.as_ref();
        if !self.exact.is_empty() && self.exact.contains(host) {
            return true;
        }
        if !self.suffix.is_empty() && self.suffix_matches(host) {
            return true;
        }
        if self.has_keywords && self.keywords.find_iter(host).next().is_some() {
            return true;
        }
        self.has_regexes && self.regexes.is_match(host)
    }

    /// Whether `host` hits any suffix entry.
    ///
    /// A small set is cheaper to scan with `ends_with` than to hash a
    /// label per entry; the label walk pays off once the set is large.
    /// `SCAN_MAX` sits between the two bench shapes: the `rules_{8,64}`
    /// fillers carry 2 suffixes (linear) and `suffix_scan/1024` walks.
    #[inline]
    fn suffix_matches(&self, host: &str) -> bool {
        const SCAN_MAX: usize = 8;
        if self.suffix.len() <= SCAN_MAX {
            return self.suffix.iter().any(|s| host.ends_with(s.as_str()));
        }
        suffix_hit(&self.suffix, host)
    }

    /// Whether no rule is registered.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.n_rules == 0
    }
}

/// Whether any stored suffix matches `host`, for a suffix set too large to
/// scan.
///
/// Entries are dot-prefixed, so every dot in the host starts a slice that IS
/// the candidate key: `a.b.foo.com` probes `.b.foo.com`, `.foo.com`, `.com`.
/// No allocation, O(dots) probes. The full host is never a candidate, so a
/// suffix never matches the bare host. A trailing dot leaves the last slice
/// as `.`-terminated (`.foo.com.`), which cannot equal `.foo.com`.
fn suffix_hit(suffix: &RapidHashSet<String>, host: &str) -> bool {
    let bytes = host.as_bytes();
    let mut from = 0;
    while let Some(pos) = memchr(b'.', &bytes[from..]) {
        let at = from + pos;
        if at + 1 < bytes.len() && suffix.contains(&host[at..]) {
            return true;
        }
        from = at + 1;
    }
    false
}

/// Inclusive host-order ranges per family; membership is one binary search.
///
/// A CIDR set is a *union*: normalising every prefix to its `[first, last]`
/// range at build time and merging the overlaps makes `contains` a single
/// `partition_point` over ≤N disjoint ranges, with no per-candidate mask
/// compare. The old linear `prefix_match` form is kept in [`Cidr::contains`]
/// for single-block checks.
#[derive(Debug, Clone, Default)]
pub struct CidrSetBuilder {
    v4: Vec<(u32, u32)>,
    v6: Vec<(u128, u128)>,
}

impl CidrSetBuilder {
    /// Adds a CIDR block to the set.
    ///
    /// # Errors
    /// Returns [`RouteError::Parse`] when `c.bits` exceeds the address
    /// family's maximum (hand-built or deserialized values can carry an
    /// out-of-range prefix length that would panic in [`CidrSet::contains`]).
    pub fn insert(&mut self, c: Cidr) -> Result<(), RouteError> {
        let max = match c.addr {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if c.bits > max {
            return Err(RouteError::Parse {
                rule_index: 0,
                field: "cidr",
                message: format!("prefix length {} exceeds /{max}", c.bits),
            });
        }
        match c.addr {
            IpAddr::V4(a) => self.v4.push(v4_range(a.octets(), c.bits)),
            IpAddr::V6(a) => self.v6.push(v6_range(a.octets(), c.bits)),
        }
        Ok(())
    }

    /// Adds an inclusive address range (sing-box rule sets store ranges, not
    /// prefixes).
    ///
    /// # Errors
    /// Returns [`RouteError::Parse`] when the ends are from different families
    /// or inverted.
    pub fn insert_range(&mut self, from: IpAddr, to: IpAddr) -> Result<(), RouteError> {
        match (from, to) {
            (IpAddr::V4(a), IpAddr::V4(b)) => {
                let (start, end) = (u32::from(a), u32::from(b));
                if start > end {
                    return Err(RouteError::Parse {
                        rule_index: 0,
                        field: "ip_range",
                        message: format!("inverted range {from}-{to}"),
                    });
                }
                self.v4.push((start, end));
            }
            (IpAddr::V6(a), IpAddr::V6(b)) => {
                let (start, end) = (u128::from(a), u128::from(b));
                if start > end {
                    return Err(RouteError::Parse {
                        rule_index: 0,
                        field: "ip_range",
                        message: format!("inverted range {from}-{to}"),
                    });
                }
                self.v6.push((start, end));
            }
            _ => {
                return Err(RouteError::Parse {
                    rule_index: 0,
                    field: "ip_range",
                    message: format!("range {from}-{to} mixes address families"),
                });
            }
        }
        Ok(())
    }

    /// Builds the [`CidrSet`], merging overlapping ranges.
    #[must_use]
    pub fn build(self) -> CidrSet {
        CidrSet::new(self.v4, self.v6)
    }
}

/// The built read-only set of prefixes.
#[derive(Debug, Clone, Default)]
pub struct CidrSet {
    v4: Vec<(u32, u32)>,
    v6: Vec<(u128, u128)>,
}

impl CidrSet {
    fn new(mut v4: Vec<(u32, u32)>, mut v6: Vec<(u128, u128)>) -> Self {
        merge_ranges(&mut v4);
        merge_ranges(&mut v6);
        Self { v4, v6 }
    }

    /// Whether `ip` falls inside any stored prefix: one binary search over
    /// the merged ranges of its family.
    #[must_use]
    pub fn contains(&self, ip: &IpAddr) -> bool {
        match *ip {
            IpAddr::V4(b) => contains_range(&self.v4, u32::from_be_bytes(b.octets())),
            IpAddr::V6(b) => contains_range(&self.v6, u128::from_be_bytes(b.octets())),
        }
    }

    /// Whether no prefixes are stored.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.v4.is_empty() && self.v6.is_empty()
    }

    /// RFC1918 + CGNAT + loopback + link-local + ULA prefixes.
    #[must_use]
    pub fn private_set() -> Self {
        Self::new(
            vec![
                v4_range([10, 0, 0, 0], 8),
                v4_range([172, 16, 0, 0], 12),
                v4_range([192, 168, 0, 0], 16),
                v4_range([100, 64, 0, 0], 10),
                v4_range([127, 0, 0, 0], 8),
                v4_range([169, 254, 0, 0], 16),
            ],
            vec![
                v6_range(Ipv6Addr::LOCALHOST.octets(), 128),
                v6_range(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0).octets(), 10),
                v6_range(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 0).octets(), 7),
            ],
        )
    }
}

/// The inclusive host-order range a v4 prefix covers.
///
/// `checked_shr` encodes both edges: `/0` leaves the whole space (`MAX >> 0`)
/// and `/32` covers exactly the address (`MAX >> 32` overflows → `0`).
fn v4_range(addr: [u8; 4], bits: u8) -> (u32, u32) {
    let inv = u32::MAX.checked_shr(u32::from(bits)).unwrap_or(0);
    let start = u32::from_be_bytes(addr) & !inv;
    (start, start | inv)
}

/// The inclusive host-order range a v6 prefix covers (see [`v4_range`]).
fn v6_range(addr: [u8; 16], bits: u8) -> (u128, u128) {
    let inv = u128::MAX.checked_shr(u32::from(bits)).unwrap_or(0);
    let start = u128::from_be_bytes(addr) & !inv;
    (start, start | inv)
}

/// Sorts by start and merges overlapping ranges (adjacent ranges need no
/// merge: `partition_point` still finds the one that contains the key).
fn merge_ranges<T: Ord + Copy>(ranges: &mut Vec<(T, T)>) {
    ranges.sort_unstable_by_key(|range| range.0);
    let mut merged: Vec<(T, T)> = Vec::with_capacity(ranges.len());
    for (start, end) in ranges.drain(..) {
        match merged.last_mut() {
            Some(last) if start <= last.1 => {
                if end > last.1 {
                    last.1 = end;
                }
            }
            _ => merged.push((start, end)),
        }
    }
    *ranges = merged;
}

/// Membership over merged, start-sorted ranges.
fn contains_range<T: Ord + Copy>(ranges: &[(T, T)], key: T) -> bool {
    let idx = ranges.partition_point(|range| range.0 <= key);
    idx > 0 && key <= ranges[idx - 1].1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_suffix_requires_dot_boundary() {
        // "foo.com" matches "a.foo.com" NOT "xfoo.com"
        let m = CompiledDomain::build(&DomainRulesSpec {
            suffix: vec!["foo.com".into()],
            ..empty_spec()
        })
        .unwrap();
        assert!(m.matches_domain("a.FOO.com"));
        assert!(!m.matches_domain("xfoo.com"));
    }

    #[test]
    fn domain_exact_and_regex() {
        let m = CompiledDomain::build(&DomainRulesSpec {
            exact: vec!["api.example.com".into()],
            regexes: vec![r"^cdn\d+\.example\.com$".into()],
            ..empty_spec()
        })
        .unwrap();
        assert!(m.matches_domain("api.example.com") && m.matches_domain("cdn42.example.com"));
        assert!(!m.matches_domain("cdn.example.com"));
        assert!(matches!(
            CompiledDomain::build(&DomainRulesSpec {
                regexes: vec!["(".into()],
                ..empty_spec()
            }),
            Err(RouteError::Parse { .. })
        ));
    }

    #[test]
    fn suffix_matches_only_parent_labels() {
        let m = CompiledDomain::build(&DomainRulesSpec {
            suffix: vec!["foo.com".into()],
            ..empty_spec()
        })
        .unwrap();
        // A suffix is a PARENT: the bare host does not match itself.
        assert!(!m.matches_domain("foo.com"));
        assert!(m.matches_domain("a.foo.com"));
        assert!(m.matches_domain("a.b.foo.com"));
        // A label that merely ends with the same bytes is not a match.
        assert!(!m.matches_domain("xfoo.com"));
        assert!(!m.matches_domain("a.xfoo.com"));
        assert!(!m.matches_domain("foo.com.evil.test"));
    }

    #[test]
    fn suffix_walk_over_a_large_set_keeps_label_boundaries() {
        let mut suffix: Vec<String> = (0..16).map(|i| format!("cdn{i}.example.net")).collect();
        suffix.push("foo.com".into());
        let m = CompiledDomain::build(&DomainRulesSpec {
            suffix,
            ..empty_spec()
        })
        .unwrap();
        assert!(m.matches_domain("a.b.foo.com"));
        assert!(!m.matches_domain("foo.com"));
        assert!(!m.matches_domain("xfoo.com"));
        // Trailing dot: `.foo.com` is not the tail of `a.foo.com.`.
        assert!(!m.matches_domain("a.foo.com."));
        assert!(m.matches_domain("a.cdn3.example.net"));
        assert!(!m.matches_domain("cdn3.example.net"));
    }

    #[test]
    fn suffix_walk_handles_non_ascii_labels() {
        let mut suffix: Vec<String> = (0..16).map(|i| format!("cdn{i}.example.net")).collect();
        suffix.push("例え.テスト".into());
        let m = CompiledDomain::build(&DomainRulesSpec {
            suffix,
            ..empty_spec()
        })
        .unwrap();
        // Full-Unicode lowercasing feeds the label walk; the dot is ASCII, so
        // the slice starts on a char boundary.
        assert!(m.matches_domain("WWW.例え.テスト"));
        assert!(m.matches_domain("café.例え.テスト"));
        assert!(!m.matches_domain("例え.テスト"));
        assert!(!m.matches_domain("café.example.net"));
    }

    #[test]
    fn cidrset_merges_overlaps_and_edges() {
        let mut b = CidrSetBuilder::default();
        for c in [
            "10.0.0.0/8",
            "10.1.0.0/16", // nested inside 10/8
            "192.168.0.0/16",
            "192.168.0.0/16", // duplicate
            "0.0.0.0/0",      // every v4 address
        ] {
            b.insert(Cidr::parse(c).unwrap()).unwrap();
        }
        b.insert(Cidr::parse("2001:db8::/32").unwrap()).unwrap();
        b.insert(Cidr::parse("2001:db8:1::/48").unwrap()).unwrap();
        let s = b.build();
        // The /0 subsumes every v4 range, including ones never inserted.
        assert!(s.contains(&"8.8.8.8".parse().unwrap()));
        assert!(s.contains(&"10.2.0.1".parse().unwrap()));
        assert!(s.contains(&"192.168.5.5".parse().unwrap()));
        // v6 stays family-separated and nested prefixes still match.
        assert!(s.contains(&"2001:db8:1::1".parse().unwrap()));
        assert!(!s.contains(&"2001:db9::1".parse().unwrap()));

        // A /32 matches exactly its address; a neighbouring one does not.
        let mut host = CidrSetBuilder::default();
        host.insert(Cidr::parse("203.0.113.7/32").unwrap()).unwrap();
        let host = host.build();
        assert!(host.contains(&"203.0.113.7".parse().unwrap()));
        assert!(!host.contains(&"203.0.113.8".parse().unwrap()));
    }

    #[test]
    fn cidrset_v6_contains_exact_prefix() {
        let mut b = CidrSetBuilder::default();
        b.insert(Cidr::parse("fd00::/8").unwrap()).unwrap();
        let s = b.build();
        assert!(s.contains(&"fd00:dead::1".parse().unwrap()));
        assert!(!s.contains(&"fe80::1".parse().unwrap()));
    }

    #[test]
    fn private_set_classifications() {
        let p = CidrSet::private_set();
        assert!(
            p.contains(&"10.9.9.9".parse().unwrap())
                && p.contains(&"172.31.0.1".parse().unwrap())
                && p.contains(&"100.64.0.7".parse().unwrap())
                && p.contains(&"::1".parse().unwrap())
                && p.contains(&"fc00::".parse().unwrap())
                && !p.contains(&"8.8.8.8".parse().unwrap())
        );
    }

    #[test]
    fn domain_keyword_substring_case_insensitive() {
        let m = CompiledDomain::build(&DomainRulesSpec {
            keywords: vec!["GOOGLE".into()],
            ..empty_spec()
        })
        .unwrap();
        assert!(m.matches_domain("www.GoogleMail.com"));
    }

    #[test]
    fn empty_spec_and_empty_cidrset() {
        assert!(CompiledDomain::build(&empty_spec()).unwrap().is_empty());
        assert!(CidrSetBuilder::default().build().is_empty());
    }

    #[test]
    fn insert_rejects_out_of_range_bits_no_panic() {
        // Hand-built/deserialized values can carry bits above the family max.
        let mut b = CidrSetBuilder::default();
        let bad = Cidr {
            addr: "192.0.2.1".parse().unwrap(),
            bits: 100,
        };
        assert!(matches!(b.insert(bad), Err(RouteError::Parse { .. })));
        assert!(CidrSetBuilder::default().build().is_empty());
    }

    #[test]
    fn suffix_normalizes_leading_dots_and_rejects_empty() {
        let m = CompiledDomain::build(&DomainRulesSpec {
            suffix: vec![".foo.com".into()],
            ..empty_spec()
        })
        .unwrap();
        assert!(m.matches_domain("a.foo.com"));
        assert!(!m.matches_domain("xfoo.com"));
        assert!(matches!(
            CompiledDomain::build(&DomainRulesSpec {
                suffix: vec!["..".into()],
                ..empty_spec()
            }),
            Err(RouteError::Parse {
                field: "suffix",
                ..
            })
        ));
    }
}
