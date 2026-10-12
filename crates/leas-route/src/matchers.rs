//! Compiled domain matchers and CIDR prefix sets.

use crate::addr::{Cidr, prefix_match};
use crate::error::RouteError;
use aho_corasick::AhoCorasick;
use regex::RegexSet;
use std::borrow::Cow;
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

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
    exact: HashSet<String>,
    suffix: HashSet<String>,
    keywords: AhoCorasick,
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
        // Suffix entries are stored dot-prefixed so `ends_with` enforces the
        // label boundary ("a.foo.com" hits ".foo.com"; "xfoo.com" does not).
        // Leading dots on the input are trimmed; empty entries are rejected.
        let mut suffix = HashSet::new();
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
        let keywords = AhoCorasick::new(&keyword_pats).map_err(|e| RouteError::Parse {
            rule_index: 0,
            field: "keyword",
            message: e.to_string(),
        })?;
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
        if self.suffix.iter().any(|s| host.ends_with(s.as_str())) {
            return true;
        }
        if self.has_keywords && self.keywords.is_match(host) {
            return true;
        }
        self.has_regexes && self.regexes.is_match(host)
    }

    /// Whether no rule is registered.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.n_rules == 0
    }
}

/// Correctness-first CIDR prefix storage; radix/prefix trie explicitly deferred.
#[derive(Debug, Clone, Default)]
pub struct CidrSetBuilder {
    v4: Vec<(Ipv4Addr /* masked */, u8 /* bits */)>,
    v6: Vec<(Ipv6Addr, u8)>,
}

impl CidrSetBuilder {
    /// Adds a CIDR block to the set; the network address is masked to `bits`.
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
            IpAddr::V4(a) => self.v4.push((mask_v4(a, c.bits), c.bits)),
            IpAddr::V6(a) => self.v6.push((mask_v6(a, c.bits), c.bits)),
        }
        Ok(())
    }

    /// Builds the [`CidrSet`].
    #[must_use]
    pub fn build(self) -> CidrSet {
        CidrSet {
            v4: self.v4,
            v6: self.v6,
        }
    }
}

/// The built read-only set of prefixes.
#[derive(Debug, Clone, Default)]
pub struct CidrSet {
    v4: Vec<(Ipv4Addr /* masked */, u8 /* bits */)>,
    v6: Vec<(Ipv6Addr, u8)>,
}

impl CidrSet {
    /// Linear scan over stored prefixes matching `ip`'s family plus bits compare.
    #[must_use]
    pub fn contains(&self, ip: &IpAddr) -> bool {
        match *ip {
            IpAddr::V4(b) => self
                .v4
                .iter()
                .any(|(a, bits)| prefix_match(&a.octets(), &b.octets(), *bits)),
            IpAddr::V6(b) => self
                .v6
                .iter()
                .any(|(a, bits)| prefix_match(&a.octets(), &b.octets(), *bits)),
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
        // All entries below are already exact network addresses for their bits.
        Self {
            v4: vec![
                (Ipv4Addr::new(10, 0, 0, 0), 8),
                (Ipv4Addr::new(172, 16, 0, 0), 12),
                (Ipv4Addr::new(192, 168, 0, 0), 16),
                (Ipv4Addr::new(100, 64, 0, 0), 10),
                (Ipv4Addr::new(127, 0, 0, 0), 8),
                (Ipv4Addr::new(169, 254, 0, 0), 16),
            ],
            v6: vec![
                (Ipv6Addr::LOCALHOST, 128),
                (Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0), 10),
                (Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 0), 7),
            ],
        }
    }
}

/// Masks an octet array down to its network address for `bits`.
fn mask_octets<const N: usize>(octets: [u8; N], bits: u8) -> [u8; N] {
    let mut m = [0u8; N];
    for (i, byte) in octets.iter().enumerate() {
        let shift = i * 8;
        if shift >= bits as usize {
            break;
        }
        let nb = (bits as usize - shift).min(8);
        m[i] = byte
            & match nb {
                8 => u8::MAX,
                _ => !(u8::MAX >> nb),
            };
    }
    m
}

/// Masks an IPv4 address down to its network address for `bits`.
fn mask_v4(a: Ipv4Addr, bits: u8) -> Ipv4Addr {
    Ipv4Addr::from(mask_octets(a.octets(), bits))
}

/// Masks an IPv6 address down to its network address for `bits`.
fn mask_v6(a: Ipv6Addr, bits: u8) -> Ipv6Addr {
    Ipv6Addr::from(mask_octets(a.octets(), bits))
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
