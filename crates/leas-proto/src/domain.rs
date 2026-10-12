//! The ONE DNS-name split (db-rewamp D2/D6).
//!
//! A DNS host splits into a registrable `domain` and a `sub_domain`. This
//! module is the SINGLE owner of that split — validation (`import_export::validate_host`),
//! the row-build owner (`state::endpoint_from_essentials`) and the prefix-search
//! predicate all read it, so the accepted name, the stored name and the
//! identity cannot drift.
//!
//! `psl2::analyze` normalizes ONCE (IDNA → punycode, lowercased) and returns the
//! suffix, the registrable domain and the subdomain together. Calling
//! `registrable_domain` and `subdomain` separately would normalize twice and can
//! disagree, so this module never does that.
//!
//! ## The PSL version is an identity input
//!
//! `psl2`'s embedded list is republished when upstream changes, so a
//! `cargo update` can move `psl2::psl_version()` and thereby re-key (or reject)
//! hosts with no code change. The version is stamped in the DB (a one-row meta,
//! the `rank_weight_meta` pattern) and a mismatch is surfaced as a re-import
//! requirement — never a silent shift.

/// A DNS host split into its registrable domain and its subdomain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainSplit {
    /// The fully normalized (lowercased, ASCII/punycode) host.
    pub ascii: String,
    /// The registrable domain (eTLD+1), e.g. `example.co.uk`.
    pub domain: String,
    /// The labels left of the registrable domain; empty when the host IS the
    /// registrable domain (`example.com`).
    pub sub_domain: String,
}

/// Split a DNS host into `(domain, sub_domain)`, or `None`.
///
/// `None` when the host has no registrable domain — a single label
/// (`localhost`, `pl`) or a bare public suffix (`co.uk`, `github.io`). The
/// caller rejects (validation) or skips.
///
/// The PRIVATE section of the list is honoured: `github.io`/`blogspot.com`/
/// `pages.dev` are public suffixes (so a bare one yields `None`), while
/// `foo.github.io` is registrable and yields `domain = "foo.github.io"`.
#[must_use]
pub fn split(host: &str) -> Option<DomainSplit> {
    let info = psl2::analyze(host)?;
    let domain = info.registrable_domain()?.to_string();
    let sub_domain = info.subdomain().unwrap_or("").to_string();
    Some(DomainSplit {
        ascii: info.as_ascii().to_string(),
        domain,
        sub_domain,
    })
}

/// The upstream Public Suffix List version this build embedded. An identity
/// input: a change re-keys stored endpoints.
#[must_use]
pub fn psl_version() -> &'static str {
    psl2::psl_version()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_a_registrable_host() {
        let s = split("www.example.co.uk").expect("registrable");
        assert_eq!(s.domain, "example.co.uk");
        assert_eq!(s.sub_domain, "www");
    }

    #[test]
    fn a_bare_registrable_host_has_no_subdomain() {
        let s = split("example.com").expect("registrable");
        assert_eq!(s.domain, "example.com");
        assert_eq!(s.sub_domain, "");
    }

    #[test]
    fn unlisted_tlds_are_admitted_by_the_psl_default_rule() {
        // The PSL default rule gives an unlisted TLD a registrable domain, so
        // LAN/private-scope names are NOT rejected by the T4/T5 rule (only
        // single-label names and bare suffixes are).
        for host in ["nas.local", "router.lan", "server.home.arpa"] {
            assert!(split(host).is_some(), "{host} must be admitted");
        }
    }

    #[test]
    fn single_label_and_bare_suffix_are_rejected() {
        for host in ["localhost", "pl", "co.uk", "com"] {
            assert!(split(host).is_none(), "{host} has no registrable domain");
        }
    }

    #[test]
    fn private_suffix_semantics() {
        // A bare PRIVATE suffix is a public suffix (rejected); a host under it
        // is registrable.
        assert!(split("github.io").is_none(), "bare private suffix");
        assert!(split("blogspot.com").is_none(), "bare private suffix");
        let s = split("foo.github.io").expect("registrable under a private suffix");
        assert_eq!(s.domain, "foo.github.io");
    }

    #[test]
    fn idna_is_normalized_to_punycode() {
        let s = split("食狮.公司.cn").expect("registrable");
        assert_eq!(s.domain, "xn--85x722f.xn--55qx5d.cn");
        assert!(s.ascii.is_ascii());
    }

    #[test]
    fn case_is_lowercased() {
        let s = split("WWW.Example.COM").expect("registrable");
        assert_eq!(s.domain, "example.com");
        assert_eq!(s.sub_domain, "www");
    }

    #[test]
    fn the_psl_version_is_nonempty() {
        assert_ne!(psl_version(), "");
    }
}
