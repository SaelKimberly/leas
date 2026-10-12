//! Exit-IP providers the real-ping probe reads its egress address from.
//!
//! One owner for the whole fixed provider set: a variant knows its endpoint and
//! how to read that endpoint's JSON body, so the probe never has to interpret a
//! user-supplied URL whose response shape nothing guarantees. The setting picks
//! which provider is asked FIRST; the remaining family-agnostic providers are
//! the automatic fallback order ([`IpProvider::fallback_chain`]).
//!
//! Adapted from v2rayN (`ServiceLib/Global.cs::IPAPIUrls`), which lists
//! `api.ip.sb`, `api-ipv4.ip.sb`, `api-ipv6.ip.sb`, `api.ipapi.is` and a
//! trailing `""` "no provider" sentinel, offered as free-text combo
//! suggestions. Three divergences, all deliberate: the set also carries
//! ip-api.com (this project's existing default, not one v2rayN ships), the
//! empty sentinel has no counterpart (there is no way to switch the exit-IP
//! read off), and the free text is gone (a keyed/custom endpoint has no
//! verifiable body shape). The list is a closed set whose variants own their
//! parsing; the selection names which is asked first and the rest of the
//! family-agnostic set follows automatically, which v2rayN's selection-only
//! model does not do — its free tiers' rate limits (~45 requests/minute for
//! ip-api against the ~156 a feed-wide real level asks for) need a fallback
//! rather than a replacement.

use serde::{Deserialize, Serialize};
use strum::{Display, EnumIter, EnumString, IntoEnumIterator};

/// The exit-IP endpoints, in declaration order.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Default,
    Serialize,
    Deserialize,
    Display,
    EnumIter,
    EnumString,
)]
#[serde(rename_all = "kebab-case")]
#[strum(serialize_all = "kebab-case")]
pub enum IpProvider {
    /// ip-api's free tier. HTTP only — its HTTPS form refuses with
    /// `403 {"status":"fail","message":"SSL unavailable for this endpoint"}` —
    /// and published at ~45 requests/minute.
    #[default]
    IpApi,
    /// api.ip.sb/geoip: HTTPS, and answers whichever family the request
    /// arrived over.
    IpSb,
    /// api-ipv4.ip.sb/geoip: an A-record-only host, so it reports the exit's
    /// IPv4 address (a v6-only exit cannot reach it at all).
    IpSbIpv4,
    /// api-ipv6.ip.sb/geoip: the AAAA-only counterpart.
    IpSbIpv6,
    /// api.ipapi.is: HTTPS.
    ///
    /// Named explicitly: the derived kebab-case (`ip-api-is`) reads as an
    /// ip-api variant, which it is not.
    #[serde(rename = "ipapi-is")]
    #[strum(serialize = "ipapi-is")]
    IpApiIs,
}

/// The `Select:` cell the Settings form renders for this setting, in
/// declaration order.
///
/// It lives beside the enum so a new variant cannot be invisible to the form
/// without a failing test
/// ([`tests::the_select_cell_offers_every_variant`]).
pub const SELECT_CELL: &str = "Select:ip-api,ip-sb,ip-sb-ipv4,ip-sb-ipv6,ipapi-is";

impl IpProvider {
    /// The provider's endpoint.
    #[must_use]
    pub const fn url(self) -> &'static str {
        match self {
            Self::IpApi => "http://ip-api.com/json/",
            Self::IpSb => "https://api.ip.sb/geoip",
            Self::IpSbIpv4 => "https://api-ipv4.ip.sb/geoip",
            Self::IpSbIpv6 => "https://api-ipv6.ip.sb/geoip",
            Self::IpApiIs => "https://api.ipapi.is/",
        }
    }

    /// Whether the provider's answer is pinned to one address family.
    ///
    /// A family-forced host can only RESTRICT what an exit can answer, so it is
    /// a deliberate choice and never an automatic fallback.
    #[must_use]
    pub const fn is_family_forced(self) -> bool {
        matches!(self, Self::IpSbIpv4 | Self::IpSbIpv6)
    }

    /// The providers to ask, in order: `self` first, then every family-agnostic
    /// provider.
    ///
    /// The exit IP is provider-independent — every endpoint reports the same
    /// address — so the rest of the chain is pure capacity against the free
    /// tiers' rate limits. Family-forced variants are selection-only.
    pub fn fallback_chain(self) -> impl Iterator<Item = Self> {
        std::iter::once(self)
            .chain(Self::iter().filter(move |p| *p != self && !p.is_family_forced()))
    }

    /// `"<ip> | <country>"` from this provider's JSON body; `None` when the body
    /// is not the provider's object (the probe's latency result does not depend
    /// on it).
    ///
    /// Each provider names its own fields: ip-api publishes the address as
    /// `query`, every other endpoint as `ip`. The country is the provider's
    /// spelling — the persisted flag comes from the mmdb, never from here.
    pub fn parse(self, body: &[u8]) -> Option<String> {
        let json: serde_json::Value = serde_json::from_slice(body).ok()?;
        let (addr_field, country_field) = match self {
            Self::IpApi => ("query", "country"),
            Self::IpSb | Self::IpSbIpv4 | Self::IpSbIpv6 | Self::IpApiIs => ("ip", "country"),
        };
        let ip = json.get(addr_field)?.as_str()?;
        let country = json
            .get(country_field)
            .and_then(serde_json::Value::as_str)
            .unwrap_or("-");
        Some(format!("{ip} | {country}"))
    }
}

#[cfg(test)]
mod tests {
    use super::IpProvider;
    use strum::IntoEnumIterator;

    /// The settings form writes `Display` into a `Select:` cell and reads it
    /// back with `FromStr`, and `config.json` round-trips through serde — three
    /// spellings of the same name that nothing else keeps aligned.
    #[test]
    fn every_variant_has_one_name_across_strum_and_serde() {
        for provider in IpProvider::iter() {
            let name = provider.to_string();
            assert_eq!(
                serde_json::to_value(provider).unwrap().as_str(),
                Some(name.as_str()),
                "{provider:?}: strum and serde disagree"
            );
            assert_eq!(
                name.parse::<IpProvider>().ok(),
                Some(provider),
                "{provider:?}: {name} does not parse back"
            );
            assert!(
                !name.is_empty()
                    && name
                        .chars()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'),
                "{provider:?}: {name} is not a kebab-case name"
            );
        }
    }

    /// Every URL is fetched by the probe as-is, so a typo is a provider that
    /// never answers.
    #[test]
    fn every_provider_url_is_an_absolute_http_url() {
        for provider in IpProvider::iter() {
            let url = url::Url::parse(provider.url())
                .unwrap_or_else(|e| panic!("{provider:?}: {} is not a URL: {e}", provider.url()));
            assert!(
                matches!(url.scheme(), "http" | "https"),
                "{provider:?}: {} is not http(s)",
                provider.url()
            );
            assert!(url.host_str().is_some(), "{provider:?}: no host");
        }
    }

    /// The Settings form ships this CSV, and a variant missing from it is a
    /// provider a user cannot select.
    #[test]
    fn the_select_cell_offers_every_variant() {
        let listed: Vec<&str> = super::SELECT_CELL
            .strip_prefix("Select:")
            .expect("the cell must declare its options")
            .split(',')
            .collect();
        let variants: Vec<String> = IpProvider::iter().map(|p| p.to_string()).collect();
        assert_eq!(
            listed,
            variants.iter().map(String::as_str).collect::<Vec<_>>()
        );
    }

    /// Captured live on 2026-09-18 (`curl` of each endpoint).
    #[test]
    fn parses_each_providers_own_body() {
        // ip-api names the address `query`.
        let ip_api = br#"{"status":"success","country":"Russia","query":"188.226.17.90"}"#;
        assert_eq!(
            IpProvider::IpApi.parse(ip_api).as_deref(),
            Some("188.226.17.90 | Russia")
        );
        // api.ip.sb, and its IPv4 counterpart, name it `ip`. api-ipv6 serves the
        // same body from the same software, but needs an IPv6 route to capture.
        let ip_sb = br#"{"region":"North Holland","city":"Amsterdam","ip":"84.32.101.85","country":"The Netherlands","country_code":"NL"}"#;
        for provider in [IpProvider::IpSb, IpProvider::IpSbIpv4, IpProvider::IpSbIpv6] {
            assert_eq!(
                provider.parse(ip_sb).as_deref(),
                Some("84.32.101.85 | The Netherlands"),
                "{provider:?}"
            );
        }
        // api.ipapi.is.
        let ipapi_is = br#"{"ip":"84.32.101.85","city":"Amsterdam","country":"The Netherlands","asn":"AS59642 UAB Cherry Servers"}"#;
        assert_eq!(
            IpProvider::IpApiIs.parse(ipapi_is).as_deref(),
            Some("84.32.101.85 | The Netherlands")
        );
    }

    /// The address field is the provider's, so one provider must not read
    /// another's body.
    #[test]
    fn a_foreign_body_is_not_an_answer() {
        let ip_api = br#"{"status":"success","country":"Russia","query":"1.2.3.4"}"#;
        let ip_sb = br#"{"ip":"1.2.3.4","country":"Russia"}"#;
        assert_eq!(IpProvider::IpSb.parse(ip_api), None);
        assert_eq!(IpProvider::IpApiIs.parse(ip_api), None);
        assert_eq!(IpProvider::IpApi.parse(ip_sb), None);
        // A refusal body and garbage are no answer either way.
        assert_eq!(IpProvider::IpApi.parse(br#"{"status":"fail"}"#), None);
        assert_eq!(IpProvider::IpSb.parse(b"<html>captive portal</html>"), None);
    }

    #[test]
    fn a_missing_country_still_yields_the_address() {
        assert_eq!(
            IpProvider::IpApi
                .parse(br#"{"query":"203.0.113.7"}"#)
                .as_deref(),
            Some("203.0.113.7 | -")
        );
    }

    /// The chain is the failover, so its first entry and its exclusions are its
    /// contract: the user's choice leads, and a family-forced provider can never
    /// be asked by accident.
    #[test]
    fn the_chain_leads_with_the_choice_and_skips_family_forced() {
        for provider in IpProvider::iter() {
            let chain: Vec<IpProvider> = provider.fallback_chain().collect();
            assert_eq!(chain.first(), Some(&provider), "{provider:?}");
            // Only the user's own choice may be family-forced.
            assert!(
                !chain.iter().skip(1).any(|p| p.is_family_forced()),
                "{provider:?}: {chain:?}"
            );
            let mut urls: Vec<&str> = chain.iter().map(|p| p.url()).collect();
            let len = urls.len();
            urls.sort_unstable();
            urls.dedup();
            assert_eq!(urls.len(), len, "{provider:?}: {chain:?}");
        }
        // The generic providers are the whole chain, in declaration order.
        assert_eq!(
            IpProvider::IpApi.fallback_chain().collect::<Vec<_>>(),
            vec![IpProvider::IpApi, IpProvider::IpSb, IpProvider::IpApiIs]
        );
        // A family-forced choice leads its own chain and still falls back.
        assert_eq!(
            IpProvider::IpSbIpv4.fallback_chain().collect::<Vec<_>>(),
            vec![
                IpProvider::IpSbIpv4,
                IpProvider::IpApi,
                IpProvider::IpSb,
                IpProvider::IpApiIs
            ]
        );
    }
}
