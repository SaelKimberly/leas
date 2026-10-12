//! Typed rule-set intermediate representation consumed by compilers, merge,
//! and the evaluation engine.

use crate::addr::{Cidr, NetAddr, PortRange};
use serde::{Deserialize, Serialize};

/// A complete routing configuration: ordered rules plus fallthrough defaults.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RuleSet {
    /// First-match-wins rule list.
    pub rules: Vec<Rule>,
    /// Route taken when no rule matches.
    pub default: DefaultRoute,
    /// When domain resolution happens relative to matching.
    pub resolve_strategy: ResolveStrategy,
    /// Must-resolve probe hostnames (spec §6 probes).
    pub probes: Vec<String>,
}

/// One conditional routing rule.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Rule {
    /// Human-readable identifier; `None` for synthesized rules.
    pub name: Option<String>,
    /// Match predicate.
    pub cond: Cond,
    /// What to do on match.
    pub action: Action,
}

/// Composable match predicate.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Cond {
    /// Every item matches.
    All(Vec<MatchItem>),
    /// Any sub-condition matches.
    Any(Vec<Self>),
    /// Logical negation of the inner condition.
    Invert(Box<Self>),
}

/// A single leaf matcher.
///
/// Externally tagged (`snake_case`): internally tagging by `kind` is
/// impossible for newtype variants like `Ports`; distinct variant names make
/// external tags unambiguous.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchItem {
    /// Destination-domain matchers, all OR-combined.
    Domain {
        exact: Vec<String>,
        suffix: Vec<String>,
        keywords: Vec<String>,
        regexes: Vec<String>,
    },
    /// Destination CIDR / private-range / geo-country matchers.
    IpCidr {
        cidrs: Vec<Cidr>,
        private: bool,
        geo_country: Vec<String>,
    },
    /// Source-side payload mirrors [`MatchItem::IpCidr`].
    SourceIpCidr {
        cidrs: Vec<Cidr>,
        private: bool,
        geo_country: Vec<String>,
    },
    /// Destination port ranges.
    Ports(Vec<PortRange>),
    /// Source port ranges.
    SourcePorts(Vec<PortRange>),
    /// Transport-protocol mask (TCP/UDP).
    Network(NetworkMask),
    /// Sniffed application protocol whitelist.
    Protocol(SniffedProtocol),
    /// Inbound tag membership.
    InboundTag { tags: Vec<String> },
    /// Outbound tag membership.
    OutboundTag { tags: Vec<String> },
}

/// Routing outcome for a matched rule.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    /// Forward to the outbound `tag`, optionally rewriting the address.
    Route {
        tag: String,
        override_addr: Option<NetAddr>,
    },
    /// Reject with a method.
    Reject { method: RejectMethod },
    /// Intercept DNS traffic into the built-in resolver.
    HijackDns,
}

/// How a rejected connection is disposed of.
#[derive(Default, Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RejectMethod {
    /// Silently drop packets.
    #[default]
    Drop,
    /// Reply with a standard refusal.
    DefaultReply,
}

/// Fallthrough behavior when no rule matches.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DefaultRoute {
    /// Forward to the outbound `tag`.
    Route { tag: String },
    /// Reject with a method.
    Reject { method: RejectMethod },
}

/// Domain-resolution timing strategy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResolveStrategy {
    /// Match without resolving; resolve only after routing.
    AsIs,
    /// Resolve when no rule matches so IP-based rules can apply.
    IfNonMatch,
}

/// Whitelist of sniffable application protocols.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SniffedProtocol {
    Http,
    Tls,
    Dns,
    /// QUIC (`Initial` packet carrying a TLS `ClientHello`).
    Quic,
}

/// Transport-protocol mask used against `ConnMeta.network`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct NetworkMask {
    /// TCP flag.
    pub tcp: bool,
    /// UDP flag.
    pub udp: bool,
}

impl NetworkMask {
    /// TCP only.
    pub const TCP: Self = Self {
        tcp: true,
        udp: false,
    };
    /// UDP only.
    pub const UDP: Self = Self {
        tcp: false,
        udp: true,
    };

    /// Bit-subset check: `self` contains `other` when every transport set in
    /// `other` is also set in `self`.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        !other.tcp | self.tcp && !other.udp | self.udp
    }
}

#[cfg(test)]
mod tests {
    use crate::addr::{Cidr, NetAddr, NetHost, PortRange};
    use crate::ir::*;

    /// Builds a rule set exercising every variant arm of every type.
    fn sample() -> RuleSet {
        RuleSet {
            rules: vec![
                // Named rule, Cond::All with one of each MatchItem arm.
                Rule {
                    name: Some("catch-all".to_owned()),
                    cond: Cond::All(vec![
                        MatchItem::Domain {
                            exact: vec!["example.com".to_owned()],
                            suffix: vec!["google.com".to_owned()],
                            keywords: vec!["github".to_owned()],
                            regexes: vec![r"^ads\.".to_owned()],
                        },
                        MatchItem::IpCidr {
                            cidrs: vec![
                                Cidr::parse("10.0.0.0/8").unwrap(),
                                Cidr::parse("fc00::/7").unwrap(),
                            ],
                            private: true,
                            geo_country: vec!["cn".to_owned()],
                        },
                        MatchItem::SourceIpCidr {
                            cidrs: vec![Cidr::parse("192.168.0.0/16").unwrap()],
                            private: false,
                            geo_country: vec![],
                        },
                        MatchItem::Ports(vec![PortRange {
                            start: 80,
                            end: 443,
                        }]),
                        MatchItem::SourcePorts(vec![PortRange {
                            start: 1000,
                            end: 1000,
                        }]),
                        MatchItem::Network(NetworkMask::TCP),
                        MatchItem::Protocol(SniffedProtocol::Http),
                        MatchItem::InboundTag {
                            tags: vec!["in-1".to_owned()],
                        },
                        MatchItem::OutboundTag {
                            tags: vec!["out-1".to_owned()],
                        },
                    ]),
                    action: Action::Route {
                        tag: "proxy".to_owned(),
                        override_addr: Some(NetAddr {
                            host: NetHost::Domain("relay.example.org".to_owned()),
                            port: 8443,
                        }),
                    },
                },
                // Anonymous rule, nested Any/Invert cond, Reject action.
                Rule {
                    name: None,
                    cond: Cond::Any(vec![
                        Cond::Invert(Box::new(Cond::All(vec![
                            MatchItem::Network(NetworkMask::UDP),
                            MatchItem::Protocol(SniffedProtocol::Dns),
                        ]))),
                        Cond::All(vec![MatchItem::Protocol(SniffedProtocol::Tls)]),
                    ]),
                    action: Action::Reject {
                        method: RejectMethod::Drop,
                    },
                },
                // HijackDns + RejectMethod::DefaultReply coverage.
                Rule {
                    name: Some("dns-hijack".to_owned()),
                    cond: Cond::All(vec![
                        MatchItem::Ports(vec![PortRange { start: 53, end: 53 }]),
                        MatchItem::Network(NetworkMask {
                            tcp: false,
                            udp: true,
                        }),
                        MatchItem::Network(NetworkMask {
                            tcp: true,
                            udp: true,
                        }),
                        MatchItem::Network(NetworkMask {
                            tcp: false,
                            udp: false,
                        }),
                    ]),
                    action: Action::HijackDns,
                },
            ],
            default: DefaultRoute::Reject {
                method: RejectMethod::DefaultReply,
            },
            resolve_strategy: ResolveStrategy::IfNonMatch,
            probes: vec!["probe.example.com".to_owned()],
        }
    }

    #[test]
    fn ruleset_json_roundtrip_lossless() {
        let rs = sample();
        let json = serde_json::to_string(&rs).expect("serialize");
        let back: RuleSet = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(rs, back);
    }

    #[test]
    fn default_route_route_variant_roundtrips() {
        let route = DefaultRoute::Route {
            tag: "direct".to_owned(),
        };
        let json = serde_json::to_string(&route).expect("serialize");
        let back: DefaultRoute = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(route, back);
    }

    #[test]
    fn network_mask_contains_truth_rows() {
        let none = NetworkMask {
            tcp: false,
            udp: false,
        };
        let tcp = NetworkMask::TCP;
        let udp = NetworkMask::UDP;
        let both = NetworkMask {
            tcp: true,
            udp: true,
        };
        // self ⊇ other rows
        assert!(none.contains(none));
        assert!(tcp.contains(tcp));
        assert!(tcp.contains(none));
        assert!(udp.contains(none));
        assert!(both.contains(tcp));
        assert!(both.contains(udp));
        assert!(both.contains(none));
        assert!(both.contains(both));
        // non-containing rows
        assert!(!none.contains(tcp));
        assert!(!none.contains(udp));
        assert!(!none.contains(both));
        assert!(!tcp.contains(udp));
        assert!(!tcp.contains(both));
        assert!(!udp.contains(tcp));
        assert!(!udp.contains(both));
    }
}
