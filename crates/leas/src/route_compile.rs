//! Compiles DB `RoutingRule` rows (Settings → Routing) into native routing IR.
//!
//! Pure mapping: no DB access, no sorting (the caller orders rows by
//! `sort_order`), no [`leas_route::engine::Engine`] construction.

use leas_db::models_toasty::RoutingRule;
use leas_route::RouteError;
use leas_route::addr::{Cidr, PortRange};
use leas_route::ir::{Action, Cond, MatchItem, NetworkMask, Rule, SniffedProtocol};

/// Compiles one [`RoutingRule`] row into a native IR [`Rule`].
///
/// Mapping (fixed item order `Domain`, `IpCidr`, `Ports`, `SourcePorts`,
/// `Network`, `Protocol`, `InboundTag`; only non-empty fields produce items):
/// - `domains` + `domain_matcher` `Some("exact")` ⇒ `Domain.exact`;
///   otherwise (None or "domain") ⇒ `Domain.suffix`.
/// - `ips`: CIDR entries ⇒ `IpCidr.cidrs`; `geoip:private` ⇒ `private`;
///   `geoip:<cc>` ⇒ `geo_country`; unparseable entries are skipped and
///   reported by [`warnings_from_row`].
/// - `ports`/`source_ports` ⇒ `Ports`/`SourcePorts` (one `PortRange` per
///   port); `network` comma-able `"tcp,udp"` ⇒ one `NetworkMask` item;
///   IANA `http`/`tls`/`dns`/`quic` protocols ⇒ AND-ed `Protocol` items;
///   `inbound_tags` ⇒ `InboundTag`; `outbound_tag` ⇒ `Action::Route`.
///
/// # Errors
/// - [`RouteError::Unsupported`] when `balancer_tag` is set (balancers
///   deferred — see routing spec §1); checked first so balancer rows never
///   fall into the empty-row rejection.
/// - [`RouteError::Parse`] on `field: "row"` when the row yields no match
///   conditions — including the bare catch-all (only `outbound_tag`), which
///   xray-core 26+ likewise rejects; on `field: "outbound_tag"` when the row
///   has conditions but nothing to route to.
pub fn rule_from_row(row: &RoutingRule, index: usize) -> Result<Rule, RouteError> {
    if row.balancer_tag.is_some() {
        return Err(RouteError::Unsupported(
            "balancers deferred — see routing spec §1",
        ));
    }
    let items = match_items(row);
    if items.is_empty() {
        return Err(RouteError::Parse {
            rule_index: index,
            field: "row",
            message: "rule has no match conditions (bare catch-all rejected)".to_owned(),
        });
    }
    let Some(tag) = row.outbound_tag.clone() else {
        return Err(RouteError::Parse {
            rule_index: index,
            field: "outbound_tag",
            message: "rule has match conditions but no outbound_tag".to_owned(),
        });
    };
    let cond = match split_protocol_alternation(items) {
        Ok(any) => any,
        Err(items) => Cond::All(items),
    };
    Ok(Rule {
        name: Some(row.id.clone()),
        cond,
        action: Action::Route {
            tag,
            override_addr: None,
        },
    })
}

/// Splits AND-ed `Protocol` leaves into a genuine `Cond::Any` over
/// per-protocol `Cond::All` arms (the engine evaluates Any since T11): a
/// multi-protocol whitelist is an OR, and AND-ing the leaves would make the
/// rule unsatisfiable. [`Err`] hands the items back untouched when there is
/// nothing to split (fewer than two `Protocol` items). Other items are shared
/// into every arm.
fn split_protocol_alternation(items: Vec<MatchItem>) -> Result<Cond, Vec<MatchItem>> {
    let mut protocols: Vec<SniffedProtocol> = items
        .iter()
        .filter_map(|it| match it {
            MatchItem::Protocol(p) => Some(*p),
            _ => None,
        })
        .collect();
    if protocols.len() < 2 {
        return Err(items);
    }
    protocols.dedup();
    let shared: Vec<MatchItem> = items
        .into_iter()
        .filter(|it| !matches!(it, MatchItem::Protocol(_)))
        .collect();
    Ok(Cond::Any(
        protocols
            .into_iter()
            .map(|p| {
                let mut arm = shared.clone();
                arm.push(MatchItem::Protocol(p));
                Cond::All(arm)
            })
            .collect(),
    ))
}

/// Caller-visible warnings for one row (never silently dropped):
/// - unparseable `ips` entries that are neither CIDRs nor `geoip:` prefixes;
/// - `protocols` names outside IANA `http`/`tls`/`dns`/`quic`;
/// - `network` tokens outside `tcp`/`udp`;
/// - legacy per-row `domain_strategy` (xray noise; ignored);
/// - `rule_set_file`/`rule_set_url` ruleset references (no native
///   equivalent yet).
#[must_use]
pub fn warnings_from_row(row: &RoutingRule) -> Vec<String> {
    let mut out = Vec::new();
    for ip in &row.ips {
        if Cidr::parse(ip).is_err() && !ip.starts_with("geoip:") {
            out.push(format!("ips entry `{ip}` is not a CIDR or geoip: prefix"));
        }
    }
    for p in &row.protocols {
        if sniffed(p).is_none() {
            out.push(format!("protocol `{p}` is not http/tls/dns/quic"));
        }
    }
    for tok in row
        .network
        .as_deref()
        .into_iter()
        .flat_map(|n| n.split(',').map(str::trim))
        .filter(|t| !t.is_empty())
    {
        if !matches!(tok, "tcp" | "udp") {
            out.push(format!("network token `{tok}` is not tcp/udp"));
        }
    }
    if let Some(ds) = &row.domain_strategy {
        out.push(format!(
            "per-row domain_strategy `{ds}` is xray legacy noise; ignored"
        ));
    }
    if let Some(f) = &row.rule_set_file {
        out.push(format!(
            "rule_set_file `{f}` has no native equivalent; ruleset refs deferred"
        ));
    }
    if let Some(u) = &row.rule_set_url {
        out.push(format!(
            "rule_set_url `{u}` has no native equivalent; ruleset refs deferred"
        ));
    }
    out
}

/// Builds match items in the fixed contract order; only non-empty fields
/// produce items. Unparseable `ips` entries and unknown protocols/network
/// tokens are skipped here and reported by [`warnings_from_row`].
fn match_items(row: &RoutingRule) -> Vec<MatchItem> {
    let mut items = Vec::new();

    if !row.domains.is_empty() {
        let exact = row.domain_matcher.as_deref() == Some("exact");
        let (exact, suffix) = if exact {
            (row.domains.clone(), Vec::new())
        } else {
            (Vec::new(), row.domains.clone())
        };
        items.push(MatchItem::Domain {
            exact,
            suffix,
            keywords: Vec::new(),
            regexes: Vec::new(),
        });
    }

    let mut cidrs = Vec::new();
    let mut geo_country = Vec::new();
    let mut private = false;
    for ip in &row.ips {
        if let Some(cc) = ip.strip_prefix("geoip:") {
            if cc.eq_ignore_ascii_case("private") {
                private = true;
            } else {
                geo_country.push(cc.to_owned());
            }
        } else if let Ok(c) = Cidr::parse(ip) {
            cidrs.push(c);
        }
    }
    if !cidrs.is_empty() || private || !geo_country.is_empty() {
        items.push(MatchItem::IpCidr {
            cidrs,
            private,
            geo_country,
        });
    }

    let ports: Vec<PortRange> = row
        .ports
        .iter()
        .map(|&p| PortRange { start: p, end: p })
        .collect();
    if !ports.is_empty() {
        items.push(MatchItem::Ports(ports));
    }

    let source_ports: Vec<PortRange> = row
        .source_ports
        .iter()
        .map(|&p| PortRange { start: p, end: p })
        .collect();
    if !source_ports.is_empty() {
        items.push(MatchItem::SourcePorts(source_ports));
    }

    if let Some(n) = &row.network {
        let mut mask = NetworkMask {
            tcp: false,
            udp: false,
        };
        for tok in n.split(',').map(str::trim).filter(|t| !t.is_empty()) {
            match tok {
                "tcp" => mask.tcp = true,
                "udp" => mask.udp = true,
                _ => {}
            }
        }
        if mask.tcp || mask.udp {
            items.push(MatchItem::Network(mask));
        }
    }

    for p in &row.protocols {
        if let Some(sp) = sniffed(p) {
            items.push(MatchItem::Protocol(sp));
        }
    }

    if !row.inbound_tags.is_empty() {
        items.push(MatchItem::InboundTag {
            tags: row.inbound_tags.clone(),
        });
    }

    items
}

/// IANA protocol name → sniffable whitelisted protocol.
fn sniffed(p: &str) -> Option<SniffedProtocol> {
    match p {
        "http" => Some(SniffedProtocol::Http),
        "tls" => Some(SniffedProtocol::Tls),
        "dns" => Some(SniffedProtocol::Dns),
        "quic" => Some(SniffedProtocol::Quic),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use leas_route::addr::PortRange;
    use leas_route::ir::MatchItem as MI;

    /// Minimal valid row: one domain condition, one outbound tag.
    fn row() -> RoutingRule {
        RoutingRule {
            id: "r1".to_string(),
            group_id: None,
            r#type: 0,
            domain_matcher: None,
            domains: vec!["example.com".to_string()],
            ips: Vec::new(),
            inbound_tags: Vec::new(),
            ports: Vec::new(),
            source_ports: Vec::new(),
            network: None,
            protocols: Vec::new(),
            domain_strategy: None,
            outbound_tag: Some("direct".to_string()),
            balancer_tag: None,
            rule_set_file: None,
            rule_set_url: None,
            sort_order: None,
        }
    }

    /// Row with every column set to a non-default value.
    fn full_row() -> RoutingRule {
        RoutingRule {
            id: "full".to_string(),
            group_id: Some("g1".to_string()),
            r#type: 7,
            domain_matcher: Some("exact".to_string()),
            domains: vec!["a.com".to_string()],
            ips: vec![
                "10.0.0.0/8".to_string(),
                "geoip:private".to_string(),
                "geoip:cn".to_string(),
                "nope".to_string(),
            ],
            inbound_tags: vec!["socks-in".to_string()],
            ports: vec![80, 443],
            source_ports: vec![1000],
            network: Some("tcp,udp".to_string()),
            protocols: vec![
                "http".to_string(),
                "tls".to_string(),
                "dns".to_string(),
                "quic".to_string(),
            ],
            domain_strategy: Some("AsIs".to_string()),
            outbound_tag: Some("proxy".to_string()),
            balancer_tag: None,
            rule_set_file: Some("/etc/geosite.dat".to_string()),
            rule_set_url: Some("https://example.com/rs.json".to_string()),
            sort_order: Some(3),
        }
    }

    fn items_of(rule: &Rule) -> &Vec<MatchItem> {
        let Cond::All(items) = &rule.cond else {
            panic!("expected Cond::All, got {:?}", rule.cond);
        };
        items
    }

    /// Shared non-Protocol items of a multi-protocol row's per-protocol arms.
    fn shared_items_of(rule: &Rule) -> Vec<MatchItem> {
        let Cond::Any(arms) = &rule.cond else {
            panic!("expected Cond::Any, got {:?}", rule.cond);
        };
        let Cond::All(items) = &arms[0] else {
            panic!("each arm must be Cond::All");
        };
        items
            .iter()
            .filter(|it| !matches!(it, MatchItem::Protocol(_)))
            .cloned()
            .collect()
    }

    fn arm_protocols(rule: &Rule) -> Vec<SniffedProtocol> {
        let Cond::Any(arms) = &rule.cond else {
            panic!("expected Cond::Any, got {:?}", rule.cond);
        };
        arms.iter()
            .filter_map(|arm| match arm {
                Cond::All(items) => items.iter().find_map(|it| match it {
                    MatchItem::Protocol(p) => Some(*p),
                    _ => None,
                }),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn full_row_maps_every_column() {
        let r = full_row();
        let rule = rule_from_row(&r, 0).expect("full row compiles");
        assert_eq!(rule.name.as_deref(), Some("full"));
        assert_eq!(
            rule.action,
            Action::Route {
                tag: "proxy".to_string(),
                override_addr: None
            }
        );
        // Multi-protocol row: genuine Cond::Any over per-protocol arms
        // sharing every other item (ANDing the leaves would be
        // unsatisfiable).
        assert_eq!(
            arm_protocols(&rule),
            vec![
                SniffedProtocol::Http,
                SniffedProtocol::Tls,
                SniffedProtocol::Dns,
                SniffedProtocol::Quic,
            ]
        );
        assert_eq!(
            shared_items_of(&rule),
            vec![
                MatchItem::Domain {
                    exact: vec!["a.com".to_string()],
                    suffix: vec![],
                    keywords: vec![],
                    regexes: vec![],
                },
                MatchItem::IpCidr {
                    cidrs: vec![Cidr::parse("10.0.0.0/8").unwrap()],
                    private: true,
                    geo_country: vec!["cn".to_string()],
                },
                MatchItem::Ports(vec![
                    PortRange { start: 80, end: 80 },
                    PortRange {
                        start: 443,
                        end: 443
                    },
                ]),
                MatchItem::SourcePorts(vec![PortRange {
                    start: 1000,
                    end: 1000
                }]),
                MatchItem::Network(NetworkMask {
                    tcp: true,
                    udp: true
                }),
                MatchItem::InboundTag {
                    tags: vec!["socks-in".to_string()],
                },
            ]
        );
        // Warnings: "nope" ip, domain_strategy, rule_set_file, rule_set_url.
        // "quic" is a valid sniffed protocol (no warning since T-QUIC).
        let ws = warnings_from_row(&r);
        assert_eq!(ws.len(), 4, "warnings: {ws:?}");
        assert!(ws.iter().any(|w| w.contains("nope")));
        assert!(ws.iter().any(|w| w.contains("AsIs")));
        assert!(ws.iter().any(|w| w.contains("/etc/geosite.dat")));
        assert!(ws.iter().any(|w| w.contains("https://example.com/rs.json")));
    }

    #[test]
    fn domain_matcher_selects_exact_vs_suffix() {
        let mut r = row();
        let rule = rule_from_row(&r, 0).unwrap();
        assert_eq!(
            items_of(&rule)[0],
            MI::Domain {
                exact: vec![],
                suffix: vec!["example.com".to_string()],
                keywords: vec![],
                regexes: vec![],
            }
        );

        r.domain_matcher = Some("domain".to_string());
        let rule = rule_from_row(&r, 0).unwrap();
        assert_eq!(
            items_of(&rule)[0],
            MI::Domain {
                exact: vec![],
                suffix: vec!["example.com".to_string()],
                keywords: vec![],
                regexes: vec![],
            }
        );

        r.domain_matcher = Some("exact".to_string());
        let rule = rule_from_row(&r, 0).unwrap();
        assert_eq!(
            items_of(&rule)[0],
            MI::Domain {
                exact: vec!["example.com".to_string()],
                suffix: vec![],
                keywords: vec![],
                regexes: vec![],
            }
        );
    }

    #[test]
    fn balancer_tag_is_unsupported() {
        let mut r = row();
        r.balancer_tag = Some("bal".to_string());
        assert!(matches!(
            rule_from_row(&r, 3),
            Err(RouteError::Unsupported(msg)) if msg.contains("balancers deferred")
        ));
        // Balancer is checked before the empty-row rejection.
        let mut bare = row();
        bare.domains = Vec::new();
        bare.outbound_tag = None;
        bare.balancer_tag = Some("bal".to_string());
        assert!(matches!(
            rule_from_row(&bare, 0),
            Err(RouteError::Unsupported(_))
        ));
    }

    #[test]
    fn empty_and_catch_all_rows_rejected() {
        // Only an outbound tag, no conditions: bare catch-all (xray-core 26+
        // rejects conditionless rules).
        let mut r = row();
        r.domains = Vec::new();
        assert!(matches!(
            rule_from_row(&r, 2),
            Err(RouteError::Parse {
                rule_index: 2,
                field: "row",
                ..
            })
        ));
        // Fully empty row.
        let bare = RoutingRule {
            id: "bare".to_string(),
            group_id: None,
            r#type: 0,
            domain_matcher: None,
            domains: Vec::new(),
            ips: Vec::new(),
            inbound_tags: Vec::new(),
            ports: Vec::new(),
            source_ports: Vec::new(),
            network: None,
            protocols: Vec::new(),
            domain_strategy: None,
            outbound_tag: None,
            balancer_tag: None,
            rule_set_file: None,
            rule_set_url: None,
            sort_order: None,
        };
        assert!(matches!(
            rule_from_row(&bare, 5),
            Err(RouteError::Parse {
                rule_index: 5,
                field: "row",
                ..
            })
        ));
        // Conditions without an outbound tag: nothing to route to.
        let mut r = row();
        r.outbound_tag = None;
        assert!(matches!(
            rule_from_row(&r, 1),
            Err(RouteError::Parse {
                rule_index: 1,
                field: "outbound_tag",
                ..
            })
        ));
    }

    #[test]
    fn unparseable_ip_entry_warns_not_errors() {
        let mut r = row();
        r.ips = vec!["not-a-cidr".to_string()];
        let rule = rule_from_row(&r, 0).unwrap();
        assert_eq!(items_of(&rule).len(), 1, "only the Domain item survives");
        let ws = warnings_from_row(&r);
        assert_eq!(ws.len(), 1);
        assert!(ws[0].contains("not-a-cidr"), "warning: {}", ws[0]);
    }

    #[test]
    fn warnings_report_rule_set_and_legacy_fields() {
        let mut r = row();
        assert!(
            warnings_from_row(&r).is_empty(),
            "clean row has no warnings"
        );

        r.rule_set_file = Some("geosite.dat".to_string());
        r.rule_set_url = Some("https://example.com/rs.json".to_string());
        r.domain_strategy = Some("IPIfNonMatch".to_string());
        r.protocols = vec!["http".to_string(), "snmp".to_string()];
        r.ips = vec!["999.1.2.3/8".to_string()];
        r.network = Some("tcp,banana".to_string());

        let ws = warnings_from_row(&r);
        assert_eq!(
            ws.len(),
            6,
            "ip+protocol+network+domain_strategy+file+url: {ws:?}"
        );
        assert!(ws.iter().any(|w| w.contains("geosite.dat")));
        assert!(ws.iter().any(|w| w.contains("https://example.com/rs.json")));
        assert!(ws.iter().any(|w| w.contains("IPIfNonMatch")));
        assert!(ws.iter().any(|w| w.contains("snmp")));
        assert!(ws.iter().any(|w| w.contains("999.1.2.3/8")));
        assert!(ws.iter().any(|w| w.contains("banana")));
        // "tcp" still parses out of the mixed network field.
        let rule = rule_from_row(&r, 0).unwrap();
        assert!(items_of(&rule).contains(&MI::Network(NetworkMask {
            tcp: true,
            udp: false
        })));
    }
}
