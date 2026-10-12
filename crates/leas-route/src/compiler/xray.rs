//! Xray-core routing JSON compiler.
//!
//! Vocabulary mapping (spec §4, xray rules):
//!
//! | xray token / field            | IR target                                  |
//! |-------------------------------|--------------------------------------------|
//! | bare host in `domain`         | `Domain.exact` AND `Domain.suffix` pair    |
//! | `domain:x`                    | suffix + exact pair (`x`, `x`)             |
//! | `keyword:x`                   | `Domain.keywords`                          |
//! | `regexp:x`                    | `Domain.regexes`                           |
//! | `ext:`                        | [`RouteError::Parse`] (file lists deferred)|
//! | `geosite:`                    | [`RouteError::Parse`] (.dat loader deferred)|
//! | CIDR entry in `ip`            | `IpCidr.cidrs`                             |
//! | `geoip:private`               | `IpCidr.private = true`                    |
//! | `geoip:<cc>`                  | `IpCidr.geo_country` (inert until Engine)  |
//! | `ports` `"80,443,1000-2000"`  | `Ports`                                    |
//! | `protocol` http/tls/dns/quic| `Protocol`; anything else is unsupported   |
//! | `outboundTag`                 | `Action::Route { tag }`                    |
//!
//! A rule whose item set ends up empty is skipped (no matchable condition)
//! with a warning. Unknown object keys are tolerated as warnings; unknown
//! *values* abort with positional [`RouteError::Parse`]. With no fallback
//! key present, `ruleset.default` is the documented constant
//! [`DEFAULT_FALLBACK_TAG`].

use crate::addr::{Cidr, PortRange};
use crate::error::RouteError;
use crate::ir::{
    Action, Cond, DefaultRoute, MatchItem, NetworkMask, ResolveStrategy, Rule, RuleSet,
    SniffedProtocol,
};

use super::{CompileOutput, field_strings};

/// Fallback tag when the config has no default/fallback routing key.
pub const DEFAULT_FALLBACK_TAG: &str = "proxy";

/// Compiles an Xray-core `routing` JSON document into IR.
///
/// Configuration-level warnings (no rules key, unknown strategy, unknown
/// config keys) are reported under rule index [`CONFIG_WARNING_INDEX`].
pub fn compile_xray(json_text: &str) -> Result<CompileOutput, RouteError> {
    let root: serde_json::Value = serde_json::from_str(json_text)
        .map_err(|e| parse_err(CONFIG_WARNING_INDEX, "root", e.to_string()))?;
    let routing = root
        .get("routing")
        .ok_or_else(|| parse_err(CONFIG_WARNING_INDEX, "routing", "missing routing block"))?
        .as_object()
        .ok_or_else(|| parse_err(CONFIG_WARNING_INDEX, "routing", "not an object"))?;

    let mut warnings: Vec<(usize, String)> = Vec::new();
    let resolve_strategy = match routing.get("domainStrategy").and_then(Value::as_str) {
        None | Some("") => ResolveStrategy::AsIs,
        Some(s) if s.eq_ignore_ascii_case("AsIs") => ResolveStrategy::AsIs,
        // ponytail: IPOnDemand's eager-resolve-every-hop variant is folded
        // into IfNonMatch; split it out only when a caller needs to tell.
        Some(s) if s.eq_ignore_ascii_case("IPIfNonMatch") => ResolveStrategy::IfNonMatch,
        Some(s) if s.eq_ignore_ascii_case("IPOnDemand") => {
            warnings.push((
                CONFIG_WARNING_INDEX,
                format!(
                    "domainStrategy {s}: compiled as IfNonMatch; eager on-demand \
                         resolution distinction is deferred"
                ),
            ));
            ResolveStrategy::IfNonMatch
        }
        Some(other) => {
            return Err(parse_err(
                CONFIG_WARNING_INDEX,
                "domainStrategy",
                format!("unknown strategy {other:?}"),
            ));
        }
    };

    let mut rules: Vec<Rule> = Vec::new();
    if let Some(rules_v) = routing.get("rules") {
        let arr = rules_v
            .as_array()
            .ok_or_else(|| parse_err(CONFIG_WARNING_INDEX, "rules", "rules must be an array"))?;
        for (i, rv) in arr.iter().enumerate() {
            let obj = rv
                .as_object()
                .ok_or_else(|| parse_err(i, "rule", "rule must be an object"))?;
            for (key, val) in obj {
                if !KNOWN_RULE_KEYS.contains(&key.as_str()) {
                    warnings.push((i, format!("ignored unknown key `{key}`: {val}")));
                }
            }

            let ty = obj.get("type").and_then(Value::as_str).unwrap_or("");
            if ty != "field" {
                return Err(parse_err(
                    i,
                    "type",
                    format!("only \"field\" rules are supported, got {ty:?}"),
                ));
            }
            let tag = obj
                .get("outboundTag")
                .and_then(Value::as_str)
                .filter(|t| !t.is_empty())
                .ok_or_else(|| parse_err(i, "outboundTag", "missing or empty outbound tag"))?;
            let action = Action::Route {
                tag: tag.to_owned(),
                override_addr: None,
            };

            let mut domains = DomainBucket {
                exact: vec![],
                suffix: vec![],
                keywords: vec![],
                regexes: vec![],
            };
            let mut ip = IpCidr::default();
            let mut ports: Vec<PortRange> = vec![];
            let mut source_ports: Vec<PortRange> = vec![];
            let mut network = NetworkMask {
                tcp: false,
                udp: false,
            };
            let mut inbound_tags: Vec<String> = vec![];
            let mut protocols: Vec<SniffedProtocol> = vec![];

            // Upstream Xray accepts camelCase AND a few legacy snake_case
            // spellings (`port`/`sourcePort` predate `ports`/`sourcePorts`;
            // `domains` mirrors `domain`). Unknown keys warn but pass.
            for (field, target) in [
                ("domain", 0u8),
                ("domains", 0),
                ("ip", 1),
                ("ports", 2),
                ("port", 2),
                ("sourcePorts", 3),
                ("sourcePort", 3),
                ("network", 4),
                ("inboundTag", 5),
                ("protocol", 6),
            ] {
                let Some(v) = obj.get(field) else {
                    continue;
                };
                match target {
                    0 => collect_domain(v, i, &mut domains)?,
                    1 => collect_ip(v, i, &mut ip)?,
                    2 => ports = parse_ports(v, i, "ports")?,
                    3 => source_ports = parse_ports(v, i, "sourcePorts")?,
                    4 => network = parse_network(v, i)?,
                    5 => inbound_tags = field_strings(v, i, "inboundTag")?,
                    _ => collect_protocols(v, i, &mut protocols)?,
                }
            }

            let mut items: Vec<MatchItem> = Vec::new();
            if !domains.exact.is_empty()
                || !domains.suffix.is_empty()
                || !domains.keywords.is_empty()
                || !domains.regexes.is_empty()
            {
                let DomainBucket {
                    exact,
                    suffix,
                    keywords,
                    regexes,
                } = domains;
                items.push(MatchItem::Domain {
                    exact,
                    suffix,
                    keywords,
                    regexes,
                });
            }
            if !ip.cidrs.is_empty() || ip.private || !ip.geo_country.is_empty() {
                items.push(MatchItem::IpCidr {
                    cidrs: std::mem::take(&mut ip.cidrs),
                    private: ip.private,
                    geo_country: std::mem::take(&mut ip.geo_country),
                });
            }
            if !ports.is_empty() {
                items.push(MatchItem::Ports(ports));
            }
            if !source_ports.is_empty() {
                items.push(MatchItem::SourcePorts(source_ports));
            }
            if network.tcp || network.udp {
                items.push(MatchItem::Network(network));
            }
            if !inbound_tags.is_empty() {
                items.push(MatchItem::InboundTag { tags: inbound_tags });
            }
            if items.is_empty() && protocols.is_empty() {
                warnings.push((i, "rule has no matchable condition; skipped".to_owned()));
                continue;
            }
            // A multi-protocol whitelist is an OR over sniff results while
            // every other item is an AND. `Cond::All` only holds
            // `MatchItem`s (and today's engine rejects `Cond::Any`), so the
            // conjunction is expanded distributively — (A∧B∧p) ∨ (A∧B∧q) —
            // into one flat rule per protocol value sharing this action;
            // first-match semantics are preserved.
            match protocols.len() {
                0 => rules.push(Rule {
                    name: None,
                    cond: Cond::All(items),
                    action,
                }),
                1 => {
                    items.push(MatchItem::Protocol(protocols[0]));
                    rules.push(Rule {
                        name: None,
                        cond: Cond::All(items),
                        action,
                    });
                }
                _ => {
                    for p in protocols {
                        let mut sub = items.clone();
                        sub.push(MatchItem::Protocol(p));
                        rules.push(Rule {
                            name: None,
                            cond: Cond::All(sub),
                            action: action.clone(),
                        });
                    }
                }
            }
        }
    } else {
        warnings.push((
            CONFIG_WARNING_INDEX,
            "routing block declares no rules".to_owned(),
        ));
    }

    Ok(CompileOutput {
        ruleset: RuleSet {
            rules,
            default: DefaultRoute::Route {
                tag: DEFAULT_FALLBACK_TAG.to_owned(),
            },
            resolve_strategy,
            probes: vec![],
        },
        warnings,
    })
}

/// Rule index used for configuration-level (non-rule) warnings and errors.
const CONFIG_WARNING_INDEX: usize = 0;

type Value = serde_json::Value;

fn parse_err(rule_index: usize, field: &'static str, message: impl Into<String>) -> RouteError {
    RouteError::Parse {
        rule_index,
        field,
        message: message.into(),
    }
}

/// Keys understood on an xray `field` rule; anything else warns but passes.
/// `port`/`sourcePort` are legacy aliases of `ports`/`sourcePorts`;
/// `domains` mirrors `domain` (both spellings appear in upstream configs).
const KNOWN_RULE_KEYS: [&str; 12] = [
    "type",
    "outboundTag",
    "domain",
    "domains",
    "ip",
    "ports",
    "port",
    "sourcePorts",
    "sourcePort",
    "network",
    "inboundTag",
    "protocol",
];

struct DomainBucket {
    exact: Vec<String>,
    suffix: Vec<String>,
    keywords: Vec<String>,
    regexes: Vec<String>,
}

#[derive(Default)]
struct IpCidr {
    cidrs: Vec<Cidr>,
    private: bool,
    geo_country: Vec<String>,
}

fn collect_domain(v: &Value, i: usize, d: &mut DomainBucket) -> Result<(), RouteError> {
    for tok in field_strings(v, i, "domain")? {
        if let Some(rest) = tok.strip_prefix("geosite:") {
            return Err(parse_err(
                i,
                "domain",
                format!("geosite lists (.dat loaders) are not supported yet: geosite:{rest}"),
            ));
        }
        if let Some(rest) = tok.strip_prefix("ext:") {
            return Err(parse_err(
                i,
                "domain",
                format!("external file lists are not supported yet: ext:{rest}"),
            ));
        }
        if let Some(kw) = tok.strip_prefix("keyword:") {
            d.keywords.push(kw.to_owned());
        } else if let Some(re) = tok.strip_prefix("regexp:") {
            d.regexes.push(re.to_owned());
        } else {
            // Bare host or domain:x: upstream semantics self-match the bare
            // domain too, so register BOTH suffix and exact entries.
            let host = tok.strip_prefix("domain:").unwrap_or(&tok);
            d.suffix.push(host.to_owned());
            d.exact.push(host.to_owned());
        }
    }
    Ok(())
}

fn collect_ip(v: &Value, i: usize, out: &mut IpCidr) -> Result<(), RouteError> {
    for tok in field_strings(v, i, "ip")? {
        if let Some(cc) = tok.strip_prefix("geoip:") {
            if cc.eq_ignore_ascii_case("private") {
                out.private = true;
            } else {
                out.geo_country.push(cc.to_owned());
            }
        } else {
            // Single addresses have no prefix length; treat them as full hosts.
            let spec = if tok.contains('/') {
                tok.clone()
            } else {
                let bits = if tok.contains(':') { "/128" } else { "/32" };
                format!("{tok}{bits}")
            };
            let cidr = Cidr::parse(&spec).map_err(|e| remap_rule(e, i, "ip"))?;
            out.cidrs.push(cidr);
        }
    }
    Ok(())
}

const fn remap_rule(mut e: RouteError, rule_index: usize, field: &'static str) -> RouteError {
    if let RouteError::Parse {
        rule_index: idx,
        field: f,
        ..
    } = &mut e
    {
        *idx = rule_index;
        *f = field;
    }
    e
}

/// Port field values: string, bare JSON number, or arrays thereof (upstream
/// router.go `IntList`/`PortList` accepts both shapes). Numbers stringify;
/// anything else falls through to the string-array error.
fn port_strings(
    v: &serde_json::Value,
    rule_index: usize,
    field: &'static str,
) -> Result<Vec<String>, RouteError> {
    match v {
        serde_json::Value::Number(n) => Ok(vec![n.to_string()]),
        serde_json::Value::Array(items) => {
            let mut out = Vec::with_capacity(items.len());
            for it in items {
                match it {
                    serde_json::Value::Number(n) => out.push(n.to_string()),
                    other => out.extend(field_strings(other, rule_index, field)?),
                }
            }
            Ok(out)
        }
        other => field_strings(other, rule_index, field),
    }
}

fn parse_ports(v: &Value, i: usize, field: &'static str) -> Result<Vec<PortRange>, RouteError> {
    let mut ranges = Vec::new();
    for part in port_strings(v, i, field)?.join(",").split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let (start, end) = match part.split_once('-') {
            Some((a, b)) => (a.trim(), b.trim()),
            None => (part, part),
        };
        let start: u16 = start
            .parse()
            .map_err(|_| parse_err(i, field, format!("invalid port range `{part}`")))?;
        let end: u16 = end
            .parse()
            .map_err(|_| parse_err(i, field, format!("invalid port range `{part}`")))?;
        ranges.push(PortRange { start, end });
    }
    Ok(ranges)
}

fn parse_network(v: &Value, i: usize) -> Result<NetworkMask, RouteError> {
    let mut mask = NetworkMask {
        tcp: false,
        udp: false,
    };
    for tok in field_strings(v, i, "network")?.join(",").split(',') {
        let tok = tok.trim();
        if tok.is_empty() {
            continue;
        }
        if tok.eq_ignore_ascii_case("tcp") && !mask.tcp {
            mask.tcp = true;
        } else if tok.eq_ignore_ascii_case("udp") && !mask.udp {
            mask.udp = true;
        } else {
            return Err(parse_err(
                i,
                "network",
                format!("unknown network token {tok:?}"),
            ));
        }
    }
    Ok(mask)
}
fn collect_protocols(
    v: &Value,
    i: usize,
    out: &mut Vec<SniffedProtocol>,
) -> Result<(), RouteError> {
    for tok in field_strings(v, i, "protocol")? {
        let p = if tok.eq_ignore_ascii_case("http") {
            SniffedProtocol::Http
        } else if tok.eq_ignore_ascii_case("tls") {
            SniffedProtocol::Tls
        } else if tok.eq_ignore_ascii_case("dns") {
            SniffedProtocol::Dns
        } else if tok.eq_ignore_ascii_case("quic") {
            SniffedProtocol::Quic
        } else {
            return Err(RouteError::Unsupported(
                "sniffed protocol outside http/tls/dns/quic",
            ));
        };
        out.push(p);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Decision;

    const FIXTURE: &str = include_str!("../../tests/fixtures/xray_sample.json");

    fn err_at(txt: &str, idx: usize) -> RouteError {
        match compile_xray(txt) {
            Err(e @ RouteError::Parse { rule_index, .. }) if rule_index == idx => e,
            other => panic!("expected Parse at {idx}, got {other:?}"),
        }
    }

    #[test]
    fn fixture_parses_to_golden_ir() {
        let out = compile_xray(FIXTURE).unwrap();
        assert_eq!(out.ruleset.rules.len(), 3);
        assert_eq!(out.warnings.len(), 0);
        assert!(
            matches!(&out.ruleset.default, DefaultRoute::Route { tag } if tag == DEFAULT_FALLBACK_TAG)
        );
        assert_eq!(out.ruleset.resolve_strategy, ResolveStrategy::AsIs);
        assert_eq!(out.ruleset.probes.len(), 0);

        // Rule 0: domain:doubleclick.net (suffix+exact pair), keyword:adservice.
        let r0 = &out.ruleset.rules[0];
        let Cond::All(items) = &r0.cond else {
            panic!("rule 0 cond");
        };
        assert_eq!(items.len(), 1);
        assert_eq!(
            items[0],
            MatchItem::Domain {
                exact: vec!["doubleclick.net".into()],
                suffix: vec!["doubleclick.net".into()],
                keywords: vec!["adservice".into()],
                regexes: vec![],
            }
        );
        assert_eq!(
            r0.action,
            Action::Route {
                tag: "block".into(),
                override_addr: None
            }
        );

        // Rule 1: geoip:private + 10.0.0.0/8; ports 80,443,1000-2000.
        let r1 = &out.ruleset.rules[1];
        let Cond::All(items) = &r1.cond else {
            panic!("rule 1 cond");
        };
        assert_eq!(
            items[0],
            MatchItem::IpCidr {
                cidrs: vec![Cidr::parse("10.0.0.0/8").unwrap()],
                private: true,
                geo_country: vec![],
            }
        );
        assert_eq!(
            items[1],
            MatchItem::Ports(vec![
                PortRange { start: 80, end: 80 },
                PortRange {
                    start: 443,
                    end: 443
                },
                PortRange {
                    start: 1000,
                    end: 2000
                },
            ])
        );
        assert_eq!(
            r1.action,
            Action::Route {
                tag: "direct".into(),
                override_addr: None
            }
        );

        // Rule 2: bare example.com is suffix+exact pair; network tcp,udp.
        let r2 = &out.ruleset.rules[2];
        let Cond::All(items) = &r2.cond else {
            panic!("rule 2 cond");
        };
        assert_eq!(
            items[0],
            MatchItem::Domain {
                exact: vec!["example.com".into()],
                suffix: vec!["example.com".into()],
                keywords: vec![],
                regexes: vec![]
            }
        );
        assert_eq!(
            items[1],
            MatchItem::Network(NetworkMask {
                tcp: true,
                udp: true
            })
        );
        assert_eq!(
            r2.action,
            Action::Route {
                tag: "proxy-a".into(),
                override_addr: None
            }
        );
    }

    #[test]
    fn upstream_port_spellings_and_domains_key_compile() {
        // Mirrors upstream app/router/router_test.go shapes: `"port": 123`
        // (bare JSON number), `"port": "53, 443, 1000-2000"` (comma string),
        // and the `domains`/`sourcePort` alias spellings. All must compile —
        // an unknown-key rejection here would silently drop the port
        // condition and widen the rule.
        let txt = r#"{
          "routing": {
            "domainStrategy": "AsIs",
            "rules": [
              {
                "type": "field",
                "outboundTag": "num",
                "domains": ["example.com"],
                "port": 123
              },
              {
                "type": "field",
                "outboundTag": "csv",
                "port": "53, 443, 1000-2000",
                "sourcePort": "9050"
              },
              {
                "type": "field",
                "outboundTag": "arr",
                "port": [80, "81-82"],
                "domains": ["regexp:^a\\.com$"]
              }
            ]
          }
        }"#;
        let out = compile_xray(txt).unwrap();
        assert_eq!(
            out.warnings.len(),
            0,
            "alias keys are KNOWN: {:?}",
            out.warnings
        );
        assert_eq!(out.ruleset.rules.len(), 3);
        let port_ranges = |idx: usize| match &out.ruleset.rules[idx].cond {
            Cond::All(items) => items.iter().find_map(|it| match it {
                MatchItem::Ports(r) => Some(r.clone()),
                _ => None,
            }),
            _ => panic!("rule {idx} must be flat All"),
        };
        assert_eq!(
            port_ranges(0),
            Some(vec![PortRange {
                start: 123,
                end: 123
            }])
        );
        assert_eq!(
            port_ranges(1),
            Some(vec![
                PortRange { start: 53, end: 53 },
                PortRange {
                    start: 443,
                    end: 443
                },
                PortRange {
                    start: 1000,
                    end: 2000
                },
            ])
        );
        assert_eq!(
            port_ranges(2),
            Some(vec![
                PortRange { start: 80, end: 80 },
                PortRange { start: 81, end: 82 },
            ])
        );
        // sourcePort alias landed on the source side.
        match &out.ruleset.rules[1].cond {
            Cond::All(items) => assert!(items.iter().any(
                |it| matches!(it, MatchItem::SourcePorts(r) if r.len() == 1 && r[0].start == 9050)
            )),
            _ => panic!(),
        }
    }

    #[test]
    fn unsupported_dat_geosite_is_positional_error() {
        let txt = r#"{ "routing": { "rules": [{ "type":"field","outboundTag":"x",
            "domain":["geosite:cn"] }] } }"#;
        match compile_xray(txt) {
            Err(RouteError::Parse { rule_index: 0, .. }) => {}
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn ext_lists_are_positional_errors() {
        let txt = r#"{ "routing": { "rules": [{ "type":"field","outboundTag":"x",
            "domain":["ext:cn.dat:ad"] }] } }"#;
        err_at(txt, 0);
        let two_rules = r#"{"routing":{"rules":[
            {"type":"field","outboundTag":"a"},
            {"type":"field","outboundTag":"x","domain":["ext:x.dat:spam"]}]}
        }"#;
        err_at(two_rules, 1);
    }

    #[test]
    fn regexp_and_geoip_country_map_to_ir() {
        let txt = r#"{"routing":{"rules":[
            {"type":"field","outboundTag":"a",
             "domain":["regexp:^(?!.*\\bgoogle\\b)","regexp:www\\.example\\.[a-z]{2,3}$"],
             "ip":["geoip:cn","2001:db8::/32"]}]}}"#;
        let out = compile_xray(txt).unwrap();
        let Cond::All(items) = &out.ruleset.rules[0].cond else {
            panic!();
        };
        assert_eq!(
            items[0],
            MatchItem::Domain {
                exact: vec![],
                suffix: vec![],
                keywords: vec![],
                regexes: vec![r"^(?!.*\bgoogle\b)", r"www\.example\.[a-z]{2,3}$"]
                    .into_iter()
                    .map(Into::into)
                    .collect(),
            }
        );
        assert!(matches!(
            &items[1],
            MatchItem::IpCidr { geo_country, .. } if geo_country == &vec!["cn".to_string()]
        ));
    }

    #[test]
    fn source_ports_inbound_tags_protocol_network_map() {
        let txt = r#"{"routing":{"rules":[
            {"type":"field","outboundTag":"b","sourcePorts":"53-64,9050",
             "network":"udp","inboundTag":["tun","dokodemo"],
             "protocol":["http","dns","tls"]}]}}"#;
        let out = compile_xray(txt).unwrap();
        assert_eq!(out.ruleset.rules.len(), 3, "one flat rule per protocol");
        let shared = [
            MatchItem::SourcePorts(vec![
                PortRange { start: 53, end: 64 },
                PortRange {
                    start: 9050,
                    end: 9050,
                },
            ]),
            MatchItem::Network(NetworkMask {
                tcp: false,
                udp: true,
            }),
            MatchItem::InboundTag {
                tags: vec!["tun".into(), "dokodemo".into()],
            },
        ];
        for (rule, proto) in out.ruleset.rules.iter().zip([
            SniffedProtocol::Http,
            SniffedProtocol::Dns,
            SniffedProtocol::Tls,
        ]) {
            let Cond::All(items) = &rule.cond else {
                panic!("expanded rule cond must stay All");
            };
            let mut expected = shared.to_vec();
            expected.push(MatchItem::Protocol(proto));
            assert_eq!(items[..], expected[..]);
            assert_eq!(
                rule.action,
                Action::Route {
                    tag: "b".into(),
                    override_addr: None
                }
            );
        }
    }

    #[test]
    fn multi_protocol_whitelist_routes_on_any_sniffed_value() {
        // Regression: a multi-value `protocol` array used to emit one Protocol
        // leaf per value inside the same AND-cond — unsatisfiable. It now
        // expands to one flat rule per value; each is buildable and exactly
        // one matches per sniff result.
        let txt = r#"{"routing":{"rules":[
            {"type":"field","outboundTag":"sniffed",
             "domain":["keyword:example"],"protocol":["http","tls"]}]}}"#;
        let out = compile_xray(txt).unwrap();
        assert_eq!(out.ruleset.rules.len(), 2);
        let engine = crate::Engine::build(out.ruleset).unwrap();
        let routed_to =
            |d: &Decision, tag: &str| matches!(d, Decision::Route { tag: t, .. } if &**t == tag);
        let mut http = conn("api.example.com", 80, NetworkMask::TCP);
        http.sniffed = Some(SniffedProtocol::Http);

        let mut tls = conn("api.example.com", 443, NetworkMask::TCP);
        tls.sniffed = Some(SniffedProtocol::Tls);
        assert!(routed_to(&engine.decide(&tls), "sniffed"));

        let mut dns = conn("api.example.com", 53, NetworkMask::UDP);
        dns.sniffed = Some(SniffedProtocol::Dns);
        assert!(!routed_to(&engine.decide(&dns), "sniffed"));

        // No sniff agreement at all falls through to the default route.
        assert!(!routed_to(
            &engine.decide(&conn("api.example.com", 443, NetworkMask::TCP)),
            "sniffed"
        ));
    }

    #[test]
    fn network_trailing_comma_is_tolerated_like_ports() {
        let out = compile_xray(
            r#"{"routing":{"rules":[
                {"type":"field","outboundTag":"a","network":"tcp,udp,"}]}}"#,
        )
        .unwrap();
        let Cond::All(items) = &out.ruleset.rules[0].cond else {
            panic!()
        };
        assert_eq!(
            items[0],
            MatchItem::Network(NetworkMask {
                tcp: true,
                udp: true
            })
        );
    }

    /// Minimal engine-test fixture mirroring `ConnMeta` construction.
    fn conn(host: &str, port: u16, network: NetworkMask) -> crate::ConnMeta {
        crate::ConnMeta {
            target: crate::NetAddr {
                host: crate::NetHost::new(host),
                port,
            },
            network,
            inbound_tag: None,
            source: None,
            source_resolved_ips: vec![],
            payload_prefix: None,
            sniffed: None,
            sni_host: None,
            resolved_host_ips: vec![],
        }
    }

    #[test]
    fn quic_sniff_protocol_is_accepted() {
        let txt =
            r#"{"routing":{"rules":[{"type":"field","outboundTag":"a","protocol":["quic"]}]}}"#;
        let out = compile_xray(txt).unwrap();
        assert_eq!(out.ruleset.rules.len(), 1);
        let Cond::All(items) = &out.ruleset.rules[0].cond else {
            panic!("cond must be All");
        };
        assert_eq!(items.len(), 1);
        assert_eq!(items[0], MatchItem::Protocol(SniffedProtocol::Quic));
    }

    #[test]
    fn malformed_values_are_positional_parse_errors() {
        let bad_port = r#"{"routing":{"rules":[
                {"type":"field","outboundTag":"s"},
                {"type":"field","outboundTag":"s"},
                {"type":"field","outboundTag":"s"},
                {"type":"field","outboundTag":"a","ports":"http"}]}}"#;
        err_at(bad_port, 3);
        let bad_cidr = r#"{"routing":{"rules":[
            {"type":"field","outboundTag":"a","ip":["10.0.0.0/33"]}]}}"#;
        err_at(bad_cidr, 0);
        let no_outbound = r#"{"routing":{"rules":[{"type":"field","domain":["a.com"]}]}}"#;
        err_at(no_outbound, 0);
        let wrong_type = r#"{"routing":{"rules":[{"type":"proxy","outboundTag":"a"}]}}"#;
        err_at(wrong_type, 0);
    }

    #[test]
    fn empty_rule_is_skipped_with_warning() {
        let txt = r#"{"routing":{"rules":[
            {"type":"field","outboundTag":"a"},
            {"type":"field","outboundTag":"b","domain":["k.com"]}]}}"#;
        let out = compile_xray(txt).unwrap();
        assert_eq!(out.ruleset.rules.len(), 1);
        assert_eq!(out.warnings.len(), 1);
        assert_eq!(out.warnings[0].0, 0);
    }

    #[test]
    fn unknown_rule_key_is_tolerated_with_warning() {
        let txt = r#"{"routing":{"rules":[
            {"type":"field","outboundTag":"a","domain":["k.com"],"balancerTag":"bal"}]}}"#;
        let out = compile_xray(txt).unwrap();
        assert_eq!(out.ruleset.rules.len(), 1);
        assert_eq!(out.warnings.len(), 1);
        assert!(out.warnings[0].1.contains("balancerTag"));
    }

    #[test]
    fn domain_strategy_maps_all_three_variants() {
        let mk = |s: &str| format!(r#"{{"routing":{{"domainStrategy":"{s}","rules":[]}}}}"#);
        let as_is = compile_xray(&mk("AsIs")).unwrap();
        assert_eq!(as_is.ruleset.resolve_strategy, ResolveStrategy::AsIs);
        let if_non_match = compile_xray(&mk("IPIfNonMatch")).unwrap();
        assert_eq!(
            if_non_match.ruleset.resolve_strategy,
            ResolveStrategy::IfNonMatch
        );
        let on_demand = compile_xray(&mk("IPOnDemand")).unwrap();
        assert_eq!(
            on_demand.ruleset.resolve_strategy,
            ResolveStrategy::IfNonMatch
        );
        assert_eq!(on_demand.warnings.len(), 1);
    }

    #[test]
    fn missing_routing_block_is_root_parse_error() {
        err_at("{}", 0);
    }
}
