//! Routing-engine decision benches: first-match scan cost at N ∈ {0, 8, 64}
//! rules for a domain hit, an IP-CIDR hit, and a full miss.
//!
//! [`Engine::decide`] is synchronous and pure — no DNS, no sniffing, no I/O —
//! so every row is CPU-only and needs no runtime. Row names
//! (`decide/rules_{0,8,64}/{domain_hit,ip_hit,miss}`) are contract: medians
//! are compared by name across runs.
//!
//! `rules_0` is production's shape (`leas-native`'s server builds the
//! engine with `rules: Vec::new()`); 8 and 64 exist so the linear-scan claim
//! stays falsifiable. For N > 0 the only rule the hit inputs can match is the
//! LAST one, so every row walks the whole rule list — worst case for a
//! first-match engine.

use std::hint::black_box;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use leas_route::{
    Cidr, ConnMeta, Decision, Engine, NetAddr, NetHost,
    ir::{Action, Cond, DefaultRoute, MatchItem, NetworkMask, ResolveStrategy, Rule, RuleSet},
};

/// Domain suffix carried by the terminal rule only; `domain_hit`'s host ends
/// with it.
const HIT_SUFFIX: &str = "hit.example.org";
/// Domain keyword carried by the terminal rule only.
const HIT_KEYWORD: &str = "bench-hit";
/// CIDR carried by the terminal rule only. TEST-NET-3 sits outside the
/// engine's private-range set, so the explicit block is the only thing that
/// can match it.
const HIT_CIDR: &str = "203.0.113.0/24";
/// Outbound tag of the terminal rule; the fallthrough default is `direct`.
const HIT_TAG: &str = "hit";
/// Fallthrough tag, and therefore the `miss` rows' expected outcome.
const DEFAULT_TAG: &str = "direct";

const fn domain_item(suffix: Vec<String>, keywords: Vec<String>) -> MatchItem {
    MatchItem::Domain {
        exact: Vec::new(),
        suffix,
        keywords,
        regexes: Vec::new(),
    }
}

fn cidr_item(cidr: &str) -> MatchItem {
    MatchItem::IpCidr {
        cidrs: vec![Cidr::parse(cidr).expect("bench CIDR literal parses")],
        private: false,
        geo_country: Vec::new(),
    }
}

fn route(tag: &str) -> Action {
    Action::Route {
        tag: tag.to_owned(),
        override_addr: None,
    }
}

/// Filler rule `i`: alternating domain-only and IP-only conjunctions — the
/// shape the xray/sing-box compilers emit for a single-field rule
/// (`Cond::All` over one item). None of them can match any bench input, so
/// the scan always reaches the terminal rule.
fn filler_rule(i: usize) -> Rule {
    let (name, cond) = if i.is_multiple_of(2) {
        (
            format!("filler-domain-{i}"),
            Cond::All(vec![domain_item(
                vec![format!("cdn{i}.example.com"), format!("api{i}.example.net")],
                vec![format!("track{i}")],
            )]),
        )
    } else {
        (
            format!("filler-ip-{i}"),
            Cond::All(vec![cidr_item(&format!("10.{i}.0.0/16"))]),
        )
    };
    Rule {
        name: Some(name),
        cond,
        action: route(&format!("out{i}")),
    }
}

/// The rule both hit rows match, always LAST. Two-arm `Cond::Any`
/// (domain OR ip) — what sing-box's logical `mode: "or"` compiles to — so one
/// terminal rule serves the domain row and the IP row without the
/// unsatisfiable `Cond::All([Domain, IpCidr])` shape.
fn hit_rule() -> Rule {
    Rule {
        name: Some(HIT_KEYWORD.to_owned()),
        cond: Cond::Any(vec![
            Cond::All(vec![domain_item(
                vec![HIT_SUFFIX.to_owned()],
                vec![HIT_KEYWORD.to_owned()],
            )]),
            Cond::All(vec![cidr_item(HIT_CIDR)]),
        ]),
        action: route(HIT_TAG),
    }
}

/// `n` rules with the matching one last; `n == 0` is the default route alone.
fn rule_set(n: usize) -> RuleSet {
    let rules = if n == 0 {
        Vec::new()
    } else {
        let mut rules: Vec<Rule> = (0..n - 1).map(filler_rule).collect();
        rules.push(hit_rule());
        rules
    };
    RuleSet {
        rules,
        default: DefaultRoute::Route {
            tag: DEFAULT_TAG.to_owned(),
        },
        resolve_strategy: ResolveStrategy::AsIs,
        probes: Vec::new(),
    }
}

fn meta(host: &str, port: u16) -> ConnMeta {
    ConnMeta {
        target: NetAddr {
            host: NetHost::new(host),
            port,
        },
        network: NetworkMask::TCP,
        inbound_tag: None,
        source: None,
        source_resolved_ips: Vec::new(),
        payload_prefix: None,
        sniffed: None,
        sni_host: None,
        resolved_host_ips: Vec::new(),
    }
}

/// The three inputs, in row order: the terminal rule's domain suffix, an IP
/// inside the terminal rule's CIDR, and a destination no rule can match.
fn inputs() -> [(&'static str, ConnMeta); 3] {
    [
        ("domain_hit", meta("assets.hit.example.org", 443)),
        ("ip_hit", meta("203.0.113.7", 443)),
        ("miss", meta("miss.example.test", 8443)),
    ]
}

fn criterion_benches(c: &mut Criterion) {
    let mut group = c.benchmark_group("decide");
    // One decision per iteration — rows report decisions/second.
    group.throughput(Throughput::Elements(1));
    for n in [0_usize, 8, 64] {
        let engine = Engine::build(rule_set(n)).expect("bench rule set compiles");
        for (row, meta) in inputs() {
            // Fixture guard: a row only measures what its name claims when the
            // input reaches the intended rule. With zero rules there is
            // nothing to hit, so all three inputs take the default route.
            let want = if n == 0 || row == "miss" {
                DEFAULT_TAG
            } else {
                HIT_TAG
            };
            assert_eq!(
                engine.decide(&meta),
                Decision::Route {
                    tag: want.into(),
                    override_addr: None,
                },
                "decide/rules_{n}/{row} must reach the `{want}` route"
            );
            group.bench_function(format!("rules_{n}/{row}"), |b| {
                b.iter(|| engine.decide(black_box(&meta)));
            });
        }
    }
    group.finish();
}

criterion_group!(benches, criterion_benches);
criterion_main!(benches);
