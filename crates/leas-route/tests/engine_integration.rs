//! Task 12 integration battery: lazy resolve + sniff enrichment wired into
//! `decide_async`, needs declarations, probe breakdown/recovery end-to-end.

mod common;

use std::{net::IpAddr, sync::Arc};

use common::SeqSink;
use leas_route::addr;
use leas_route::engine::decide_async;
use leas_route::ir::NetworkMask;
use leas_route::ir::{
    Action, Cond, DefaultRoute, MatchItem, RejectMethod, ResolveStrategy, Rule, RuleSet,
    SniffedProtocol,
};
use leas_route::{Cidr, ConnMeta, Decision, Engine, NetAddr, NetHost, RouteError, RouteEvent};

fn meta(target: &str, port: u16) -> ConnMeta {
    ConnMeta {
        target: NetAddr {
            host: NetHost::new(target),
            port,
        },
        network: NetworkMask::TCP,
        inbound_tag: None,
        source: None,
        source_resolved_ips: vec![],
        payload_prefix: None,
        sniffed: None,
        sni_host: None,
        resolved_host_ips: vec![],
    }
}

fn ip_rule(prefix: &str, tag: &str) -> Rule {
    Rule {
        name: None,
        cond: Cond::All(vec![MatchItem::IpCidr {
            cidrs: vec![Cidr::parse(prefix).unwrap()],
            private: false,
            geo_country: vec![],
        }]),
        action: Action::Route {
            tag: tag.to_owned(),
            override_addr: None,
        },
    }
}

fn if_non_match_set(rules: Vec<Rule>, probes: Vec<String>) -> RuleSet {
    RuleSet {
        rules,
        default: DefaultRoute::Route {
            tag: "direct".to_owned(),
        },
        resolve_strategy: ResolveStrategy::IfNonMatch,
        probes,
    }
}

fn seq_sink(results: Vec<Result<Vec<IpAddr>, RouteError>>) -> Arc<SeqSink> {
    Arc::new(SeqSink {
        results: parking_lot::Mutex::new(results),
    })
}

#[tokio::test]
async fn if_non_match_resolves_once_then_matches_ip_rule() {
    let sink = seq_sink(vec![Ok(vec![
        "93.184.216.34".parse::<std::net::IpAddr>().unwrap(),
    ])]);
    let engine = Engine::build(if_non_match_set(
        vec![ip_rule("93.184.0.0/16", "example")],
        vec![],
    ))
    .unwrap()
    .with_resolver(sink.clone());
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let mut engine = engine;
    engine.set_event_sink(tx);

    let mut m = meta("example.com", 443);
    let d = decide_async(&engine, &mut m).await;
    assert!(
        matches!(d, Decision::Route { ref tag, .. } if &**tag == "example"),
        "resolved ips must satisfy the ip rule: {d:?}"
    );
    assert_eq!(
        m.resolved_host_ips,
        vec!["93.184.216.34".parse::<std::net::IpAddr>().unwrap()]
    );
    assert!(
        sink.results.lock().is_empty(),
        "exactly one sink lookup must occur"
    );

    // Resolved event for the lookup, then the terminal decision.
    let ev0 = rx.try_recv().unwrap();
    assert!(
        matches!(&ev0, RouteEvent::Resolved { host, ips, .. }
            if &**host == "example.com" && ips.len() == 1),
        "expected Resolved, got {ev0:?}"
    );
    let ev1 = rx.try_recv().unwrap();
    let RouteEvent::DecisionApplied { tag, sni, .. } = ev1 else {
        panic!("expected DecisionApplied, got {ev1:?}");
    };
    assert_eq!(tag.as_deref(), Some("example"));
    assert_eq!(sni, None);
}

#[tokio::test]
async fn cycle_guard_prevents_second_resolution_pass() {
    // Resolved ip misses the only ip rule; the guard must forbid a second
    // resolve pass even though no rule matched after the retry.
    let sink = seq_sink(vec![Ok(vec![
        "8.8.8.8".parse::<std::net::IpAddr>().unwrap(),
    ])]);
    let engine = Engine::build(if_non_match_set(vec![ip_rule("10.0.0.0/8", "lan")], vec![]))
        .unwrap()
        .with_resolver(sink.clone());

    let mut m = meta("example.com", 443);
    let d = decide_async(&engine, &mut m).await;
    assert!(
        matches!(d, Decision::Route { ref tag, .. } if &**tag == "direct"),
        "falls through to default: {d:?}"
    );
    assert_eq!(
        m.resolved_host_ips,
        vec!["8.8.8.8".parse::<std::net::IpAddr>().unwrap()]
    );
    assert!(
        sink.results.lock().is_empty(),
        "cycle guard: exactly one lookup despite still-missing rule"
    );
}

#[tokio::test]
async fn protocol_item_consumes_payload_prefix_sniff() {
    let fixture = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/tls_hello_chrome.bin"
    ))
    .expect("tls fixture present");
    let set = if_non_match_set(
        vec![Rule {
            name: Some("tls".to_owned()),
            cond: Cond::All(vec![MatchItem::Protocol(SniffedProtocol::Tls)]),
            action: Action::Route {
                tag: "tls-out".to_owned(),
                override_addr: None,
            },
        }],
        vec![],
    );
    // AsIs-style resolution path irrelevant here; sniffing alone must drive
    // the decision. Resolver absent on purpose.
    let engine = Engine::build(set).unwrap();

    let mut m = meta("1.2.3.4", 443);
    m.payload_prefix = Some(fixture.into());
    let d = decide_async(&engine, &mut m).await;
    assert!(
        matches!(d, Decision::Route { ref tag, .. } if &**tag == "tls-out"),
        "sniffed TLS must satisfy the Protocol item: {d:?}"
    );
    assert_eq!(
        m.sniffed,
        Some(SniffedProtocol::Tls),
        "sniff result stashed onto meta"
    );
    assert_eq!(
        m.sni_host.as_deref(),
        Some("example.com"),
        "SNI host stashed onto meta"
    );

    // Sync decide stays fully usable without prefix: the same ruleset with
    // no payload must fall through to default.
    let set2 = if_non_match_set(
        vec![Rule {
            name: None,
            cond: Cond::All(vec![MatchItem::Protocol(SniffedProtocol::Tls)]),
            action: Action::Route {
                tag: "tls-out".to_owned(),
                override_addr: None,
            },
        }],
        vec![],
    );
    let engine2 = Engine::build(set2).unwrap();
    let m2 = meta("1.2.3.4", 443);
    assert!(matches!(
        engine2.decide(&m2),
        Decision::Route { ref tag, .. } if &**tag == "direct"
    ));
}

#[tokio::test]
async fn probe_breakdown_and_recovery_flow_end_to_end_via_events_rx() {
    let sink = seq_sink(vec![
        Err(RouteError::Resolve("dial failed".into())),
        Ok(vec!["10.0.0.1".parse::<std::net::IpAddr>().unwrap()]),
    ]);
    let engine = Engine::build(if_non_match_set(
        vec![ip_rule("10.0.0.0/8", "lan")],
        vec!["probe.example".to_owned()],
    ))
    .unwrap()
    .with_resolver(sink.clone());
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let mut engine = engine;
    engine.set_event_sink(tx);

    // Cycle 1: probe host fails to resolve → NetworkBreakdown, degraded
    // (default) decision.
    let mut m1 = meta("probe.example", 443);
    let d1 = decide_async(&engine, &mut m1).await;
    assert!(matches!(d1, Decision::Route { ref tag, .. } if &**tag == "direct"));
    assert!(m1.resolved_host_ips.is_empty(), "failure degrades silently");

    // Cycle 2: same host resolves → Resolved + ProbeRecovered, ip rule now
    // matches.
    let mut m2 = meta("probe.example", 443);
    let d2 = decide_async(&engine, &mut m2).await;
    assert!(matches!(d2, Decision::Route { ref tag, .. } if &**tag == "lan"));
    assert_eq!(
        m2.resolved_host_ips,
        vec!["10.0.0.1".parse::<std::net::IpAddr>().unwrap()]
    );

    let ev0 = rx.try_recv().unwrap();
    assert!(
        matches!(&ev0, RouteEvent::NetworkBreakdown { failed_probe, .. } if &**failed_probe == "probe.example"),
        "expected NetworkBreakdown, got {ev0:?}"
    );
    let RouteEvent::DecisionApplied { tag, .. } = rx.try_recv().unwrap() else {
        panic!("expected DecisionApplied for degraded conn");
    };
    assert_eq!(tag.as_deref(), Some("direct"));

    let ev2 = rx.try_recv().unwrap();
    assert!(
        matches!(&ev2, RouteEvent::Resolved { host, .. } if &**host == "probe.example"),
        "expected Resolved, got {ev2:?}"
    );
    let ev3 = rx.try_recv().unwrap();
    assert!(
        matches!(&ev3, RouteEvent::ProbeRecovered { probe, .. } if &**probe == "probe.example"),
        "expected ProbeRecovered, got {ev3:?}"
    );
    let RouteEvent::DecisionApplied { tag, .. } = rx.try_recv().unwrap() else {
        panic!("expected DecisionApplied for recovered conn");
    };
    assert_eq!(tag.as_deref(), Some("lan"));
    assert!(rx.try_recv().is_err(), "no extra events");
    assert!(sink.results.lock().is_empty(), "both scripted lookups ran");
}

#[test]
fn needs_flags_reflect_declared_item_mix() {
    let protocol_rule = Rule {
        name: None,
        cond: Cond::All(vec![MatchItem::Protocol(SniffedProtocol::Http)]),
        action: Action::Reject {
            method: RejectMethod::Drop,
        },
    };
    let build = |rules: Vec<Rule>, strategy: ResolveStrategy| RuleSet {
        rules,
        default: DefaultRoute::Route {
            tag: "direct".to_owned(),
        },
        resolve_strategy: strategy,
        probes: vec![],
    };

    // Protocol item ⇒ sniff needed.
    let e = Engine::build(build(vec![protocol_rule], ResolveStrategy::AsIs)).unwrap();
    assert!(e.needs_sniff());
    assert!(!e.needs_resolve(), "AsIs + no ip items ⇒ no resolve");

    // IP-bearing rule ⇒ resolve needed even under AsIs.
    let e = Engine::build(build(
        vec![ip_rule("10.0.0.0/8", "lan")],
        ResolveStrategy::AsIs,
    ))
    .unwrap();
    assert!(!e.needs_sniff());
    assert!(e.needs_resolve());

    // SourceIpCidr also counts as IP-bearing.
    let e = Engine::build(build(
        vec![Rule {
            name: None,
            cond: Cond::Any(vec![Cond::All(vec![MatchItem::SourceIpCidr {
                cidrs: vec![Cidr::parse("192.168.0.0/16").unwrap()],
                private: false,
                geo_country: vec![],
            }])]),
            action: Action::Reject {
                method: RejectMethod::Drop,
            },
        }],
        ResolveStrategy::AsIs,
    ))
    .unwrap();
    assert!(e.needs_resolve(), "SourceIpCidr is IP-bearing");

    // IfNonMatch forces resolve needs with zero ip rules; plain ports don't.
    let e = Engine::build(build(
        vec![Rule {
            name: None,
            cond: Cond::All(vec![MatchItem::Ports(vec![addr::PortRange {
                start: 80,
                end: 80,
            }])]),
            action: Action::Reject {
                method: RejectMethod::Drop,
            },
        }],
        ResolveStrategy::IfNonMatch,
    ))
    .unwrap();
    assert!(e.needs_resolve(), "IfNonMatch strategy alone forces it");
    assert!(!e.needs_sniff());

    // Protocol item nested under Invert still requires sniffing.
    let e = Engine::build(build(
        vec![Rule {
            name: None,
            cond: Cond::Invert(Box::new(Cond::All(vec![MatchItem::Protocol(
                SniffedProtocol::Http,
            )]))),
            action: Action::Reject {
                method: RejectMethod::Drop,
            },
        }],
        ResolveStrategy::AsIs,
    ))
    .unwrap();
    assert!(e.needs_sniff(), "Invert-wrapped Protocol still needs sniff");
}

#[tokio::test]
async fn invert_ip_rule_decides_first_pass_resolution_not_consumed() {
    // Sanity per plan: Invert over IpCidr interacting with resolve. Under
    // first-match, an `Invert` whose inner cannot hold on pass 1 (no
    // resolved ips yet for a domain target) is TRUE on pass 1, so the rule
    // decides WITHOUT consuming the connection's resolution pass — the
    // sink must stay untouched. A flip driven by resolved ips is
    // unobservable: pass-1 no-match requires the inverted subtree to hold
    // on pass 1, and non-IP leaves inside it never change across passes.
    let sink = seq_sink(vec![]);
    let set = if_non_match_set(
        vec![
            ip_rule("10.0.0.0/8", "lan"),
            Rule {
                name: None,
                cond: Cond::Any(vec![Cond::Invert(Box::new(Cond::All(vec![
                    MatchItem::IpCidr {
                        cidrs: vec![Cidr::parse("10.0.0.0/8").unwrap()],
                        private: false,
                        geo_country: vec![],
                    },
                ])))]),
                action: Action::Route {
                    tag: "not-lan".to_owned(),
                    override_addr: None,
                },
            },
        ],
        vec![],
    );
    let engine = Engine::build(set).unwrap().with_resolver(sink.clone());

    let mut m = meta("host.example", 443);
    let d = decide_async(&engine, &mut m).await;
    assert!(
        matches!(d, Decision::Route { ref tag, .. } if &**tag == "not-lan"),
        "invert rule wins pass 1 against the empty resolved set: {d:?}"
    );
    assert!(
        sink.results.lock().is_empty(),
        "pass-1 terminal decision consumes no resolution"
    );
    assert!(m.resolved_host_ips.is_empty());
}

#[tokio::test]
async fn pre_sniffed_meta_is_not_reprobed() {
    // Idempotence: `sniffed` already set ⇒ the payload is never probed and
    // `sni_host` keeps the caller's value (here: None, proving no overwrite).
    let fixture = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/tls_hello_chrome.bin"
    ))
    .expect("tls fixture present");
    let set = if_non_match_set(
        vec![Rule {
            name: None,
            cond: Cond::All(vec![MatchItem::Protocol(SniffedProtocol::Tls)]),
            action: Action::Route {
                tag: "tls-out".to_owned(),
                override_addr: None,
            },
        }],
        vec![],
    );
    let engine = Engine::build(set).unwrap();

    let mut m = meta("1.2.3.4", 443);
    m.payload_prefix = Some(fixture.into());
    m.sniffed = Some(SniffedProtocol::Dns); // caller-pre-populated
    let d = decide_async(&engine, &mut m).await;
    // Protocol(Tls) evaluates against the PRE-EXISTING sniffed value, not
    // a fresh probe of the TLS payload.
    assert!(
        matches!(d, Decision::Route { ref tag, .. } if &**tag == "direct"),
        "no re-probe: pre-set sniffed (Dns) does not satisfy Protocol(Tls): {d:?}"
    );
    assert_eq!(m.sniffed, Some(SniffedProtocol::Dns), "sniffed untouched");
    assert_eq!(m.sni_host, None, "sni_host never overwritten");
}

#[tokio::test]
async fn second_connection_hits_resolve_cache_without_sink() {
    // Conn 1 resolves via the sink and populates the TTL cache; conn 2 for
    // the SAME host must be served from the cache — zero sink traffic.
    let sink = seq_sink(vec![Ok(vec![
        "93.184.216.34".parse::<std::net::IpAddr>().unwrap(),
    ])]);
    let engine = Engine::build(if_non_match_set(
        vec![ip_rule("93.184.0.0/16", "example")],
        vec![],
    ))
    .unwrap()
    .with_resolver(sink.clone());

    let mut m1 = meta("example.com", 443);
    let d1 = decide_async(&engine, &mut m1).await;
    assert!(matches!(d1, Decision::Route { ref tag, .. } if &**tag == "example"));
    assert!(sink.results.lock().is_empty(), "first lookup drains queue");

    let mut m2 = meta("example.com", 443);
    let d2 = decide_async(&engine, &mut m2).await;
    assert!(matches!(d2, Decision::Route { ref tag, .. } if &**tag == "example"));
    assert_eq!(
        m2.resolved_host_ips, m1.resolved_host_ips,
        "cache hit supplies the same ips"
    );
}

#[tokio::test]
async fn quic_protocol_item_consumes_payload_prefix_sniff() {
    // Real quic-go `Initial` packet carrying a ClientHello with SNI
    // `www.google.com` (fixture from xray sniff_test.go). A Protocol(Quic)
    // rule must be satisfied by sniffing the payload prefix, exactly like
    // the TLS row above.
    let fixture = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/quic_initial_google.bin"
    ))
    .expect("quic fixture present");
    let set = if_non_match_set(
        vec![Rule {
            name: Some("quic".to_owned()),
            cond: Cond::All(vec![MatchItem::Protocol(SniffedProtocol::Quic)]),
            action: Action::Route {
                tag: "quic-out".to_owned(),
                override_addr: None,
            },
        }],
        vec![],
    );
    let engine = Engine::build(set.clone()).unwrap();

    // QUIC is UDP-only; the sniff must be adopted only on UDP.
    let mut m = meta("1.2.3.4", 443);
    m.network = NetworkMask::UDP;
    m.payload_prefix = Some(fixture.clone().into());
    let d = decide_async(&engine, &mut m).await;
    assert!(
        matches!(d, Decision::Route { ref tag, .. } if &**tag == "quic-out"),
        "sniffed QUIC must satisfy the Protocol item: {d:?}"
    );
    assert_eq!(
        m.sniffed,
        Some(SniffedProtocol::Quic),
        "sniff result stashed onto meta"
    );
    assert_eq!(
        m.sni_host.as_deref(),
        Some("www.google.com"),
        "SNI host stashed onto meta"
    );

    // On TCP the same payload must be ignored: the QUIC decrypt path is
    // gated off non-UDP, so the rule cannot fire.
    let engine_tcp = Engine::build(set).unwrap();
    let mut tcp = meta("1.2.3.4", 443);
    tcp.payload_prefix = Some(fixture.clone().into());
    let dt = decide_async(&engine_tcp, &mut tcp).await;
    assert!(
        matches!(dt, Decision::Route { ref tag, .. } if &**tag == "direct"),
        "QUIC sniff must be rejected on TCP: {dt:?}"
    );
    assert_eq!(tcp.sniffed, None, "no sniff result on TCP");

    // Sync decide stays fully usable without prefix: the same ruleset with
    // no payload must fall through to default.
    let set2 = if_non_match_set(
        vec![Rule {
            name: None,
            cond: Cond::All(vec![MatchItem::Protocol(SniffedProtocol::Quic)]),
            action: Action::Route {
                tag: "quic-out".to_owned(),
                override_addr: None,
            },
        }],
        vec![],
    );
    let engine2 = Engine::build(set2).unwrap();
    let mut plain = meta("1.2.3.4", 443);
    let d2 = decide_async(&engine2, &mut plain).await;
    assert!(
        matches!(d2, Decision::Route { ref tag, .. } if &**tag == "direct"),
        "no payload -> no sniff -> default route: {d2:?}"
    );
}
