//! Rule routing engine: build-once compilation of full `Cond` trees
//! (`All`/`Any`/`Invert`) and synchronous pure first-match evaluation.

use std::{
    net::{IpAddr, SocketAddr},
    sync::{Arc, LazyLock},
};

use parking_lot::Mutex;

use bytes::Bytes;

use crate::{
    addr::{NetAddr, NetHost, PortRange},
    error::RouteError,
    events::RouteEvent,
    ir::{Action, Cond, DefaultRoute, NetworkMask, SniffedProtocol},
    matchers::{CidrSet, CidrSetBuilder, CompiledDomain, DomainRulesSpec},
    resolve::{DnsSink, ProbeTracker, ResolvedCache},
    sniff,
};

/// Metadata describing one connection to route.
pub struct ConnMeta {
    /// Destination address.
    pub target: NetAddr,
    /// Transport-protocol bit mask of the connection.
    pub network: NetworkMask,
    /// Tag of the inbound the connection arrived on.
    pub inbound_tag: Option<String>,
    /// Peer address on the source side, when known.
    pub source: Option<SocketAddr>,
    /// Pre-resolved source IPs.
    pub source_resolved_ips: Vec<IpAddr>,
    /// Caller-owned leading payload bytes (spec §2 data-flow 3). Shared
    /// `Bytes` per the Task 2 relay convention — sniffing borrows it, never
    /// copies it.
    pub payload_prefix: Option<Bytes>,
    /// Application protocol detected by sniffing, when available.
    pub sniffed: Option<SniffedProtocol>,
    /// SNI host carried on the wire, stashed by the sniff-enrichment pass
    /// (`decide_async`); the sync path only reads it.
    pub sni_host: Option<String>,
    /// Filled by the `IfNonMatch` pass or pre-seeded by the caller.
    pub resolved_host_ips: Vec<IpAddr>,
}

impl ConnMeta {
    /// Candidate destination IPs contributed by prior resolution passes.
    ///
    /// A literal-IP [`NetHost`] is considered separately at evaluation time
    /// and does not appear here; pass-based enrichment appends to the same
    /// backing vector.
    #[must_use]
    pub fn target_ips(&self) -> &[IpAddr] {
        &self.resolved_host_ips
    }
}

/// Terminal outcome of evaluating a connection against the rule set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Forward to the outbound `tag`, optionally rewriting the address.
    Route {
        /// Outbound tag to forward through.
        tag: Arc<str>,
        /// Rewritten destination, if the matched action requested one.
        /// Shared: a decision clone is then a refcount bump instead of a
        /// deep `Domain(String)` copy (the scan's working set stays clean).
        override_addr: Option<Arc<NetAddr>>,
    },
    /// Refuse the connection with a method.
    Reject {
        /// How the rejection manifests.
        method: crate::ir::RejectMethod,
    },
    /// Intercept into the built-in DNS resolver.
    HijackDns,
}

/// A match item compiled once at build time.
///
/// `geo_country` entries are carried verbatim but evaluate `false` this task:
/// the geoip feature resolves them later, and erasing them here would let a
/// CN-routing config compile clean while silently routing through default.
enum ItemMatcher {
    Domain(CompiledDomain),
    IpCidr {
        cidrs: CidrSet,
        private: bool,
        // Retained verbatim for the geoip feature's later resolution pass.
        #[allow(dead_code)]
        geo_country: Vec<String>,
    },
    SourceIpCidr {
        cidrs: CidrSet,
        private: bool,
        // Retained verbatim for the geoip feature's later resolution pass.
        #[allow(dead_code)]
        geo_country: Vec<String>,
    },
    Ports(Vec<PortRange>),
    SourcePorts(Vec<PortRange>),
    Network(NetworkMask),
    Protocol(SniffedProtocol),
    InboundTag(std::collections::HashSet<String>),
    /// Inert until `ConnMeta` gains an outbound-tag field (Task 12).
    OutboundTag,
}

impl ItemMatcher {
    /// Evaluates one compiled item against connection metadata.
    fn matches(&self, meta: &ConnMeta) -> bool {
        match self {
            Self::Domain(c) => match &meta.target.host {
                NetHost::Domain(d) => c.matches_domain(d.as_str()),
                // IP targets fail domain items for now; Task 12 wires
                // SNI/DNS enrichment as the reverse-lookup path.
                NetHost::Ip(_) => false,
            },
            Self::IpCidr { cidrs, private, .. } => {
                let literal_hit = match &meta.target.host {
                    NetHost::Ip(ip) => ip_candidate_matches(cidrs, *private, ip),
                    NetHost::Domain(_) => false,
                };
                literal_hit
                    || meta
                        .resolved_host_ips
                        .iter()
                        .any(|ip| ip_candidate_matches(cidrs, *private, ip))
            }
            Self::SourceIpCidr { cidrs, private, .. } => {
                let socket_hit = meta
                    .source
                    .as_ref()
                    .is_some_and(|s| ip_candidate_matches(cidrs, *private, &s.ip()));
                socket_hit
                    || meta
                        .source_resolved_ips
                        .iter()
                        .any(|ip| ip_candidate_matches(cidrs, *private, ip))
            }
            Self::Ports(ranges) => ranges.iter().any(|r| r.contains(meta.target.port)),
            // Absent source information can never satisfy source items.
            Self::SourcePorts(ranges) => meta
                .source
                .as_ref()
                .is_some_and(|s| ranges.iter().any(|r| r.contains(s.port()))),
            Self::Network(mask) => mask.contains(meta.network),
            Self::Protocol(p) => meta.sniffed == Some(*p),
            Self::InboundTag(tags) => meta.inbound_tag.as_ref().is_some_and(|t| tags.contains(t)),
            Self::OutboundTag => false,
        }
    }

    /// True for matchers whose outcome can change once destination/source
    /// IPs become known (used by [`Engine::needs_resolve`]).
    const fn is_ip_bearing(&self) -> bool {
        matches!(self, Self::IpCidr { .. } | Self::SourceIpCidr { .. })
    }
}

/// CIDR or private-range membership for one candidate IP.
fn ip_candidate_matches(cidrs: &CidrSet, private: bool, ip: &IpAddr) -> bool {
    cidrs.contains(ip) || (private && private_contains(ip))
}

/// True when `ip` falls inside the shared compiled private-address set.
fn private_contains(ip: &IpAddr) -> bool {
    static PRIVATE: LazyLock<CidrSet> = LazyLock::new(CidrSet::private_set);
    PRIVATE.contains(ip)
}

/// One rule with its predicate pre-compiled into a condition tree and its
/// [`Decision`] pre-built, so a match clones a ready value instead of
/// rebuilding it from the IR action.
struct CompiledRule {
    name: Option<String>,
    cond: CompiledCond,
    decision: Decision,
}

impl CompiledRule {
    fn matches(&self, meta: &ConnMeta) -> bool {
        self.cond.eval(meta)
    }
}

/// Maximum condition-tree nesting accepted at build time.
///
/// Conditions originate in config files; a bound turns pathological nesting
/// into a clean build error instead of unbounded recursion. 64 mirrors
/// typical parser limits and is far above any real config.
const MAX_COND_DEPTH: u32 = 64;

/// A condition tree compiled once at build time.
///
/// Interior nodes mirror [`Cond`]'s `All`/`Any`/`Invert` logic; leaves are
/// [`ItemMatcher`]s. An empty `All` evaluates to `true` (vacuous
/// conjunction, mirroring upstream's empty-rule catch-all); empty `Any` is
/// `false`. The vacuous `All` cannot arise from real configs: the xray and
/// sing-box producers skip condition-less rules outright and `merge`
/// synthesizes none — it passes existing rules through verbatim. Only a
/// hand-built `RuleSet` can hand one to the engine.
enum CompiledCond {
    All(Vec<ItemMatcher>),
    Any(Vec<Self>),
    Invert(Box<Self>),
}

impl CompiledCond {
    /// Compiles a condition tree with a build-time depth guard. The root
    /// sits at depth 1; a node deeper than [`MAX_COND_DEPTH`] is rejected.
    /// `rule_idx` attributes leaf-matcher parse errors to their rule.
    fn build(cond: crate::ir::Cond, rule_idx: usize, depth: u32) -> Result<Self, RouteError> {
        if depth > MAX_COND_DEPTH {
            return Err(RouteError::Unsupported("condition nesting deeper than 64"));
        }
        Ok(match cond {
            Cond::All(items) => Self::All(
                items
                    .into_iter()
                    .map(|item| compile_item(item, rule_idx))
                    .collect::<Result<Vec<_>, _>>()?,
            ),
            Cond::Any(children) => Self::Any(
                children
                    .into_iter()
                    .map(|c| Self::build(c, rule_idx, depth + 1))
                    .collect::<Result<Vec<_>, _>>()?,
            ),
            Cond::Invert(inner) => {
                Self::Invert(Box::new(Self::build(*inner, rule_idx, depth + 1)?))
            }
        })
    }

    /// Recursive evaluation: `All` = every leaf holds (vacuously true when
    /// empty), `Any` = short-circuit on the first true child, `Invert` =
    /// negation of the subtree.
    fn eval(&self, meta: &ConnMeta) -> bool {
        match self {
            Self::All(items) => items.iter().all(|item| item.matches(meta)),
            Self::Any(children) => children.iter().any(|c| c.eval(meta)),
            Self::Invert(inner) => !inner.eval(meta),
        }
    }

    /// Visits every leaf matcher in the tree, recursing through
    /// `Any`/`Invert`. Short-circuits (stops) when `f` returns true.
    fn walk_items(&self, f: &mut impl FnMut(&ItemMatcher) -> bool) -> bool {
        match self {
            Self::All(items) => items.iter().any(f),
            Self::Any(children) => children.iter().any(|c| c.walk_items(f)),
            Self::Invert(inner) => inner.walk_items(f),
        }
    }
}

/// First-match flat-rule routing engine.
pub struct Engine {
    rules: Vec<CompiledRule>,
    /// The rule-set default, pre-built like every rule's decision.
    default_decision: Decision,
    /// Whether any rule carries a `Protocol` item, computed at build time:
    /// [`decide_async`] consults it per connection AND per UDP datagram, and
    /// the walk is O(rules x items).
    needs_sniff: bool,
    resolve_strategy: crate::ir::ResolveStrategy,
    event_sink: Option<tokio::sync::mpsc::UnboundedSender<RouteEvent>>,
    /// DNS seam installed via [`Engine::with_resolver`]; absent ⇒ no
    /// resolution ever happens.
    resolver: Option<Arc<dyn DnsSink>>,
    /// TTL cache fronting `resolver`; present iff `resolver` is. Fixed
    /// 300-second TTL: `RuleSet` carries no TTL field this task.
    resolve_cache: Option<Arc<Mutex<ResolvedCache>>>,
    /// Consecutive-failure streaks for `probes`; emits
    /// Breakdown/Recovered events per resolve attempt.
    probe_tracker: Mutex<ProbeTracker>,
    /// Probe hostnames from the rule set, consulted per resolve attempt.
    probes: Vec<String>,
}

impl Engine {
    /// Compiles a [`RuleSet`] into an evaluation-ready engine.
    ///
    /// Regexes and keyword automata compile once here; port ranges are
    /// sanity-checked so evaluation cannot encounter inverted bounds, and
    /// the full `Cond` tree (`All`/`Any`/`Invert`) is lowered to
    /// [`CompiledCond`]. Conditions nesting deeper than 64 levels are
    /// rejected here at build time, never at evaluation time.
    ///
    /// # Errors
    /// Returns [`RouteError::Parse`] when any rule fails to compile, and
    /// [`RouteError::Unsupported`] when conditions nest deeper than 64.
    pub fn build(rs: crate::ir::RuleSet) -> Result<Self, RouteError> {
        let mut rules = Vec::with_capacity(rs.rules.len());
        for (idx, rule) in rs.rules.into_iter().enumerate() {
            // Built once, here: at runtime a match only clones it. The tag is
            // an `Arc<str>`, which measured faster than `String` on this path
            // at every rule count (benches/baseline.md v2 records the A/B):
            // the scan's working set stays clean when the decision clone does
            // not touch the allocator.
            let decision = match rule.action {
                Action::Route { tag, override_addr } => Decision::Route {
                    tag: Arc::from(tag),
                    override_addr: override_addr.map(Arc::new),
                },
                Action::Reject { method } => Decision::Reject { method },
                Action::HijackDns => Decision::HijackDns,
            };
            rules.push(CompiledRule {
                name: rule.name,
                cond: CompiledCond::build(rule.cond, idx, 1)?,
                decision,
            });
        }
        let default_decision = match rs.default {
            DefaultRoute::Route { tag } => Decision::Route {
                tag: Arc::from(tag),
                override_addr: None,
            },
            DefaultRoute::Reject { method } => Decision::Reject { method },
        };
        let needs_sniff = rules.iter().any(|rule| {
            rule.cond
                .walk_items(&mut |m| matches!(m, ItemMatcher::Protocol(_)))
        });
        Ok(Self {
            rules,
            default_decision,
            needs_sniff,
            resolve_strategy: rs.resolve_strategy,
            event_sink: None,
            resolver: None,
            resolve_cache: None,
            probe_tracker: Mutex::new(ProbeTracker::default()),
            probes: rs.probes,
        })
    }
    /// Synchronous pure evaluation against [`ConnMeta`]: first matching
    /// rule wins; otherwise the rule-set default.
    ///
    /// Read-only: no DNS resolution, no sniffing side effects, no I/O. A
    /// `Protocol` item evaluates false unless `meta.sniffed` is already
    /// populated; IP items see only the literal target and whatever the
    /// caller pre-seeded into `resolved_host_ips` / `source_resolved_ips`.
    /// Use [`decide_async`] for lazy sniff/resolve enrichment.
    pub fn decide(&self, meta: &ConnMeta) -> Decision {
        if let Some(rule) = self.rules.iter().find(|rule| rule.matches(meta)) {
            let decision = rule.decision.clone();
            self.emit_decision(&decision, rule.name.as_deref(), meta.sni_host.as_deref());
            return decision;
        }
        let decision = self.default_decision.clone();
        self.emit_decision(&decision, None, meta.sni_host.as_deref());
        decision
    }

    /// Installs the DNS seam and enables lazy `IfNonMatch` resolution +
    /// probe tracking. A TTL [`ResolvedCache`] (fixed 300 s — the rule set
    /// carries no TTL field) fronts the sink.
    #[must_use]
    pub fn with_resolver(mut self, sink: Arc<dyn DnsSink>) -> Self {
        self.resolver = Some(sink);
        self.resolve_cache = Some(Arc::new(Mutex::new(ResolvedCache::new(300))));
        self
    }

    /// True when any rule carries a `Protocol` item needing
    /// `payload_prefix` sniffing (decided at build time).
    #[must_use]
    pub const fn needs_sniff(&self) -> bool {
        self.needs_sniff
    }

    /// True when strategy == `IfNonMatch` OR any `IpCidr`/`SourceIpCidr`
    /// leaf could need target/source resolution.
    #[must_use]
    pub fn needs_resolve(&self) -> bool {
        self.resolve_strategy == crate::ir::ResolveStrategy::IfNonMatch
            || self
                .rules
                .iter()
                .any(|rule| rule.cond.walk_items(&mut |m| m.is_ip_bearing()))
    }

    /// Registers a sink receiving events after terminal decisions.
    pub fn set_event_sink(&mut self, tx: tokio::sync::mpsc::UnboundedSender<RouteEvent>) {
        self.event_sink = Some(tx);
    }

    /// Emits `DecisionApplied` when a sink is registered; drops on send error
    /// (a closed receiver must never fail routing). Tag extraction happens
    /// only here so the sink-less hot path clones nothing.
    fn emit_decision(&self, decision: &Decision, rule_name: Option<&str>, sni: Option<&str>) {
        let Some(tx) = &self.event_sink else { return };
        let tag = match decision {
            // Refcount bump, not a deep copy.
            Decision::Route { tag, .. } => Some(Arc::clone(tag)),
            _ => None,
        };
        let _ = tx.send(RouteEvent::DecisionApplied {
            rule_name: rule_name.map(Arc::from),
            tag,
            sni: sni.map(Arc::from),
            at: jiff::Timestamp::now(),
        });
    }

    /// Emits a `Resolved` event for one successful lookup.
    fn emit_resolved(&self, host: &str, ips: &[IpAddr]) {
        if let Some(tx) = &self.event_sink {
            let _ = tx.send(RouteEvent::Resolved {
                host: Arc::from(host),
                ips: ips.to_vec(),
                at: jiff::Timestamp::now(),
            });
        }
    }
}

/// Asynchronous enrichment pass: sniff + lazy resolve wired over an
/// [`Engine`]'s pure [`Engine::decide`].
///
/// Locked semantics (plan §5 / spec):
/// - `Protocol(item)`: if `meta.sniffed.is_none()` &&
///   `meta.payload_prefix.is_some()` → run [`sniff::probe`] once per
///   connection, stash protocol + SNI onto `meta`. Missing both ⇒ the item
///   evaluates FALSE; sync [`Engine::decide`] remains fully usable sans
///   prefix.
/// - `IfNonMatch`: resolver Some + unresolved domain target ⇒ await resolve
///   once, fill `resolved_host_ips`, retry the whole loop under a
///   cycle-guard flag preventing further passes.
/// - After EVERY resolve attempt run the [`ProbeTracker`] with combined
///   result semantics: success only when `Ok(non-empty)`; `Ok(vec![])`
///   (NXDOMAIN-style miss) counts failed=true; `Err(_)` (transport broke)
///   ALSO counts failed=true — breakdown probing measures reachability.
/// - Resolver failures degrade silently per-connection (no Decision-level
///   error branch).
///
/// Interpretation note: probing is additionally gated on
/// [`Engine::needs_sniff`] — a rule set declaring no `Protocol` item never
/// spends the payload, so `meta.sniffed`/`meta.sni_host` stay `None` there
/// and `DecisionApplied.sni` is `None`. Only rule sets that declare the
/// intent to sniff get enrichment.
pub async fn decide_async(engine: &Engine, meta: &mut ConnMeta) -> Decision {
    // Sniff enrichment runs once per connection before the first pass: a
    // Protocol item in any rule means declared intent to look at payload.
    // The probe result borrows `meta.payload_prefix`, so it is reduced to
    // owned (protocol, host) fields before `meta` is mutated — the SNI is
    // stashed by value (one alloc) because a `ConnMeta` cannot hold a
    // borrow of its own payload buffer.
    let sniff_outcome = if engine.needs_sniff() && meta.sniffed.is_none() {
        meta.payload_prefix
            .as_deref()
            .and_then(sniff::probe)
            .and_then(|result| {
                // QUIC is UDP-only (RFC 9000): a QUIC sniff on a non-UDP
                // connection is rejected — prevents the decrypt path from
                // running on TCP binary handshakes (VMess, VLESS, etc.).
                (result.protocol != sniff::SniffedProtocol::Quic
                    || meta.network == NetworkMask::UDP)
                    .then(|| {
                        (
                            result.protocol,
                            result.host.map(std::borrow::Cow::into_owned),
                        )
                    })
            })
    } else {
        None
    };
    if let Some((protocol, host)) = sniff_outcome {
        meta.sni_host = host;
        meta.sniffed = Some(protocol.into());
    }

    let mut resolved_this_call = false;
    loop {
        if let Some(rule) = engine.rules.iter().find(|rule| rule.matches(meta)) {
            let decision = rule.decision.clone();
            engine.emit_decision(&decision, rule.name.as_deref(), meta.sni_host.as_deref());
            return decision;
        }
        // IfNonMatch retry: only when nothing matched, the target is a bare
        // domain, a resolver is installed, and this connection has not
        // already consumed its single resolution pass (cycle guard).
        if resolved_this_call
            || engine.resolve_strategy != crate::ir::ResolveStrategy::IfNonMatch
            || !meta.resolved_host_ips.is_empty()
            || !matches!(&meta.target.host, NetHost::Domain(_))
        {
            break;
        }
        let Some(resolver) = &engine.resolver else {
            break;
        };
        let host = match &meta.target.host {
            NetHost::Domain(d) => d.clone(),
            // Guarded above: only a domain target reaches the resolve pass.
            NetHost::Ip(_) => break,
        };

        // Cache-first: a fresh entry satisfies the pass without the sink.
        let now = jiff::Timestamp::now();
        let cached = engine
            .resolve_cache
            .as_ref()
            .and_then(|c| c.lock().get_fresh(&host, now).map(<[IpAddr]>::to_vec));
        let outcome = match cached {
            Some(ips) => Ok(ips),
            // Borrowed host: the sink's boxed future holds the `&str` and
            // is awaited right here, so no `String` clone crosses the seam.
            None => resolver.lookup_ip(&host).await,
        };
        // Success emits Resolved first, then ProbeTracker bookkeeping —
        // the resolved host may itself be a probe target. Reachability
        // semantics: empty-Ok and Err are both failure. The TTL cache is
        // filled last so `host` and `ips` move into it (entry API reuses
        // the owned key — no clones).
        if let Ok(ips) = &outcome
            && !ips.is_empty()
        {
            engine.emit_resolved(&host, ips);
            meta.resolved_host_ips.clone_from(ips);
        }
        let failed = outcome.as_ref().map_or(true, std::vec::Vec::is_empty);
        engine.probe_tracker.lock().update(
            &engine.probes,
            failed,
            Some((failed, Some(host.as_str()))),
            &engine.event_sink,
        );
        if let Ok(ips) = outcome
            && !ips.is_empty()
            && let Some(cache) = &engine.resolve_cache
        {
            cache.lock().put(host, ips, now);
        }

        // Errors and empty results degrade silently: nothing stashed, the
        // loop re-evaluates once and falls through to default.
        resolved_this_call = true;
    }
    let decision = engine.default_decision.clone();
    engine.emit_decision(&decision, None, meta.sni_host.as_deref());
    decision
}

/// Compiles one [`crate::ir::MatchItem`] with rule-index attribution on errors.
fn compile_item(item: crate::ir::MatchItem, idx: usize) -> Result<ItemMatcher, RouteError> {
    use crate::ir::MatchItem as M;
    Ok(match item {
        M::Domain {
            exact,
            suffix,
            keywords,
            regexes,
        } => ItemMatcher::Domain(
            CompiledDomain::build(&DomainRulesSpec {
                exact,
                suffix,
                keywords,
                regexes,
            })
            .map_err(|e| reindex(e, idx))?,
        ),
        M::IpCidr {
            cidrs,
            private,
            geo_country,
        } => ItemMatcher::IpCidr {
            cidrs: build_cidr_set(cidrs, idx)?,
            private,
            geo_country,
        },
        M::SourceIpCidr {
            cidrs,
            private,
            geo_country,
        } => ItemMatcher::SourceIpCidr {
            cidrs: build_cidr_set(cidrs, idx)?,
            private,
            geo_country,
        },
        M::Ports(ranges) => ItemMatcher::Ports(check_ranges(ranges, idx, "ports")?),
        M::SourcePorts(ranges) => {
            ItemMatcher::SourcePorts(check_ranges(ranges, idx, "source_ports")?)
        }
        M::Network(mask) => ItemMatcher::Network(mask),
        M::Protocol(p) => ItemMatcher::Protocol(p),
        M::InboundTag { tags } => ItemMatcher::InboundTag(tags.into_iter().collect()),
        M::OutboundTag { .. } => ItemMatcher::OutboundTag,
    })
}

/// Builds a CIDR set, attributing out-of-range prefixes to their rule.
fn build_cidr_set(cidrs: Vec<crate::addr::Cidr>, idx: usize) -> Result<CidrSet, RouteError> {
    let mut builder = CidrSetBuilder::default();
    for c in cidrs {
        builder.insert(c).map_err(|e| reindex(e, idx))?;
    }
    Ok(builder.build())
}

/// Rejects inverted `[start, end]` port ranges at compile time.
fn check_ranges(
    ranges: Vec<PortRange>,
    idx: usize,
    field: &'static str,
) -> Result<Vec<PortRange>, RouteError> {
    for r in &ranges {
        if r.start > r.end {
            return Err(RouteError::Parse {
                rule_index: idx,
                field,
                message: format!("inverted range {}-{}", r.start, r.end),
            });
        }
    }
    Ok(ranges)
}

/// Rewrites a matcher error's placeholder rule index to the real one.
const fn reindex(mut e: RouteError, idx: usize) -> RouteError {
    if let RouteError::Parse { rule_index, .. } = &mut e {
        *rule_index = idx;
    }
    e
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use super::*;
    use crate::{
        addr::Cidr,
        ir::{Action, Cond, DefaultRoute, MatchItem, RejectMethod, ResolveStrategy, Rule, RuleSet},
    };

    const ALL_PORTS: PortRange = PortRange {
        start: 0,
        end: u16::MAX,
    };

    fn base_default() -> RuleSet {
        RuleSet {
            rules: vec![],
            default: DefaultRoute::Route {
                tag: "direct".to_owned(),
            },
            resolve_strategy: ResolveStrategy::AsIs,
            probes: vec![],
        }
    }

    fn single_item_rule(item: MatchItem, action: Action) -> Rule {
        Rule {
            name: None,
            cond: Cond::All(vec![item]),
            action,
        }
    }

    fn rs(rules: Vec<(MatchItem, Action)>) -> RuleSet {
        let mut set = base_default();
        set.rules = rules
            .into_iter()
            .map(|(item, action)| single_item_rule(item, action))
            .collect();
        set
    }

    fn meta(host: &str, port: u16, network: NetworkMask) -> ConnMeta {
        ConnMeta {
            target: NetAddr {
                host: NetHost::new(host),
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

    fn route(tag: &str) -> Action {
        Action::Route {
            tag: tag.to_owned(),
            override_addr: None,
        }
    }

    fn domain(exact: &[&str], suffix: &[&str]) -> MatchItem {
        MatchItem::Domain {
            exact: exact.iter().map(ToString::to_string).collect(),
            suffix: suffix.iter().map(ToString::to_string).collect(),
            keywords: vec![],
            regexes: vec![],
        }
    }

    #[test]
    fn first_match_wins_in_declaration_order() {
        let e = Engine::build(rs(vec![
            (
                MatchItem::Ports(vec![PortRange { start: 80, end: 80 }]),
                route("a"),
            ),
            (MatchItem::Network(NetworkMask::TCP), route("b")),
        ]))
        .unwrap();
        assert_eq!(
            e.decide(&meta("example.com", 80, NetworkMask::TCP)),
            Decision::Route {
                tag: "a".into(),
                override_addr: None
            }
        );
    }

    #[test]
    fn unmatched_items_skip_the_rule_not_abort() {
        let mut set = base_default();
        set.rules.push(Rule {
            name: None,
            cond: Cond::All(vec![
                MatchItem::Ports(vec![PortRange { start: 80, end: 80 }]),
                MatchItem::Network(NetworkMask::TCP),
            ]),
            action: route("blocked"),
        });
        let e = Engine::build(set).unwrap();
        assert_eq!(
            e.decide(&meta("example.com", 443, NetworkMask::UDP)),
            Decision::Route {
                tag: "direct".into(),
                override_addr: None
            }
        );
    }

    #[test]
    fn default_fallback_when_nothing_matched() {
        let e = Engine::build(rs(vec![(
            MatchItem::Ports(vec![PortRange {
                start: 9999,
                end: 9999,
            }]),
            route("rare"),
        )]))
        .unwrap();
        assert_eq!(
            e.decide(&meta("example.org", 443, NetworkMask::TCP)),
            Decision::Route {
                tag: "direct".into(),
                override_addr: None
            }
        );
    }

    #[test]
    fn reject_and_hijackdns_are_terminal() {
        let reject = Engine::build(rs(vec![(
            MatchItem::Ports(vec![ALL_PORTS]),
            Action::Reject {
                method: RejectMethod::Drop,
            },
        )]))
        .unwrap();
        assert_eq!(
            reject.decide(&meta("example.com", 443, NetworkMask::TCP)),
            Decision::Reject {
                method: RejectMethod::Drop
            }
        );

        let hijack = Engine::build(rs(vec![(
            MatchItem::Ports(vec![ALL_PORTS]),
            Action::HijackDns,
        )]))
        .unwrap();
        assert_eq!(
            hijack.decide(&meta("dns.example.com", 53, NetworkMask::UDP)),
            Decision::HijackDns
        );

        // DefaultRoute maps identically.
        let mut set = base_default();
        set.default = DefaultRoute::Reject {
            method: RejectMethod::DefaultReply,
        };
        let default_reject = Engine::build(set).unwrap();
        assert_eq!(
            default_reject.decide(&meta("example.com", 1234, NetworkMask::TCP)),
            Decision::Reject {
                method: RejectMethod::DefaultReply
            }
        );
    }

    #[test]
    fn event_sink_receives_decision_applied_after_terminal_decision() {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let mut rules = rs(vec![(
            domain(&["block.example.net"], &[]),
            route("blackhole"),
        )]);
        rules.rules[0].name = Some("ad-block".to_owned());
        let mut e = Engine::build(rules).unwrap();
        e.set_event_sink(tx);

        let d = e.decide(&meta("block.example.net", 80, NetworkMask::TCP));
        assert_eq!(
            d,
            Decision::Route {
                tag: "blackhole".into(),
                override_addr: None
            },
            "decision itself is unchanged by the sink"
        );

        let ev = rx
            .try_recv()
            .expect("event emitted after terminal decision");
        let crate::events::RouteEvent::DecisionApplied {
            rule_name,
            tag,
            sni,
            at,
        } = ev
        else {
            panic!("expected DecisionApplied, got other variant");
        };
        assert_eq!(rule_name.as_deref(), Some("ad-block"));
        assert_eq!(tag.as_deref(), Some("blackhole"));
        assert_eq!(sni, None, "sni stays None until Task 12 wires sniffing");
        let _ = at; // wall-clock timestamp present
    }

    #[test]
    fn no_sink_means_no_event_and_decisions_still_flow() {
        let e = Engine::build(rs(vec![(MatchItem::Ports(vec![ALL_PORTS]), route("a"))])).unwrap();
        assert!(
            e.decide(&meta("h.example", 1, NetworkMask::UDP))
                .is_routed_to("a")
        );
    }

    #[test]
    fn domain_exact_and_suffix_match_destination_only_when_domain_target() {
        let e = Engine::build(rs(vec![(
            domain(&["example.com"], &["sub.corp"]),
            route("d"),
        )]))
        .unwrap();
        assert!(
            e.decide(&meta("example.com", 80, NetworkMask::TCP))
                .is_routed_to("d")
        );
        assert!(
            e.decide(&meta("x.sub.CORP", 80, NetworkMask::TCP))
                .is_routed_to("d")
        );
        // Suffix requires a label boundary.
        assert!(
            !e.decide(&meta("xfoo.com", 80, NetworkMask::TCP))
                .is_routed_to("d")
        );
        // IP targets fail domain items this task (Task 12 wires enrichment).
        assert!(
            !e.decide(&meta("93.184.216.34", 80, NetworkMask::TCP))
                .is_routed_to("d")
        );
    }

    #[test]
    fn regexes_participate_in_domain_matching() {
        let item = MatchItem::Domain {
            exact: vec![],
            suffix: vec![],
            keywords: vec![],
            regexes: vec![r"\.cdn\d*\.net$".to_owned()],
        };
        let e = Engine::build(rs(vec![(item, route("fast"))])).unwrap();
        assert!(
            e.decide(&meta("img.cdn7.net", 443, NetworkMask::TCP))
                .is_routed_to("fast")
        );
        assert!(
            !e.decide(&meta("plain.net", 443, NetworkMask::TCP))
                .is_routed_to("fast")
        );
    }

    #[test]
    fn ip_cidr_hits_via_literal_target_or_resolved_host_ips() {
        let cidrs = || vec![Cidr::parse("10.0.0.0/8").unwrap()];
        let e = Engine::build(rs(vec![(
            MatchItem::IpCidr {
                cidrs: cidrs(),
                private: false,
                geo_country: vec![],
            },
            route("lan"),
        )]))
        .unwrap();
        // Literal IP target.
        assert!(
            e.decide(&meta("10.1.2.3", 8000, NetworkMask::TCP))
                .is_routed_to("lan")
        );
        assert!(
            !e.decide(&meta("8.8.8.8", 8000, NetworkMask::TCP))
                .is_routed_to("lan")
        );
        // Domain target resolved to a LAN IP counts as a hit.
        let mut m = meta("nas.home", 5000, NetworkMask::TCP);
        m.resolved_host_ips.push(IpAddr::from([10u8, 9, 9, 9]));
        assert!(e.decide(&m).is_routed_to("lan"));
    }

    #[test]
    fn private_cidr_matches_private_ranges_and_geo_country_is_inert() {
        let e = Engine::build(rs(vec![(
            MatchItem::IpCidr {
                cidrs: vec![],
                private: true,
                geo_country: vec![],
            },
            route("home"),
        )]))
        .unwrap();
        assert!(
            e.decide(&meta("192.168.1.5", 22, NetworkMask::TCP))
                .is_routed_to("home")
        );
        assert!(
            !e.decide(&meta("8.8.8.8", 22, NetworkMask::TCP))
                .is_routed_to("home")
        );

        // geo_country is carried verbatim through compilation but evaluates
        // false this task; the geoip feature resolves it later.
        let geo = Engine::build(rs(vec![(
            MatchItem::IpCidr {
                cidrs: vec![],
                private: false,
                geo_country: vec!["CN".into()],
            },
            route("cn"),
        )]))
        .unwrap();
        assert!(
            !geo.decide(&meta("1.2.3.4", 80, NetworkMask::TCP))
                .is_routed_to("cn")
        );
        // Entries survive compilation verbatim (no silent erasure): a later
        // task's geoip feature finds them right where it needs them.
        let CompiledCond::All(items) = &geo.rules[0].cond else {
            panic!("expected compiled All condition");
        };
        let ItemMatcher::IpCidr { geo_country, .. } = &items[0] else {
            panic!("expected compiled IpCidr item");
        };
        assert_eq!(geo_country, &["CN".to_owned()]);
        // Source-side mirror carries them too.
        let src_geo = Engine::build(rs(vec![(
            MatchItem::SourceIpCidr {
                cidrs: vec![],
                private: false,
                geo_country: vec!["DE".into()],
            },
            route("de"),
        )]))
        .unwrap();
        let CompiledCond::All(items) = &src_geo.rules[0].cond else {
            panic!("expected compiled All condition");
        };
        let ItemMatcher::SourceIpCidr { geo_country, .. } = &items[0] else {
            panic!("expected compiled SourceIpCidr item");
        };
        assert_eq!(geo_country, &["DE".to_owned()]);
    }

    #[test]
    fn source_items_need_source_data_and_use_both_source_fields() {
        let sp = |p: u16| MatchItem::SourcePorts(vec![PortRange { start: p, end: p }]);
        let e = Engine::build(rs(vec![(sp(5000), route("elevated"))])).unwrap();
        // Absent source => item false.
        assert!(
            !e.decide(&meta("srv.example", 443, NetworkMask::TCP))
                .is_routed_to("elevated")
        );

        let mut with_src = meta("srv.example", 443, NetworkMask::TCP);
        with_src.source = Some(SocketAddr::from(([127u8, 0, 0, 1], 5000)));
        assert!(e.decide(&with_src).is_routed_to("elevated"));

        // SourceIpCidr reads source_resolved_ips too.
        let sic = MatchItem::SourceIpCidr {
            cidrs: vec![Cidr::parse("10.0.0.0/8").unwrap()],
            private: false,
            geo_country: vec![],
        };
        let e2 = Engine::build(rs(vec![(sic, route("corp-client"))])).unwrap();
        let mut via_resolved = meta("relay.example", 993, NetworkMask::TCP);
        via_resolved
            .source_resolved_ips
            .push(IpAddr::from([10u8, 77, 0, 1]));
        assert!(e2.decide(&via_resolved).is_routed_to("corp-client"));
    }

    #[test]
    fn network_mask_requires_connection_within_item_bits() {
        // Item tcp&&udp accepts either transport.
        let both = Engine::build(rs(vec![(
            MatchItem::Network(NetworkMask {
                tcp: true,
                udp: true,
            }),
            route("any"),
        )]))
        .unwrap();
        assert!(
            both.decide(&meta("h", 1, NetworkMask::TCP))
                .is_routed_to("any")
        );
        assert!(
            both.decide(&meta("h", 1, NetworkMask::UDP))
                .is_routed_to("any")
        );

        // Single-bit item needs equality: conn carrying both bits escapes it.
        let tcp_only = Engine::build(rs(vec![(
            MatchItem::Network(NetworkMask::TCP),
            route("tcp"),
        )]))
        .unwrap();
        let both_bits = meta(
            "h",
            1,
            NetworkMask {
                tcp: true,
                udp: true,
            },
        );
        assert!(!tcp_only.decide(&both_bits).is_routed_to("tcp"));
    }

    #[test]
    fn protocol_requires_sniffed_agreement_and_none_misses() {
        let e = Engine::build(rs(vec![(
            MatchItem::Protocol(crate::ir::SniffedProtocol::Tls),
            route("tls-out"),
        )]))
        .unwrap();
        assert!(
            !e.decide(&meta("a.b", 443, NetworkMask::TCP))
                .is_routed_to("tls-out")
        );
        let mut tls = meta("a.b", 443, NetworkMask::TCP);
        tls.sniffed = Some(crate::ir::SniffedProtocol::Tls);
        assert!(e.decide(&tls).is_routed_to("tls-out"));
        let mut dns = meta("a.b", 443, NetworkMask::TCP);
        dns.sniffed = Some(crate::ir::SniffedProtocol::Dns);
        assert!(!e.decide(&dns).is_routed_to("tls-out"));
    }

    #[test]
    fn inbound_tag_membership_matches_outbound_tag_inert_until_field_exists() {
        let ib = MatchItem::InboundTag {
            tags: vec!["proxy-in".to_owned()],
        };
        let e = Engine::build(rs(vec![(ib, route("in"))])).unwrap();
        let mut tagged = meta("h", 1, NetworkMask::TCP);
        tagged.inbound_tag = Some("proxy-in".to_owned());
        assert!(e.decide(&tagged).is_routed_to("in"));
        let mut wrong = meta("h", 1, NetworkMask::TCP);
        wrong.inbound_tag = Some("other".to_owned());
        assert!(!e.decide(&wrong).is_routed_to("in"));

        // No ConnMeta.outbound_tag field exists yet; the item never matches.
        let ob = MatchItem::OutboundTag {
            tags: vec!["x".to_owned()],
        };
        let e2 = Engine::build(rs(vec![(ob, route("out"))])).unwrap();
        assert!(
            !e2.decide(&meta("h", 1, NetworkMask::TCP))
                .is_routed_to("out")
        );
    }

    #[test]
    fn target_ips_exposes_pass_resolution_results() {
        let mut m = meta("mixed.example", 443, NetworkMask::TCP);
        assert!(m.target_ips().is_empty());
        m.resolved_host_ips.push(IpAddr::from([203u8, 0, 113, 7]));
        assert_eq!(m.target_ips().len(), 1);
    }

    #[test]
    fn build_validates_compilable_pieces() {
        // Invalid regex fails at build time, not decide time.
        let bad_regex = MatchItem::Domain {
            exact: vec![],
            suffix: vec![],
            keywords: vec![],
            regexes: vec!["[".to_owned()],
        };
        let res = Engine::build(rs(vec![(bad_regex, route("x"))]));
        assert!(res.is_err(), "invalid regex must fail at build time");

        // Out-of-range CIDR prefix length fails at build time.
        let res = Engine::build(rs(vec![(
            MatchItem::IpCidr {
                cidrs: vec![Cidr {
                    addr: IpAddr::from([10u8, 0, 0, 0]),
                    bits: 33,
                }],
                private: false,
                geo_country: vec![],
            },
            route("x"),
        )]));
        assert!(
            res.is_err(),
            "out-of-range prefix length must fail at build time"
        );

        // Inverted port range sanity check.
        let res = Engine::build(rs(vec![(
            MatchItem::Ports(vec![PortRange {
                start: 200,
                end: 100,
            }]),
            route("x"),
        )]));
        assert!(res.is_err(), "inverted port range must fail at build time");
    }

    #[test]
    fn any_short_circuits_on_first_true_arm() {
        let arm = |p: u16| Cond::All(vec![MatchItem::Ports(vec![PortRange { start: p, end: p }])]);
        let e = Engine::build(RuleSet {
            rules: vec![Rule {
                name: Some("any".to_owned()),
                cond: Cond::Any(vec![arm(80), arm(443), arm(8080)]),
                action: route("any"),
            }],
            ..base_default()
        })
        .unwrap();
        // Arms are pure, so short-circuiting is an evaluation-order guarantee
        // rather than an observable side effect; first hit decides the rule.
        assert!(
            e.decide(&meta("h", 80, NetworkMask::TCP))
                .is_routed_to("any")
        );
        assert!(
            e.decide(&meta("h", 443, NetworkMask::UDP))
                .is_routed_to("any")
        );
        // No arm true => the Any is false and the rule is skipped.
        assert!(
            !e.decide(&meta("h", 9000, NetworkMask::TCP))
                .is_routed_to("any")
        );
    }

    #[test]
    fn invert_negates_subtree_result() {
        let arm = |p: u16| Cond::All(vec![MatchItem::Ports(vec![PortRange { start: p, end: p }])]);
        // Flat inversion: everything but port 80 lands in "elsewhere".
        let e = Engine::build(RuleSet {
            rules: vec![Rule {
                name: None,
                cond: Cond::Invert(Box::new(arm(80))),
                action: route("elsewhere"),
            }],
            ..base_default()
        })
        .unwrap();
        assert!(
            !e.decide(&meta("h", 80, NetworkMask::TCP))
                .is_routed_to("elsewhere")
        );
        assert!(
            e.decide(&meta("h", 443, NetworkMask::TCP))
                .is_routed_to("elsewhere")
        );

        // Negation composes over Any: neither 80 nor 443 satisfies the
        // inverted alternation.
        let e2 = Engine::build(RuleSet {
            rules: vec![Rule {
                name: None,
                cond: Cond::Invert(Box::new(Cond::Any(vec![arm(80), arm(443)]))),
                action: route("rare"),
            }],
            ..base_default()
        })
        .unwrap();
        assert!(
            e2.decide(&meta("h", 8443, NetworkMask::TCP))
                .is_routed_to("rare")
        );
        assert!(
            !e2.decide(&meta("h", 443, NetworkMask::TCP))
                .is_routed_to("rare")
        );
    }

    #[test]
    fn nested_any_inside_all_inside_invert_evaluates_correctly() {
        // Deepest mixed tree the IR allows: `Cond::All` holds leaf
        // `MatchItem`s only, so the nesting realized here is
        // Invert(Any([All(...), Invert(All(...))])) — All leaves inside Any
        // arms inside one Invert. Upstream semantics (xray
        // route/rule/rule_abstract.go fires a rule when
        // `condition.Match(...) == !invert`; sing-box logical rules AND/OR
        // their children identically): the whole subtree's verdict is
        // negated, so this rule fires when NOT ((tcp AND port 80) OR (NOT
        // dns)) — i.e. exactly non-TCP/non-80 connections that sniff as DNS.
        // All-leaves-in-Any-arms realizes the "Any inside All" conjunction
        // context of the brief.
        let e = Engine::build(RuleSet {
            rules: vec![Rule {
                name: Some("udp-non-dns".to_owned()),
                cond: Cond::Invert(Box::new(Cond::Any(vec![
                    Cond::All(vec![
                        MatchItem::Network(NetworkMask::TCP),
                        MatchItem::Ports(vec![PortRange { start: 80, end: 80 }]),
                    ]),
                    Cond::Invert(Box::new(Cond::All(vec![MatchItem::Protocol(
                        SniffedProtocol::Dns,
                    )]))),
                ]))),
                action: route("udp"),
            }],
            ..base_default()
        })
        .unwrap();
        // UDP, un-sniffed: arm1 false (not tcp-80), NOT dns is true so arm2
        // true => Any true => Invert false => rule skipped.
        assert!(
            !e.decide(&meta("h", 443, NetworkMask::UDP))
                .is_routed_to("udp")
        );
        // TCP 80: arm1 true => Any true => Invert false => skipped.
        assert!(
            !e.decide(&meta("h", 80, NetworkMask::TCP))
                .is_routed_to("udp")
        );
        // TCP 443: arm1 false; sniffed DNS makes NOT-dns false, arm2 false
        // => Any false => Invert true => rule fires.
        let mut dns = meta("h", 443, NetworkMask::TCP);
        dns.sniffed = Some(SniffedProtocol::Dns);
        assert!(e.decide(&dns).is_routed_to("udp"));
        // TCP 80 WITH sniffed DNS: arm1 is already true, so the rule is
        // skipped regardless of the dns arm.
        let mut dns80 = meta("h", 80, NetworkMask::TCP);
        dns80.sniffed = Some(SniffedProtocol::Dns);
        assert!(!e.decide(&dns80).is_routed_to("udp"));
    }

    #[test]
    fn flat_all_compiles_identically_to_before_task11() {
        // Task 4's truth table, re-run against the tree evaluator: flat
        // `Cond::All` rules must behave bit-identically.
        let e = Engine::build(rs(vec![
            (
                MatchItem::Ports(vec![PortRange { start: 80, end: 80 }]),
                route("a"),
            ),
            (MatchItem::Network(NetworkMask::TCP), route("b")),
        ]))
        .unwrap();
        // First-match declaration order preserved.
        assert!(
            e.decide(&meta("example.com", 80, NetworkMask::TCP))
                .is_routed_to("a")
        );
        assert!(
            e.decide(&meta("example.com", 443, NetworkMask::TCP))
                .is_routed_to("b")
        );
        assert!(
            e.decide(&meta("example.com", 443, NetworkMask::UDP))
                .is_routed_to("direct")
        );

        // Multi-item conjunction inside one flat rule.
        let mut set = base_default();
        set.rules.push(Rule {
            name: None,
            cond: Cond::All(vec![
                MatchItem::Network(NetworkMask::TCP),
                MatchItem::Ports(vec![PortRange {
                    start: 443,
                    end: 443,
                }]),
            ]),
            action: route("tls"),
        });
        let e2 = Engine::build(set).unwrap();
        assert!(
            e2.decide(&meta("h", 443, NetworkMask::TCP))
                .is_routed_to("tls")
        );
        assert!(
            !e2.decide(&meta("h", 443, NetworkMask::UDP))
                .is_routed_to("tls")
        );
        assert!(
            !e2.decide(&meta("h", 80, NetworkMask::TCP))
                .is_routed_to("tls")
        );
    }

    #[test]
    fn condition_nesting_deeper_than_64_is_rejected_at_build() {
        // Conditions come from config files, so runaway nesting is rejected
        // once at build time instead of risking runtime stack depth: 65
        // nested Inverts put the innermost node at depth 65 > 64.
        let deep = (0..65).fold(
            Cond::All(vec![MatchItem::Network(NetworkMask::TCP)]),
            |c, _| Cond::Invert(Box::new(c)),
        );
        let set = RuleSet {
            rules: vec![Rule {
                name: None,
                cond: deep,
                action: route("x"),
            }],
            ..base_default()
        };
        assert!(
            matches!(
                Engine::build(set),
                Err(RouteError::Unsupported("condition nesting deeper than 64"))
            ),
            "65 levels of nesting must fail at build time"
        );

        // Exactly at the boundary: 63 wraps put the innermost leaf at depth
        // 64, which compiles. 63 negations are an odd count, so the TCP item
        // decides inverted.
        let ok = (0..63).fold(
            Cond::All(vec![MatchItem::Network(NetworkMask::TCP)]),
            |c, _| Cond::Invert(Box::new(c)),
        );
        let e = Engine::build(RuleSet {
            rules: vec![Rule {
                name: None,
                cond: ok,
                action: route("odd"),
            }],
            ..base_default()
        })
        .unwrap();
        assert!(
            e.decide(&meta("h", 1, NetworkMask::TCP))
                .is_routed_to("direct")
        );
        assert!(
            e.decide(&meta("h", 1, NetworkMask::UDP))
                .is_routed_to("odd")
        );
    }

    #[test]
    fn leaf_errors_inside_nested_conditions_carry_their_rule_index() {
        // Regression guard: `CompiledCond::build` threads the rule position
        // through recursion so parse errors deep inside Any/Invert trees
        // still name the offending rule. Rule 1's bad regex must surface as
        // `rule 1:`, not rule 0 or a placeholder.
        let bad_item = MatchItem::Domain {
            exact: vec![],
            suffix: vec![],
            keywords: vec![],
            regexes: vec!["[".to_owned()],
        };
        let set = RuleSet {
            rules: vec![
                Rule {
                    name: None,
                    cond: Cond::All(vec![MatchItem::Network(NetworkMask::TCP)]),
                    action: route("ok"),
                },
                Rule {
                    name: None,
                    cond: Cond::Any(vec![Cond::Invert(Box::new(Cond::All(vec![bad_item])))]),
                    action: route("bad"),
                },
            ],
            ..base_default()
        };
        let Err(e) = Engine::build(set) else {
            panic!("rule 1's invalid regex must fail at build time");
        };
        assert!(
            matches!(
                e,
                RouteError::Parse {
                    rule_index: 1,
                    field: "regex",
                    ..
                }
            ),
            "expected Parse error attributed to rule 1, got: {e}"
        );
    }

    #[test]
    fn empty_all_is_vacuously_true_and_compiler_gating_keeps_it_unreachable() {
        // Engine semantics: an empty conjunction holds vacuously — the
        // standard logical meaning (empty AND is true, empty OR is false).
        // That cannot arise from real configs: the xray and sing-box
        // producers skip condition-less rules outright and `merge`
        // synthesizes none, so only a hand-built `RuleSet` reaches the
        // engine with a catch-all `Cond::All([])`.
        let mut set = base_default();
        set.rules.push(Rule {
            name: Some("catch".to_owned()),
            cond: Cond::All(vec![]),
            action: route("catch"),
        });
        let e = Engine::build(set).unwrap();
        assert!(
            e.decide(&meta("anything.example", 1, NetworkMask::UDP))
                .is_routed_to("catch")
        );
    }

    /// Test-only helper naming which outbound a decision selects.
    trait DecisionExt {
        fn is_routed_to(&self, tag: &str) -> bool;
    }
    impl DecisionExt for Decision {
        fn is_routed_to(&self, tag: &str) -> bool {
            matches!(self, Self::Route { tag: t, .. } if &**t == tag)
        }
    }
}
