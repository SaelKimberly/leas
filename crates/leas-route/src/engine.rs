//! Rule routing engine: build-once compilation of full `Cond` trees
//! (`All`/`Any`/`Invert`) and synchronous pure first-match evaluation.

use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::{Arc, LazyLock},
};

use parking_lot::Mutex;
use rapidhash::RapidHashSet;

use bytes::Bytes;

use crate::{
    addr::{NetAddr, NetHost, PortRange},
    error::RouteError,
    events::RouteEvent,
    geo::{CountryLookup, GeoSource},
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
    pub inbound_tag: Option<Arc<str>>,
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
    pub sni_host: Option<compact_str::CompactString>,
    /// Filled by the `IfNonMatch` pass or pre-seeded by the caller.
    pub resolved_host_ips: Vec<IpAddr>,
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

/// A destination-domain matcher: positive sets OR'ed, plus one matcher per
/// reverse (`geosite:!code`) token, each of which holds when the host is NOT
/// in that set.
struct CompiledDomainItem {
    positive: CompiledDomain,
    negated: Vec<CompiledDomain>,
}

impl CompiledDomainItem {
    fn matches(&self, host: &str) -> bool {
        self.positive.matches_domain(host)
            || self.negated.iter().any(|set| !set.matches_domain(host))
    }
}

/// Resolved geoip matcher for destination or source addresses.
enum GeoMatcher {
    /// No geo condition.
    None,
    /// `geoip.dat`: positive CIDR sets plus reverse sets (`!code`).
    Dat {
        positive: CidrSet,
        negated: Vec<CidrSet>,
    },
    /// `GeoLite2` mmdb: country membership.
    Mmdb {
        db: Arc<dyn CountryLookup>,
        positive: Vec<Arc<str>>,
        negated: Vec<Arc<str>>,
    },
}

impl GeoMatcher {
    fn matches(&self, ip: &IpAddr) -> bool {
        match self {
            Self::None => false,
            Self::Dat { positive, negated } => {
                positive.contains(ip) || negated.iter().any(|set| !set.contains(ip))
            }
            Self::Mmdb {
                db,
                positive,
                negated,
            } => {
                let country = db.country(*ip);
                positive
                    .iter()
                    .any(|code| country.as_deref() == Some(code.as_ref()))
                    || negated
                        .iter()
                        .any(|code| country.as_deref() != Some(code.as_ref()))
            }
        }
    }
}

/// A match item compiled once at build time.
enum ItemMatcher {
    Domain(CompiledDomainItem),
    IpCidr {
        cidrs: CidrSet,
        private: bool,
        geo: GeoMatcher,
    },
    SourceIpCidr {
        cidrs: CidrSet,
        private: bool,
        geo: GeoMatcher,
    },
    Ports(Vec<PortRange>),
    SourcePorts(Vec<PortRange>),
    Network(NetworkMask),
    Protocol(SniffedProtocol),
    InboundTag(RapidHashSet<Arc<str>>),
    /// Inert until `ConnMeta` gains an outbound-tag field (Task 12).
    OutboundTag,
    /// sing-box rule-set domain set, kept succinct.
    #[cfg(feature = "geoip")]
    SrsDomain {
        set: Option<Arc<leas_geoip::geodata::srs::DomainSet>>,
        extras: CompiledDomain,
    },
    /// Compiled external rule-set subtree.
    Sub(Box<CompiledCond>),
}

impl ItemMatcher {
    /// Evaluates one compiled item against connection metadata.
    fn matches(&self, meta: &ConnMeta) -> bool {
        match self {
            Self::Domain(item) => domain_host(meta).is_some_and(|host| item.matches(host)),
            Self::IpCidr {
                cidrs,
                private,
                geo,
            } => {
                let literal_hit = match &meta.target.host {
                    NetHost::Ip(ip) => ip_candidate_matches(cidrs, *private, geo, ip),
                    NetHost::Domain(_) => false,
                };
                literal_hit
                    || meta
                        .resolved_host_ips
                        .iter()
                        .any(|ip| ip_candidate_matches(cidrs, *private, geo, ip))
            }
            Self::SourceIpCidr {
                cidrs,
                private,
                geo,
            } => {
                let socket_hit = meta
                    .source
                    .as_ref()
                    .is_some_and(|s| ip_candidate_matches(cidrs, *private, geo, &s.ip()));
                socket_hit
                    || meta
                        .source_resolved_ips
                        .iter()
                        .any(|ip| ip_candidate_matches(cidrs, *private, geo, ip))
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
            #[cfg(feature = "geoip")]
            Self::SrsDomain { set, extras } => domain_host(meta).is_some_and(|host| {
                set.as_ref().is_some_and(|set| set.matches(host)) || extras.matches_domain(host)
            }),
            Self::Sub(cond) => cond.eval(meta),
        }
    }

    /// True for matchers whose outcome can change once destination/source
    /// IPs become known (used by [`Engine::needs_resolve`]).
    fn is_ip_bearing(&self) -> bool {
        match self {
            Self::IpCidr { .. } | Self::SourceIpCidr { .. } => true,
            Self::Sub(cond) => cond.walk_items(&mut |m| m.is_ip_bearing()),
            _ => false,
        }
    }
}

/// The domain a domain item evaluates: the literal target, or the sniffed
/// SNI/host when the target is an IP.
fn domain_host(meta: &ConnMeta) -> Option<&str> {
    match &meta.target.host {
        NetHost::Domain(domain) => Some(domain.as_str()),
        NetHost::Ip(_) => meta.sni_host.as_deref(),
    }
}

/// CIDR, private-range, or geo membership for one candidate IP.
fn ip_candidate_matches(cidrs: &CidrSet, private: bool, geo: &GeoMatcher, ip: &IpAddr) -> bool {
    cidrs.contains(ip) || (private && private_contains(ip)) || geo.matches(ip)
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
/// `false`. `merge` synthesizes no empty `All`; hand-built rule sets and
/// sing-box rule-set logical groups may legitimately produce one.
enum CompiledCond {
    All(Vec<ItemMatcher>),
    Any(Vec<Self>),
    Invert(Box<Self>),
}

impl CompiledCond {
    /// Compiles a condition tree with a build-time depth guard. The root
    /// sits at depth 1; a node deeper than [`MAX_COND_DEPTH`] is rejected.
    /// `rule_idx` attributes leaf-matcher parse errors to their rule.
    fn build(
        cond: crate::ir::Cond,
        rule_idx: usize,
        depth: u32,
        geo: &mut GeoCompiler<'_>,
    ) -> Result<Self, RouteError> {
        if depth > MAX_COND_DEPTH {
            return Err(RouteError::Unsupported("condition nesting deeper than 64"));
        }
        Ok(match cond {
            Cond::All(items) => Self::All(
                items
                    .into_iter()
                    .map(|item| compile_item(item, rule_idx, geo))
                    .collect::<Result<Vec<_>, _>>()?,
            ),
            Cond::Any(children) => Self::Any(
                children
                    .into_iter()
                    .map(|c| Self::build(c, rule_idx, depth + 1, geo))
                    .collect::<Result<Vec<_>, _>>()?,
            ),
            Cond::Invert(inner) => {
                Self::Invert(Box::new(Self::build(*inner, rule_idx, depth + 1, geo)?))
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
    /// Compiles a [`RuleSet`] with no geo data: any geo reference is an
    /// error. Delegates to [`Engine::build_with_geo`].
    ///
    /// # Errors
    /// Same as [`Engine::build_with_geo`].
    pub fn build(rs: crate::ir::RuleSet) -> Result<Self, RouteError> {
        Self::build_with_geo(rs, &GeoSource::default())
    }

    /// Compiles a [`RuleSet`] into an evaluation-ready engine, resolving
    /// `geoip:`/`geosite:`/`rule_set` references from `geo`.
    ///
    /// Regexes and keyword automata compile once here; port ranges are
    /// sanity-checked so evaluation cannot encounter inverted bounds, and
    /// the full `Cond` tree (`All`/`Any`/`Invert`) is lowered to
    /// [`CompiledCond`]. Conditions nesting deeper than 64 levels are
    /// rejected here at build time, never at evaluation time. A geo
    /// reference with no matching dataset is a [`RouteError::Parse`] naming
    /// the category and file — never a silent false matcher.
    ///
    /// # Errors
    /// Returns [`RouteError::Parse`] when any rule or geo reference fails to
    /// compile, and [`RouteError::Unsupported`] when conditions nest deeper
    /// than 64.
    pub fn build_with_geo(
        rs: crate::ir::RuleSet,
        geo_source: &GeoSource,
    ) -> Result<Self, RouteError> {
        let mut geo = GeoCompiler::new(geo_source);
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
                cond: CompiledCond::build(rule.cond, idx, 1, &mut geo)?,
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
    // stashed by value because a `ConnMeta` cannot hold a borrow of its own
    // payload buffer. `CompactString` keeps the common short SNI inline; only
    // a name past 24 bytes reaches the heap.
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
                            result
                                .host
                                .map(|h| compact_str::CompactString::new(h.as_ref())),
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
fn compile_item(
    item: crate::ir::MatchItem,
    idx: usize,
    geo: &mut GeoCompiler<'_>,
) -> Result<ItemMatcher, RouteError> {
    use crate::ir::MatchItem as M;
    Ok(match item {
        M::Domain {
            exact,
            suffix,
            keywords,
            regexes,
            geosite,
        } => ItemMatcher::Domain(compile_domain_item(
            exact, suffix, keywords, regexes, &geosite, idx, geo,
        )?),
        M::IpCidr {
            cidrs,
            private,
            geo_country,
        } => ItemMatcher::IpCidr {
            cidrs: build_cidr_set(cidrs, idx)?,
            private,
            geo: compile_geo_country(geo, &geo_country, idx, "geoip")?,
        },
        M::SourceIpCidr {
            cidrs,
            private,
            geo_country,
        } => ItemMatcher::SourceIpCidr {
            cidrs: build_cidr_set(cidrs, idx)?,
            private,
            geo: compile_geo_country(geo, &geo_country, idx, "geoip")?,
        },
        M::Ports(ranges) => ItemMatcher::Ports(check_ranges(ranges, idx, "ports")?),
        M::SourcePorts(ranges) => {
            ItemMatcher::SourcePorts(check_ranges(ranges, idx, "source_ports")?)
        }
        M::Network(mask) => ItemMatcher::Network(mask),
        M::Protocol(p) => ItemMatcher::Protocol(p),
        M::InboundTag { tags } => {
            ItemMatcher::InboundTag(tags.into_iter().map(Arc::from).collect())
        }
        M::OutboundTag { .. } => ItemMatcher::OutboundTag,
        M::RuleSet { files, urls } => compile_rule_sets(geo, files, urls, idx)?,
    })
}

/// Per-build geo resolver: dataset paths plus a rule-set parse cache.
struct GeoCompiler<'a> {
    source: &'a GeoSource,
    #[cfg(feature = "geoip")]
    srs: HashMap<PathBuf, Arc<leas_geoip::geodata::srs::RuleSet>>,
}

impl<'a> GeoCompiler<'a> {
    fn new(source: &'a GeoSource) -> Self {
        Self {
            source,
            #[cfg(feature = "geoip")]
            srs: HashMap::new(),
        }
    }

    #[cfg(feature = "geoip")]
    fn load_rule_set(
        &mut self,
        path: &std::path::Path,
        idx: usize,
    ) -> Result<Arc<leas_geoip::geodata::srs::RuleSet>, RouteError> {
        if let Some(cached) = self.srs.get(path) {
            return Ok(Arc::clone(cached));
        }
        let set = Arc::new(
            leas_geoip::geodata::srs::load_rule_set(path)
                .map_err(|e| geo_err(idx, "rule_set", format!("{e:#}")))?,
        );
        self.srs.insert(path.to_path_buf(), Arc::clone(&set));
        Ok(set)
    }
}

fn geo_err(rule_index: usize, field: &'static str, message: impl Into<String>) -> RouteError {
    RouteError::Parse {
        rule_index,
        field,
        message: message.into(),
    }
}

fn split_reverse(raw: &str) -> (bool, &str) {
    let mut reverse = false;
    let mut rest = raw;
    while let Some(stripped) = rest.strip_prefix('!') {
        reverse = !reverse;
        rest = stripped;
    }
    (reverse, rest)
}

fn dedup_strings(list: &mut Vec<String>) {
    list.sort_unstable();
    list.dedup();
}

fn compile_domain_item(
    mut exact: Vec<String>,
    mut suffix: Vec<String>,
    mut keywords: Vec<String>,
    mut regexes: Vec<String>,
    geosite: &[String],
    idx: usize,
    geo: &GeoCompiler<'_>,
) -> Result<CompiledDomainItem, RouteError> {
    let mut negated_specs: Vec<DomainRulesSpec> = Vec::new();
    if !geosite.is_empty() {
        #[cfg(feature = "geoip")]
        {
            let path = geo.source.geosite.clone().ok_or_else(|| {
                geo_err(
                    idx,
                    "geosite",
                    format!("geosite:{} needs geosite.dat", geosite.join(",")),
                )
            })?;
            let loaded = leas_geoip::geodata::load_geosite(&path, geosite)
                .map_err(|e| geo_err(idx, "geosite", format!("{e:#}")))?;
            for (token, domains) in loaded {
                let mut spec = DomainRulesSpec {
                    exact: domains.exact,
                    suffix: domains.suffix,
                    keywords: domains.keywords,
                    regexes: domains.regexes,
                };
                // `Domain` entries match the bare host as well as subdomains.
                spec.exact.extend(spec.suffix.iter().cloned());
                let (reverse, _) = split_reverse(token.trim());
                if reverse {
                    negated_specs.push(spec);
                } else {
                    exact.extend(spec.exact);
                    suffix.extend(spec.suffix);
                    keywords.extend(spec.keywords);
                    regexes.extend(spec.regexes);
                }
            }
        }
        #[cfg(not(feature = "geoip"))]
        {
            return Err(RouteError::Unsupported(
                "geosite matching requires the geoip feature",
            ));
        }
    }
    dedup_strings(&mut keywords);
    dedup_strings(&mut regexes);
    let positive = CompiledDomain::build(&DomainRulesSpec {
        exact,
        suffix,
        keywords,
        regexes,
    })
    .map_err(|e| reindex(e, idx))?;
    let mut negated = Vec::with_capacity(negated_specs.len());
    for spec in negated_specs {
        negated.push(CompiledDomain::build(&spec).map_err(|e| reindex(e, idx))?);
    }
    Ok(CompiledDomainItem { positive, negated })
}

fn compile_geo_country(
    geo: &GeoCompiler<'_>,
    tokens: &[String],
    idx: usize,
    field: &'static str,
) -> Result<GeoMatcher, RouteError> {
    if tokens.is_empty() {
        return Ok(GeoMatcher::None);
    }
    #[cfg(feature = "geoip")]
    {
        if let Some(path) = &geo.source.geoip {
            let loaded = leas_geoip::geodata::load_geoip(path, tokens)
                .map_err(|e| geo_err(idx, field, format!("{e:#}")))?;
            let mut positive = CidrSetBuilder::default();
            let mut negated = Vec::new();
            for (_token, nets) in loaded {
                let mut reverse = CidrSetBuilder::default();
                let mut has_reverse = false;
                for net in nets {
                    let cidr = crate::addr::Cidr {
                        addr: net.addr,
                        bits: net.prefix,
                    };
                    if net.reverse {
                        has_reverse = true;
                        reverse.insert(cidr).map_err(|e| reindex(e, idx))?;
                    } else {
                        positive.insert(cidr).map_err(|e| reindex(e, idx))?;
                    }
                }
                if has_reverse {
                    negated.push(reverse.build());
                }
            }
            return Ok(GeoMatcher::Dat {
                positive: positive.build(),
                negated,
            });
        }
        if let Some(db) = &geo.source.country {
            let mut positive = Vec::new();
            let mut negated = Vec::new();
            for token in tokens {
                let (reverse, code) = split_reverse(token);
                let code = code.trim();
                if code.is_empty() {
                    return Err(geo_err(
                        idx,
                        field,
                        format!("empty geo code in token {token:?}"),
                    ));
                }
                let code: Arc<str> = Arc::from(code.to_ascii_lowercase());
                if reverse {
                    negated.push(code);
                } else {
                    positive.push(code);
                }
            }
            return Ok(GeoMatcher::Mmdb {
                db: Arc::clone(db),
                positive,
                negated,
            });
        }
        Err(geo_err(
            idx,
            field,
            format!(
                "geoip:{} needs geoip.dat or a loaded GeoLite2 database (geoip_mode)",
                tokens.join(",")
            ),
        ))
    }
    #[cfg(not(feature = "geoip"))]
    {
        Err(RouteError::Unsupported(
            "geoip matching requires the geoip feature",
        ))
    }
}

fn compile_rule_sets(
    geo: &mut GeoCompiler<'_>,
    files: Vec<String>,
    urls: Vec<String>,
    idx: usize,
) -> Result<ItemMatcher, RouteError> {
    #[cfg(feature = "geoip")]
    {
        let mut conditions = Vec::new();
        for key in files.into_iter().chain(urls) {
            let path = geo.source.rule_sets.get(&key).cloned().ok_or_else(|| {
                geo_err(
                    idx,
                    "rule_set",
                    format!("rule-set `{key}` was not prepared by the caller"),
                )
            })?;
            let set = geo.load_rule_set(&path, idx)?;
            conditions.push(compile_srs_rule_set(&set, idx)?);
        }
        let cond = match conditions.len() {
            0 => {
                return Err(geo_err(
                    idx,
                    "rule_set",
                    "rule-set reference has no sources",
                ));
            }
            1 => conditions.remove(0),
            _ => CompiledCond::Any(conditions),
        };
        Ok(ItemMatcher::Sub(Box::new(cond)))
    }
    #[cfg(not(feature = "geoip"))]
    {
        let _ = (geo, files, urls);
        Err(RouteError::Unsupported(
            "rule_set matching requires the geoip feature",
        ))
    }
}

#[cfg(feature = "geoip")]
fn compile_srs_rule_set(
    set: &leas_geoip::geodata::srs::RuleSet,
    idx: usize,
) -> Result<CompiledCond, RouteError> {
    let mut rules = Vec::with_capacity(set.rules.len());
    for rule in &set.rules {
        rules.push(compile_srs_rule(rule, idx)?);
    }
    Ok(match rules.len() {
        0 => CompiledCond::Any(Vec::new()),
        1 => rules.remove(0),
        _ => CompiledCond::Any(rules),
    })
}

#[cfg(feature = "geoip")]
fn compile_srs_rule(
    rule: &leas_geoip::geodata::srs::Rule,
    idx: usize,
) -> Result<CompiledCond, RouteError> {
    use leas_geoip::geodata::srs::Rule;
    match rule {
        Rule::Default(default) => compile_srs_default(default, idx),
        Rule::Logical { and, rules, invert } => {
            let mut children = Vec::with_capacity(rules.len());
            for child in rules {
                children.push(compile_srs_rule(child, idx)?);
            }
            let base = if *and {
                if children.len() == 1 {
                    children.remove(0)
                } else {
                    // AND over condition trees: every child is one operand.
                    CompiledCond::All(
                        children
                            .into_iter()
                            .map(|cond| ItemMatcher::Sub(Box::new(cond)))
                            .collect(),
                    )
                }
            } else {
                match children.len() {
                    0 => CompiledCond::Any(Vec::new()),
                    1 => children.remove(0),
                    _ => CompiledCond::Any(children),
                }
            };
            Ok(if *invert {
                CompiledCond::Invert(Box::new(base))
            } else {
                base
            })
        }
    }
}

#[cfg(feature = "geoip")]
fn compile_srs_default(
    default: &leas_geoip::geodata::srs::DefaultRule,
    idx: usize,
) -> Result<CompiledCond, RouteError> {
    let mut groups: Vec<CompiledCond> = Vec::new();

    // sing-box: destination domains and destination `ip_cidr` are ONE OR
    // group; every other group is ANDed.
    let has_domains =
        default.domains.is_some() || !default.keywords.is_empty() || !default.regexes.is_empty();
    if has_domains || !default.ips.is_empty() {
        let mut alternatives = Vec::new();
        if has_domains {
            let extras = CompiledDomain::build(&DomainRulesSpec {
                exact: Vec::new(),
                suffix: Vec::new(),
                keywords: default.keywords.clone(),
                regexes: default.regexes.clone(),
            })
            .map_err(|e| reindex(e, idx))?;
            alternatives.push(CompiledCond::All(vec![ItemMatcher::SrsDomain {
                set: default.domains.clone().map(Arc::new),
                extras,
            }]));
        }
        if !default.ips.is_empty() {
            alternatives.push(CompiledCond::All(vec![ItemMatcher::IpCidr {
                cidrs: cidr_set_from_ranges(&default.ips, idx)?,
                private: false,
                geo: GeoMatcher::None,
            }]));
        }
        groups.push(any_of(alternatives));
    }
    if !default.source_ips.is_empty() {
        groups.push(CompiledCond::All(vec![ItemMatcher::SourceIpCidr {
            cidrs: cidr_set_from_ranges(&default.source_ips, idx)?,
            private: false,
            geo: GeoMatcher::None,
        }]));
    }
    if !default.source_ports.is_empty() {
        groups.push(CompiledCond::All(vec![ItemMatcher::SourcePorts(
            default
                .source_ports
                .iter()
                .map(|&(start, end)| PortRange { start, end })
                .collect(),
        )]));
    }
    if !default.ports.is_empty() {
        groups.push(CompiledCond::All(vec![ItemMatcher::Ports(
            default
                .ports
                .iter()
                .map(|&(start, end)| PortRange { start, end })
                .collect(),
        )]));
    }
    if let Some(network) = default.network {
        groups.push(CompiledCond::All(vec![ItemMatcher::Network(NetworkMask {
            tcp: network.tcp,
            udp: network.udp,
        })]));
    }

    let base = match groups.len() {
        0 => CompiledCond::All(Vec::new()),
        1 => groups.remove(0),
        _ => CompiledCond::All(
            groups
                .into_iter()
                .map(|cond| ItemMatcher::Sub(Box::new(cond)))
                .collect(),
        ),
    };
    Ok(if default.invert {
        CompiledCond::Invert(Box::new(base))
    } else {
        base
    })
}

#[cfg(feature = "geoip")]
fn any_of(mut conditions: Vec<CompiledCond>) -> CompiledCond {
    match conditions.len() {
        0 => CompiledCond::All(Vec::new()),
        1 => conditions.remove(0),
        _ => CompiledCond::Any(conditions),
    }
}

#[cfg(feature = "geoip")]
fn cidr_set_from_ranges(
    ranges: &[leas_geoip::geodata::srs::GeoRange],
    idx: usize,
) -> Result<CidrSet, RouteError> {
    let mut builder = CidrSetBuilder::default();
    for range in ranges {
        builder
            .insert_range(range.from, range.to)
            .map_err(|e| reindex(e, idx))?;
    }
    Ok(builder.build())
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
            geosite: Vec::new(),
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
            geosite: Vec::new(),
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
    fn private_cidr_matches_private_ranges() {
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
        tagged.inbound_tag = Some(Arc::from("proxy-in"));
        assert!(e.decide(&tagged).is_routed_to("in"));
        let mut wrong = meta("h", 1, NetworkMask::TCP);
        wrong.inbound_tag = Some(Arc::from("other"));
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
    fn build_validates_compilable_pieces() {
        // Invalid regex fails at build time, not decide time.
        let bad_regex = MatchItem::Domain {
            exact: vec![],
            suffix: vec![],
            keywords: vec![],
            regexes: vec!["[".to_owned()],
            geosite: Vec::new(),
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
            geosite: Vec::new(),
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

#[cfg(all(test, feature = "geoip"))]
mod geo_tests {
    use std::collections::HashMap;
    use std::net::IpAddr;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;

    use super::*;
    use crate::geo::{CountryLookup, GeoSource};
    use crate::ir::{Action, Cond, DefaultRoute, MatchItem, ResolveStrategy, Rule, RuleSet};

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

    fn route(tag: &str) -> Action {
        Action::Route {
            tag: tag.to_owned(),
            override_addr: None,
        }
    }

    fn rs(rules: Vec<(MatchItem, Action)>) -> RuleSet {
        RuleSet {
            rules: rules
                .into_iter()
                .map(|(cond, action)| Rule {
                    name: None,
                    cond: Cond::All(vec![cond]),
                    action,
                })
                .collect(),
            default: DefaultRoute::Route {
                tag: "default".to_owned(),
            },
            resolve_strategy: ResolveStrategy::AsIs,
            probes: Vec::new(),
        }
    }

    fn routed(decision: &Decision, tag: &str) -> bool {
        matches!(decision, Decision::Route { tag: t, .. } if &**t == tag)
    }

    // ── dat fixtures ────────────────────────────────────────────────

    fn uvarint(mut value: u64, out: &mut Vec<u8>) {
        while value >= 0x80 {
            out.push(u8::try_from(value & 0x7f).unwrap() | 0x80);
            value >>= 7;
        }
        out.push(u8::try_from(value & 0x7f).unwrap());
    }

    fn field_bytes(num: u64, bytes: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        uvarint((num << 3) | 2, &mut out);
        uvarint(bytes.len() as u64, &mut out);
        out.extend_from_slice(bytes);
        out
    }

    fn field_varint(num: u64, value: u64) -> Vec<u8> {
        let mut out = Vec::new();
        uvarint(num << 3, &mut out);
        uvarint(value, &mut out);
        out
    }

    fn domain(kind: u64, value: &str) -> Vec<u8> {
        let mut out = field_varint(1, kind);
        out.extend(field_bytes(2, value.as_bytes()));
        out
    }

    fn site_entry(code: &str, domains: &[Vec<u8>]) -> Vec<u8> {
        let mut out = field_bytes(1, code.as_bytes());
        for domain in domains {
            out.extend(field_bytes(2, domain));
        }
        out
    }

    fn geoip_entry(code: &str, cidrs: &[(&str, u8)], reverse: bool) -> Vec<u8> {
        let mut out = field_bytes(1, code.as_bytes());
        for (addr, prefix) in cidrs {
            let addr: IpAddr = addr.parse().unwrap();
            let octets: Vec<u8> = match addr {
                IpAddr::V4(a) => a.octets().to_vec(),
                IpAddr::V6(a) => a.octets().to_vec(),
            };
            let mut cidr = field_bytes(1, &octets);
            cidr.extend(field_varint(2, u64::from(*prefix)));
            out.extend(field_bytes(2, &cidr));
        }
        if reverse {
            out.extend(field_varint(3, 1));
        }
        out
    }

    fn list(entries: &[Vec<u8>]) -> Vec<u8> {
        let mut out = Vec::new();
        for entry in entries {
            out.extend(field_bytes(1, entry));
        }
        out
    }

    fn write(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, bytes).unwrap();
        path
    }

    struct FakeCountry(HashMap<IpAddr, Arc<str>>);
    impl CountryLookup for FakeCountry {
        fn country(&self, ip: IpAddr) -> Option<Arc<str>> {
            self.0.get(&ip).cloned()
        }
    }

    #[test]
    fn geosite_dat_tokens_and_reverse() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(
            dir.path(),
            "geosite.dat",
            &list(&[site_entry(
                "cn",
                &[domain(2, "example.cn"), domain(3, "exact.cn")],
            )]),
        );
        let source = GeoSource {
            geosite: Some(path),
            ..GeoSource::default()
        };
        let engine = Engine::build_with_geo(
            rs(vec![(
                MatchItem::Domain {
                    exact: vec![],
                    suffix: vec![],
                    keywords: vec![],
                    regexes: vec![],
                    geosite: vec!["cn".into()],
                },
                route("cn"),
            )]),
            &source,
        )
        .unwrap();
        assert!(routed(&engine.decide(&meta("sub.example.cn", 443)), "cn"));
        assert!(routed(&engine.decide(&meta("example.cn", 443)), "cn"));
        assert!(routed(&engine.decide(&meta("exact.cn", 443)), "cn"));
        assert!(!routed(&engine.decide(&meta("other.cn", 443)), "cn"));

        let reversed = Engine::build_with_geo(
            rs(vec![(
                MatchItem::Domain {
                    exact: vec![],
                    suffix: vec![],
                    keywords: vec![],
                    regexes: vec![],
                    geosite: vec!["!cn".into()],
                },
                route("not-cn"),
            )]),
            &source,
        )
        .unwrap();
        assert!(routed(&reversed.decide(&meta("other.cn", 443)), "not-cn"));
        assert!(!routed(
            &reversed.decide(&meta("sub.example.cn", 443)),
            "not-cn"
        ));
    }

    #[test]
    fn geoip_dat_positive_reverse_and_mmdb() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(
            dir.path(),
            "geoip.dat",
            &list(&[
                geoip_entry("cn", &[("1.0.1.0", 24)], false),
                geoip_entry("rev", &[("10.0.0.0", 8)], true),
            ]),
        );
        let source = GeoSource {
            geoip: Some(path),
            ..GeoSource::default()
        };
        let engine = Engine::build_with_geo(
            rs(vec![
                (
                    MatchItem::IpCidr {
                        cidrs: vec![],
                        private: false,
                        geo_country: vec!["cn".into()],
                    },
                    route("cn"),
                ),
                (
                    MatchItem::IpCidr {
                        cidrs: vec![],
                        private: false,
                        geo_country: vec!["rev".into()],
                    },
                    route("rev"),
                ),
            ]),
            &source,
        )
        .unwrap();
        assert!(routed(&engine.decide(&meta("1.0.1.5", 80)), "cn"));
        assert!(!routed(&engine.decide(&meta("8.8.8.8", 80)), "cn"));
        assert!(routed(&engine.decide(&meta("8.8.4.4", 80)), "rev"));
        assert!(!routed(&engine.decide(&meta("10.1.2.3", 80)), "rev"));

        let mut countries = HashMap::new();
        countries.insert("1.2.3.4".parse::<IpAddr>().unwrap(), Arc::<str>::from("cn"));
        let mmdb = GeoSource {
            country: Some(Arc::new(FakeCountry(countries))),
            ..GeoSource::default()
        };
        let engine = Engine::build_with_geo(
            rs(vec![
                (
                    MatchItem::IpCidr {
                        cidrs: vec![],
                        private: false,
                        geo_country: vec!["cn".into()],
                    },
                    route("cn"),
                ),
                (
                    MatchItem::IpCidr {
                        cidrs: vec![],
                        private: false,
                        geo_country: vec!["!cn".into()],
                    },
                    route("not-cn"),
                ),
            ]),
            &mmdb,
        )
        .unwrap();
        assert!(routed(&engine.decide(&meta("1.2.3.4", 80)), "cn"));
        assert!(routed(&engine.decide(&meta("8.8.8.8", 80)), "not-cn"));
        assert!(!routed(&engine.decide(&meta("1.2.3.4", 80)), "not-cn"));
    }

    #[test]
    fn missing_geo_data_or_code_is_a_parse_error() {
        let err = Engine::build(rs(vec![(
            MatchItem::IpCidr {
                cidrs: vec![],
                private: false,
                geo_country: vec!["cn".into()],
            },
            route("cn"),
        )]))
        .err()
        .expect("expected an error");
        assert!(
            matches!(err, RouteError::Parse { field: "geoip", .. }),
            "{err:?}"
        );

        let err = Engine::build(rs(vec![(
            MatchItem::Domain {
                exact: vec![],
                suffix: vec![],
                keywords: vec![],
                regexes: vec![],
                geosite: vec!["cn".into()],
            },
            route("cn"),
        )]))
        .err()
        .expect("expected an error");
        assert!(
            matches!(
                err,
                RouteError::Parse {
                    field: "geosite",
                    ..
                }
            ),
            "{err:?}"
        );

        let dir = tempfile::tempdir().unwrap();
        let path = write(dir.path(), "geosite.dat", &list(&[site_entry("cn", &[])]));
        let source = GeoSource {
            geosite: Some(path),
            ..GeoSource::default()
        };
        let err = Engine::build_with_geo(
            rs(vec![(
                MatchItem::Domain {
                    exact: vec![],
                    suffix: vec![],
                    keywords: vec![],
                    regexes: vec![],
                    geosite: vec!["typo".into()],
                },
                route("x"),
            )]),
            &source,
        )
        .err()
        .expect("expected an error");
        assert!(format!("{err}").contains("typo"), "{err}");
    }

    #[test]
    fn domain_rules_use_sni_host_for_ip_targets() {
        let engine = Engine::build(rs(vec![(
            MatchItem::Domain {
                exact: vec!["sni.test".into()],
                suffix: vec![],
                keywords: vec![],
                regexes: vec![],
                geosite: vec![],
            },
            route("sni"),
        )]))
        .unwrap();
        let mut with_sni = meta("1.2.3.4", 443);
        with_sni.sni_host = Some(compact_str::CompactString::new("sni.test"));
        assert!(routed(&engine.decide(&with_sni), "sni"));
        assert!(!routed(&engine.decide(&meta("1.2.3.4", 443)), "sni"));
    }

    // ── srs fixtures ────────────────────────────────────────────────

    fn ip_set(ranges: &[(&str, &str)]) -> Vec<u8> {
        let mut out = vec![1u8];
        out.extend_from_slice(&(ranges.len() as u64).to_be_bytes());
        for (from, to) in ranges {
            for addr in [*from, *to] {
                let addr: IpAddr = addr.parse().unwrap();
                let bytes: Vec<u8> = match addr {
                    IpAddr::V4(a) => a.octets().to_vec(),
                    IpAddr::V6(a) => a.octets().to_vec(),
                };
                uvarint(bytes.len() as u64, &mut out);
                out.extend_from_slice(&bytes);
            }
        }
        out
    }

    fn string_item(id: u8, values: &[&str]) -> Vec<u8> {
        let mut out = vec![id];
        uvarint(values.len() as u64, &mut out);
        for value in values {
            uvarint(value.len() as u64, &mut out);
            out.extend_from_slice(value.as_bytes());
        }
        out
    }

    fn pack_srs(rules: &[Vec<u8>]) -> Vec<u8> {
        use flate2::Compression;
        use flate2::write::ZlibEncoder;
        use std::io::Write as _;
        let mut body = Vec::new();
        uvarint(rules.len() as u64, &mut body);
        for rule in rules {
            body.extend_from_slice(rule);
        }
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&body).unwrap();
        let compressed = encoder.finish().unwrap();
        let mut out = b"SRS".to_vec();
        out.push(5);
        out.extend_from_slice(&compressed);
        out
    }

    #[test]
    fn srs_rule_set_ip_and_port_groups() {
        let dir = tempfile::tempdir().unwrap();
        let mut items: Vec<u8> = vec![0u8];
        items.extend(
            vec![6]
                .into_iter()
                .chain(ip_set(&[("10.0.0.0", "10.255.255.255")])),
        );
        items.extend(string_item(10, &["443:443"]));
        items.push(0xFF);
        items.push(0);
        let rule = items;
        let path = write(dir.path(), "set.srs", &pack_srs(&[rule]));
        let mut rule_sets = HashMap::new();
        rule_sets.insert("set".to_owned(), path);
        let source = GeoSource {
            rule_sets,
            ..GeoSource::default()
        };
        let engine = Engine::build_with_geo(
            rs(vec![(
                MatchItem::RuleSet {
                    files: vec!["set".into()],
                    urls: vec![],
                },
                route("internal"),
            )]),
            &source,
        )
        .unwrap();
        assert!(routed(&engine.decide(&meta("10.1.2.3", 443)), "internal"));
        assert!(!routed(&engine.decide(&meta("10.1.2.3", 80)), "internal"));
        assert!(!routed(&engine.decide(&meta("8.8.8.8", 443)), "internal"));
    }

    #[test]
    fn rule_set_without_a_prepared_source_is_an_error() {
        let err = Engine::build(rs(vec![(
            MatchItem::RuleSet {
                files: vec!["ghost".into()],
                urls: vec![],
            },
            route("x"),
        )]))
        .err()
        .expect("expected an error");
        assert!(
            matches!(
                err,
                RouteError::Parse {
                    field: "rule_set",
                    ..
                }
            ),
            "{err:?}"
        );
    }
}
