//! Toasty models for the typed data model (phase B).
//!
//! Seven tables replace the old nine: `endpoints`, `protocols`,
//! `profile_stats` (per endpoint-protocol pair state), `endpoint_groups`
//! (many-to-many link), `groups`, `routing_rules`, `dns_settings`.
//! All values are typed — newtype ids, embedded enums/structs, jiff
//! timestamps, deferred JSON config blobs — and every read in
//! [`crate::database`] goes through the typed query API.

#![allow(
    clippy::used_underscore_binding,
    reason = "toasty-macros synthesizes `_0`-named parameters in the Update builder setters for unnamed tuple fields (`EndpointId`, `ProtocolId`) and uses them; the generated impls carry the field's span so no narrower scope reaches them, and no handwritten code here uses underscore-prefixed bindings"
)]
// Same root cause, different lint: `#[shared(..)]` emits one accessor per
// variant that reads the shared column, and the expansion takes `&self` without
// using it. The lint's span is the VARIANT, so an allow on the variant or the
// enum does not reach it — only this module scope does, and no handwritten code
// in this file defines a method that ignores `self`.
#![allow(clippy::unused_self)]

use std::collections::HashMap;

use jiff::Timestamp;
use leas_proto::proto_spec::{ProtocolConfig, ProtocolKind, SecurityType, TransportType};
use toasty::{Deferred, Json};

// ── Typed embed types ───────────────────────────────────────────────────
//
// Toasty embeds flatten into columns of the owning table (no separate
// tables). Proto's typed configs are stored opaque as deferred JSON columns.

/// Endpoint id. Non-zero invariant — toasty has no `NonZero` column support,
/// so the constructor enforces it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, toasty::Embed)]
pub struct EndpointId(i64);

impl EndpointId {
    /// Construct a new id. Panics (debug builds) when `v == 0`.
    #[must_use]
    pub const fn new(v: i64) -> Self {
        debug_assert!(v != 0, "EndpointId must be non-zero");
        Self(v)
    }

    /// The raw column value.
    #[must_use]
    pub const fn get(self) -> i64 {
        self.0
    }
}

/// Protocol row id. Non-zero invariant — see [`EndpointId`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, toasty::Embed)]
pub struct ProtocolId(i64);

impl ProtocolId {
    /// Construct a new id. Panics (debug builds) when `v == 0`.
    #[must_use]
    pub const fn new(v: i64) -> Self {
        debug_assert!(v != 0, "ProtocolId must be non-zero");
        Self(v)
    }

    /// The raw column value.
    #[must_use]
    pub const fn get(self) -> i64 {
        self.0
    }
}

/// Epoch SECONDS of a `jiff` timestamp — the storage form of every timestamp
/// column.
///
/// Timestamps are integers, not RFC3339 text: a column that is only ever
/// compared (windows, cutoffs, recency ordering) stores what the comparison
/// needs, and the TUI formats the integer on the way to the screen. Second
/// precision is the ordering law's original granularity (a link seen twice in
/// the same second ties, and the protocol id breaks the tie).
#[must_use]
pub fn to_epoch(ts: Timestamp) -> i64 {
    ts.as_second()
}

/// A `jiff` timestamp from an epoch-seconds column. A value outside jiff's
/// range (impossible for rows this crate writes) reads as the epoch.
#[must_use]
pub fn from_epoch(secs: i64) -> Timestamp {
    Timestamp::from_second(secs).unwrap_or_else(|_| Timestamp::from_second(0).expect("epoch"))
}

/// Now, as a stored timestamp value.
#[must_use]
pub fn now_epoch() -> i64 {
    to_epoch(Timestamp::now())
}

/// Endpoint host kind (replaces the legacy `host_type` string).
#[derive(Debug, Clone, Copy, PartialEq, Eq, toasty::Embed)]
pub enum HostType {
    Ipv4,
    Ipv6,
    Dns,
    Undefined,
}

impl HostType {
    /// The `host_type` column's stored spelling — the **embed derive's**
    /// `snake_case` of the Rust variant ident, which is NEITHER `Debug` NOR any
    /// wire form. Verified against the 2026-10-01 feed: `ipv4`, `dns`, `ipv6`
    /// across 74,014 endpoints, no other spelling present.
    ///
    /// This exists because the raw multi-row import writer needs the label and
    /// the typed upsert cannot supply it. A wrong label does not fail the
    /// write — `host_type` is unconstrained text — it silently mis-classifies the
    /// endpoint, so the DNS gate starts disagreeing with the row.
    #[must_use]
    pub const fn as_db_label(self) -> &'static str {
        match self {
            Self::Ipv4 => "ipv4",
            Self::Ipv6 => "ipv6",
            Self::Dns => "dns",
            Self::Undefined => "undefined",
        }
    }

    /// Parse a stored label back, accepting only what [`Self::as_db_label`]
    /// writes. The round-trip is pinned by a test against a real database.
    #[must_use]
    pub fn from_db_label(label: &str) -> Option<Self> {
        match label {
            "ipv4" => Some(Self::Ipv4),
            "ipv6" => Some(Self::Ipv6),
            "dns" => Some(Self::Dns),
            "undefined" => Some(Self::Undefined),
            _ => None,
        }
    }
}

/// Kind of latency/ping task.
#[derive(Debug, Clone, Copy, PartialEq, Eq, toasty::Embed)]
pub enum TaskKind {
    FastPing,
    RealPing,
    UdpPing,
    UdpTest,
    SpeedTest,
}

/// Which error bucket a profile error belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, toasty::Embed)]
pub enum ProfileErr {
    Real,
    Fast,
    Name,
}

/// Group status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, toasty::Embed)]
pub enum GroupStatus {
    Ok,
    Error,
    Never,
}

/// IP selection strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, toasty::Embed)]
pub enum QueryStrategy {
    UseIp,
    UseIpv4,
    UseIpv6,
}

/// Conversion target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, toasty::Embed)]
pub enum ConvertTarget {
    Clash,
}

/// Error info attached to a failed test.
#[derive(Debug, Clone, PartialEq, Eq, toasty::Embed)]
pub struct ErrorInfo {
    pub kind: ProfileErr,
    pub text: String,
}

/// Why a link was moved to Purgatory permanently (spec
/// `2026-09-17-purge-reason-design.md` §7).
///
/// Fieldless on purpose: the exact case IS the variant, so the row needs ONE
/// nullable column and one CHECK list — the HTTP status and the human detail
/// stay in `error_text` beside it. Distinct from [`ErrorInfo`]: that is a
/// measurement marker the error-TTL sweep clears, this is a verdict only a
/// data-carrying success clears.
#[derive(Debug, Clone, Copy, PartialEq, Eq, toasty::Embed)]
pub enum PurgeReason {
    /// A REALITY handshake was answered by a real certificate: wrong
    /// `pbk`/`sid`, or the host is not a REALITY endpoint.
    RealityFallback,
    /// The server's certificate does not cover the configured host/SNI.
    CertificateMismatch,
    /// The server's certificate is expired (or not yet valid).
    CertificateExpired,
    /// The port answered in cleartext: not the TLS endpoint the config claims.
    NotTls,
    /// The config as stored cannot dial (missing `pbk`, unknown xhttp mode,
    /// unusable PSK, a request its own host/path cannot compose).
    ConfigInvalid,
    /// The proxy's OWN upgrade handshake was answered with an HTTP status.
    TransportRejected,
    /// The CDN answered an origin error (530/521/522/526).
    OriginUnreachable,
}

/// Traffic accounting for an endpoint/group.
#[derive(Debug, Clone, Copy, PartialEq, Eq, toasty::Embed)]
pub struct TrafficStats {
    pub today_up: i64,
    pub today_down: i64,
    pub total_up: i64,
    pub total_down: i64,
}

/// Transport-layer kind.
///
/// The scalar projection the page reads without touching the JSON. The full
/// transport config lives inside `Protocol.config` (the single owner); a
/// second `data` JSON column was a write-only duplicate and is dropped
/// (db-rewamp D8).
#[derive(Debug, Clone, toasty::Embed)]
pub struct Transport {
    pub r#type: TransportType,
}

/// Security (TLS/REALITY) scalar projection.
///
/// The page reads these without the JSON. The full security config lives
/// inside `Protocol.config` (the single owner); the write-only `data` JSON
/// duplicate is dropped (db-rewamp D8).
#[derive(Debug, Clone, toasty::Embed)]
pub struct Security {
    pub r#type: SecurityType,
    pub sni: Option<String>,
    pub fp: Option<String>,
    pub insecure: Option<bool>,
}

/// Latency of one probe, real or fast. Both variants share the `delay`
/// column (`latency_delay`); `ip` exists only on `Real` (`latency_ip`).
#[derive(Debug, Clone, PartialEq, Eq, toasty::Embed)]
pub enum Latency {
    Real {
        #[shared(delay)]
        delay: i32,
        ip: Option<String>,
    },
    Fast {
        #[shared(delay)]
        delay: i32,
    },
}

// ── Primary models (toasty ORM, mapped to DB tables) ────────────────────

/// Endpoint: a network endpoint identified by host+port.
#[derive(Debug, Clone, toasty::Model)]
#[table = "endpoints"]
pub struct Endpoint {
    #[key]
    pub id: EndpointId, // identity = stable_hash(canonical_name, port); see `Endpoint::derive_name`
    /// Registrable domain (eTLD+1, db-rewamp D2), empty for an IP-literal or
    /// exotic host. The identity input.
    pub domain: String,
    /// Labels left of the domain; empty when the host IS the domain or is not
    /// DNS. Host-kind is DERIVED (`is_dns`).
    pub sub_domain: String,
    pub port: u16,                   // primary port; 0 for undefined
    pub ports: Vec<u16>,             // full port spec; empty when single-port
    pub last_source: Option<String>, // hash of source subscription
    /// Manual protocol override (FK -> protocols.id); NULL = auto-select best.
    pub manual_protocol_override: Option<ProtocolId>,
    /// Timestamp of the DNS lookup that produced this endpoint's addresses;
    /// NULL = never, or the host is an IP. The addresses themselves live in
    /// [`EndpointIp`] (one row per address) — this column is the TTL gate, so
    /// it stays here: an attempt that resolved nothing still has to age out.
    pub resolved_at: Option<i64>, // epoch seconds
    pub created_at: i64, // epoch seconds; writers stamp it (no `#[auto]`: on an
    // integer column toasty's auto strategy is Increment, not "now")
    #[has_many]
    pub links: Deferred<Vec<ProfileStats>>,
    #[has_many]
    pub group_links: Deferred<Vec<EndpointGroup>>,
}

impl Endpoint {
    /// Derive `(domain, sub_domain)` from a host + its kind (db-rewamp D2/D10).
    /// A DNS host splits via psl2 (validated importers always split; the
    /// fallback lowercases); an IP/exotic host stores empty strings and its
    /// literal (if an IP) is written to `endpoint_ip` by the import path.
    #[must_use]
    pub fn derive_domain(host: &str, kind: HostType) -> (String, String) {
        match kind {
            HostType::Dns => match leas_proto::domain::split(host) {
                Some(d) => (d.domain, d.sub_domain),
                None => (host.to_lowercase(), String::new()),
            },
            HostType::Ipv4 | HostType::Ipv6 | HostType::Undefined => (String::new(), String::new()),
        }
    }

    /// The identity input: the canonical DNS name, the IP literal, or empty.
    #[must_use]
    pub fn derive_name(host: &str, kind: HostType) -> String {
        match kind {
            HostType::Dns => leas_proto::domain::split(host).map_or_else(
                || host.to_lowercase(),
                |d| {
                    if d.sub_domain.is_empty() {
                        d.domain
                    } else {
                        format!("{}.{}", d.sub_domain, d.domain)
                    }
                },
            ),
            HostType::Ipv4 | HostType::Ipv6 => host.to_string(),
            HostType::Undefined => String::new(),
        }
    }

    /// The canonical DNS name (`sub_domain.domain`), empty for a non-DNS host.
    #[must_use]
    pub fn dns_name(&self) -> String {
        if self.sub_domain.is_empty() {
            self.domain.clone()
        } else {
            format!("{}.{}", self.sub_domain, self.domain)
        }
    }

    /// The endpoint's host as text for DISPLAY and dialing (db-rewamp D10): the
    /// reconstructed DNS name, else the first address literal. `dns_name()` is
    /// empty for an IP-literal host, so a bare `dns_name()` renders "" for ~75%
    /// of a real feed — this is the ONE accessor every display/edit/dial site
    /// reads (the dial sites were `ping::dial_host` before it moved here).
    #[must_use]
    pub fn display_host(&self, addresses: &[std::net::IpAddr]) -> String {
        if self.is_dns() {
            self.dns_name()
        } else {
            addresses
                .first()
                .map_or_else(String::new, ToString::to_string)
        }
    }

    /// True for a DNS-name host (`domain` non-empty). The DERIVED kind (D10).
    #[must_use]
    pub const fn is_dns(&self) -> bool {
        !self.domain.is_empty()
    }
}

/// One resolved address of one DNS endpoint (`endpoint_ip`).
///
/// Replaces the JSON-array `endpoints.resolved_as` column: the set is
/// relational, so an address is stored once (the PK is
/// `(endpoint_id, ip_key)`) and it is queryable and orderable.
///
/// The column IS the address — a packed encoding (`crate::endpoint_ip`): a
/// family byte (the `IpAddr` discriminant: 4 = IPv4, 6 = IPv6) then the
/// big-endian octets. Byte order is therefore numeric order, and every IPv4
/// sorts before every IPv6. There is no second, textual column: the text is
/// rendered from the bytes on read (`Ipv4Addr`/`Ipv6Addr`), which is an
/// 8/16-byte copy, not a parse, and one fact cannot disagree with itself.
///
/// That is the one thing the engine's own `inet` type cannot do. Turso
/// declares it `BASE text ENCODE validate_ipaddr(value) DECODE value` — no
/// `OPERATOR '<'`, so `ORDER BY ip` / `CREATE INDEX … (ip)` are parse errors;
/// adding the operator makes them legal but orders the TEXT form, i.e.
/// `10.0.0.1 < 9.0.0.1` (measured 2026-09-15,
/// `docs/aegis/specs/2026-09-15-endpoint-ip-storage-design.md`).
///
/// The rows of one endpoint are a SET keyed by the address, so the displayed
/// order is canonical (IPv4 by address, then IPv6) rather than whatever order
/// the resolver happened to return. Nothing else about the value changes.
#[derive(Debug, Clone, toasty::Model)]
#[table = "endpoint_ip"]
#[key(endpoint_id, ip_key)]
pub struct EndpointIp {
    /// No `#[index]` of its own: it is the FIRST PK column, so the composite
    /// PK's autoindex `(endpoint_id, ip_key)` already serves the per-endpoint
    /// reads (`… WHERE endpoint_id IN (…)` seeks that prefix). The `#[index]`
    /// on `profile_stats.endpoint_id` exists because there it is the SECOND PK
    /// column — a suffix, which no prefix seek reaches.
    pub endpoint_id: EndpointId,
    /// The address, packed; the PK's second half, so duplicates cannot exist.
    pub ip_key: Vec<u8>,
    /// ISO-3166 alpha-2 of this address (`country.iso_code` from the mmdb).
    ///
    /// Written once, when the geo lookup for the address succeeds, and read
    /// back by the enrichment seed — the flag a row shows on a later launch
    /// then needs no mmdb walk (and no 60 MB database download) at all.
    /// `None` = not looked up yet, or the database has no entry for the
    /// address: those are the only addresses worth a lookup.
    pub country: Option<String>,
    #[belongs_to(key = endpoint_id, references = id)]
    pub endpoint: Deferred<Option<Endpoint>>,
}

/// `Protocol`: a protocol configuration.
///
/// PK = uid = `sig ^ cred_hash`, computed by the crate-private per-kind
/// `identity` writer in `leas-proto` (non-credential, non-default fields ->
/// `sig`; credentials -> the second, domain-separated hash). Only the uid is
/// stored: the two inputs are recomputed from the config when a row is written,
/// and nothing reads them back.
#[derive(Debug, Clone, toasty::Model)]
#[table = "protocols"]
pub struct Protocol {
    #[key]
    pub id: ProtocolId, // = uid (protocol essentials only)
    pub sig: i64, // the non-credential half of the uid (grouping key)
    pub proto_kind: ProtocolKind,
    pub transport: Transport, // embed (T7): transport kind (display projection)
    pub security: Security,   // embed (T7): security type/sni/fp/insecure
    /// Full exact definition, sans host/port.
    #[column(type = text)]
    pub config: Deferred<Json<ProtocolConfig>>,
    pub created_at: i64, // epoch seconds (stamped by the writer)
    #[has_many]
    pub links: Deferred<Vec<ProfileStats>>,
}

/// Per endpoint-protocol pair state (traffic, latency, errors).
#[derive(Debug, Clone, toasty::Model)]
#[table = "profile_stats"]
#[key(protocol_id, endpoint_id)]
pub struct ProfileStats {
    // `protocol_id` is the FIRST column of the composite PK, and the PK
    // autoindex already serves a prefix seek, so it carries no `#[index]`
    // (db-rewamp §3.2 — a redundant secondary index costs every write).
    // `endpoint_id` is the SECOND PK column, so IT does need one: the
    // `endpoint_id IN (...)` page read and `Endpoint::links` seek that prefix,
    // which the PK autoindex cannot serve.
    pub protocol_id: ProtocolId,
    #[index]
    pub endpoint_id: EndpointId,
    pub last_used_at: Option<i64>, // epoch seconds
    /// Per-link staleness tracking (epoch seconds). Indexed: the retention
    /// purge's cutoff and the staleness windows scan on it.
    #[index]
    pub last_seen_at: i64,
    pub latency: Option<Latency>, // embed enum, shared delay column
    pub speed_bps: Option<i64>,
    /// Persisted failure marker (`error` + `error_kind` + `error_text`).
    ///
    /// Not indexed on purpose: it is an embed, and `#[index]` has no
    /// `IndexableField` for one. The error-TTL sweep scans on it (~7 ms over
    /// 15k rows, on a reload only), which does not pay for a third raw DDL
    /// statement next to the schema tag.
    pub error: Option<ErrorInfo>,
    /// Permanent-purge verdict from the last real probe (spec §7/§8).
    ///
    /// Not indexed: the page predicate reads the derived rank keys, and the
    /// rank refresh reads this column per endpoint. Written only by a
    /// [`LinkGroups::PURGE`] patch — the classifier's own group — so a fast
    /// probe's result can neither set nor clear it.
    ///
    /// [`LinkGroups::PURGE`]: crate::LinkGroups::PURGE
    pub purge_reason: Option<PurgeReason>,
    /// The stability ring: the last [`crate::STAB_WINDOW`] real-probe outcomes,
    /// bit `i` = the `i`-th OLDEST live sample, `1` = success (spec
    /// `2026-10-09-stab-bin-design` §5.1). Bits `[stab_len, 64)` are always
    /// zero, so `count_ones()` is the success count.
    ///
    /// Typed, not raw: `decode_projected_link` builds a `ProfileStats` from the
    /// page projection, and the panel renders the ratio from these two fields —
    /// a non-model column would have no home in the decoded row.
    #[column("stab_mask")]
    pub stab_mask: i64,
    /// Live samples in the ring, `0..=STAB_WINDOW`.
    #[column("stab_len")]
    pub stab_len: i64,
    pub traffic: TrafficStats, // today/total up/down
    pub created_at: i64,       // epoch seconds (stamped by the writer)
    pub updated_at: i64,       // epoch seconds (stamped by the writer)
    #[version]
    pub version: u64, // optimistic concurrency
    #[belongs_to(key = protocol_id, references = id)]
    pub protocol: Deferred<Option<Protocol>>,
    #[belongs_to(key = endpoint_id, references = id)]
    pub endpoint: Deferred<Option<Endpoint>>,
}

/// Many-to-many link between endpoints and groups.
/// Replaces Connection (was `profile_id/group_id`, now `endpoint_id/group_id`).
#[derive(Debug, Clone, toasty::Model)]
#[table = "endpoint_groups"]
#[key(endpoint_id, group_id)]
pub struct EndpointGroup {
    // `endpoint_id` is the FIRST column of the composite PK
    // `(endpoint_id, group_id)`, so a prefix seek uses the PK autoindex — no
    // `#[index]` (db-rewamp §3.2). `group_id` is the SECOND column and the
    // per-group membership filter seeks it, so it keeps one.
    pub endpoint_id: EndpointId,
    #[index]
    pub group_id: String,
    pub last_seen_at: i64, // per-source last confirmation (epoch seconds)
    pub sort_order: Option<i32>,
    #[belongs_to(key = endpoint_id, references = id)]
    pub endpoint: Deferred<Option<Endpoint>>,
    #[belongs_to(key = group_id, references = id)]
    pub group: Deferred<Option<Group>>,
}

/// Group: merged with old Subscription fields. Removed `is_system`.
#[derive(Debug, Clone, toasty::Model)]
#[table = "groups"]
pub struct Group {
    #[key]
    pub id: String, // UUID
    pub name: Option<String>,
    pub url: Option<String>,
    pub enabled: bool,
    pub user_agent: Option<String>,
    pub convert_target: Option<ConvertTarget>,
    pub sort_order: Option<i32>,
    pub last_refreshed: Option<i64>, // epoch seconds
    pub status: Option<GroupStatus>,
    pub error_message: Option<String>,
    pub refresh_interval: Option<i64>, // minutes; None = default 1440 (24h)
}

#[derive(Debug, Clone, toasty::Model)]
#[table = "routing_rules"]
pub struct RoutingRule {
    #[key]
    pub id: String,

    pub group_id: Option<String>,
    pub r#type: i32, // opaque free-form number, no consumer; kept for form
    pub domain_matcher: Option<String>,
    pub domains: Vec<String>,
    pub ips: Vec<String>,
    pub inbound_tags: Vec<String>,
    pub ports: Vec<u16>, // "80,443" -> [80, 443]
    pub source_ports: Vec<u16>,
    pub network: Option<String>,         // pass-through, comma-able
    pub protocols: Vec<String>,          // IANA protocol names, NOT ProtocolKind
    pub domain_strategy: Option<String>, // pass-through
    pub outbound_tag: Option<String>,
    pub balancer_tag: Option<String>,
    pub rule_set_file: Option<String>,
    pub rule_set_url: Option<String>,
    pub sort_order: Option<i32>,
}

#[derive(Debug, Clone, toasty::Model)]
#[table = "dns_settings"]
pub struct DnsSetting {
    #[key]
    pub id: String,

    pub name: Option<String>,
    pub servers: Vec<String>,
    pub hosts: Vec<String>,
    pub query_strategy: Option<QueryStrategy>,
    pub disable_cache: bool,
    pub disable_fallback: bool,
    pub client_ip: Option<String>,
    /// TTL (secs) for the TUI-side DNS resolution cache; None = default 300.
    pub cache_ttl_secs: Option<i64>,
}

/// Must-resolve probe hostnames, one global singleton row (`id == "global"`).
#[derive(Debug, Clone, toasty::Model)]
#[table = "route_probes"]
pub struct RouteProbes {
    #[key]
    pub id: String,
    pub hosts: Vec<String>,
}

/// A generic key/value stamp (db-rewamp D2).
///
/// Guards the STORED identity against a change in a build-time input: the first
/// key is `psl_version`, the `psl2` Public Suffix List version, whose change can
/// re-key endpoints. A typed model (not raw DDL) so `push_schema` owns the
/// table and the raw-SQL inventory stays clean.
#[derive(Debug, Clone, toasty::Model)]
#[table = "app_meta"]
pub struct AppMeta {
    #[key]
    pub key: String,
    pub value: String,
}

/// Materialized per-endpoint ordering keys (ADR 0003).
///
/// Derived state of the decision-16 law, computed in Rust by
/// [`crate::endpoint_rank`] — never re-derived in SQL — and read by the page
/// query through the covering index `endpoint_rank_test`. The page drives from
/// this table, so every write that changes a link refreshes the endpoint's row
/// (the write methods in [`crate::database`] own that).
#[derive(Debug, Clone, toasty::Model)]
#[table = "endpoint_rank"]
pub struct EndpointRank {
    /// The endpoint these keys describe.
    #[key]
    #[column("endpoint_id")]
    pub endpoint_id: EndpointId,
    /// The representative link's delay BIN (db-rewamp D11): real<50..real≥1000
    /// 0-5, fast<50..fast≥1000 6-11, untested 12, real-err 13, fast-err 14,
    /// dns-err 15, purged 16. Folds the retired dns/tier/latency columns.
    #[column("rank_bin")]
    pub bin: i64,
    /// Registrable domain of the endpoint host (empty for an IP/exotic host) —
    /// the address tiebreak, materialized here so the page is one index scan.
    #[column("rank_domain")]
    pub domain: String,
    /// The labels left of the domain (empty when the host IS the domain).
    #[column("rank_sub_domain")]
    pub sub_domain: String,
    /// The IP literal's packed key for an IP host (empty for a DNS host) —
    /// the address tiebreak's second term.
    #[column("rank_addr")]
    pub addr: Vec<u8>,
    /// The representative link's stability bin, `0` (best) `..=7` (worst) —
    /// its recent real-probe success rate, coarsened (spec
    /// `2026-10-09-stab-bin-design`). Sits in the ordering key between `bin`
    /// and `weight`: inside one delay bin the more reliable link leads. `4`
    /// (neutral) while the link's window is warming up or empty.
    #[column("rank_stab")]
    pub stab: i64,
    /// Whether the endpoint has ANY live, unpurged link whose stability window
    /// holds at least one real success. Derived from the rings, never a durable
    /// flag, so it clears on its own once every success ages out. This — not
    /// `rank_bin` — is what the `Successful` scope selects: a proven endpoint
    /// can still carry a bin of 12/13 when a sibling is untested or failing.
    #[column("rank_proven")]
    pub proven: i64,
    /// Newest `last_seen_at` across the endpoint's links (epoch seconds): the
    /// view windows ask whether any link falls in the band, which is the same
    /// question as whether the newest one does — and reading it here keeps the
    /// predicate single-table, so the page is an index scan.
    #[column("rank_newest_seen")]
    pub newest_seen: i64,
}

// ── Data-transfer types ──────────────────────────────────────────────────

/// An endpoint with its per-pair links and their protocols, as loaded by the
/// typed read paths in [`crate::database`].
#[derive(Debug, Clone)]
pub struct EndpointRow {
    pub endpoint: Endpoint,
    pub links: Vec<ProfileStats>, // per-pair state, sorted by test priority
    pub protocols: HashMap<ProtocolId, Protocol>, // included via links
    /// The endpoint's resolved addresses, in key order (the display order) —
    /// read from `endpoint_ip`, the table that owns them. Empty = not a DNS
    /// host, or not resolved yet (the distinction is `endpoint.host_type`).
    pub resolved_ips: Vec<std::net::IpAddr>,
    pub selected_protocol: usize, // index into links
    pub expanded: bool,
}

impl EndpointRow {
    /// Returns the currently active link, respecting manual override.
    /// Falls back to `selected_protocol` if the override is unset or the
    /// override protocol is not found among the links.
    #[must_use]
    pub fn active_link(&self) -> Option<&ProfileStats> {
        if let Some(pid) = self.endpoint.manual_protocol_override
            && let Some(link) = self.links.iter().find(|l| l.protocol_id == pid)
        {
            return Some(link);
        }
        self.links.get(self.selected_protocol)
    }

    /// The active link together with its included [`Protocol`] row.
    #[must_use]
    pub fn active_protocol(&self) -> Option<(&ProfileStats, &Protocol)> {
        let link = self.active_link()?;
        let protocol = self.protocols.get(&link.protocol_id)?;
        Some((link, protocol))
    }

    /// Ascending sort key `(tier, !weight, latency, recency, protocol_id)` —
    /// the decision-16 law with the static config weight inside the tier.
    /// `recency` is the negated `last_seen_at` epoch so newer links sort first
    /// on ties. Only success tiers (0/1) rank by latency; untested and
    /// error/dns tiers use `i32::MAX` so they order by weight, then recency,
    /// then protocol id.
    ///
    /// The weight is passed in, not derived here: a `ProfileStats` row carries
    /// no protocol, so the caller resolves it from `self.protocols`. This is
    /// the HOT path — `sort_links_by_test_priority` re-runs on every ping
    /// result and every load — and it delegates to
    /// [`crate::endpoint_rank::RankLink::key`], the single implementation the
    /// stored `endpoint_rank` keys also read, so the panel order and the SQL
    /// order cannot drift.
    fn link_test_key(
        link: &ProfileStats,
        weight: crate::weight::ConfigWeight,
        dns_unresolved: bool,
    ) -> (u8, u8, u64, i64, i64) {
        crate::endpoint_rank::RankLink::new(link, weight).key(dns_unresolved)
    }

    /// This endpoint's link weights, keyed by protocol id. One lookup per link
    /// on the paths that have no other access to the protocol; a link whose
    /// protocol row is absent sorts as "worst".
    #[must_use]
    pub fn link_weights(&self) -> HashMap<ProtocolId, crate::weight::ConfigWeight> {
        self.protocols
            .iter()
            .map(|(id, p)| (*id, crate::endpoint_rank::weight_of_protocol(p)))
            .collect()
    }

    /// Re-sort `links` by test priority: real-ping success first, then fast
    /// success (latency ascending), then untested (highest static weight,
    /// newest `last_seen_at` first), then persisted failures (real below fast),
    /// then DNS-unresolved endpoints at the bottom. Deterministic tiebreak by
    /// protocol id.
    pub fn sort_links_by_test_priority(&mut self, dns_unresolved: bool) {
        let weights = self.link_weights();
        let zero = crate::weight::ZERO_WEIGHT;
        self.links.sort_by_key(|l| {
            Self::link_test_key(
                l,
                weights.get(&l.protocol_id).copied().unwrap_or(zero),
                dns_unresolved,
            )
        });
    }

    /// Set `selected_protocol` (the single-row display preference) to the
    /// endpoint's best MEASURED link: a real success with the lowest delay,
    /// else a fast success with the lowest delay. Error markers do NOT
    /// disqualify a measured link — a link that has both a successful
    /// measurement and a later failure marker still carries the result the
    /// row should show (decision: display preference follows measurements;
    /// the sub-table order keeps full test-priority tiers, where fresh
    /// failures dominate). Untested links rank last; when nothing is
    /// measured the current selection is kept. A pinned manual override is
    /// unaffected — `active_link()` checks it first.
    pub fn select_best_measured_link(&mut self) {
        // The purge gate, mirroring `endpoint_rank::display_link_index`: a
        // purged link never supplies the row's headline delay while a live link
        // exists, and an all-purged endpoint falls back to its purged links
        // (the Purgatory view's case).
        let live = self.links.iter().any(|l| l.purge_reason.is_none());
        let Some((best, _)) = self
            .links
            .iter()
            .enumerate()
            .filter(|(_, l)| !live || l.purge_reason.is_none())
            .filter_map(|(i, l)| {
                let (rank, delay) = match l.latency {
                    Some(Latency::Real { delay, .. }) => (0u8, delay),
                    Some(Latency::Fast { delay }) => (1u8, delay),
                    None => return None,
                };
                Some((i, (rank, delay)))
            })
            .min_by_key(|&(_, (rank, delay))| (rank, delay))
        else {
            return;
        };
        self.selected_protocol = best;
    }

    /// The endpoint's representative sort key = its best (minimum) link key —
    /// used by the main-table Test column sort. `None` when the endpoint has
    /// no links.
    #[must_use]
    pub fn best_test_priority_key(&self, dns_unresolved: bool) -> Option<(u8, u8, u64, i64, i64)> {
        let weights = self.link_weights();
        let zero = crate::weight::ZERO_WEIGHT;
        self.links
            .iter()
            .map(|l| {
                Self::link_test_key(
                    l,
                    weights.get(&l.protocol_id).copied().unwrap_or(zero),
                    dns_unresolved,
                )
            })
            .min()
    }

    /// Index of the endpoint's REPRESENTATIVE link: the one whose
    /// [`Self::link_test_key`] is the endpoint's minimum.
    ///
    /// This is the link [`crate::endpoint_rank::compute_rank`] stores the
    /// endpoint's tier from, so a reader that selects it reports the endpoint's
    /// own tier band — the Test cell and the Test sort cannot disagree. Note it
    /// is NOT `active_link()`: that one prefers the lowest-delay MEASURED link
    /// and honours a manual override, so on an endpoint whose measured link also
    /// carries a failure marker it returns a link the ordering law ranks three
    /// tiers below the endpoint's own position.
    ///
    /// Ties keep the lowest index, matching `Iterator::min`'s first-wins rule in
    /// `compute_rank`.
    #[must_use]
    pub fn representative_link_index(&self, dns_unresolved: bool) -> Option<usize> {
        let weights = self.link_weights();
        let zero = crate::weight::ZERO_WEIGHT;
        self.links
            .iter()
            .enumerate()
            .map(|(i, l)| {
                let weight = weights.get(&l.protocol_id).copied().unwrap_or(zero);
                (i, Self::link_test_key(l, weight, dns_unresolved))
            })
            .min_by_key(|&(_, key)| key)
            .map(|(i, _)| i)
    }
}

/// Three-way toggle for the Profiles tab.
///
/// `Purgatory` is "not confirmed live and recent": links whose newest LIVE link
/// is older than the TTL, plus endpoints whose every link carries a purge
/// verdict (spec `2026-09-17-purge-reason-design.md` §5). The `Active` view is
/// the effective-profiles list and hides purged links.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PurgatoryView {
    #[default]
    Active,
    Purgatory,
    All,
}

#[cfg(test)]
mod tests {
    use super::*;
    use leas_proto::proto_spec::SecurityConfig;
    use leas_proto::proto_spec::common::TransportConfig;
    use toasty::Deferred;

    /// Endpoint with links `(protocol_id, last_seen_at_secs, latency, error)`.
    fn row(links: &[(i64, i64, Option<Latency>, Option<ErrorInfo>)]) -> EndpointRow {
        let mut row = EndpointRow {
            endpoint: Endpoint {
                id: EndpointId::new(1),
                domain: Endpoint::derive_domain("h.example", HostType::Ipv4).0,
                sub_domain: Endpoint::derive_domain("h.example", HostType::Ipv4).1,
                port: 443,
                ports: Vec::new(),
                last_source: None,
                manual_protocol_override: None,
                resolved_at: None,
                created_at: 0,
                links: Deferred::default(),
                group_links: Deferred::default(),
            },
            resolved_ips: Vec::new(),
            links: Vec::new(),
            protocols: HashMap::new(),
            selected_protocol: 0,
            expanded: false,
        };
        for (pid, last_seen, latency, error) in links {
            row.links.push(ProfileStats {
                protocol_id: ProtocolId::new(*pid),
                endpoint_id: EndpointId::new(1),
                last_used_at: None,
                last_seen_at: *last_seen,
                latency: latency.clone(),
                speed_bps: None,
                error: error.clone(),
                purge_reason: None,
                stab_mask: 0,
                stab_len: 0,
                traffic: TrafficStats {
                    today_up: 0,
                    today_down: 0,
                    total_up: 0,
                    total_down: 0,
                },
                created_at: 0,
                updated_at: 0,
                version: 1,
                protocol: Deferred::default(),
                endpoint: Deferred::default(),
            });
        }
        row
    }

    fn ids(r: &EndpointRow) -> Vec<i64> {
        r.links.iter().map(|l| l.protocol_id.get()).collect()
    }

    fn real(delay: i32) -> Latency {
        Latency::Real { delay, ip: None }
    }

    fn fast(delay: i32) -> Latency {
        Latency::Fast { delay }
    }

    fn err(kind: ProfileErr) -> ErrorInfo {
        ErrorInfo {
            kind,
            text: "boom".to_string(),
        }
    }

    /// Stamp a purge verdict on one link — the classifier's write.
    fn purge(r: &mut EndpointRow, pid: i64, reason: PurgeReason) {
        let link = r
            .links
            .iter_mut()
            .find(|l| l.protocol_id.get() == pid)
            .expect("link exists");
        link.purge_reason = Some(reason);
    }

    #[test]
    fn select_best_measured_link_prefers_real_ok_lowest_delay() {
        // fast-ok 44 + error marker, real-ok 50, untested — the measured
        // real-ok wins despite the error-carrying fast sibling (sub-table
        // tiers still rank the error low; the display preference follows
        // measurements).
        let mut r = row(&[
            (10, 1, Some(fast(44)), Some(err(ProfileErr::Fast))),
            (11, 2, Some(real(50)), None),
            (12, 3, None, None),
        ]);
        r.select_best_measured_link();
        assert_eq!(r.selected_protocol, 1, "real-ok lowest delay wins");
        assert_eq!(r.active_link().map(|l| l.protocol_id.get()), Some(11));
    }

    #[test]
    fn select_best_measured_link_fast_ok_when_no_real() {
        let mut r = row(&[(10, 1, Some(fast(90)), None), (11, 2, Some(fast(44)), None)]);
        r.select_best_measured_link();
        assert_eq!(r.selected_protocol, 1, "fast-ok lowest delay wins");
    }

    #[test]
    fn select_best_measured_link_keeps_selection_when_unmeasured() {
        let mut r = row(&[
            (10, 1, None, None),
            (11, 2, None, Some(err(ProfileErr::Real))),
        ]);
        r.select_best_measured_link();
        assert_eq!(r.selected_protocol, 0, "no measurement -> keep selection");
    }

    #[test]
    fn select_best_measured_link_error_with_latency_still_measured() {
        // A link that carries both a success and a later failure marker is
        // still the best measured link (user-facing: the row shows 44ms).
        let mut r = row(&[
            (10, 1, Some(fast(44)), Some(err(ProfileErr::Fast))),
            (11, 2, None, None),
        ]);
        r.select_best_measured_link();
        assert_eq!(r.selected_protocol, 0);
    }

    #[test]
    fn select_best_measured_link_skips_a_purged_link() {
        // The purged link has the better delay, and must not supply the row's
        // headline numbers while a live link exists.
        let mut r = row(&[(10, 1, Some(fast(10)), None), (11, 2, Some(fast(90)), None)]);
        purge(&mut r, 10, PurgeReason::NotTls);
        r.select_best_measured_link();
        assert_eq!(
            r.active_link().map(|l| l.protocol_id.get()),
            Some(11),
            "a purged link is not the display link"
        );
    }

    #[test]
    fn select_best_measured_link_falls_back_when_every_link_is_purged() {
        // The Purgatory view's case: nothing live, so the row still shows the
        // values its links have.
        let mut r = row(&[(10, 1, Some(fast(10)), None), (11, 2, Some(fast(90)), None)]);
        purge(&mut r, 10, PurgeReason::NotTls);
        purge(&mut r, 11, PurgeReason::OriginUnreachable);
        r.select_best_measured_link();
        assert_eq!(
            r.active_link().map(|l| l.protocol_id.get()),
            Some(10),
            "all purged: the best measured purged link still shows"
        );
    }

    #[test]
    fn purged_links_sink_below_every_live_tier() {
        // The purged link carries the best measurement of the three (real-ok
        // 12ms) and must still sort last: tier 6 is below every live band.
        let mut r = row(&[
            (10, 1, Some(real(12)), None),
            (11, 2, Some(fast(90)), None),
            (12, 3, None, None),
        ]);
        purge(&mut r, 10, PurgeReason::RealityFallback);
        r.sort_links_by_test_priority(false);
        assert_eq!(
            ids(&r),
            vec![11, 12, 10],
            "live fast-ok, live untested, then the purged real-ok"
        );
        assert_eq!(
            r.best_test_priority_key(false).expect("key").0,
            7,
            "the endpoint's representative key follows a LIVE link (fast<100 bin)"
        );
    }

    #[test]
    fn real_ok_above_fast_ok_above_untested() {
        // real-ok 200ms outranks fast-ok 10ms — tier beats latency.
        let mut r = row(&[
            (10, 1, Some(real(200)), None), // real-ok
            (20, 2, Some(fast(10)), None),  // fast-ok
            (30, 3, None, None),            // untested
        ]);
        r.sort_links_by_test_priority(false);
        assert_eq!(ids(&r), vec![10, 20, 30]);
    }

    #[test]
    fn latency_orders_within_success_tiers() {
        let mut r = row(&[
            (10, 1, Some(fast(50)), None),
            (20, 2, Some(fast(10)), None),
            (30, 3, Some(real(120)), None),
            (40, 4, Some(real(90)), None),
        ]);
        r.sort_links_by_test_priority(false);
        // real tier first (30:120, 40:90 by latency), then fast tier (20:10, 10:50)
        assert_eq!(ids(&r), vec![40, 30, 20, 10]);
    }

    #[test]
    fn fresh_failure_dominates_stored_success() {
        // 10 has a stored real-ok delay but a persisted real error -> sinks
        // below the untested 30; 20 has a fast error -> below 10 (fast worse
        // than real).
        let mut r = row(&[
            (10, 1, Some(real(50)), Some(err(ProfileErr::Real))),
            (20, 2, Some(fast(80)), Some(err(ProfileErr::Fast))),
            (30, 3, None, None),
        ]);
        r.sort_links_by_test_priority(false);
        assert_eq!(ids(&r), vec![30, 10, 20]);
    }

    #[test]
    fn both_failed_uses_fast_tier() {
        // Both links carry a fast error: tie on tier, order by recency.
        let mut r = row(&[
            (10, 1, None, Some(err(ProfileErr::Fast))),
            (20, 2, None, Some(err(ProfileErr::Fast))),
        ]);
        r.sort_links_by_test_priority(false);
        assert_eq!(ids(&r), vec![20, 10]);
    }

    #[test]
    fn dns_unresolved_sinks_all_protocols() {
        let mut r = row(&[(10, 1, Some(real(50)), None), (20, 2, None, None)]);
        r.sort_links_by_test_priority(true);
        assert_eq!(ids(&r), vec![20, 10]); // untested first; dns tier wins for both
    }

    #[test]
    fn untested_keeps_last_seen_recency_order() {
        let mut r = row(&[
            (10, 5, None, None),
            (20, 9, None, None),
            (30, 1, None, None),
        ]);
        r.sort_links_by_test_priority(false);
        assert_eq!(ids(&r), vec![20, 10, 30]); // newest first
    }

    #[test]
    fn best_key_returns_min_over_links() {
        let r = row(&[
            (10, 1, Some(real(200)), None),
            (20, 2, Some(fast(10)), None),
            (30, 3, None, None),
        ]);
        // Best = real-ok (tier 0), latency 200. Recency is epoch SECONDS —
        // the stored unit, so the key compares exactly what
        // `endpoint_rank.seen` and the retiring SQL's `last_seen_at DESC`
        // compare. Two links seen inside one second tie here, and the
        // protocol id breaks it.
        // The weight term is `u64::MAX - packed`; this fixture carries no
        // protocol rows, so every link is the zero weight and the term is the
        // maximum — the negation a "no known stack" link sorts under.
        assert_eq!(
            r.best_test_priority_key(false),
            Some((2, crate::endpoint_rank::STAB_NEUTRAL, u64::MAX, -1, 10))
        );
        // Empty links -> None
        let empty = row(&[]);
        assert_eq!(empty.best_test_priority_key(false), None);
    }

    #[test]
    fn active_link_respects_override() {
        let mut r = row(&[(10, 1, Some(real(50)), None), (20, 2, Some(fast(10)), None)]);
        r.endpoint.manual_protocol_override = Some(ProtocolId::new(20));
        assert_eq!(r.active_link().unwrap().protocol_id, ProtocolId::new(20));
        // Override to a protocol with no link -> fall back to selection.
        r.endpoint.manual_protocol_override = Some(ProtocolId::new(99));
        assert_eq!(r.active_link().unwrap().protocol_id, ProtocolId::new(10));
        // No links -> None.
        let empty = row(&[]);
        assert!(empty.active_link().is_none());
    }

    #[test]
    fn active_protocol_pairs_link_with_protocol() {
        let mut r = row(&[(10, 1, Some(real(50)), None)]);
        let protocol = Protocol {
            id: ProtocolId::new(10),
            sig: 10,
            proto_kind: ProtocolKind::Vless,
            transport: Transport {
                r#type: TransportType::Tcp,
            },
            security: Security {
                r#type: SecurityType::None,
                sni: None,
                fp: None,
                insecure: None,
            },
            config: Deferred::from(Json(vless_config())),
            created_at: 0,
            links: Deferred::default(),
        };
        r.protocols.insert(protocol.id, protocol);
        let (link, proto) = r.active_protocol().expect("active protocol");
        assert_eq!(link.protocol_id, ProtocolId::new(10));
        assert_eq!(proto.proto_kind, ProtocolKind::Vless);
    }

    fn vless_config() -> ProtocolConfig {
        ProtocolConfig::Vless(leas_proto::proto_spec::VlessConfig {
            uuid: "00000000-0000-0000-0000-000000000000".to_string(),
            uuid_origin: None,
            security: SecurityConfig::default(),
            transport: TransportConfig::Tcp,
            encryption: None,
            flow: None,
            path: None,
            splice: None,
            remarks: None,
            mux: None,
        })
    }

    // ── Scratch-model probes: typed embeds end-to-end in SQLite ──────────
    //
    // These tests pin the embed behavior (shared columns, deferred JSON,
    // enum/struct round-trips, newtype key columns) in an in-memory DB.

    #[derive(Debug, toasty::Model)]
    struct ScratchEmbedProbe {
        #[key]
        #[auto]
        id: i64,
        latency: Option<Latency>,
        transport: Transport,
        security: Security,
        traffic: TrafficStats,
        kind: TaskKind,
        err: Option<ErrorInfo>,
    }

    /// Fresh in-memory DB holding only the scratch probe model.
    async fn probe_db() -> toasty::Db {
        let driver = crate::driver::Turso::in_memory();
        let db = toasty::Db::builder()
            .models(toasty::models!(ScratchEmbedProbe))
            .build(driver)
            .await
            .expect("build db");
        db.push_schema().await.expect("push schema");
        db
    }

    fn tcp_transport() -> Transport {
        Transport {
            r#type: TransportType::Tcp,
        }
    }

    fn no_security() -> Security {
        Security {
            r#type: SecurityType::None,
            sni: None,
            fp: None,
            insecure: None,
        }
    }

    /// Zeroed traffic stats — the flattened columns default to 0 anyway, but
    /// the create! validation requires the non-Option embed field.
    fn zero_traffic() -> TrafficStats {
        TrafficStats {
            today_up: 0,
            today_down: 0,
            total_up: 0,
            total_down: 0,
        }
    }

    #[tokio::test]
    async fn latency_shared_delay_column_roundtrip() {
        let mut db = probe_db().await;

        let mut created = toasty::create!(ScratchEmbedProbe {
            latency: Some(Latency::Real {
                delay: 42,
                ip: Some("1.2.3.4".to_string()),
            }),
            transport: tcp_transport(),
            security: no_security(),
            traffic: zero_traffic(),
            kind: TaskKind::RealPing,
        })
        .exec(&mut db)
        .await
        .expect("create");

        assert_eq!(
            created.latency,
            Some(Latency::Real {
                delay: 42,
                ip: Some("1.2.3.4".to_string()),
            })
        );

        // Round-trips as Real (shared delay column + variant ip column).
        let read = ScratchEmbedProbe::filter_by_id(created.id)
            .get(&mut db)
            .await
            .expect("read back");
        assert_eq!(
            read.latency,
            Some(Latency::Real {
                delay: 42,
                ip: Some("1.2.3.4".to_string()),
            })
        );

        // Variant switch Real -> Fast: the shared `latency_delay` column
        // carries 99 into the new variant; `latency_ip` clears to NULL.
        toasty::update!(created {
            latency: Some(Latency::Fast { delay: 99 }),
        })
        .exec(&mut db)
        .await
        .expect("update");

        let read = ScratchEmbedProbe::filter_by_id(created.id)
            .get(&mut db)
            .await
            .expect("read back");
        assert_eq!(read.latency, Some(Latency::Fast { delay: 99 }));
    }

    #[tokio::test]
    async fn transport_security_scalar_roundtrip() {
        let mut db = probe_db().await;

        let created = toasty::create!(ScratchEmbedProbe {
            transport: Transport {
                r#type: TransportType::Ws,
            },
            security: Security {
                r#type: SecurityType::Tls,
                sni: Some("example.com".to_string()),
                fp: Some("chrome".to_string()),
                insecure: Some(true),
            },
            traffic: zero_traffic(),
            kind: TaskKind::SpeedTest,
        })
        .exec(&mut db)
        .await
        .expect("create");

        let read = ScratchEmbedProbe::filter_by_id(created.id)
            .get(&mut db)
            .await
            .expect("read back");
        assert_eq!(read.transport.r#type, TransportType::Ws);
        assert_eq!(read.security.r#type, SecurityType::Tls);
        assert_eq!(read.security.sni.as_deref(), Some("example.com"));
        assert_eq!(read.security.fp.as_deref(), Some("chrome"));
        assert_eq!(read.security.insecure, Some(true));
    }

    #[tokio::test]
    async fn task_kind_and_error_roundtrip() {
        let mut db = probe_db().await;

        let mut created = toasty::create!(ScratchEmbedProbe {
            transport: tcp_transport(),
            security: no_security(),
            traffic: TrafficStats {
                today_up: 1,
                today_down: 2,
                total_up: 3,
                total_down: 4,
            },
            kind: TaskKind::UdpTest,
            err: Some(ErrorInfo {
                kind: ProfileErr::Real,
                text: "timeout".to_string(),
            }),
        })
        .exec(&mut db)
        .await
        .expect("create");

        let read = ScratchEmbedProbe::filter_by_id(created.id)
            .get(&mut db)
            .await
            .expect("read back");
        assert_eq!(read.kind, TaskKind::UdpTest);
        assert_eq!(
            read.err,
            Some(ErrorInfo {
                kind: ProfileErr::Real,
                text: "timeout".to_string(),
            })
        );
        assert_eq!(
            read.traffic,
            TrafficStats {
                today_up: 1,
                today_down: 2,
                total_up: 3,
                total_down: 4,
            }
        );

        // Every TaskKind variant round-trips through the discriminant column.
        for kind in [
            TaskKind::FastPing,
            TaskKind::RealPing,
            TaskKind::UdpPing,
            TaskKind::UdpTest,
            TaskKind::SpeedTest,
        ] {
            toasty::update!(created { kind: kind })
                .exec(&mut db)
                .await
                .expect("update kind");
            let read = ScratchEmbedProbe::filter_by_id(created.id)
                .get(&mut db)
                .await
                .expect("read back");
            assert_eq!(read.kind, kind);
        }
    }

    /// Endpoint's newtype key column round-trips through the real model.
    #[tokio::test]
    async fn endpoint_id_newtype_column_roundtrip() {
        let driver = crate::driver::Turso::in_memory();
        let mut db = toasty::Db::builder()
            .models(toasty::models!(Endpoint))
            .build(driver)
            .await
            .expect("build db");
        db.push_schema().await.expect("push schema");

        let created = toasty::create!(Endpoint {
            created_at: 0,
            id: EndpointId::new(42),
            domain: Endpoint::derive_domain("1.2.3.4", HostType::Ipv4).0,
            sub_domain: Endpoint::derive_domain("1.2.3.4", HostType::Ipv4).1,
            port: 443,
            ports: Vec::<u16>::new(),
        })
        .exec(&mut db)
        .await
        .expect("create");

        assert_eq!(created.id, EndpointId::new(42));

        let read = Endpoint::filter_by_id(EndpointId::new(42))
            .get(&mut db)
            .await
            .expect("read back");
        assert_eq!(read.id.get(), 42);
        assert_eq!(read.port, 443);
    }

    #[test]
    fn endpoint_id_accepts_nonzero() {
        assert_eq!(EndpointId::new(42).get(), 42);
        assert_eq!(ProtocolId::new(7).get(), 7);
    }

    #[test]
    #[should_panic(expected = "EndpointId must be non-zero")]
    fn endpoint_id_rejects_zero() {
        let _ = EndpointId::new(0);
    }

    #[test]
    #[should_panic(expected = "ProtocolId must be non-zero")]
    fn protocol_id_rejects_zero() {
        let _ = ProtocolId::new(0);
    }
}
