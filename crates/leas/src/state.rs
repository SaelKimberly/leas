use std::cell::{Cell, RefCell};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use leas_config::AppConfig;
use leas_core::CoreType;
use leas_core::grpc_client;
use leas_core::log_heed::HeedLogStorage;
use leas_core::speed_test::TestType;
use leas_db::Database;
use leas_db::hash::stable_hash;
use leas_db::models::PurgatoryView;
use leas_db::models::{
    Endpoint, EndpointGroup, EndpointId, Group, HostType, Latency, ProfileStats, Protocol,
    ProtocolId, RoutingRule, Security, TrafficStats, Transport,
};
use leas_db::profiles_query::{AggregateCounts, PageRequest, PageSort, PlanScope};
use leas_proto::proto_spec::common::TransportConfig;
use leas_proto::proto_spec::{
    EndpointEssentials, HostKind, ParsedProto, ProtoSpec, ProtocolConfig,
};
use toasty::{Deferred, Json};

use crate::BackendUpdateStatus;
use crate::ops::{
    compact, connect, events, ping, profiles, scheduler, settings, subscriptions, updates,
};
use crate::types::{
    AppMode, ConfirmAction, CoreEvent, EndpointInfo, EndpointRow, FocusedPane, LogLine,
    NativeActivityLog, Pane1Tab, Pane2Tab, SectionList, SettingsSearch, SettingsSection,
    SplitRightPane,
};

/// The scope an [`AggregateCache`] was computed for.
///
/// Two caches with the same key describe the same set; a change to any field
/// discards the cache (spec D21 — refresh on filter change and job events,
/// never on a timer).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AggregateKey {
    pub view: PurgatoryView,
    pub search: Option<String>,
    pub group_id: Option<String>,
    pub scope: PlanScope,
}

/// The cached aggregate counts plus the key they were computed for.
#[derive(Debug, Clone)]
pub struct AggregateCache {
    pub counts: AggregateCounts,
    pub key: AggregateKey,
}

/// Global UI/connection state.
#[allow(
    clippy::struct_excessive_bools,
    reason = "fields are orthogonal UI flags (one per independent behavior); a state machine would obscure them"
)]
pub struct AppState {
    pub db: Arc<Database>,
    pub config: AppConfig,
    /// Per-(protocol, endpoint) task gate (design §6.2): one live task per
    /// link, FIFO queue, orphan sweep, DNS-deferral. Limits come from
    /// `config.speed_test` (queue limit, DNS deferral window) and stay
    /// runtime-settable via `TaskScheduler::set_limits` on settings save.
    /// Wrapped in `Arc` so the T19 batch pipeline can clone it into its
    /// spawned task.
    pub scheduler: Arc<scheduler::TaskScheduler>,
    /// Write-behind persistence for `profile_stats` mutations. Result writes
    /// and scheduler transitions `stage()` here instead of committing on the
    /// UI task; the flush task turns a window of staged rows into one
    /// transaction — a `WriteBehind<LinkSpec>` driver, the generic form of the
    /// `LinkWriter` this field replaced (see
    /// `docs/aegis/specs/2026-10-05-rowcache-write-behind-design.md`).
    pub link_stage: Arc<leas_db::WriteBehind<leas_db::LinkSpec>>,
    /// The loaded theme (opaline), with the app's roles registered.
    ///
    /// One owner: `config.theme_name` is the kebab-case slug this was loaded
    /// from. `AppState::current_palette()` and the `ratatui-cheese` bridge are
    /// gone — every style resolves from here.
    pub theme: opaline::Theme,
    /// Pane shell state (spec D2): which pane owns the keyboard and each
    /// pane's active tab. Replaces the old 6-entry `Tab` cycle.
    pub focused_pane: FocusedPane,
    pub pane1_tab: Pane1Tab,
    pub pane2_tab: Pane2Tab,
    /// Pane-2 height override (rows), 0 = per-tab default (Details 8 /
    /// Metrics 14). Session-only, adjusted with `Alt+↑/↓` (spec D3).
    pub pane2_height: u16,
    /// Settings popup dirty-tracking (spec P3): the form values as loaded.
    /// `None` when no form pane is open or the form is clean.
    pub settings_form_snapshot: Option<Vec<(String, String)>>,
    /// Settings section list: selection and per-group expansion (spec D2/D4).
    pub settings_sections: SectionList,
    /// Settings search bar state (spec D8).
    pub settings_search: SettingsSearch,
    /// Transient settings message for the popup's status row (spec A7).
    pub settings_notice: Option<String>,
    /// The loaded Profiles page: the window the tab renders and indexes.
    /// `selected_index` indexes this vector, never the whole feed.
    pub endpoints: Vec<EndpointRow>,
    /// Filtered total across all pages (footer count).
    pub page_total: u64,
    /// Offset of the loaded page in the ordered view.
    pub page_offset: usize,
    /// Set when the Profiles page needs a refetch (search, sort, view, or a
    /// mutation landed); the event loop refetches before rendering.
    pub filter_cache_valid: Cell<bool>,
    /// Generation counter bumped on every profile mutation.
    /// Used to skip redundant reloads.
    pub endpoints_gen: u64,
    /// Monotonic reload generation: a synchronous `reload_profiles` (or a
    /// spawned subscription reload) bumps this; a late
    /// `CoreEvent::ProfilesRowsReady` whose `gen` no longer matches is
    /// dropped instead of clobbering fresher rows.
    pub reload_gen: u64,
    /// Cached groups for subscriptions/settings UI.
    pub groups: Vec<Group>,

    pub purgatory_view: PurgatoryView,
    /// Purgatory TTL in seconds (default 7 days).
    pub purgatory_ttl_secs: i64,
    /// Purgatory retention in seconds (default 30 days).
    pub purgatory_retention_secs: i64,
    pub selected_index: usize,
    /// Optional protocol sub-row index for expanded endpoint tree navigation.
    pub selected_sub: Option<usize>,
    /// Scroll offset from the bottom of the log buffer (0 = newest visible).
    ///
    /// Always clamped to the loaded buffer by `clamp_log_scroll`: an
    /// unbounded value made `Up` grow forever while the viewport saturated at
    /// row 0 (a frozen screen), and `Down` then had to decrement through the
    /// whole surplus before the view moved again.
    pub log_scroll: usize,
    /// Anchor for multi-line selection in logs tab (offset from bottom).
    /// `None` = no active selection.
    pub log_select_anchor: Option<usize>,
    /// Rows the log viewport can actually show, published by the log render
    /// pass each frame.
    ///
    /// The key handler needs this because pane 1 no longer owns the terminal:
    /// it sits above pane 2 and the status bar, so the old `term_height - 5`
    /// estimate paged by roughly double the visible rows and left the user
    /// hunting for the cursor.
    pub log_viewport_rows: Cell<usize>,
    pub search_query: String,
    pub search_focused: bool,
    pub connected_core: Option<CoreType>,
    pub connecting: bool,
    pub system_stats: Option<grpc_client::SysStats>,
    /// Session-only native-core trace log for the Native Activity tab.
    pub native_activity: NativeActivityLog,
    /// Cached log entries for the Logs tab, newest at end.
    pub log_cache: VecDeque<LogLine>,
    /// Whether there may be older entries in the DB to load.
    pub log_has_older: bool,
    /// Flag to trigger progressive loading of all logs to top (Home key).
    pub log_seek_home: bool,
    pub connection_error: Option<String>,
    pub core_event_rx: Option<mpsc::Receiver<CoreEvent>>,
    pub core_event_tx: Option<mpsc::Sender<CoreEvent>>,
    pub disconnect_tx: Option<tokio::sync::oneshot::Sender<()>>,
    pub should_quit: bool,
    pub mode: AppMode,
    /// Previous mode before opening help overlay
    pub previous_mode: Option<Box<AppMode>>,
    pub multi_select: HashSet<i64>,
    pub clipboard: Option<String>,
    pub confirmation: Option<ConfirmAction>,
    pub updating_groups: HashSet<String>,
    /// Profile IDs currently being tested
    /// Test sessions in flight, keyed by `(endpoint_id, protocol_id)` — the
    /// unique `ProfileStats` pair. Protocol-only keys collide across
    /// endpoints that share a `Protocol` row (identity dedup excludes
    /// host/port), which is exactly how results used to land on the wrong
    /// endpoint's row.
    pub testing_profiles: HashSet<(i64, i64)>,
    /// Which test type is currently running per link (for display), keyed by
    /// `(endpoint_id, protocol_id)` like `testing_profiles`.
    pub testing_details: HashMap<(i64, i64), TestType>,
    /// Cached update status for both backends.
    pub update_status: HashMap<CoreType, BackendUpdateStatus>,
    pub actions_compact: bool,
    pub connected_protocol_id: Option<i64>,
    /// Shared stop flag for batch speed tests.
    pub speed_test_stop: Arc<AtomicBool>,
    pub last_test_tcp: Option<u64>,
    /// Live batch meters (plan pages + the two probe levels), displayed in the
    /// status bar and the Actions Log panel: shared with the batch task, which
    /// writes them in place.
    pub batch_progress: Option<Arc<crate::types::BatchMeters>>,
    /// Meters for a running maintenance command (`ops::compact`): the DNS
    /// retry's `Name` bar and the Compact's `Comp` bar, rendered by the same
    /// surfaces as `batch_progress`. Installed at spawn, cleared when the
    /// command's terminal event arrives.
    pub maint_progress: Option<Arc<crate::types::MaintMeters>>,
    /// The running `Fill Exit IPs` command's meters — its own `Look` bar and
    /// its own ok/fail/retry counts. A separate slot from `maint_progress`
    /// because the fill is its own command with its own lifecycle: it starts
    /// when the user asks for it and ends when its last link is settled.
    pub fill_progress: Option<Arc<crate::types::FillMeters>>,
    /// The scheduler's queue: the tasks waiting to run, earliest first
    /// (spec §14). In-memory, process lifetime — a restart drops it.
    pub task_queue: std::collections::VecDeque<crate::ops::job_scheduler::TaskSpec>,
    /// The task currently running, if any. `None` when the scheduler is idle.
    /// There is never more than one: the scheduler is the only entry point.
    pub running_task: Option<crate::ops::job_scheduler::TaskSpec>,
    /// Whether the queue is paused (`s`) — the contents survive for `r`.
    pub scheduler_paused: bool,
    /// The tasks that have finished, newest last. Read by the Tasks pane's
    /// history and by the quit path.
    pub task_history: Vec<crate::ops::job_scheduler::TaskSpec>,
    /// The cached aggregate counts + the scope key they were computed for.
    /// `None` until the first refresh; a scope change discards it (spec D21).
    pub aggregates: Option<AggregateCache>,
    /// Set when a job finishes (its terminal event) — the counts changed, so
    /// the next tick refreshes. Filter changes are detected by the key
    /// comparison in the event loop, so they need no flag.
    pub aggregates_dirty: std::cell::Cell<bool>,
    /// The Details pane's own scroll offset — NOT the native ring's
    /// (`native_activity::SCROLL` is a module-global counting back from the
    /// newest ring entry, so sharing it would couple two unrelated surfaces).
    pub details_scroll: usize,
    /// The Tasks pane's cursor over the queued list (spec D38).
    pub tasks_cursor: usize,
    /// The running batch's shared state (counters, class histograms, phase
    /// timings), published by `run_batch` once its plan resolves — the value
    /// comes from the batch task, hence `OnceLock` over `LazyLock`/`Mutex`.
    ///
    /// Set and cleared together with `batch_progress`, and read at quit: a batch
    /// cancelled by the runtime drop never reaches its own summary line, so this
    /// is the only way the interrupted run's classification is reported
    /// (`crate::ops::ping::interrupted_summary_line`). `pub(crate)` because its
    /// type is the batch internals, not state anyone outside the crate may hold.
    pub(crate) batch: Option<Arc<std::sync::OnceLock<Arc<crate::ops::ping::BatchShared>>>>,
    pub last_test_real: Option<u64>,
    pub last_test_speed: Option<u64>,
    /// When the last result-driven Profiles page refetch was scheduled.
    ///
    /// A test result patches its row in memory; the DB refetch exists only to
    /// re-place the row in the ordered window. Every result used to invalidate
    /// the page unconditionally, which costs one full page query + hydrate per
    /// UI tick (measured 23 ms against a 16 ms tick on the 7,486-endpoint
    /// reference feed, for the whole length of a batch) — see
    /// `RESULT_RELOAD_THROTTLE`.
    pub last_result_reload: Cell<Option<std::time::Instant>>,
    pub current_traffic_up: i64,
    pub current_traffic_down: i64,
    pub current_memory: u64,
    pub term_height: Cell<u16>,
    pub routing_rules: Vec<RoutingRule>,
    pub shutdown_token: Arc<AtomicBool>,
    /// Handle to the core process task, used for clean shutdown.
    pub core_task_handle: Option<JoinHandle<()>>,
    /// Heed-backed persistent log storage.
    pub heed_storage: Option<Arc<HeedLogStorage>>,
    /// Highest `timestamp_ns` we've seen (for polling new logs).
    pub last_seen_log_ns: u64,
    /// Known target names from the heed targets database.
    pub known_targets: Vec<String>,
    /// Selected targets for filtering (empty = show all). A set so the
    /// per-line filter probe in the Logs render pass is O(1), not O(n).
    pub selected_targets: HashSet<String>,
    /// Last time we polled heed for new log entries.
    pub last_heed_poll: std::time::Instant,
    /// Channel sender for non-blocking log persistence.
    /// `TuiLogLayer` and core log forwarder send `LogMessage` here; background writer batches and writes to heed.
    pub log_sender_tx: Option<std::sync::mpsc::SyncSender<leas_core::log_heed::LogMessage>>,
    /// Channel sender for core subprocess log lines (String lines from stdout/stderr).
    pub core_log_tx: Option<tokio::sync::mpsc::Sender<String>>,
    /// Whether initial logs have been loaded from heed into `log_cache` yet.
    pub logs_loaded: bool,

    /// Geo IP mmdb lookup (None until constructed; construction is cheap, no I/O).
    pub geo_ip: Option<Arc<leas_geoip::GeoIp>>,
    /// Cached DNS resolver (construction is cheap, no I/O).
    pub dns_resolver: Option<Arc<leas_dns::DnsResolver>>,
    /// Whitelist checker (loaded in background; None until `HostFeaturesLoaded`).
    pub host_features: Option<Arc<leas_host_features::HostFeaturesChecker>>,
    pub endpoint_info: HashMap<i64, EndpointInfo>,
    /// mmdb country per outbound (exit) IP, keyed by the IP string. Filled at
    /// profile load and on real-ping success; survives reruns because the
    /// source (`latency.ip`) is persisted and lookups rerun at load.
    /// A 512-entry LRU (not the old unbounded `HashMap`): a long-lived
    /// session touching many exit IPs stays bounded; `lru::LruCache::get`
    /// needs `&mut`, hence the `Mutex` (the old plain `HashMap` had no
    /// eviction at all, so the lock discipline is unchanged in practice).
    pub outbound_country_cache: Arc<parking_lot::Mutex<lru::LruCache<String, Option<String>>>>,
    /// TTL (secs) for the DNS-resolution cache; default 300.
    pub dns_cache_ttl_secs: i64,
    /// Profiles display-row cache (part-2 runtime bounds): rebuilt when a row
    /// input changed — structural `endpoints_gen`, selection/connection (in
    /// the key), or the dirty bits set by the async mutation sites
    /// (traffic/test/country). `RefCell` because `render` rebuilds under
    /// `&self`; the UI loop is single-threaded and only this cache sits
    /// behind the cell.
    pub display_rows_cache: RefCell<crate::ui::profiles::DisplayRowsCache>,
}

impl AppState {
    /// Pane-1 Profiles keys are live only when pane 1 is focused and showing
    /// Profiles (spec D2: keys are pane-scoped).
    pub const fn profiles_active(&self) -> bool {
        matches!(self.focused_pane, crate::types::FocusedPane::Pane1)
            && matches!(self.pane1_tab, crate::types::Pane1Tab::Profiles)
    }

    /// Effective pane-2 height in rows: the user override, else the per-tab
    /// default (Details 12 / Metrics 16 / Tasks 10 — spec §14).
    pub const fn pane2_rows(&self) -> u16 {
        if self.pane2_height > 0 {
            self.pane2_height
        } else {
            match self.pane2_tab {
                crate::types::Pane2Tab::Details => 12,
                crate::types::Pane2Tab::Metrics => 16,
                crate::types::Pane2Tab::Tasks => 10,
            }
        }
    }

    /// The scope key the aggregates are computed for.
    ///
    /// The view group's key is the CURRENT filter (view + search + group), so
    /// the panel and the footer cannot disagree. The global group has no
    /// filter — its key is the same for every view.
    #[must_use]
    pub fn aggregate_key(&self) -> AggregateKey {
        AggregateKey {
            view: self.purgatory_view,
            search: (!self.search_query.is_empty()).then(|| self.search_query.clone()),
            // The tab never narrows by group (`ProfilesLoad::from` hardcodes
            // `group_id: None`), so the aggregate must not either.
            group_id: None,
            scope: PlanScope::All,
        }
    }

    /// The Active-window bound, computed the same way the page query does
    /// (`ops/profiles.rs::page_request`), so the panel's view group and the
    /// table's membership cannot drift.
    fn active_threshold(&self) -> i64 {
        let now = leas_db::models::now_epoch();
        match self.purgatory_view {
            PurgatoryView::Active | PurgatoryView::Purgatory => {
                now.saturating_sub(self.purgatory_ttl_secs)
            }
            PurgatoryView::All => 0,
        }
    }

    /// Refresh the cached aggregates for the current scope.
    ///
    /// Called on a filter/view/search/group change and on a job event — never on
    /// a timer (spec D21): the counts freeze while idle, and `alive` drifts
    /// against the wall clock until the next refresh.
    pub async fn refresh_aggregates(&mut self) {
        let key = self.aggregate_key();
        let req = PageRequest {
            view: key.view,
            active_threshold: self.active_threshold(),
            search: key.search.clone(),
            group_id: key.group_id.clone(),
            scope: key.scope,
            sort: PageSort::Test,
            ascending: true,
            offset: 0,
            limit: 1,
        };
        // The view group: the swept `band`, so it describes the same set the
        // table shows.
        let view = self
            .db
            .profiles_aggregate(&req, false)
            .await
            .unwrap_or_default();
        // The global group: live liveness, computed against the wall clock.
        let global = self
            .db
            .profiles_aggregate(&req, true)
            .await
            .unwrap_or_default();
        self.aggregates = Some(AggregateCache {
            counts: AggregateCounts {
                total: view.total,
                alive: global.alive,
                proven: view.proven,
                reliable: view.reliable,
                untested: view.untested,
                failed: view.failed,
                other: view.other,
            },
            key,
        });
    }

    /// ISO-3166 alpha-2 for an outbound IP from the in-memory cache (None =
    /// unknown/not yet looked up).
    pub fn outbound_country_for(&self, ip: &str) -> Option<String> {
        self.outbound_country_cache
            .lock()
            .get(ip)
            .cloned()
            .flatten()
    }

    /// Mark the profiles display-row cache stale for `bits` (`ROWS_DIRTY_*`).
    /// Called by the async mutation sites (`ops::events` handlers, the ping
    /// entry points) so `build_display_rows` rebuilds without re-deriving
    /// every row input. Sticky: cleared only by a successful rebuild.
    pub fn mark_rows_dirty(&mut self, bits: u8) {
        let mut cache = self.display_rows_cache.borrow_mut();
        cache.dirty |= bits;
    }
}

/// Derive the typed [`Transport`] embed from a protocol config: the transport
/// kind plus the exact [`TransportConfig`] payload for the deferred JSON
/// column. Only vless/vmess/trojan carry a transport field; the quic-family
/// protocols (hy/hy2/tuic) are [`TransportConfig::Quic`]; everything else is
/// TCP — mirroring the `ProtoSpec::transport_type` accessor.
fn transport_embed(config: &ProtocolConfig) -> Transport {
    let transport = match config {
        ProtocolConfig::Vless(c) => c.transport.clone(),
        ProtocolConfig::Vmess(c) => c.transport.clone(),
        ProtocolConfig::Trojan(c) => c.transport.clone(),
        ProtocolConfig::Hysteria2(_) | ProtocolConfig::Tuic(_) | ProtocolConfig::Hysteria1(_) => {
            TransportConfig::Quic
        }
        _ => TransportConfig::Tcp,
    };
    let r#type = transport
        .type_str()
        .parse::<leas_proto::proto_spec::TransportType>()
        .unwrap_or(leas_proto::proto_spec::TransportType::Tcp);
    Transport { r#type }
}

/// Derive the typed [`Security`] embed from a protocol config: the security
/// kind plus the queryable `sni`/`fp`/`insecure` columns and the exact
/// [`leas_proto::proto_spec::SecurityConfig`] payload for the deferred
/// JSON column. The columns are populated from the same `config.security()`
/// accessors the UI reads, so they are queryable without loading the
/// deferred `config` JSON.
fn security_embed(config: &ProtocolConfig) -> Security {
    let security = config.security().cloned().unwrap_or_default();
    let r#type = match security.type_str() {
        Some("tls") => leas_proto::proto_spec::SecurityType::Tls,
        Some("reality") => leas_proto::proto_spec::SecurityType::Reality,
        _ => leas_proto::proto_spec::SecurityType::None,
    };
    Security {
        r#type,
        sni: security.sni().map(str::to_string),
        fp: security.fp().map(str::to_string),
        insecure: security.insecure(),
    }
}

/// Build a typed `Endpoint` row from parse-boundary endpoint essentials.
///
/// Identity = `stable_hash(canonical_name, port)` (db-rewamp D10): the
/// once-normalized DNS name, the IP literal, or empty for an exotic host; the
/// split fills `domain`/`sub_domain`.
#[must_use]
pub fn endpoint_from_essentials(ep: &EndpointEssentials) -> Endpoint {
    let host_type = match ep.host_type {
        HostKind::Ipv4 => HostType::Ipv4,
        HostKind::Ipv6 => HostType::Ipv6,
        HostKind::Dns => HostType::Dns,
        HostKind::Undefined => HostType::Undefined,
    };
    let name = Endpoint::derive_name(&ep.host, host_type);
    let (domain, sub_domain) = Endpoint::derive_domain(&ep.host, host_type);
    Endpoint {
        id: EndpointId::new(stable_hash(&name, i64::from(ep.port))),
        domain,
        sub_domain,
        port: ep.port,
        ports: ep.ports.clone(),
        last_source: None,
        manual_protocol_override: None,
        resolved_at: None,
        created_at: leas_db::models::now_epoch(),
        links: Deferred::default(),
        group_links: Deferred::default(),
    }
}

/// Build a typed `Protocol` row from a parse result, with the deferred
/// `config` JSON loaded so it is ready for `Database::upsert_protocol`.
///
/// Identity: id = `uid()`, computed from ONE canonical serialization
/// (`identity_once`) — the three separate `sig()`/`cred_hash()`/`uid()` calls
/// would serialize 3×.
#[must_use]
pub fn protocol_from_parsed(parsed: &ParsedProto) -> Protocol {
    // Canonicalize the transport paths ONCE, before the identity is computed
    // AND before the stored columns are built: the stored `config` is what the
    // dial reads, and the identity must hash that same canonical value — a raw
    // path would both fail to frame (`ws request: HTTP format error`) and split
    // one logical path across two uids. This is the single application owner:
    // every flow (share URL, Clash, Add/Edit form, stream import) reaches the
    // `protocols` table through here.
    // See docs/aegis/specs/2026-09-23-ws-path-canonicalization-design.md §4.2.
    // Identity is computed from `ProtocolEssentials` alone, so the endpoints
    // are NOT cloned: a temporary holder carries the canonical config through
    // `identity_once` and is then moved on, so the config is cloned exactly
    // once — the same single clone the Json column needed before.
    let mut holder = ParsedProto {
        endpoints: Vec::new(),
        protocol: parsed.protocol.clone(),
    };
    holder.protocol.config.normalize_transport();
    let (sig, _cred_hash, uid) = holder.identity_once();
    let essentials = holder.protocol;

    let transport = transport_embed(&essentials.config);
    let security = security_embed(&essentials.config);
    Protocol {
        id: ProtocolId::new(uid),
        sig,
        proto_kind: essentials.proto_kind,
        transport,
        security,
        config: Deferred::from(Json(essentials.config)),
        created_at: leas_db::models::now_epoch(),
        links: Deferred::default(),
    }
}

/// The per-pair `ProfileStats` link for one parsed endpoint, reusing the
/// already-computed protocol id (no `uid()` rehash per endpoint).
#[must_use]
pub fn link_from_parsed_with_id(protocol_id: ProtocolId, endpoint_id: EndpointId) -> ProfileStats {
    let now = leas_db::models::now_epoch();
    ProfileStats {
        protocol_id,
        endpoint_id,
        last_used_at: None,
        last_seen_at: now,
        latency: Latency::default(),
        speed_bps: None,
        error: None,
        purge_reason: None,
        stab_mask: 0,
        stab_len: 0,
        traffic: TrafficStats {
            today_up: 0,
            today_down: 0,
            total_up: 0,
            total_down: 0,
        },
        created_at: now,
        updated_at: now,
        version: 1,
        protocol: Deferred::default(),
        endpoint: Deferred::default(),
    }
}
/// Persist a parsed protocol as typed rows, returning the endpoint count.
///
/// Rows written: one endpoint per parsed endpoint, one shared protocol row,
/// one per-pair link, plus the endpoint-group link when `group_id` is `Some`.
///
/// Dedup is natural: endpoint ids (`stable_hash(host, port)`) and protocol
/// ids (`uid()`) are deterministic, so re-imports update the existing rows
/// instead of duplicating — profiles missing from a later fetch keep their
/// old `last_seen_at` and age into the Stale view (old orphan-to-purgatory
/// semantics via the typed staleness clock).
///
/// # Errors
///
/// Propagates the first failed upsert.
pub async fn persist_parsed(
    db: &Database,
    parsed: &ParsedProto,
    group_id: Option<&str>,
) -> Result<usize, leas_db::DatabaseError> {
    // Build the whole batch, then write it in ONE transaction — the shape
    // `ops::stream_import` already uses for a subscription body. Per-row
    // autocommit upserts cost a commit each; a batch shares one, so a crash
    // mid-import can no longer leave half a subscription stored.
    if parsed.endpoints.is_empty() {
        return Ok(0);
    }
    let protocol = protocol_from_parsed(parsed);
    let mut endpoints = Vec::with_capacity(parsed.endpoints.len());
    let mut links = Vec::with_capacity(parsed.endpoints.len());
    let mut group_links = Vec::with_capacity(parsed.endpoints.len());
    let mut ip_literals: Vec<(EndpointId, std::net::IpAddr)> = Vec::new();
    for ep in &parsed.endpoints {
        let endpoint = endpoint_from_essentials(ep);
        // An IP-literal host's address is the DIAL target and the rank `addr`
        // tiebreak; with `host` gone (db-rewamp D10) it lives in `endpoint_ip`,
        // so the import writes it (75% of a feed is IP literals).
        if let Ok(ip) = ep.host.parse::<std::net::IpAddr>() {
            ip_literals.push((endpoint.id, ip));
        }
        let link = link_from_parsed_with_id(protocol.id, endpoint.id);
        if let Some(gid) = group_id {
            group_links.push(EndpointGroup {
                endpoint_id: endpoint.id,
                group_id: gid.to_owned(),
                last_seen_at: link.last_seen_at,
                sort_order: None,
                endpoint: Deferred::default(),
                group: Deferred::default(),
            });
        }
        endpoints.push(endpoint);
        links.push(link);
    }

    let protocols = [protocol];
    let count = endpoints.len();
    let persist = || async {
        let mut conn = db.connection().await?;
        let mut tx = conn.transaction().await?;
        leas_db::upsert_endpoints_bulk(&mut tx, &endpoints).await?;
        leas_db::upsert_protocols_bulk(&mut tx, &protocols).await?;
        leas_db::upsert_links_bulk(&mut tx, &links).await?;
        leas_db::upsert_endpoint_group_links_bulk(&mut tx, &group_links).await?;
        leas_db::endpoint_ip::insert_literals_bulk(&mut tx, &ip_literals).await?;
        tx.commit().await?;
        Ok(())
    };
    leas_db::retry_on_busy(persist, 5).await?;
    Ok(count)
}

/// A link carries a persisted failure marker (`error.kind` — the old
/// in-memory round maps were replaced by persisted errors in T17). Drives the
/// "Remove Bad Servers" flow.
#[must_use]
pub const fn link_is_failed(link: &ProfileStats) -> bool {
    link.error.is_some()
}

/// Load a `Protocol` row with its deferred `config` JSON included.
///
/// Default read paths exclude deferred columns (the `EndpointRow` list ships
/// unloaded `Protocol`s); `ConfigBuilder::build` and
/// `Database::upsert_protocol` require them loaded. Returns `Ok(None)` when
/// no such protocol row exists.
pub async fn load_protocol_with_config(
    db: &Database,
    id: ProtocolId,
) -> Result<Option<Protocol>, leas_db::DatabaseError> {
    let mut conn = db.connection().await?;
    let protocol = Protocol::filter_by_id(id)
        .include(Protocol::fields().config())
        .first()
        .exec(&mut conn)
        .await?;
    Ok(protocol)
}

/// Raise a configured DNS-failure deferral window to the floor that can
/// actually defer anything.
///
/// The window is measured from the moment a resolution REPORTS, so a window
/// shorter than [`crate::ops::enrich::DNS_LOOKUP_TIMEOUT`] has already expired
/// by the time there is a failure to defer. The shipped 5s against an 8s
/// deadline is exactly that inversion, and it is why the 2026-09-27 Windows run
/// reported `deferred=0` against 196 DNS failures.
///
/// Applied here, where the user's setting enters the runtime, rather than
/// inside `TaskScheduler`: the scheduler is also constructed directly by the
/// batch tests with a deliberately short window, and there is no resolver
/// deadline to outlive in a test. `0` is the explicit "deferral off" choice and
/// passes through.
pub(crate) fn clamp_dns_defer_secs(configured: i64) -> i64 {
    use crate::ops::scheduler::MIN_DNS_DEFER_SECS;
    if configured > 0 && configured < MIN_DNS_DEFER_SECS {
        tracing::warn!(
            target: "tui::state",
            configured,
            MIN_DNS_DEFER_SECS,
            lookup_timeout_secs = crate::ops::enrich::DNS_LOOKUP_TIMEOUT.as_secs(),
            "DNS-failure deferral window is shorter than one resolution; a \
             window that expires before the lookup reports defers nothing, \
             so it was raised",
        );
        return MIN_DNS_DEFER_SECS;
    }
    configured
}

impl AppState {
    pub async fn new(db: Arc<Database>, config: AppConfig) -> Self {
        let theme = crate::ui::theme::load(&config.theme_name).unwrap_or_else(|e| panic!("{e}"));
        let (core_tx, core_rx) = tokio::sync::mpsc::channel(65536);
        let purgatory_ttl_secs = (config.purgatory.ttl_days * 86400) as i64;
        let purgatory_retention_secs = (config.purgatory.retention_days * 86400) as i64;
        // The stored `band` (Active membership) is materialized against
        // `now − ttl`, so the DB layer must use the same ttl the page means.
        db.set_band_ttl_secs(purgatory_ttl_secs);
        // Continuity-independent catch-up: `now` advanced while the app was
        // closed (and the configured ttl may differ from the open-time
        // default), so reband every row against the current threshold before
        // the first page renders.
        if let Err(e) = db.reband_all().await {
            tracing::warn!(target: "tui::state", "reband_all at startup: {e}");
        }
        // Scheduler limits come from the speed-test config (T21); they stay
        // runtime-settable afterwards via `TaskScheduler::set_limits` on
        // settings save.
        let queue_limit = config.speed_test.task_queue_limit;
        let dns_defer_secs = clamp_dns_defer_secs(config.speed_test.dns_failure_defer_secs);
        let link_stage = leas_db::WriteBehind::<leas_db::LinkSpec>::new(
            Arc::clone(&db),
            leas_db::write_behind::DEFAULT_FLUSH_ROWS,
            leas_db::write_behind::DEFAULT_FLUSH_INTERVAL,
        );
        let mut state = Self {
            db,
            config,
            scheduler: Arc::new(scheduler::TaskScheduler::new(queue_limit, dns_defer_secs)),
            link_stage,
            theme,
            focused_pane: FocusedPane::Pane1,
            pane1_tab: Pane1Tab::Profiles,
            pane2_tab: Pane2Tab::Details,
            pane2_height: 0,
            settings_form_snapshot: None,
            settings_sections: SectionList::default(),
            settings_search: SettingsSearch::default(),
            settings_notice: None,
            update_status: HashMap::new(),
            endpoints: Vec::new(),
            filter_cache_valid: Cell::new(true),
            page_total: 0,
            page_offset: 0,
            endpoints_gen: 0,
            reload_gen: 0,
            groups: Vec::new(),
            purgatory_view: PurgatoryView::Active,
            purgatory_ttl_secs,
            purgatory_retention_secs,

            selected_sub: None,
            selected_index: 0,
            log_scroll: 0,
            log_select_anchor: None,
            log_viewport_rows: Cell::new(0),
            search_query: String::new(),
            search_focused: false,
            log_cache: VecDeque::new(),
            log_has_older: false,
            log_seek_home: false,
            connected_core: None,
            connecting: false,
            connection_error: None,
            core_event_rx: Some(core_rx),
            core_event_tx: Some(core_tx),
            disconnect_tx: None,
            should_quit: false,
            mode: AppMode::List,
            previous_mode: None,
            multi_select: HashSet::new(),
            clipboard: None,
            confirmation: None,
            updating_groups: HashSet::new(),
            native_activity: NativeActivityLog::new(2000),
            system_stats: None,
            testing_profiles: HashSet::new(),
            testing_details: HashMap::new(),
            actions_compact: false,
            connected_protocol_id: None,
            last_test_tcp: None,
            last_test_real: None,
            last_test_speed: None,
            last_result_reload: std::cell::Cell::new(None),
            current_traffic_up: 0,
            current_traffic_down: 0,
            current_memory: 0,
            routing_rules: Vec::new(),
            core_task_handle: None,
            shutdown_token: Arc::new(AtomicBool::new(false)),
            speed_test_stop: Arc::new(AtomicBool::new(false)),
            batch_progress: None,
            maint_progress: None,
            fill_progress: None,
            task_queue: std::collections::VecDeque::new(),
            running_task: None,
            details_scroll: 0,
            tasks_cursor: 0,
            scheduler_paused: false,
            task_history: Vec::new(),
            aggregates: None,
            aggregates_dirty: Cell::new(false),
            batch: None,
            term_height: Cell::new(80),
            heed_storage: None,
            last_seen_log_ns: 0,
            known_targets: Vec::new(),
            selected_targets: HashSet::new(),
            last_heed_poll: std::time::Instant::now(),
            log_sender_tx: None,
            core_log_tx: None,
            logs_loaded: false,
            geo_ip: None,
            dns_resolver: None,
            host_features: None,
            endpoint_info: HashMap::new(),
            // 512-entry LRU: hot exit IPs stay resident; cold ones evict.
            outbound_country_cache: Arc::new(parking_lot::Mutex::new(lru::LruCache::new(
                std::num::NonZeroUsize::new(512).expect("512 is nonzero"),
            ))),
            dns_cache_ttl_secs: 300,
            display_rows_cache: RefCell::new(crate::ui::profiles::DisplayRowsCache::default()),
        };
        // Cheap constructors — no I/O until first lookup.
        let config_dir = dirs::config_dir()
            .unwrap_or_else(|| std::path::Path::new(".").to_path_buf())
            .join("leas");
        state.geo_ip = Some(Arc::new(leas_geoip::GeoIp::new(
            config_dir.join("GeoLite2-City.mmdb"),
        )));
        state.dns_resolver = Some(Arc::new(leas_dns::DnsResolver::new(
            config_dir.join("dns-cache"),
        )));
        state.dns_cache_ttl_secs = state
            .db
            .get_dns_settings()
            .await
            .ok()
            .flatten()
            .and_then(|d| d.cache_ttl_secs)
            .unwrap_or(300);
        state.reload_profiles().await;
        state.reload_groups().await;
        state.spawn_auto_update();
        // Background whitelist load (downloads missing files). Result arrives
        // via CoreEvent::HostFeaturesLoaded → state.host_features.
        let tx = state.core_event_tx.clone();
        tokio::spawn(async move {
            let w = config_dir.join("whitelist");
            match leas_host_features::HostFeaturesChecker::load(
                &w.join("whitelist.txt"),
                &w.join("ipwhitelist.txt"),
                &w.join("cidrwhitelist.txt"),
            )
            .await
            {
                Ok(c) => {
                    if let Some(t) = tx {
                        let _ = t.try_send(CoreEvent::HostFeaturesLoaded(Arc::new(c)));
                    }
                }
                Err(e) => tracing::warn!(target: "tui::state", "whitelist load failed: {e}"),
            }
        });
        state
    }
    /// Build a ratatui-cheese `Palette` from the currently selected theme.
    #[must_use]
    pub const fn theme(&self) -> &opaline::Theme {
        &self.theme
    }

    /// Load the most recent log entries from heed into [`log_cache`].
    /// Uses async heed methods that wrap LMDB reads in `spawn_blocking`.
    pub async fn load_initial_logs(&mut self) {
        let heed = match &self.heed_storage {
            Some(h) => h.clone(),
            None => return,
        };
        match heed.read_recent_async(500).await {
            Ok(entries) => {
                self.log_has_older = entries.len() >= 500;
                self.log_cache = entries
                    .into_iter()
                    .rev()
                    .map(|e| LogLine {
                        level: e.level,
                        target: e.target,
                        message: e.message,
                        // Read back from heed: `detail` is session-only by
                        // design and was never persisted, so it is absent here.
                        detail: None,
                        timestamp_nanos: e.timestamp_nanos as i64,
                    })
                    .collect();
                // Update last_seen_log_ns from the newest entry
                if let Some(newest) = self.log_cache.back() {
                    self.last_seen_log_ns = newest.timestamp_nanos as u64;
                }
                // Load known targets
                if let Ok(targets) = heed.get_targets_async().await {
                    self.known_targets = targets;
                }
            }
            Err(e) => {
                tracing::error!(target: "tui::state::log_init", "Failed to load initial logs: {e}");
            }
        }
    }

    pub async fn reload_profiles(&mut self) {
        profiles::reload_profiles(self).await;
    }

    pub async fn reload_groups(&mut self) {
        profiles::reload_groups(self).await;
    }
    pub async fn reload_routing_rules(&mut self) {
        profiles::reload_routing_rules(self).await;
    }

    /// The filtered total across all pages (the page holds one window of it).
    #[must_use]
    pub const fn profiles_total(&self) -> u64 {
        self.page_total
    }

    pub fn filtered_profiles(&self) -> impl Iterator<Item = &EndpointRow> {
        profiles::filtered_profiles(self)
    }

    pub const fn filtered_len(&self) -> usize {
        profiles::filtered_len(self)
    }

    pub const fn cycle_purgatory_view(&mut self) {
        profiles::cycle_purgatory_view(self);
    }
    /// Get the first group ID for new profile assignments (no active group filter).
    pub fn first_group_id(&self) -> String {
        self.groups
            .first()
            .map(|g| g.id.clone())
            .unwrap_or_default()
    }

    /// Log to the TUI log buffer AND the actions panel.
    ///
    /// Sends directly to the heed storage channel and the TUI event channel,
    /// bypassing the tracing subscriber (tracing's `target:` requires a
    /// `&'static str` literal at compile time, so a runtime target parameter
    /// cannot set event metadata target).
    pub fn log_trace(&mut self, level: &str, target: &str, message: &str) {
        use std::time::SystemTime;

        let timestamp_nanos = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;

        let log_msg = leas_core::log_heed::LogMessage {
            level: level.to_string(),
            target: target.to_string(),
            message: message.to_string(),
            timestamp_nanos,
        };

        // Send to heed storage (via background batched writer)
        if let Some(sender) = &self.log_sender_tx {
            let _ = sender.try_send(log_msg);
        }

        // Send to actions panel, stamped with the SAME event time the heed copy
        // carries: the two deliveries are reconciled by one watermark, so a
        // drain-time stamp here would run ahead of it and make the poll skip
        // in-flight lines.
        if let Some(tx) = &self.core_event_tx {
            let _ = tx.try_send(crate::CoreEvent::TuiLog {
                target: target.to_string(),
                level: level.to_string(),
                message: message.to_string(),
                // `log_trace` has no tracing fields to render.
                detail: None,
                timestamp_nanos: i64::try_from(timestamp_nanos).unwrap_or(i64::MAX),
                // Sent to the heed channel just above.
                persisted: true,
            });
        }
    }

    /// Session-only activity line: the actions panel and the Logs tab show it
    /// live, the heed store does **not** keep it.
    ///
    /// For per-result chatter, which is data rather than diagnostics: the
    /// outcome lives on the link (`profile_stats.latency`/`error_text`, the
    /// Test column's marker) and the batch's summary line carries the counts.
    /// Persisting it made a 31k-link batch write 16k store rows in 16 minutes
    /// (2026-09-16), which is what a log tab full of `TcpPing failed for …`
    /// looks like afterwards.
    pub fn log_activity(&mut self, level: &str, target: &str, message: &str) {
        if let Some(tx) = &self.core_event_tx {
            let _ = tx.try_send(crate::CoreEvent::TuiLog {
                target: target.to_string(),
                level: level.to_string(),
                message: message.to_string(),
                // `log_activity` has no tracing fields to render.
                detail: None,
                // Event time, for the same reason as `log_trace`.
                timestamp_nanos: std::time::SystemTime::now()
                    .duration_since(std::time::SystemTime::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos() as i64,
                // Session-only by design: the heed store does NOT keep this
                // line, so it must never move the heed watermark.
                persisted: false,
            });
        }
    }

    /// Record one native-core trace event into the session activity log.
    pub fn record_native_trace(&mut self, event: &leas_native::telemetry::TraceEvent) {
        self.native_activity.record(event);
    }
    /// Start a new native-core session: clear the trace ring and drop the
    /// Native Activity tab's scroll offset, which is a distance from the
    /// newest row and would otherwise pin the view into rows the new
    /// session has not recorded.
    pub fn reset_native_activity(&mut self) {
        self.native_activity.reset();
        crate::ui::native_activity::reset_scroll();
    }
    /// Resolve which core a profile row should use, considering (in order):
    ///   1. Per-pair override (`link.core_type` — resolved at parse time)
    ///   2. Per-protocol config override (`config.core.protocol_core_overrides`)
    ///   3. Hardcoded auto-detection (`core_for_protocol` via `resolve_core`)
    pub fn resolved_core(&self, row: &EndpointRow) -> CoreType {
        profiles::resolved_core(self, row)
    }
    // ── CRUD operations ──────────────────────────────────────────────────

    pub fn start_add_server(&mut self) {
        profiles::start_add_server(self);
    }
    pub async fn start_edit_profile(&mut self, id: &str) {
        profiles::start_edit_profile(self, id).await;
    }

    pub fn selected_profile_id(&self) -> Option<i64> {
        profiles::selected_profile_id(self)
    }

    pub fn toggle_expand(&mut self) {
        profiles::toggle_expand(self);
    }
    pub fn collapse_expand(&mut self) {
        profiles::collapse_expand(self);
    }
    pub fn nav_protocol_down(&mut self) -> bool {
        profiles::nav_protocol_down(self)
    }
    pub fn nav_protocol_up(&mut self) -> bool {
        profiles::nav_protocol_up(self)
    }
    pub const fn is_on_sub_row(&self) -> bool {
        profiles::is_on_sub_row(self)
    }
    /// Get the protocol ID for the currently selected sub-row.
    pub fn selected_sub_protocol_id(&self) -> Option<i64> {
        profiles::selected_sub_protocol_id(self)
    }

    pub async fn confirm_add_server(&mut self) {
        profiles::confirm_add_server(self).await;
    }

    pub async fn confirm_edit_server(&mut self) {
        profiles::confirm_edit_server(self).await;
    }

    pub fn cancel_form(&mut self) {
        settings::cancel_form(self);
    }

    // ── Settings helpers ──────────────────────────────────────────────────

    pub async fn enter_settings(&mut self) {
        settings::enter_settings(self).await;
    }

    pub async fn build_right_pane(&mut self, section: SettingsSection) -> SplitRightPane {
        settings::build_right_pane(self, section).await
    }
    pub fn save_settings_form(&mut self, section: SettingsSection, fields: &[(String, String)]) {
        settings::save_settings_form(self, section, fields);
    }
    pub async fn save_routing_rule(
        &mut self,
        rule_id: Option<String>,
        fields: &[(String, String)],
    ) {
        settings::save_routing_rule(self, rule_id, fields).await;
    }
    pub async fn save_dns_settings(&mut self, fields: &[(String, String)]) {
        settings::save_dns_settings(self, fields).await;
    }
    pub async fn delete_profile(&mut self, id: i64) {
        profiles::delete_profile(self, id).await;
    }
    pub fn clone_profile(&mut self, id: i64) {
        profiles::clone_profile(self, id);
    }
    pub fn toggle_multi_select(&mut self, id: i64) {
        profiles::toggle_multi_select(self, id);
    }
    pub fn import_url(&mut self, url: &str) {
        profiles::import_url(self, url);
    }
    pub fn start_batch_import(&mut self, urls: &[String]) {
        profiles::start_batch_import(self, urls);
    }
    pub async fn confirm_batch_import(&mut self) {
        profiles::confirm_batch_import(self).await;
    }
    pub fn move_profile_up(&mut self) {
        profiles::move_profile_up(self);
    }
    pub fn move_profile_down(&mut self) {
        profiles::move_profile_down(self);
    }
    pub async fn set_active(&mut self, id: &str) {
        profiles::set_active(self, id).await;
    }
    pub async fn set_protocol_default(&mut self, endpoint_id: i64, protocol_id: i64) {
        profiles::set_protocol_default(self, endpoint_id, protocol_id).await;
    }
    pub fn connect_to_profile(&mut self, protocol_id: i64) {
        connect::connect_to_profile(self, protocol_id);
    }
    pub fn disconnect(&mut self) {
        connect::disconnect(self);
    }
    pub fn start_tcp_ping(&mut self, endpoint_id: i64, protocol_id: i64) {
        ping::start_tcp_ping(self, endpoint_id, protocol_id);
    }
    pub fn start_real_ping(&mut self, endpoint_id: i64, protocol_id: i64) {
        ping::start_real_ping(self, endpoint_id, protocol_id);
    }
    pub fn start_speed_test(&mut self, endpoint_id: i64, protocol_id: i64) {
        ping::start_speed_test(self, endpoint_id, protocol_id);
    }
    pub fn start_udp_test(&mut self, endpoint_id: i64, protocol_id: i64) {
        ping::start_udp_test(self, endpoint_id, protocol_id);
    }
    /// Batch fast-ping every link of every visible endpoint (T19 rebuild on
    /// the `TaskScheduler`).
    pub fn start_batch_ping(&mut self) {
        ping::start_batch_ping(self);
    }
    /// Batch fast-ping every visible link, then real-ping each (T19).
    pub fn start_batch_then_real_ping(&mut self) {
        ping::start_batch_then_real_ping(self);
    }
    /// Fast + real over one scope of the feed (successful / successful+new /
    /// failed), the "Fast + Real Ping" menu variants.
    pub fn start_batch_then_real_ping_scoped(&mut self, scope: leas_db::profiles_query::PlanScope) {
        ping::start_batch_then_real_ping_scoped(self, scope);
    }
    /// Fill the exit IPs of a scope's links — its own command, its own scope,
    /// its own bar and its own rate limiter (spec D10/D11).
    ///
    /// It NEVER rewrites the real delay: the exit IP and the real span are
    /// independently-aged facts in one row.
    pub fn start_fill_exit_ips(&mut self, scope: leas_db::profiles_query::PlanScope) {
        ping::start_fill_exit_ips(self, scope);
    }
    /// Fast-ping every link of the selected endpoint (collapsed multi-protocol rows).
    pub fn start_endpoint_batch_ping(&mut self) {
        ping::start_endpoint_batch_ping(self);
    }
    /// Fast-ping then real-ping every link of the selected endpoint (no dedup).
    pub fn start_endpoint_batch_real_ping(&mut self) {
        ping::start_endpoint_batch_real_ping(self);
    }
    pub fn stop_speed_test(&mut self) {
        ping::stop_speed_test(self);
    }
    /// Remove profiles whose links carry a persisted failure marker
    /// (`error.kind` — the round-map labels were replaced by persisted errors
    /// in T17; batch machinery is removed until T19 rebuilds it).
    pub async fn remove_failed_servers(&mut self) {
        ping::remove_failed_servers(self).await;
    }

    /// Smart Endpoints Compact: merge provably-duplicate endpoints (same
    /// port, shared protocol config, overlapping resolved addresses). The
    /// scan + merges run OFF the event loop; the report arrives via
    /// `CoreEvent::CompactFinished`.
    pub fn compact_duplicate_endpoints(&mut self) {
        compact::spawn_compact(self);
    }

    /// Mass DNS retry: re-resolve every DNS endpoint with an empty address
    /// set, bypassing the TTL. The scan runs off the event loop; the lookups
    /// dispatch on the loop when the target list arrives.
    pub fn retry_failed_dns(&mut self) {
        compact::spawn_dns_retry(self);
    }

    /// Poll core event channel and update state accordingly.
    ///
    /// Returns `true` when an event was handled — callers should redraw
    /// immediately rather than waiting for the idle refresh cadence.
    #[must_use]
    pub async fn poll_core_events(&mut self) -> bool {
        events::poll_core_events(self).await
    }
    // ── Group management ─────────────────────────────────────────────

    pub fn start_add_group(&mut self) {
        subscriptions::start_add_group(self);
    }

    pub fn start_edit_group(&mut self, group_id: &str) {
        subscriptions::start_edit_group(self, group_id);
    }

    pub async fn confirm_add_group(&mut self) {
        subscriptions::confirm_add_group(self).await;
    }

    pub async fn confirm_edit_group(&mut self) {
        subscriptions::confirm_edit_group(self).await;
    }

    pub async fn delete_group(&mut self, group_id: &str) {
        subscriptions::delete_group(self, group_id).await;
    }

    pub async fn clear_group(&mut self, group_id: &str) {
        subscriptions::clear_group(self, group_id).await;
    }

    pub fn clear_logs(&mut self) {
        self.log_cache.clear();
        self.log_scroll = 0;
        self.log_select_anchor = None;
        // Set cursor to now so poll_new_logs doesn't re-read old entries
        self.last_seen_log_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        self.confirmation = None;
        self.log_trace("info", "tui::state", "Logs cleared");
    }

    /// Clear entire log database (heed) in addition to the in-memory cache.
    /// Note: there may be a brief race with the background log writer;
    /// any messages already in the mpsc channel will be written after the clear
    /// and may reappear on next scroll load.
    pub fn purge_logs_database(&mut self) {
        self.log_cache.clear();
        self.log_scroll = 0;
        self.log_select_anchor = None;
        self.last_seen_log_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        // Clear the heed database in the background (best-effort)
        if let Some(ref heed) = self.heed_storage {
            let heed = heed.clone();
            tokio::spawn(async move {
                if let Err(e) = heed.clear_all_async().await {
                    tracing::error!(target: "tui::state", "Failed to clear log database: {e}");
                }
            });
        }
        self.confirmation = None;
        self.log_trace("info", "tui::state", "Log database cleared");
    }

    /// Clear all server stats (traffic counters).
    pub async fn clear_all_stats(&mut self) {
        if let Err(e) = self.db.clear_all_stats().await {
            self.log_trace(
                "error",
                "tui::state",
                &format!("Failed to clear stats: {e}"),
            );
            return;
        }
        self.endpoints_gen = self.endpoints_gen.wrapping_add(1);
        self.filter_cache_valid.set(false);
        self.confirmation = None;
        self.log_trace("info", "tui::state", "All stats cleared");
    }

    // ── Subscription update ──────────────────────────────────────────

    pub fn update_group_subscriptions(&mut self, group_id: &str) {
        subscriptions::update_group_subscriptions(self, group_id);
    }

    pub fn update_all_subscriptions(&mut self) {
        subscriptions::update_all_subscriptions(self);
    }

    /// Spawn async task to check for backend updates on startup or manual trigger.
    pub fn spawn_update_check(&mut self) {
        updates::spawn_update_check(self);
    }

    /// Spawn async task to download and install an update for the given core.
    pub fn spawn_update_download(&mut self, core_type: CoreType) {
        updates::spawn_update_download(self, core_type);
    }

    /// Start a background task to check and update subscriptions.
    pub fn spawn_auto_update(&mut self) {
        subscriptions::spawn_auto_update(self);
    }
}

#[cfg(test)]
mod tests {
    use super::security_embed;
    use leas_native::security::fingerprint::resolve_fingerprint;
    use leas_proto::proto_spec::{
        Hysteria2Config, ProtoSpec, ProtocolConfig, SecurityConfig, TlsConfig, TlsOpts,
    };
    use leas_proto::urlx::TinyText;

    fn config_with_fp(fp: Option<&str>) -> ProtocolConfig {
        ProtocolConfig::Hysteria2(Hysteria2Config {
            auth: "secret".into(),
            security: SecurityConfig {
                tls: Some(TlsConfig::Tls(TlsOpts {
                    sni: Some(TinyText::from("example.com")),
                    fp: fp.map(TinyText::from),
                    ..TlsOpts::default()
                })),
                enc: None,
            },
            obfs: None,
            obfs_password: None,
            up: None,
            down: None,
            hop_interval: None,
            pin_sha256: None,
            remarks: None,
        })
    }

    /// The `ed` hoist must be **reached in production**, not merely correct in
    /// isolation: `hoist_early_data` runs only inside `normalize_transport`, and
    /// every proto-level fixture parses without it — so deleting the call from
    /// the owner would otherwise be silent.
    ///
    /// The second assertion is the path that must not regress: the stored path
    /// keeps `ed=2560` (xray's only carrier, so its `Build()` still hoists it),
    /// and the xray emitter's no-op branch leaves it byte-identical.
    #[test]
    fn protocol_from_parsed_hoists_the_early_data_and_keeps_the_carrier() {
        use super::protocol_from_parsed;
        use leas_proto::proto_spec::SecurityConfig;
        use leas_proto::proto_spec::common::{TransportConfig, to_xray_stream_settings};
        use leas_proto::urlx::RawUrlX;

        // The share-URL `path` value is itself percent-encoded, so `?`/`=`
        // arrive as part of the PATH (`RawUrlX` decodes the query value once).
        let url = "vless://6202b230-417c-4d8e-b624-0f71afa9c75d@example.com:443?security=tls&type=ws&path=%2Fws%3Fed%3D2560";
        let raw = ProtocolConfig::try_parse_proto(&RawUrlX::from(url)).expect("parse vless url");

        let row = protocol_from_parsed(&raw);
        let stored = serde_json::to_value(&row.config).expect("serialize stored config");
        assert_eq!(
            stored["transport"]["max_early_data"], 2560,
            "the owner must hoist `ed` into the typed field: {stored}"
        );
        assert_eq!(
            stored["transport"]["path"], "/ws?ed=2560",
            "the path keeps the carrier xray reads: {stored}"
        );
        assert_eq!(
            stored["transport"]["early_data_header_name"], "Sec-WebSocket-Protocol",
            "sing-box is pinned to the header route, not the path-append one: {stored}"
        );

        // The xray emitter's no-op branch: the carrier is already there, so the
        // emitted path is byte-identical (no double `ed`).
        let transport: TransportConfig =
            serde_json::from_value(stored["transport"].clone()).expect("transport round-trips");
        let ss = to_xray_stream_settings(&SecurityConfig::default(), &transport)
            .expect("a ws transport emits streamSettings");
        assert_eq!(
            ss["wsSettings"]["path"], "/ws?ed=2560",
            "the xray carrier must not regress"
        );
    }

    /// The canonicalizer has ONE application owner — `protocol_from_parsed`
    /// (`docs/aegis/specs/2026-09-23-ws-path-canonicalization-design.md` §4.2).
    /// This asserts the owner APPLIES it: a raw path and its canonical form must
    /// land on the same row id, and the stored transport payload must carry the
    /// canonical string the dial will frame.
    #[test]
    fn protocol_from_parsed_canonicalizes_the_transport_path() {
        use super::protocol_from_parsed;
        use leas_db::models::ProtocolId;
        use leas_proto::urlx::RawUrlX;

        // A double-encoded ws path: `RawUrlX::query` decodes once, so this
        // survives as the escaped form — the shape the feed actually carries.
        let url = "vless://6202b230-417c-4d8e-b624-0f71afa9c75d@example.com:443?security=tls&type=ws&path=%252FtrTelegram%2520x";
        let raw = ProtocolConfig::try_parse_proto(&RawUrlX::from(url)).expect("parse vless url");

        let mut canonical_input = raw.clone();
        canonical_input.protocol.config.normalize_transport();
        // Non-vacuous: the raw input alone hashes to a different id, or the
        // equality below would hold for any implementation.
        assert_ne!(
            ProtocolId::new(raw.identity_once().2),
            ProtocolId::new(canonical_input.identity_once().2)
        );

        let row = protocol_from_parsed(&raw);
        assert_eq!(
            row.id,
            protocol_from_parsed(&canonical_input).id,
            "the owner must canonicalize before hashing"
        );
        let stored = serde_json::to_string(&row.config.get().0).expect("serialize config");
        assert!(
            stored.contains("/trTelegram%20x"),
            "stored config carries the canonical transport path: {stored}"
        );
    }

    /// The `security_fp` column and the config's `tls.fp` are TWO inputs to one
    /// predicate, and this test is what holds them together.
    ///
    /// `security::wrap` — the dial — resolves `opts.fp` off the loaded CONFIG;
    /// the row label and `reason_for` read the `security_fp` COLUMN.
    /// `security_embed` is the projection that writes the column from that same
    /// `tls.fp`, so the two agree today only because of it. A projection bug
    /// would silently make the label and the purge rule describe a different
    /// fingerprint from the one the engine dialled with — and both would still
    /// compile, which is exactly why this is asserted rather than commented.
    #[test]
    fn the_security_fp_column_agrees_with_the_config_field() {
        for fp in [
            None,
            Some(""),
            Some("unsafe"),
            Some("chrome"),
            Some("qq"),
            Some("android"),
            Some("hellochrome_120"),
        ] {
            let config = config_with_fp(fp);
            let column = security_embed(&config);
            let from_config = config.security().and_then(|s| s.fp());

            assert_eq!(
                column.fp.as_deref(),
                from_config,
                "{fp:?}: the column must carry the config's fp verbatim"
            );
            assert_eq!(
                resolve_fingerprint(column.fp.as_deref()),
                resolve_fingerprint(from_config),
                "{fp:?} must resolve identically through both accessors, or the \
                 label and the purge rule disagree about the same link"
            );
        }
    }
}
