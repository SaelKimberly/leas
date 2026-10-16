use std::collections::HashMap;
use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::AtomicU32;

use leas_config::import_export::{ParsedProfile, ValidationSummary};
use leas_core::CoreType;
use leas_core::grpc_client;
use leas_core::speed_test::TestType;
use leas_native::telemetry::{TraceEvent, TraceKind, TraceSecurity};

/// Re-export `EndpointRow` as `EndpointRow` for backward compatibility.
pub use leas_db::models::EndpointRow;
use leas_db::models::HostType;
use leas_proto::proto_spec::ProtocolKind;

/// Clash API /traffic response struct.
#[derive(Debug, Clone, Default, serde::Deserialize)]
pub struct ClashTraffic {
    pub up: i64,
    pub down: i64,
}

/// Cached update status for a proxy backend.
#[derive(Debug, Clone, Default)]
pub struct BackendUpdateStatus {
    pub current_version: Option<String>,
    pub latest_version: Option<String>,
    pub update_available: bool,
    pub downloading: bool,
    pub download_progress: Option<(u64, u64)>,
    pub error: Option<String>,
}

/// One traced native-core connection leg, fed by `CoreEvent::NativeTrace`.
#[derive(Debug, Clone)]
pub struct NativeActivityEntry {
    pub conn_id: u64,
    pub opened_ms: i64,
    pub kind: TraceKind,
    pub dest: String,
    pub protocol: String,
    pub transport: String,
    pub security: TraceSecurity,
    pub up: u64,
    pub down: u64,
    pub closed: bool,
    pub duration_ms: u64,
    pub error: Option<String>,
}

/// Session-only trace log (not persisted): open legs plus recent finished
/// ones, with session totals. Capped — oldest entries fall off the front.
#[derive(Debug, Clone)]
pub struct NativeActivityLog {
    pub entries: VecDeque<NativeActivityEntry>,
    cap: usize,
    pub total_up: u64,
    pub total_down: u64,
    pub open_count: usize,
    pub fail_count: usize,
}

impl NativeActivityLog {
    #[must_use]
    pub fn new(cap: usize) -> Self {
        Self {
            entries: VecDeque::new(),
            cap: cap.max(1),
            total_up: 0,
            total_down: 0,
            open_count: 0,
            fail_count: 0,
        }
    }

    /// Record one trace event. `Opened` pushes a fresh row; `Closed` finds
    /// the matching row from the back (conn ids are near-monotonic).
    pub fn record(&mut self, event: &TraceEvent) {
        match event {
            TraceEvent::Opened(opened) => {
                let now_ms = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_millis().try_into().unwrap_or(i64::MAX));
                self.entries.push_back(NativeActivityEntry {
                    conn_id: opened.conn_id,
                    opened_ms: now_ms,
                    kind: opened.kind,
                    dest: opened.dest.to_string(),
                    protocol: opened.protocol.to_string(),
                    transport: opened.transport.to_string(),
                    security: opened.security,
                    up: 0,
                    down: 0,
                    closed: false,
                    duration_ms: 0,
                    error: None,
                });
                self.open_count += 1;
            }
            TraceEvent::Closed(closed) => {
                let row = self
                    .entries
                    .iter_mut()
                    .rev()
                    .find(|entry| entry.conn_id == closed.conn_id && !entry.closed);
                match row {
                    Some(entry) => {
                        entry.up = closed.up_bytes;
                        entry.down = closed.down_bytes;
                        entry.duration_ms = closed.duration_ms;
                        entry.error.clone_from(&closed.error);
                        entry.closed = true;
                        self.open_count = self.open_count.saturating_sub(1);
                    }
                    None => {
                        // Close without a matching open (dropped open event):
                        // keep a ghost closed row so the counters stay exact.
                        self.entries.push_back(NativeActivityEntry {
                            conn_id: closed.conn_id,
                            opened_ms: 0,
                            kind: TraceKind::Tcp,
                            dest: String::new(),
                            protocol: String::new(),
                            transport: String::new(),
                            security: TraceSecurity::Plain,
                            up: closed.up_bytes,
                            down: closed.down_bytes,
                            closed: true,
                            duration_ms: closed.duration_ms,
                            error: closed.error.clone(),
                        });
                    }
                }
                self.total_up = self.total_up.saturating_add(closed.up_bytes);
                self.total_down = self.total_down.saturating_add(closed.down_bytes);
                if closed.error.is_some() {
                    self.fail_count += 1;
                }
            }
        }
        while self.entries.len() > self.cap {
            let dropped = self.entries.pop_front();
            if dropped.is_some_and(|entry| !entry.closed) {
                self.open_count = self.open_count.saturating_sub(1);
            }
        }
    }

    /// Start a fresh native session: drop every row, zero every counter,
    /// keep the configured cap.
    ///
    /// The native session task is aborted on disconnect, so its final
    /// `Disconnected` can be lost; without an explicit reset the next
    /// session would render the previous one's rows and session totals.
    pub fn reset(&mut self) {
        self.entries.clear();
        self.total_up = 0;
        self.total_down = 0;
        self.open_count = 0;
        self.fail_count = 0;
    }

    /// Close out every still-open row: the session ended.
    ///
    /// A native shutdown can drop the in-flight `Closed` traces (the session
    /// task is aborted mid-copy), which would leave those connections
    /// rendered live forever. Byte totals stay as last observed — the close
    /// event that would have carried them never arrived.
    pub fn close_out_open(&mut self) {
        if self.open_count == 0 {
            return;
        }
        for entry in self.entries.iter_mut().filter(|entry| !entry.closed) {
            entry.closed = true;
        }
        self.open_count = 0;
    }
}

/// Top pane's tabs (spec D2): the table and the log viewer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pane1Tab {
    Profiles,
    Logs,
}

impl Pane1Tab {
    pub const ALL: &'static [Self] = &[Self::Profiles, Self::Logs];

    #[must_use]
    pub const fn next(self) -> Self {
        match self {
            Self::Profiles => Self::Logs,
            Self::Logs => Self::Profiles,
        }
    }

    #[must_use]
    pub const fn prev(self) -> Self {
        self.next()
    }
}

/// Bottom pane's tabs (spec D4): the actions log and the merged metrics view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pane2Tab {
    Details,
    Metrics,
}

impl Pane2Tab {
    pub const ALL: &'static [Self] = &[Self::Details, Self::Metrics];

    #[must_use]
    pub const fn next(self) -> Self {
        match self {
            Self::Details => Self::Metrics,
            Self::Metrics => Self::Details,
        }
    }

    #[must_use]
    pub const fn prev(self) -> Self {
        self.next()
    }
}

/// Which pane currently owns the keyboard (spec D2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FocusedPane {
    Pane1,
    Pane2,
}

impl FocusedPane {
    #[must_use]
    pub const fn other(self) -> Self {
        match self {
            Self::Pane1 => Self::Pane2,
            Self::Pane2 => Self::Pane1,
        }
    }
}

#[derive(Debug, Clone)]
pub struct LogLine {
    pub level: String,
    pub target: String,
    pub message: String,
    /// Session-only structured-field rendering. Rendered by the Logs panel and
    /// never persisted.
    pub detail: Option<String>,
    pub timestamp_nanos: i64,
}

/// Right pane content in the Settings split view.
#[derive(Debug, Clone)]
pub enum SplitRightPane {
    Form {
        section: SettingsSection,
        fields: Vec<(String, String)>,
        focus_index: usize,
        form_errors: HashMap<String, String>,
    },
    RoutingList {
        selected: usize,
    },
    RoutingForm {
        rule_id: Option<String>,
        fields: Vec<(String, String)>,
        focus_index: usize,
        form_errors: HashMap<String, String>,
    },
    UpdateForm {
        status_xray: BackendUpdateStatus,
        status_singbox: BackendUpdateStatus,
    },
    /// Group/subscription list shown in the settings Subscriptions section.
    GroupList {
        selected: usize,
        selected_mask: Vec<bool>,
    },
    /// Add/edit group form shown in the settings Subscriptions section.
    GroupForm {
        /// None = adding a new group; Some(gid) = editing an existing group.
        group_id: Option<String>,
        fields: Vec<(String, String)>,
        focus_index: usize,
        form_errors: HashMap<String, String>,
    },
}

/// Which pane has focus in the Settings split view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SplitFocus {
    Tree,
    Right,
}

/// Sub-modes for the Settings panel.
#[derive(Debug, Clone)]
pub enum SettingsMode {
    Split {
        focus: SplitFocus,
        right: SplitRightPane,
    },
}

/// The Settings section list (spec D2): a flat, filterable row list.
///
/// `selected` is an index into the `SETTINGS_TREE` leaves in document order,
/// so expansion and filtering never move the selection onto a different
/// section.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SectionList {
    /// Selected leaf, as a `SETTINGS_TREE` leaf index.
    pub selected: usize,
    /// Per-group expansion; a missing entry means expanded.
    pub expanded: Vec<bool>,
}

impl SectionList {
    /// A group is expanded unless it was explicitly collapsed.
    #[must_use]
    pub fn is_expanded(&self, group: usize) -> bool {
        self.expanded.get(group).copied().unwrap_or(true)
    }

    /// Toggle one group's expansion.
    pub fn toggle_expanded(&mut self, group: usize) {
        let current = self.is_expanded(group);
        if self.expanded.len() <= group {
            self.expanded.resize(group + 1, true);
        }
        self.expanded[group] = !current;
    }
}

/// The Settings search bar (spec D8): the query and whether the bar owns the
/// keyboard. Session-only; reset by `enter_settings`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SettingsSearch {
    pub query: String,
    pub active: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettingsSection {
    Core,
    Gui,
    Inbound,
    Routing,
    Dns,
    SystemProxy,
    Tun,
    Mux,
    Stats,
    ProtocolCore,
    Updates,
    SpeedTest,
    Logging,
    Subscriptions,
    RouteProbes,
}

impl std::fmt::Display for SettingsSection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Core => write!(f, "Core"),
            Self::Gui => write!(f, "GUI"),
            Self::Inbound => write!(f, "Inbound"),
            Self::Routing => write!(f, "Routing"),
            Self::Dns => write!(f, "DNS"),
            Self::SystemProxy => write!(f, "System Proxy"),
            Self::Tun => write!(f, "TUN"),
            Self::Mux => write!(f, "Mux"),
            Self::Stats => write!(f, "Statistics"),
            Self::ProtocolCore => write!(f, "Protocol Core"),
            Self::Updates => write!(f, "Updates"),
            Self::SpeedTest => write!(f, "Speed Test"),
            Self::Logging => write!(f, "Logging"),
            Self::Subscriptions => write!(f, "Subscriptions"),
            Self::RouteProbes => write!(f, "Route Probes"),
        }
    }
}

/// Enrichment data for one endpoint (inbound host), computed lazily in the
/// background by `ops::enrich`. Survives profile reloads (`AppState.endpoint_info`).
#[derive(Debug, Clone, Default)]
pub struct EndpointInfo {
    /// DNS resolution of the inbound host (or the host itself when it is an IP).
    pub resolved_ips: Vec<std::net::IpAddr>,
    /// ISO-3166 alpha-2 country of the inbound IP from mmdb; None = unknown/not found.
    pub country: Option<String>,
    /// ip/cidr whitelist membership of the resolved IP (IPv4-only).
    pub host_features: leas_host_features::HostFeatures,
    /// None = no SNI in config or checker not loaded.
    pub sni_whitelisted: Option<bool>,
    /// Exit IP parsed from real-ping `ip_info`.
    pub outbound_ip: Option<std::net::IpAddr>,
    /// ISO-3166 alpha-2 of `outbound_ip`.
    pub outbound_country: Option<String>,
    /// Unix secs of DNS resolution; None = IP host (static, never expires).
    pub resolved_at_secs: Option<i64>,
}

/// Tracks what the UI is currently showing.
#[derive(Debug, Clone)]
pub enum AppMode {
    /// The main profile list
    List,
    /// Help overlay
    Help,
    Settings {
        mode: SettingsMode,
    },
    /// Adding a new server
    AddServer {
        /// Selected protocol kind (None while protocol picker shown)
        protocol: Option<leas_proto::proto_spec::ProtocolKind>,
        /// Raw form field values: map of field key -> current input
        fields: Vec<(String, String)>,
        /// Index of the focused field
        focus_index: usize,
        /// Per-field validation errors
        form_errors: HashMap<String, String>,
    },
    EditServer {
        protocol_id: i64,
        /// The edited profile's protocol kind, captured when the form opened.
        /// The form re-derives its layout from this on every key; re-reading it
        /// from the database per keystroke was a round trip per key press.
        proto_kind: ProtocolKind,
        fields: Vec<(String, String)>,
        focus_index: usize,
        /// Per-field validation errors
        form_errors: HashMap<String, String>,
    },
    /// Import URL from paste
    ImportUrl {
        input: String,
        error: Option<String>,
    },
    /// Speed test menu overlay
    SpeedTestMenu {
        selected: usize,
    },
    ExportScope {
        selected: usize,
    },
    ExportDestination {
        scope: leas_db::export::ExportScope,
        selected: usize,
    },
    ExportPath {
        scope: leas_db::export::ExportScope,
        input: String,
        overwrite: bool,
        error: Option<String>,
    },
    /// Batch import multiple share URLs
    BatchImport {
        /// Parsed/split profiles for each URL
        results: Vec<BatchImportItem>,
        /// Current scroll position
        scroll: usize,
    },
    /// Target filter picker overlay for the logs tab.
    TargetPicker {
        selected: usize,
    },
}

/// A single item in a batch import list.
#[derive(Debug, Clone)]
pub struct BatchImportItem {
    pub url: String,
    pub profile: Option<ParsedProfile>,
    pub error: Option<String>,
    pub imported: bool,
}

/// Events from the core process manager to the UI event loop.
#[derive(Debug, Clone)]
pub enum CoreEvent {
    Connected(CoreType),
    Disconnected,
    Error(String),
    /// Non-fatal stats error — keeps `connected_core` intact
    StatsError(String),
    StatsUpdate {
        protocol_id: i64,
        today_up: i64,
        today_down: i64,
        total_up: i64,
        total_down: i64,
    },
    /// System stats update from gRPC.
    SysStatsUpdate(grpc_client::SysStats),
    /// A per-connection trace event from the in-process native core.
    NativeTrace(TraceEvent),
    /// A log line from the core process stderr.
    LogLine {
        level: String,
        target: String,
        message: String,
        timestamp_nanos: i64,
    },
    /// A log line from the TUI internals via tracing.
    ///
    /// `timestamp_nanos` is the EVENT time, not the time the UI task drained
    /// the channel. It has to be: this event and the heed poll are two
    /// deliveries of the same lines, reconciled by one watermark
    /// (`AppState::last_seen_log_ns`). A drain-time stamp runs AHEAD of the
    /// event times, so the poll would skip everything still in flight — the
    /// 2026-09-27 Windows dump shows that as lines out of order by up to 55
    /// seconds.
    ///
    /// `persisted` says whether this line's copy in the heed store is accounted
    /// for — true from the tracing layer and `log_trace`, which both write to
    /// it; false from `log_activity`, which is session-only by design. Only a
    /// `true` may advance the watermark: the poll reads the heed stream, so a
    /// session-only line moving it forward would step over every unread info+
    /// line behind it and lose them for good.
    TuiLog {
        target: String,
        level: String,
        message: String,
        /// Session-only rendering of every structured field the tracing layer
        /// captured, INCLUDING `db.params`. It deliberately does not go into
        /// `LogMessage`: bind values are application data and one of ours
        /// (`protocols.config`) carries credentials.
        detail: Option<String>,
        timestamp_nanos: i64,
        persisted: bool,
    },
    SubscriptionsUpdated {
        group_id: String,
        count: usize,
        error: Option<String>,
        summary: ValidationSummary,
    },
    /// Fresh profile rows computed OFF the UI task (a `SubscriptionsUpdated`
    /// reload at 10k+ endpoints takes seconds — awaiting it inline froze
    /// input/render after every update). `generation` must equal the request
    /// (`AppState::reload_gen`); a stale load superseded by a newer reload is
    /// dropped rather than clobbering fresher rows.
    ProfilesRowsReady {
        generation: u64,
        rows: Vec<EndpointRow>,
        /// Page position/count the rows belong to (footer + navigation).
        meta: leas_db::profiles_query::PageMeta,
    },
    /// The background retention pass reclaimed endpoints whose newest link
    /// aged past the retention window. The page the user is looking at may
    /// have lost rows, so it must be re-read (nothing else invalidates it:
    /// the purge runs off the event loop).
    RetentionPurged {
        count: usize,
    },
    /// Result from a speed test operation. `endpoint_id` + `protocol_id`
    /// together address exactly one `ProfileStats` row: protocol rows are
    /// shared across endpoints (identity dedup excludes host/port), so a
    /// protocol-only key would write the result onto the first endpoint that
    /// happens to own the protocol.
    SpeedTestResult {
        endpoint_id: i64,
        protocol_id: i64,
        test_type: TestType,
        latency_ms: Option<u64>,
        speed_bps: Option<u64>,
        ip_info: Option<String>,
        error: Option<String>,
        /// The purge verdict this failure earns, from the probe's typed
        /// evidence (`ops::purge::reason_for`). `None` for every path that did
        /// not classify one — including the batch, which stages its own result
        /// and never routes the verdict through this event.
        purge: Option<leas_db::models::PurgeReason>,
    },
    /// Result of a version check for a proxy backend.
    UpdateCheckResult {
        core_type: CoreType,
        current_version: Option<String>,
        latest_version: Option<String>,
        error: Option<String>,
    },
    /// Progress notification during update download.
    UpdateDownloadProgress {
        core_type: CoreType,
        downloaded: u64,
        total: u64,
    },
    /// Result of a download+install operation.
    UpdateCompleted {
        core_type: CoreType,
        old_version: Option<String>,
        new_version: String,
        success: bool,
        error: Option<String>,
    },
    /// Update the displayed test type for a profile without triggering cleanup.
    /// Used by `batch_then_real_ping` to switch from TcpPing→RealPing emoji.
    /// Endpoint-scoped for the same reason as `SpeedTestResult`: the protocol
    /// row is shared, the (endpoint, protocol) pair is the unique link.
    TestTypeUpdate {
        endpoint_id: i64,
        protocol_id: i64,
        test_type: TestType,
    },
    /// The batch's terminal signal: every probe has settled, the writer is
    /// flushed and the sweeps have run. Replaces the per-settle progress event
    /// (a feed-wide batch sent ~34k of them, and the shared `Arc<BatchMeters>`
    /// already publishes everything they carried).
    BatchEnded,
    ExportFinished {
        report: Option<crate::ops::export::ExportReport>,
        error: Option<String>,
    },
    /// Background whitelist files loaded; carries the ready checker.
    HostFeaturesLoaded(Arc<leas_host_features::HostFeaturesChecker>),
    /// Background enrichment (DNS resolve / geo lookup / whitelist / outbound)
    /// produced fresh data for one endpoint.
    EndpointInfoUpdated {
        endpoint_id: i64,
        info: EndpointInfo,
    },
    /// Resolve one DNS endpoint's inbound host, carrying the endpoint facts
    /// instead of an id to look up.
    ///
    /// The batch plans every endpoint in the feed but the UI holds only the
    /// loaded page, so a trigger that resolves "the endpoint by id" silently
    /// does nothing for every endpoint outside that page — which is how a
    /// feed-wide run left DNS hosts `[name]` while it persisted their exit IPs.
    /// The batch already has these facts (`PlanLink.endpoint`), so it sends them.
    DnsResolveRequest {
        endpoint_id: i64,
        host: String,
        host_type: HostType,
        /// The link's SNI, when the protocol row was loaded. `None` skips the
        /// SNI whitelist check for this pass (it is re-run on every launch).
        sni: Option<String>,
    },
    /// Native-core routing decision/probe event (surfaced in Actions Log).
    Route(leas_route::events::RouteEvent),
}

#[derive(Debug, Clone)]
pub enum ConfirmAction {
    DeleteProfile(i64),
    DeleteProfiles(Vec<i64>),
    DeleteGroup(String),
    ClearGroup(String),
    ClearLogs,
    PurgeLogsDatabase,
    ClearStats,
    Quit,
    /// Settings popup holds unsaved form edits; `y` discards them and closes.
    DiscardSettings,
}

/// Live meters for one probe level (fast or real): candidates known so far,
/// settles done, and a sampled rate for the remaining-time estimate.
///
/// `u32`, not `u16`: a batch plans every link in the feed, and a feed can exceed
/// 65,535 links. The fast level's `total` grows with the plan walk and the real
/// level's with the candidates that walk makes known — both can only grow, and
/// `done` counts items already in `total`.
#[derive(Debug, Default)]
pub struct PhaseMeters {
    pub total: AtomicU32,
    pub done: AtomicU32,
    /// results/s × 1000, sampled at most once per second by the batch task.
    /// 0 = no sample yet (the bar renders `--` rather than a wrong estimate).
    pub rate_milli: AtomicU32,
}

impl PhaseMeters {
    /// Remaining seconds at the sampled rate; `None` when the phase has no
    /// denominator yet, is complete, or has no rate sample.
    #[must_use]
    pub fn eta_secs(&self) -> Option<u64> {
        let total = self.total.load(std::sync::atomic::Ordering::Relaxed);
        let done = self.done.load(std::sync::atomic::Ordering::Relaxed);
        let rate = self.rate_milli.load(std::sync::atomic::Ordering::Relaxed);
        if total == 0 || done >= total || rate == 0 {
            return None;
        }
        Some(u64::from(total - done) * 1000 / u64::from(rate))
    }
}

/// Per-batch meters: the plan walk and the two probe levels.
///
/// Written by the batch task and read by the render path, which is why there is
/// no per-result progress event — a feed-wide batch sent ~34k of them, and each
/// described state this shared `Arc` already carries.
#[derive(Debug, Default)]
pub struct BatchMeters {
    /// Pages of the plan walk, for the "planning" state of the fast bar.
    pub plan_pages_done: AtomicU32,
    pub plan_pages_total: AtomicU32,
    pub fast: PhaseMeters,
    pub real: PhaseMeters,
}
