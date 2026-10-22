# leas Architecture

## Crate Dependency Graph

```
leas (bin)
  ├── leas-core     (Protocol, CoreType, resolve_core, config_builder, process, log_heed)
  │     └── leas-proto  (ProtocolConfig types, per-kind binary identity, URL parsing, Clash YAML)
  ├── leas-native   (in-process runtime backend — VLESS/VMess/Trojan/Hysteria2 tunnels, SOCKS5 + HTTP CONNECT inbounds, capability gate, telemetry)
  │     ├── leas-tls   (ring TLS 1.3 + TLS 1.2-fallback client, browser fingerprints, REALITY client)
  │     ├── leas-route (first-match routing engine for the local inbounds — TLS/HTTP/QUIC sniffing)
  │     └── leas-proto (typed ProtocolConfig/EndpointEssentials — config source of truth)
  ├── leas-db       (toasty ORM + direct Turso streaming export reader)
  ├── leas-config   (AppConfig load/save, import_export, forms, permissive_json)
  │     └── leas-proto  (ProtocolConfig types + EndpointEssentials for import/export round-trip)
  ├── leas-dns      (DNSCrypt-stamp DNS resolution — enrichment pipeline)
  ├── leas-geoip    (GeoLite2-City country/city lookup — enrichment pipeline)
  └── leas-host-features  (SNI/IP/CIDR whitelist membership — enrichment pipeline)
```

`leas → leas-native` is an unconditional path dependency (no feature
flag, `crates/leas/Cargo.toml`): the native core is a **runtime backend**
chosen per connect alongside the two subprocess backends, not a library-only
tunnel implementation. Nothing native is persisted — the decision is recomputed
on every connect (see "Data Flow: Connect to Proxy"), so no DB row, no
generated core config and no share link ever names it. Design brief:
`docs/architecture/native-core-integration.md`; per-protocol status: `docs/reference/native-core.md`.

	Build tooling: `leas-hakari` (crates/leas-hakari/) is a cargo-hakari
	generated feature-unification crate — every workspace member depends on it,
	its dependencies exist only to unify feature flags and are never referenced
	from code. Regenerate after any Cargo.lock change (`cargo hakari generate`).
	The `hakari-check` gate runs `cargo hakari generate --diff`,
	`cargo hakari manage-deps --dry-run` and `cargo hakari verify`;
	`--dry-run` is what catches a member missing the workspace-hack dependency,
	and `verify` alone does not.

## Crate Responsibilities

### leas (binary crate)

Entry point at `crates/leas/src/main.rs`. Creates the tokio async runtime, initializes all subsystems, enters the ratatui event loop.
### Whole-database export

`leas-db/src/export.rs` owns the file-backed direct Turso read path. Toasty 0.11 public/raw APIs buffer values, so export opens a fresh dedicated Turso connection, applies the existing WAL/MVCC journal-mode authority, begins the matching read transaction, and drains ordered rows before commit/rollback. `leas/src/ops/export.rs` owns scope policy, Resolved host transformation, and bounded clipboard/file sinks; `ui/export.rs` owns popup interaction. Export never uses a second fallback serializer.

The clipboard sink is not a direct `arboard` call. `arboard::Clipboard` on Linux *is* the X11 selection owner, so `ops/clipboard.rs` keeps one process-lifetime handle (`LazyLock<Mutex<Option<Clipboard>>>`) and every copy/paste site goes through it — export, the three logs-copy paths, and the paste/copy-URL keys. A per-call handle destroys the serving window in `Drop`, leaving the payload readable only if a clipboard manager wins a 100 ms handover race; without one (headless, SSH, bare X) the app logs a successful export and the clipboard never changes.

**Shared state** (`crates/leas/src/state.rs`):

```rust
pub struct AppState {
    pub db: Arc<Database>,
    pub config: AppConfig,
    /// Currently selected theme name.
    pub theme_name: ratatui_themes::ThemeName,
    pub current_tab: Tab,
    pub endpoints: Vec<EndpointRow>,
    pub cached_filtered_indices: RefCell<Vec<usize>>,
    pub filter_cache_valid: Cell<bool>,
    pub endpoints_gen: u64,
    pub groups: Vec<Group>,
    pub purgatory_view: PurgatoryView,
    pub purgatory_ttl_secs: i64,
    pub purgatory_retention_secs: i64,
    pub selected_index: usize,
    pub selected_sub: Option<usize>,
    pub log_scroll: usize,
    pub log_select_anchor: Option<usize>,
    pub sort_column: SortColumn,
    pub sort_ascending: bool,
    pub search_query: String,
    pub search_focused: bool,
    pub connected_core: Option<CoreType>,
    pub connecting: bool,
    pub system_stats: Option<grpc_client::SysStats>,
    pub native_activity: NativeActivityLog, // session-scoped native trace ring (2000 rows)
    pub log_cache: VecDeque<LogLine>,
    pub log_has_older: bool,
    pub log_seek_home: bool,
    pub connection_error: Option<String>,
    pub core_event_rx: Option<mpsc::Receiver<CoreEvent>>,
    pub core_event_tx: Option<mpsc::Sender<CoreEvent>>,
    pub disconnect_tx: Option<tokio::sync::oneshot::Sender<()>>,
    pub should_quit: bool,
    pub mode: AppMode,
    pub previous_mode: Option<Box<AppMode>>,
    pub multi_select: HashSet<i64>,
    pub clipboard: Option<String>,
    pub confirmation: Option<ConfirmAction>,
    pub updating_groups: HashSet<String>,
    pub testing_profiles: HashSet<i64>,
    pub testing_details: HashMap<i64, TestType>,
    pub update_status: HashMap<CoreType, BackendUpdateStatus>,
    pub actions_compact: bool,
    pub connected_protocol_id: Option<i64>,
    pub speed_test_stop: Arc<AtomicBool>,
    pub last_test_tcp: Option<u64>,
    pub batch_progress: Option<Arc<(AtomicU16, AtomicU16)>>,
    pub last_test_real: Option<u64>,
    pub last_test_speed: Option<u64>,
    pub current_traffic_up: i64,
    pub current_traffic_down: i64,
    pub current_memory: u64,
    pub term_height: Cell<u16>,
    pub routing_rules: Vec<RoutingRule>,
    pub geo_ip: Option<Arc<leas_geoip::GeoIp>>,
    pub dns_resolver: Option<Arc<leas_dns::DnsResolver>>,
    pub host_features: Option<Arc<leas_host_features::HostFeaturesChecker>>,
    pub endpoint_info: HashMap<i64, EndpointInfo>, // enrichment cache, survives reload_profiles
    pub ping_status: HashMap<i64, EndpointPingStatus>, // per-endpoint ping rounds (fast/real), session-only; drives Test column [fast]/[real] labels
    pub dns_cache_ttl_secs: i64,                   // TTL for DNS-resolution cache; default 300
    pub shutdown_token: Arc<AtomicBool>,
    pub core_task_handle: Option<JoinHandle<()>>, // running session task; disconnect() swaps in a bounded teardown waiter
    pub heed_storage: Option<Arc<HeedLogStorage>>,
    pub last_seen_log_ns: u64,
    pub known_targets: Vec<String>,
    pub selected_targets: Vec<String>,
    pub last_heed_poll: std::time::Instant,
    pub log_sender_tx: Option<std::sync::mpsc::Sender<leas_core::log_heed::LogMessage>>,
    pub logs_loaded: bool,
}

### CoreEvent Channel

```rust
pub enum CoreEvent {
    Connected(CoreType),
    Disconnected,
    Error(String),
    StatsError(String),
    StatsUpdate {
        protocol_id: i64,
        today_up: i64,
        today_down: i64,
        total_up: i64,
        total_down: i64,
    },
    SysStatsUpdate(grpc_client::SysStats),
    NativeTrace(leas_native::telemetry::TraceEvent),
    /// Resolve one DNS endpoint's inbound host. The batch sends this for the DNS
    /// endpoints it plans, carrying the endpoint facts (host/host_type/sni)
    /// because the handler can only look an endpoint up in the LOADED PAGE.
    DnsResolveRequest {
        endpoint_id: i64,
        host: String,
        host_type: HostType,
        sni: Option<String>,
    },
    LogLine {
        level: String,
        target: String,
        message: String,
        timestamp_nanos: i64,
    },
    TuiLog {
        target: String,
        level: String,
        message: String,
    },
    SubscriptionsUpdated {
        group_id: String,
        count: usize,
        error: Option<String>,
        summary: ValidationSummary,
    },
    SpeedTestResult {
        protocol_id: i64,
        test_type: TestType,
        latency_ms: Option<u64>,
        speed_bps: Option<u64>,
        ip_info: Option<String>,
        error: Option<String>,
    },
    TestTypeUpdate {
        protocol_id: i64,
        test_type: TestType,
    },
    UpdateCheckResult {
        core_type: CoreType,
        current_version: Option<String>,
        latest_version: Option<String>,
        error: Option<String>,
    },
    UpdateDownloadProgress {
        core_type: CoreType,
        downloaded: u64,
        total: u64,
    },
    UpdateCompleted {
        core_type: CoreType,
        old_version: Option<String>,
        new_version: Option<String>,
        success: bool,
        error: Option<String>,
    },
    HostFeaturesLoaded(Arc<leas_host_features::HostFeaturesChecker>),
    EndpointInfoUpdated {
        endpoint_id: i64,
        info: EndpointInfo,
    },
}
spawned `CoreManager` task and the TUI event loop. `poll_core_events()` is called each frame,
draining pending events and updating `AppState` fields (`connected_core`, `connecting`, `connection_error`).
The `disconnect_tx` oneshot channel signals the running core task to stop gracefully.

Methods previously in `lib.rs` extracted to `ops/` modules:
- `ops/connect.rs` — connect_to_profile, disconnect, `resolve_runtime_core` (per-connect native-vs-subprocess decision)
- `ops/native_connect.rs` — `run_native_session`: the in-process arm of connect_to_profile (binds the native server, forwards its telemetry as `CoreEvent`s, graceful `shutdown().await`)
- `ops/ping.rs` — start_batch_ping, start_batch_then_real_ping, stop_speed_test
- `ops/events.rs` — poll_core_events
- `ops/subscriptions.rs` — update_group_subscriptions, do_update_subscription
- `ops/updates.rs` — spawn_update_check, spawn_update_download
- `ops/settings.rs` — confirm_add_server, confirm_edit_server
- `ops/profiles.rs` — delete_profile, clone_profile, import_url, nav_protocol_up/down, toggle_expand, set_active, set_protocol_default (DB override write + in-memory row patch — `endpoints_gen` is write-only, rows only reload on subscription events)
- `ops/enrich.rs` — background enrichment: spawn_dns_resolve (TTL-gated, `x` force), spawn_enrich_ip_hosts (startup seed), spawn_whitelist_pass (on HostFeaturesLoaded), spawn_outbound_enrich (real-ping exit IP), extract_sni, protocol_row_to_profile; `ResolveTrigger` (Routine/Maintenance/Forced) picks the TTL gate, RESOLVE_SEM permit, and per-host waiter dedup
- `ops/compact.rs` — maintenance commands (Speed Test menu): Mass DNS retry (`spawn_dns_retry` — re-resolves every DNS host with an empty address set, TTL bypassed, permit-bounded; lookups dispatch on the loop from `CoreEvent::DnsRetryTargets`) and Smart Endpoints Compact (`spawn_compact` — merges provably-same-server endpoints: same port + shared protocol_id + `endpoint_ip` overlap, connected components, survivor law in `leas-db/src/merge.rs`). Both run off the event loop; progress via `AppState::maint_progress` (`MaintMeters`: status bar + Actions-Log bars, labels `Name`/`Comp`); reports through `CoreEvent::CompactFinished`/`MaintenanceDone`. Before any endpoint delete it flushes and drains `LinkSpec` + `CountrySpec` staged patches for the absorbed ids (no FKs — a stale patch re-creates an orphan row)

**TUI Screens (modules under `crates/leas/src/ui/`):**

- `profiles.rs` — 16-column endpoint rows (tree marker, indicator, #, `[flag address:port][feat]=>{protocol/transport/security}=>[ 12 ][outbound country]` — no endpoint-level Type; the protocol kind lives in the panel's Protocol Type column and inside the Protocol Info cell) over a sortable DataTable. The Test column (`[ 12 ]` etc.) describes the endpoint's REPRESENTATIVE link (`EndpointRow::representative_link_index` — the argmin of the decision-16 key, the same link `compute_rank` stores `rank_tier` from), so its content IS the row's tier band: tier 0/1 → that link's delay colored by threshold (green <500ms, yellow ≥500ms, red ≥1000ms), 2 → blank, 3/4 → `[real]`/`[fast]` (a marker on the representative link outranks its own stored delay), 5 → `[name]`, 6 → the purge label. It does not follow `selected_protocol`/`manual_protocol_override` and reads no session round — the labels come from the persisted `error_kind`. It sits after the `}=>` arrow, before Outbound's `[` bracket. Expanding an endpoint renders a rounded panel in the row's own height (IPs line + 11-col per-protocol sub-table: marker, hex id, last seen, last used, protocol type, config type, delay, speed, traffic, outbound, country; capped at 8 visible sub-rows and window-scrolled (the window follows the selected variant, the separator carries the `n-m/total` range). Sub-table rows sorted by test priority (real-ok > fast/udp-ok > untested > real-err > fast-err > DNS-unresolved; latency only within success tiers)); the selected sub-row renders as a REVERSE highlight (`ThemeStyles::panel_row_selected`: fg foreground + `bg Color::Reset` + bold — drops the panel's `surface` highlight back to the common background; explicit Reset bg required because ratatui `Cell::set_style` merges). Height-aware scroll offset (`compute_scroll_offset`) keeps expanded rows reachable; `panel_w` is viewport-capped so narrow terminals don't panic. Footer/overlays use `host:port` (remarks r…
  The scrollbar spans the SQL-filtered feed: `page_total` sizes the thumb, and `page_offset + first_visible_row` positions it; expanded panels still use a row-index local offset.
- `settings.rs` — Split-pane settings panel. Left: collapsible tree (SPLIT_SETTINGS_TREE) navigating by SettingsSection. Right: Form (SplitRightPane::Form), UpdateForm, GroupList, or GroupForm. 14 sections: Core, GUI, Protocol Core, Inbound, Routing Rules, DNS, System Proxy, TUN, Mux/Fragment, Statistics, Updates, Speed Test, Logging, Subscriptions. Ctrl+W switches focus between tree and form panels. Routes/DNS persist to DB; all others to AppConfig JSON. Replaced per-section SettingsMode variants with unified Split { tree, focus, right } architecture. Subscription-group management lives here (`g` from Profiles jumps to the Subscriptions section).
- `logs.rs` — Log viewer with source filtering (c/t toggles for core/TUI logs, v toggles validation/subscription logs)
- `native_activity.rs` — Native Activity tab (`Tab::NativeActivity`): session totals plus one line per traced native-core connection from `AppState.native_activity`. Window-then-format render (only the visible slice of the ring is turned into `Line`s), scroll offset in a module-level atomic clamped to the ring length every frame, `reset_scroll()` on each new native session; Up/Down/PageUp/PageDown/Home/End only.
- `actions_log.rs` — Live event log panel showing connection status, speed test results, core/TUI/app logs, traffic counters with color-coded levels. F1 toggles compact/full modes; auto-compacts on small terminals (<20 rows).
- `theme.rs` — ThemeStyles struct with static methods returning Style from a &Palette (container_border, container_title, hint, warning, error, success, tab_selected, etc.)
- `palette_bridge.rs` — Maps ratatui-themes ThemePalette (10 colors) to ratatui-cheese Palette (11 roles)
- `widgets/data_table.rs` — Reusable DataTable widget: sortable columns, multi-select, virtual-scrolled with themed scrollbar, DataTableRow trait (render takes `clip_bottom` so tall rows clip instead of overflowing)

**`speed_test.rs`** — Async speed test engine:
```rust
pub enum TestType { TcpPing, RealPing, SpeedTest, UdpTest }
pub struct RealPingResult { pub latency_ms: u64, pub ip_info: Option<String> }
pub enum SpeedTestError { Io, Timeout, Proxy, Http, InvalidAddress }
pub async fn tcp_ping(addr: &str, port: u16, test_timeout: Duration) -> Result<Duration, SpeedTestError>;
pub async fn real_ping(proxy: &str, port: u16, url: &str, retries: u32, test_timeout: Duration) -> Result<RealPingResult, SpeedTestError>;
pub async fn speed_test(proxy: &str, port: u16, url: &str, min_duration: Duration, max_duration: Duration) -> Result<u64, SpeedTestError>;
pub async fn udp_test(proxy: &str, port: u16, test_timeout: Duration) -> Result<Duration, SpeedTestError>;
```
tcp_ping connects directly to the target address. real_ping, speed_test, and udp_test route through the active SOCKS5 proxy.
`real_ping` sends up to `retries` HTTP GETs through SOCKS5, takes the fastest 2xx response, and optionally
fetches IP info (ISP/location) from the selected `IpProvider` through the same proxy (its URL first, then the remaining family-agnostic providers as an automatic fallback chain; retried once per provider, spaced 250 ms; the default provider is ip-api's working free endpoint — its HTTPS form answers 403 on the free tier, which made every real OK persist no exit IP). Returns `RealPingResult`
with both latency and IP metadata.
Results are sent via CoreEvent::SpeedTestResult (with optional `ip_info` field) and handled in poll_core_events(),
which writes the link's typed columns (`latency` — the Real/Fast variant carrying `latency_ip` — plus `error`/`error_kind`) in memory and stages them through `LinkWriter` (error events keep any stored measurement and set only the marker), then — for a result whose row is on the loaded PAGE — re-sorts the owning endpoint's
protocols by test priority (TcpPing/RealPing results; `selected_sub` remapped by protocol id) and invalidates
the main-table sort cache. While a batch runs the invalidation is throttled to one refetch per
`RESULT_RELOAD_THROTTLE` (500 ms, `ops/events.rs`) and `CoreEvent::BatchEnded` forces the final one: the
refetch is one `profiles_page` + `load_page_projection` on the UI task (22–25 ms against a 16 ms tick on the
7,486-endpoint reference feed), and a feed-wide run's results are ~98% off-page (ADR 0008 §3).

**Fast Test (start_batch_ping)**: the transport measurement on its own. Uses `FastPingManager` to dispatch to the appropriate adapter (TCP, UDP, or QUIC) based on protocol. TcpPingAdapter supports all TCP-based protocols; UdpPingAdapter supports WireGuard and ShadowsocksR; QuicPingAdapter (optional feature) supports QUIC-enabled protocols. Falls through to RealPingManager for protocols without a matching adapter. The Fast Test pings a page concurrently via `run_page_pings` — ONE TCP ping per unique (address, port) in the page (`buffer_unordered`), in-page owner/follower dedup plus a cross-page `fast_cache` keyed by (address, port). It takes no semaphore permit of its own: the fast half is a TCP handshake, and the one limit that matters (`real_ping_concurrency`) bounds the native handshakes. Fast ping probes inbound reachability only (every protocol of an endpoint shares its address:port), so results are all-or-none per endpoint: inbound unreachable → all protocols fast-fail (`[fast]` label), reachable → all fast-succeed and become real-ping candidates. Progress is a shared `Arc<BatchMeters>` (walk page count + two level meters); the per-(protocol, endpoint) task gate is `ops/scheduler.rs::TaskScheduler`. Supports cancellation via the `speed_test_stop` flag.

**Real Test (start_batch_then_real_ping)**: ONE probe per link on the `TaskScheduler` — the merged pipeline (spec `2026-10-21-merged-test-pipeline-design`). The probe has TWO stages with INDEPENDENT budgets: the TRANSPORT stage is the dial alone (bounded by `tcp_timeout_secs`) and its span is the Fast metric; the PROTOCOL + PROBE stage runs the security handshake, the transport upgrade, the protocol handshake, the target TLS and the request (bounded by `real_ping_timeout_secs`). There is no separate TCP ping in a real-phase batch — the probe's transport stage IS that measurement, so a link costs ONE connection instead of two.

The transport span rides on the FAILURE too (`probe::ProbeError`), so a row whose server answered but whose config did not reports the transport span beside its failure marker. Whether the transport itself failed is an explicit flag (`ProbeFailure::transport_failed`), never the class: the stage-1 and the stage-2+ deadlines share the class `Timeout`, and a class test would retire a working server whose protocol stage merely hung. A transport failure retires the row (the endpoint's other links are skipped) and writes the `[fast]` marker — not a config verdict.

The GROUP-ENTRY barrier (`ops/ping.rs`): the walk's order is unchanged (`PageSort::Test`) and an endpoint's links are CONTIGUOUS in it, so the group's first protocol is dispatched and its siblings wait for that verdict — dropped when the endpoint succeeded, released when it did not. There is no second barrier check and no cancel-on-winner: a sibling in flight completes and records its full result. The barrier is a plain `HashMap` (no bloom filter: the set is tiny and a membership test must be exact). Results are staged write-behind (`LinkWriter`, decision 22), and every result event is keyed by `(endpoint_id, protocol_id)`.

**Test-priority sorting**: One comparator drives both the expandable sub-table order and the main-table Test column sort, defined in the db crate (owns `EndpointRow`):

- `EndpointRow::sort_links_by_test_priority(dns_unresolved)` — re-sorts the row's links in place. Ascending key `(tier, latency, -last_seen_at, id)`: tier 0 real-ok (a `latency_real_delay`), 1 fast/udp-ok (a `latency_fast_delay`), 2 untested, 3 real/name-err, 4 fast-err, 5 DNS-unresolved (a `dns` host with no `endpoint_ip` row — `dns_unresolved_endpoint(host_type, has_address)`), 6 purged. Fresh failures dominate stored successes (the marker is checked before the stored delay). Latency only orders tiers 0-1.
- `EndpointRow::best_test_priority_key(...)` — min protocol key; the main-table sort representative (best protocol, user decision).
- `EndpointRow::representative_link_index(...)` — the argmin's INDEX, the link the Test cell renders, so the cell and the row's tier band cannot disagree.
- The batch's `PlanScope` (`All` / `Successful` / `SuccessfulAndNew` / `Failed`) is a predicate over the endpoint's stored `rank_tier` in `profiles_query::base_from_where` (bound; shared by the page, the walk and the count). Because `rank_tier` is derived state the batch itself mutates, a SCOPED walk reads its endpoint ids ONCE before the first probe (`PlanWalk::Feed.frozen`) and serves pages from that list; `All` streams page by page in `PageSort::Id` order — endpoint ids, which no write can move, and 3.0 ms per page against 12.1 ms for the host order the walk used before (ADR 0008 §1).
- Runs at DB load (`load_page_projection` / the typed `load_page_rows`, rounds = None, the DNS tier read from the endpoint's empty address set), live in `poll_core_events` (`SpeedTestResult` for TcpPing/RealPing success or failure; `EndpointInfoUpdated` on unresolved→resolved flip), and — for the tab itself — in SQL: ordering is the page query's job (`PageSort`, the sort cycle's `SortColumn::Test` maps to it), with this comparator kept as the oracle the SQL order is pinned against (`page_order_matches_the_rust_oracle_for_every_sort`). `endpoint_dns_unresolved` in `ops/profiles.rs` delegates to `endpoint_rank::dns_unresolved`.
- Provenance: the link's own `profile_stats` columns — `latency_real_delay` / `latency_fast_delay` / `latency_ip` / `latency_auth` (a struct embed; the `latency` discriminator column was DROPPED in schema 19), and the failure marker `error` + `error_kind` + `error_text` (kind `real`/`fast`/`name`). A row's provenance is carried by WHICH delay column is populated: a real delay outranks a fast one of any delay. Writers: the `SpeedTestResult` handler and the batch (one shared mapping, `ops::events::apply_test_result`), staged through `LinkWriter` (decision 22).
- Invariant: **error events mutate nothing** — the `SpeedTestResult` handler gates the whole ext mutation + upsert behind `error.is_none()`, so a cancelled/failed test can never rank an untested protocol as real-ok or write a `delay = 0` row.

**Stop testing**: `speed_test_stop: Arc<AtomicBool>` on AppState. Set via menu ("Stop Testing" at index 10)
or hotkey `'s'`. Auto-resets when `testing_profiles` empties. `tested_pids`/`tcp_completed` sets prevent
double-emission of "Cancelled" for already-tested profiles. Status bar shows "■ Stopping..." in red while
stop flag is active. Stopped sessions emit `error: "Cancelled"`, which the `SpeedTestResult` handler does
not count as a round failure — stopping a batch never paints spurious `[fast]`/`[real]` labels.

**Configuration**: SpeedTestConfig in `AppConfig` includes `real_ping_concurrency` (default 100) and
`real_ping_test_all_protocols` (default false = skip remaining protocols of an endpoint after one succeeds),
editable via Settings > Speed Test form. `fast_ping_concurrency` is RETIRED (spec D14): the one limit
that matters is the one that bounds native handshakes, and the fast half (a TCP handshake) takes no permit
of its own.

### leas-core (library crate)

`crates/leas-core/src/lib.rs` — Facade + re-exports. Modules:

---

**`core_type.rs`** — Core type definitions
```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CoreType {
    Xray,
    SingBox,
    Auto,
    Native,   // runtime-only: the in-process core. Never persisted, never in a core config.
}
```
`Display`/`as_str`/`FromStr` round-trip `Native` as `"native"`, so a
`protocol_core_overrides` entry can ask for it. This is the RUNTIME enum; the
persisted stamp is `leas_proto::proto_spec::CoreType`, which stays
`{Xray, SingBox}` — `resolve_core` still returns only those two. The split is
load-bearing: the persisted enum is rendered by toasty as
`TEXT ... CHECK ("core_type" IN ('xray','sing_box'))` frozen into every existing
DB (a `PRAGMA user_version` mismatch makes `Database::open` delete the file, it
is not a migration), and `core_type` is part of the identity-hashed
`ProtocolEssentials`, so a third persisted value would re-key every
`ProtocolId`.

**`process.rs`** — Dual-backend subprocess lifecycle
```rust
pub struct CoreProcess {
    child: Option<Child>,
    config_path: PathBuf,
    pub core_type: CoreType,
}

/// Abstract interface for core process lifecycle.
#[async_trait]
pub trait CoreManager: Send + Sync {
    async fn start(
        &mut self,
        core_type: CoreType,
        config: &BackendConfig,
        binary_path: &Path,
        clash_mixin: Option<&serde_json::Value>,
    ) -> Result<(), ProcessError>;
    async fn stop(&mut self) -> Result<(), ProcessError>;
    fn is_running(&self) -> bool;
    fn running_core_type(&self) -> Option<CoreType>;
    fn sighup_reload(&self) -> Result<u32, ProcessError>;
    async fn rewrite_config(&self, config: &BackendConfig, clash_mixin: Option<&serde_json::Value>) -> Result<(), ProcessError>;
}

/// Real subprocess-backed implementation. `log_tx: Sender<String>` is required —
/// callers without a log consumer must pass a drained channel.
pub struct RealCoreManager {
    current: Option<CoreProcess>,
    config_dir: tempfile::TempDir,
    log_tx: Sender<String>,
}

/// Test double implementing the same trait (Option<String> error fields).
pub struct MockCoreManager { /* start_error, stop_error, is_running, ... */ }
```

`CoreManager::start` flow:
1. Resolve core binary path via `find_binary()`
2. Build config via `ConfigBuilder::build()`
3. Write JSON config to temp file in config_dir
4. Spawn `xray run -c <path>` or `sing-box run -c <path>`
8. Poll for readiness (check process hasn't exited early, max 10s)
9. Send `CoreEvent::Connected` on the event channel
10. Create `StatsProvider` via `grpc_client::create_stats_provider(core_type)`
11. Enter stats polling + wait loop: every 3s call `provider.query_stats()` for traffic deltas;
    every 3rd tick (~9s) also call `provider.get_sys_stats()`. Send `StatsUpdate`/`SysStatsUpdate`
    events. Loop exits when `stop_rx` receives the disconnect signal.
12. Kill child process + remove config file
13. Send `CoreEvent::Disconnected`


**`bin_manager.rs`** — Binary discovery and archive extraction
```rust
pub struct CoreBinInfo {
    pub exe_names: &'static [&'static str],
    pub args_template: &'static str,
}

pub fn find_binary(core_type: CoreType, bin_dir: &Path) -> Option<PathBuf>;
pub const fn get_core_info(core_type: CoreType) -> Option<CoreBinInfo>;
pub fn exe_names(core_type: CoreType) -> Option<Vec<String>>;
pub fn find_and_extract_archives(bin_dir: &Path) -> Result<(), BinError>;
```
`find_binary` checks `bin_dir`/`core_type` first (managed install), then falls back
to the platform's PATH lookup (`where` on Windows, `which` elsewhere).
`get_core_info` returns the extensionless base names (xray: `["xray"]`; sing-box:
`["sing-box-client", "sing-box"]`); `exe_names` appends the platform's
`EXE_SUFFIX` and is the single owner of that spelling (`xray.exe` on Windows),
used by `find_binary` and by `updater`'s post-extraction search. `Auto` and
`Native` have no binary: `get_core_info` answers `None` and every `updater.rs`
entry point (`get_current_version`, `get_latest_version`, `release_asset_url`,
`install_binary`) refuses them — the in-process core is built into the binary, so
there is nothing to discover, download or update. `find_and_extract_archives`
extracts upstream archives dropped into the working directory, recognising the
platform-specific packagings (`Xray-<os>-<arch>.zip`, and for sing-box
`-linux-<arch>.tar.gz` or `-windows-<arch>.zip`); it has no in-tree caller today.

---

**`config_builder/`** — Config builder module
- `mod.rs` — Dispatches to xray or sing-box builder based on core type
- `xray.rs` — Builds xray-core format JSON. Validates emitted stream settings:
  `security: "reality"` requires `realitySettings.publicKey` + `serverName` —
  legacy VLESS blobs with `security=reality` and no realitySettings previously
  killed the core at startup (`REALITY: Empty "realitySettings"`). Shadowsocks
  methods are validated against `XRAY_SS_METHODS`.
- `singbox.rs` — Builds sing-box format JSON. Reality emits only
  `enabled`/`public_key`/`short_id` (sing-box's `OutboundRealityOptions` has no
  `spider_x`; the URL's `spx` is dropped).


pub enum BackendConfig {
    Xray(XrayConfig),
    SingBox(SingBoxConfig),
}

pub struct BuildParams {
    log_level: String,
    socks_port: u16,
    http_port: Option<u16>,
    listen: String,
    sniffing: bool,
}

pub struct ConfigBuilder;
impl ConfigBuilder {
    pub fn build(
        profile: &Profile,
        core_type: CoreType,
        params: &BuildParams,
        routing: &[RoutingRule],
        dns: &DnsSetting,
    ) -> Result<BackendConfig, BuildError>;
}
  "inbounds": [
    { "tag": "socks-in", "protocol": "socks", "listen": "127.0.0.1", "port": 10808 },
    { "tag": "api", "protocol": "dokodemo-door", "listen": "127.0.0.1", "port": 62789 }
  ],
  "outbounds": [
    { "tag": "proxy", "protocol": "vmess", "settings": { ... },
      "streamSettings": { ... }, "mux": { ... } },
    { "tag": "direct", "protocol": "freedom" },
    { "tag": "block", "protocol": "blackhole" }
  ],
  "routing": {
    "domainStrategy": "AsIs",
    "rules": [...],
    "balancers": [...]
  },
  "dns": { "servers": [...], "hosts": {...} },
  "stats": {},
  "api": { "tag": "api", "services": ["HandlerService", "LoggerService", "StatsService"] },
  "policy": {
    "levels": { "0": { "statsUserUplink": true, "statsUserDownlink": true } },
    "system": { "statsInboundUplink": true, "statsOutboundUplink": true }
  }
}
```

**Config builder — singbox.rs** produces the sing-box JSON format:
```json
{
  "log": { "level": "warn" },
  "dns": { ... },
  "inbounds": [{ "tag": "socks-in", "type": "socks", ... }],
  "outbounds": [
    { "tag": "proxy", "type": "tuic", "server": "...", "server_port": ...,
      "tls": { "enabled": true, ... } },
    { "tag": "direct", "type": "direct" },
    { "tag": "block", "type": "block" }
  ],
  "route": {
    "rules": [...],
    "final": "proxy"
  },
  "experimental": {
    "v2ray_api": {
      "listen": "127.0.0.1:62789",
      "stats": { "enabled": true, "outbounds": ["proxy", "direct"] }
    }
  }
}
```

Key differences from xray-core JSON:
- Protocol `type` field instead of `protocol` in xray-core outbound/inbound entries
- `route` key instead of `routing`
- `experimental.v2ray_api` block for stats (vs xray-core's `stats` + `api` + `policy`)
- Transport/TLS config differs: sing-box uses per-protocol `tls` sub-key vs xray-core's `streamSettings.security`
- No separate `policy` section (stats config lives under `experimental.v2ray_api`)

**`config_builder/clash_mixin.rs`** — Clash YAML overlay injection
```rust
pub fn parse_clash_mixin(path: &str) -> Result<serde_json::Value, MixinError>;
pub fn merge_mixin(config: &mut serde_json::Value, mixin: &serde_json::Value);
```
Reads Clash-compatible YAML, parses to JSON, and merges into sing-box config before writing. Supports JSON and YAML input formats (auto-detected by extension). 5 unit tests.

---

**`protocol_core_mapping.rs`** — Protocol → Core auto-resolution
```rust
pub const XRAY_SS_METHODS: &[&str];      // AEAD + 2022-blake3 + aead_* aliases
pub const SINGBOX_SS_METHODS: &[&str];  // modern + legacy (cfb/ctr/rc4-md5/none/...)
fn resolve_core(protocol, profile_override: Option<CoreType>, ss_method: Option<&str>) -> CoreType {
    match profile_override {
        Some(CoreType::Auto) | None => core_for_protocol(protocol, ss_method),
        Some(core_type) => core_type,   // forced override wins; builders validate
    }
```
Shadowsocks/Shadowsocks-2022 resolution is cipher-aware: xray-core's `CipherType` enum
covers only AEAD + 2022-blake3, so legacy ciphers (`aes-*-cfb`, `aes-*-ctr`, `rc4-md5`,
`chacha20-ietf`, `xchacha20`, `none`) auto-route to sing-box. Both config builders
validate the method against their whitelist and return `BuildError::InvalidProfile`
for ciphers neither core supports — an invalid config is never written. `ss_method`
is extracted from the profile row via `config_builder::shadowsocks_method`.
**`grpc_client.rs`** — gRPC StatsService abstraction

Proto definition in `crates/leas-core/proto/stats.proto` (vendored sing-box stats proto), compiled
via `build.rs` using `tonic_build`. Package `experimental.v2rayapi`, 3 RPCs: `GetStats`, `QueryStats`,
`GetSysStats`.

```rust
pub const API_ENDPOINT: &str = "http://127.0.0.1:62789";

#[async_trait]
pub trait StatsProvider: Send + Sync {
    async fn query_stats(&self, pattern: &str, reset: bool) -> Result<Vec<Stat>, GrpcError>;
    async fn get_sys_stats(&self) -> Result<SysStats, GrpcError>;
    fn api_endpoint(&self) -> &str;
}
```

Two implementations — `XrayGrpcClient` and `SingBoxGrpcClient` — both connect to the same endpoint
(`127.0.0.1:62789`) and use the same `StatsServiceClient<Channel>`. They are separate types for
type-level distinction only; both backends expose the same V2Ray-compatible gRPC API.

Factory function:
```rust
pub async fn create_stats_provider(core_type: CoreType) -> Result<Box<dyn StatsProvider>, GrpcError>
```

Helpers: `format_bytes(i64) -> String`, `format_uptime(u32) -> String`.


**`updater.rs`** — Backend binary auto-update
Functions: `get_current_version()` (run `{core} version`, parse output), `get_latest_version()` (GitHub releases API), `download_release()` (streaming download via reqwest, progress tracking), `install_binary()` (extract archive → verify binary runs → .bak existing → copy all files → remove .bak on success, restore from .bak on failure).

**`speedtest.rs`** — Speed testing logic (same as single-core design)

**`import_export.rs`** — Share URL parsing and config export
```rust
pub fn parse_share_url(url: &str) -> Result<Profile>;
pub fn format_share_url(profile: &Profile) -> String;
pub fn export_client_config(profile: &Profile) -> Result<String>;
```
Ports format parsing from v2rayN's `Handler/Fmt/*.cs` files plus sing-box URI formats.

---

### leas-config (library crate)

`crates/leas-config/src/lib.rs` — configuration and parsing: `AppConfig`
load/save (serde JSON on disk), `import_export` (share-URL parse/export, per-batch
`ValidationSummary`), `forms`, `permissive_json`, `duration_or_secs`, `base64_util`.
It owns the URL-parsing half of the import path; the DB half is `leas-db`.

**`subscription.rs`** — subscription decoding: `StreamingDecoder` (bytes →
base64|raw → lines → share URLs) feeding `subscription_url_chunks` /
`parse_subscription_data` / `parse_url_batch`.

The decoding pipeline is **chunking-invariant**: its output depends only on the
input bytes, never on how the caller splits them across
`StreamingDecoder::feed()`. Encoding detection buffers a head until 16 significant
base64-only bytes make it decisive, so plain-text bodies (whose scheme carries `:`)
are never misread as base64; base64 is normalized to the standard alphabet with
whitespace dropped, so MIME-wrapped and URL-safe input decode alike. Line assembly
runs on bytes, so a line ends only at its `\n` and a multi-byte codepoint
straddling a feed boundary is never replaced with `U+FFFD`. A single line is capped
at 256 KiB; a longer one is cut at the last scheme start, and a single over-long URL
is dropped and counted (`overlong_lines()`), surfaced by the import run rather than
silently lost.

### leas-native (library crate)

`crates/leas-native/src/lib.rs` — in-process proxy core: client-side protocol
implementations, the local inbounds in front of them, and the session lifecycle
that lets the whole thing stand in for a spawned xray-core / sing-box. Built
on the same `leas-proto` typed configs (`NativeConnectParams` wraps
`ProtocolConfig` + `EndpointEssentials`); no config model is defined here, and
nothing here touches the DB or the app config — `leas` passes the already
resolved values in.

Layering follows Xray composition order, folded by `connect_chain`:
`dial → transport → security → protocol → tunnel`. Each phase consumes the
previous phase's `BoxStream` (the `Stream` seam: AsyncRead+AsyncWrite+Unpin+Send)
and returns the next.

- `transport/` — TCP dial, ws/grpc/httpupgrade/xhttp/v2rayhttp upgrade framing, fresh-UDP mKCP dial, and the QUIC dial (`connect_quic` — quinn/rustls internal to QUIC, shared by the xhttp h3 arm and the hysteria2 client).
- `transport/v2ray/` — SIP003 plugin framing over an established stream:
  `http_obfs.rs` (`obfs=http`), `tls_obfs.rs` (`obfs=tls` — a SYNTHETIC
  TLS-1.0 record writer with the payload hidden in `session_ticket`, not a
  handshake; its record layouts are pinned against real `sizeof`/`offsetof`),
  `ws.rs` (v2ray-plugin WebSocket, early data OFF because the plugin path never
  populates `maxEarlyData`), and `mod.rs`'s `upgrade` dispatch. The layer is
  **framing-only**: the wire order is `TCP → TLS → WebSocket → mux → SS`, TLS
  outermost, so it reuses `security::wrap` and no chain phase is skipped.
  `mode=quic` has no arm here and none is promised — it is refused at
  `capability` before any dial (see the unpinnable-wire note).
- `transport/mux.rs` — the v1.mux.cool frame codec, EXTRACTED from
  `protocol/vless/mux.rs` so VLESS and the plugin mux share ONE implementation
  rather than growing a second; the moved vless tests are the pin.
- `mux_session.rs` + `protocol/ss/mux.rs` — the plugin mux's SS arm. Mux is a
  **protocol-phase** return type, not a transport one: `SsMux` opens sessions
  over the shared codec, each with its OWN salt/subkey/counter stream, and
  `mux_session::open_session` hands the session ownership of the tunnel.
  `MuxTunnel` is deliberately not `Clone` and is taken **by value**, so a session
  id can never be duplicated.
- `security/` — `wrap()` builds an engine `TlsConfig` from the profile's
  security config and runs `leas_tls::client::connect` (`TlsMode::Plain` |
  `TlsMode::Reality`) — the rustls client path is gone; rustls remains only
  as the server-side test double + quinn's internal QUIC TLS. Trust:
  `insecure` / `pin_sha256` (pin replaces chain walk + SAN but never the
  CertificateVerify signature).
- `protocol/` — 20 protocol modules; `vless`, `vmess`, `trojan` + `hysteria2` are implemented
  (trojan = TCP-stream family via the uniform pipeline; hysteria2 = `ConnectShape::Quic`
  fresh quinn dial), plus the `socks` CLIENT handshake (RFC 1928/1929 greeting →
  method → CONNECT over the `BoxStream` seam; its UDP side stays
  `NotImplemented` — SOCKS5 datagrams need a raw UDP socket, not this stream).
  Every other kind returns `NativeError::NotImplemented` naming the feature.
  `shape.rs` `ConnectShape` marks the divergent paths (device tunnels:
  WireGuard/Tailscale; own-handshake: SSH; outbound-only kinds: Redirect/TProxy/
  Mixed).
  `PacketTunnel` (the UDP datagram tunnel) additionally exposes
  `split() -> (PacketReader, PacketWriter)`: every carrier separates its
  per-direction framing state from the transport, so a reader task and a writer
  run concurrently. This is mandatory for any bidirectional relay — a stream
  carrier's `recv` spans several awaits, so racing it in a `select!` would drop
  a partial frame and desynchronise the tunnel. VLESS XUDP refuses to split
  (its datagrams ride a shared mux tunnel, not a stream).
- `inbound/` — the local server side: `Socks5Inbound` (`inbound/socks5.rs`) and
  `HttpInbound` (`inbound/http.rs`), both `accept → leas-route Engine`
  (`decide_async`) `→ tagged Outbound` (Direct / Block / Proxy, the proxy
  reusing `crate::connect`). Shared in `inbound/mod.rs`: `TraceCtx` (telemetry
  sink + the per-leg protocol/transport/security labels), `traced_relay`,
  `warn_if_open_relay`, `absorb_accept_error`, and the
  `shutdown: Option<watch::Receiver<bool>>` both configs carry — once the sender
  marks shutdown the accept loop stops and in-flight connections abort.
  - SOCKS5: TCP CONNECT plus UDP ASSOCIATE (`Socks5InboundConfig::udp`, default
    on): one relay task per association routes EVERY datagram through the engine
    (`NetworkMask::UDP`, whole-payload sniffing gated on `Engine::needs_sniff`),
    so a single association can reach direct and proxy outbounds at once. Direct
    traffic uses per-family upstream sockets; proxy traffic goes to a leg task
    that owns the split tunnel. The association pins to the control connection's
    peer, expires if no datagram arrives, and ends on control-TCP EOF. BIND is
    refused `0x07`; `HijackDns` drops the datagram (TCP: `0x02`).
  - HTTP: `CONNECT host:port` only. The head is scanned under a 16 KiB cap
    (`MAX_HEAD_BYTES`) with a 3-byte overlap so a `\r\n\r\n` split across reads
    is still found, and bytes the client pipelined behind the head (a
    `ClientHello` in the same `write`) are replayed into the tunnel — through the
    byte counters on the traced path, so they are attributed `up`. Every refusal
    is framed (`Content-Length` + `Connection: close`) with a one-line reason, so
    a client can tell a PROXY refusal from a destination failure: `400` (no
    `host:port`), `403` (blocked route), `407` (missing/wrong credential, with a
    `Proxy-Authenticate: Basic` challenge), `431` (over-long head), `501` (any
    other method — absolute-form requests are not forwarded), `502` (failed
    outbound dial); success is `200 Connection Established` then a raw
    bidirectional relay. `Proxy-Authorization: Basic` is optional
    (`HttpInboundConfig::with_auth`) and transient accept errors are absorbed.
- `capability.rs` — the predicate that decides whether native may serve a row at
  all. `NATIVE_KINDS` = `[Vless, Vmess, Trojan, Hysteria2, Shadowsocks,
  Shadowsocks2022]`; `kind_supported(kind)` is the cheap config-blind gate
  (display/sort paths), `supported(kind, config)` the config-aware one (connect).
  It mirrors the native dispatch arms, not xray's feature set, and fails CLOSED —
  a row native serves *worse* than the subprocess defers. Deferred: VLESS account
  `encryption` the connect path cannot dial — `mlkem_encryption_supported` runs
  the codec's OWN parser (`parse_mlkem_encryption` →
  `EncryptionConfig::try_from_parsed`), so only an unknown or malformed scheme
  defers and never `mlkem768x25519plus` itself (which native serves; the
  `pq-enc` row is green) — and any flow outside the vision pair, legacy VMess
  payload ciphers, a non-zero `alter_id`, and mKCP `seed`/`header_type` (wire
  format, not pacing — including the share-link `path` seed carrier). A TLS
  fingerprint id is NOT a refusal: an id with no roster row is dialled with the
  engine default and marked approximated (`security::fingerprint`). The
  transport match is a POSITIVE, wildcard-free match: a new `TransportConfig`
  variant breaks it at compile time instead of inheriting `true`.
- `server/` — `NativeCoreServer`, the in-process equivalent of a spawned core.
  `ServerConfig { socks, http: Option<SocketAddr>, proxy: ProxyOutbound,
  telemetry, udp }`; `start()` compiles a proxy-all engine (no rules,
  `DefaultRoute::Route { tag: "proxy" }`), binds the SOCKS5 listener plus the
  optional HTTP one, and spawns their accept loops. Teardown is cooperative
  through one `watch` channel: `stop()` fires the signal every listener and
  in-flight connection selects on (closing live sockets exactly like killing a
  subprocess would); `shutdown()` additionally awaits the accept loops and is the
  ONLY teardown that guarantees the ports are free when it returns; `Drop`
  signals and aborts the loops but cannot await them. Neither inbound
  authenticates a client, so a non-loopback bind warns once at `start`.
- `telemetry.rs` — the event seam to the TUI. `Telemetry::new(cap)` returns the
  sink plus `NativeEvents`, with SEPARATE bounded log and trace queues (a log
  burst can never starve trace rows; `recv` takes traces first). `NativeEvent` is
  `Log` / `Trace` / `Traffic`; `TraceEvent` is `Opened(TraceOpened)` /
  `Closed(TraceClosed)` keyed by `conn_id`. `Telemetry::guard` hands out a
  `TraceGuard` that emits the `Closed` row on drop, so a cancelled leg (shutdown,
  task abort) still ends its row instead of rendering live forever. `Counted<S>`
  wraps a stream and counts into shared atomics as bytes move, which is what
  makes traffic live rather than per-connection-final; `drain_traffic()` swaps the
  totals out for the 3 s poll. A full queue drops the event and counts the drop —
  drops are folded into one summary line per window, never per-event spam.
- `e2e/` (feature `native-e2e`) — real-core scenarios: spawns xray-core
  26.3.27 / sing-box 1.13.16 server inbounds, dials with the native client,
  probes HTTP through the tunnel. Transport matrix (VLESS/VMess ×
  TCP/WS/gRPC/HTTPUpgrade/XHTTP/h2/KCP/QUIC × TLS variants) + Trojan +
  Hysteria2 + Shadowsocks axes; 185 test fns = 177 green + 8 ignored
  (vless 85+7, vmess 53, trojan 14, hysteria2 3, shadowsocks 22,
  probe_e2e 0+1).
  Version-pinned: a core binary version mismatch is a hard fail, not a skip.

Per-protocol roadmap and capability tables: `docs/reference/native-core.md`. Session wiring and
the decision rules: `docs/architecture/native-core-integration.md`.

### leas-tls (library crate)

`crates/leas-tls/src/lib.rs` — ring-based TLS client (TLS 1.3, plus a
TLS 1.2 ECDHE+AEAD client path reached on a 1.2 ServerHello) with browser
fingerprint mimicry + a REALITY client (REALITY stays 1.3-only). ring-only
(no aws-lc-rs/rand/unsafe);
CSPRNG via the crate-local `SecureRandom` seam (blanket impl for
`ring::rand::SecureRandom`). One documented exception: x25519-dalek for the
REALITY keypair, because ring's `EphemeralPrivateKey` is single-use and cannot
serialize — REALITY must agree twice with the same scalar.

- `spec/` — declarative `ClientHelloSpec`/`ExtensionSpec`/`SessionIdSpec` +
  exact RFC 6066/8446 wire encodings; GREASE per RFC 8701.
- `profiles/` — two-tier roster: hand tier (`hand_selected.rs`, `spec!`-declared)
  = 2 wire-exact profiles (`chrome_130`, `edge_106`); generated tier
  (`generated/`, emitted by `gen_specs.py --emit`) = 69 JA4-faithful entries —
  the deterministic `select_roster` kept subset of the 1825-entry ja4db manifest.
- `hello/` — `build_hello`/`to_record` (GREASE pairing, 512-byte record
  padding), `parse_hello`.
- `crypto/` — TLS 1.3 key schedule (RFC 8448-verified) + TLS 1.2 key block, AEAD record keys
  (IV XOR seq), `X25519KeyPair`, JA3/JA4 codecs, and ML-KEM-768 (`mlkem.rs`, RustCrypto
  `ml-kem`, FIPS 203 — liboqs was removed 2026-09-18 because its vendored build added CMake +
  a C/C++ toolchain; the seed→ek bytes are pinned by a KAT captured before the swap). Every
  secret-producing entry point returns
  `Zeroizing<…>` (`hkdf_extract`/`hkdf_expand_label`/`derive_secret`/`master_secret`/
  `finished_key`, the `TrafficSecrets` pair alias, `X25519KeyPair::agree`, the whole
  `tls12` PRF chain), `mlkem::SharedSecret` is `ZeroizeOnDrop` with length-only `Debug`, and
  `mlkem::SecretKey` holds the RustCrypto `DecapsulationKey` (self-wiping, serialized as the
  64-byte FIPS 203 keygen seed). Wire-visible outputs stay plain `Vec<u8>` (`transcript_hash`,
  `finished_mac`), and the key bytes ring holds inside `LessSafeKey`/`Prk` are
  unwipeable — the wipeable surface is the derivation buffers on either side. Every
  non-default crypto site (this engine, xray's AES-CTR mask, the binary-context BLAKE3, the
  legacy KDFs, QUIC header protection) is inventoried in `docs/reference/crypto-dependencies.md`; both
  crypto crates carry `#![forbid(unsafe_code)]`.
- `record/` — record framing, `read_record`, `TlsStream<S>`.
- `handshake/` — client handshake (HRR detection, `ServerVerifier` seam,
  multi-record flight reassembly); TLS 1.2 fallback driver in `handshake/tls12.rs`
  reached on a 1.2 ServerHello.
- `verify/` — `WebPkiVerifier` (roots / CA DER / `insecure` / `pin_sha256`).
- `reality/` — `HelloProvisioner` + 9-step wire contract, `FixedChrome133`,
  auth-key/session-seal/server-auth.
- `http2/` — minimal h2 layer for the tls.peet.ws grader (not a client).

Tier-2 verification: `examples/grader.rs` + ignored `tests/tls_peet_ws.rs`
(tls.peet.ws). Interop proof: unit tests handshake against a real rustls server
(dev-dep).

Secrets are wiped in the native crate the same way (VMess `Session`/`cmd_key`/KDF
buffers, VLESS `mlkem768x25519plus` `nfs_key`/`united`, trojan auth token,
`Salamander.psk`, the SOCKS5 credential frame). Both crates also carry the
`zeroize` FEATURE on their crypto deps — it is off by default in the RustCrypto
ciphers and stripped from `x25519-dalek` by `default-features = false`.

### leas-db (library crate)

`crates/leas-db/src/lib.rs` — toasty ORM database layer. `retry.rs` adds
`retry_on_busy`/`is_busy_error` — SQLite write contention (`is_serialization_failure`
or "database is locked") retries with 20ms-doubling backoff (1.28s cap). MVCC
statement-level conflicts are included because the driver classifies `BusySnapshot`
and conflict text as serialization failures. Public DB mutators and rank maintenance
retry whole transaction bodies; `LinkWriter` re-stages failed drained windows.
`Database::conn()` sets `PRAGMA busy_timeout=5000` on every pooled connection
acquisition; the pragma in `open()` is per-connection and never reaches
pool-created conns (the raw `direct` connection applies the same
per-connection pragmas at open). Rank DDL uses `TransactionMode::Immediate` so MVCC data
transactions do not own schema initialization.

**The statement cache is routed at its boundary — the crate owns its driver (2026-10-08).**
The published `toasty-driver-turso` routes EVERY statement through
`turso_sdk_kit`'s `prepare_cached`, whose per-connection map is **unbounded and
keyed by SQL text**: each distinct statement is compiled and retained for the
connection's life. Our bulk writers INLINE their literals (ids, values,
timestamps) for the engine's ~0.8 ms/bind cost, so every call is a new text —
a leak measured at ~116-310 KiB per distinct text. The crate now vendors a
LOCAL-ONLY fork of that driver (`crates/leas-db/src/driver/`, from toasty
`main` at its `turso = "0.8"` bump) and routes each `Operation` by whether its
text is stable: `RawSql` (the inlined-literal bulk statements) → the UNCACHED
`prepare`; `Insert`/`QuerySql` (engine-generated) → `prepare_cached`. That
boundary IS the fix, with no LRU or counter. So the retired `SqlConn`/`RawConn`
seam and `Database::write_conn` are gone: the bulk writers run on the POOLED
driver and keep their literal-inlining win. `Database::direct` (the page's
execution-layer bypass, ~80x read win) stays. Contention classification
(`driver::error::classify_turso_error`) keeps `Busy`/`BusySnapshot`/`conflict`
errors RETRYABLE, or `retry_on_busy` would re-stage a window that should have
been retried. See `docs/reference/database-manual-sql.md`.

**Journal mode:** fresh/recreated file DBs default to WAL. **WAL is deliberate** (2026-10-02): an A/B on synthetic feeds found MVCC **1.2-4.8x slower** than WAL at 32 concurrent writers, so MVCC stays opt-in behind `LEAS_TURSO_CONCURRENT_WRITES=1`.

**Micro-batch MVCC write-behind (2026-10-20, ADR 0014):** on an MVCC handle the write-behind driver shrinks its window to 32 rows (`DEFAULT_FLUSH_ROWS_MVCC`) and skips the in-transaction `endpoint_rank::refresh` for link patches — the touched endpoints go into an in-memory `Database::dirty_ranks` set that `profiles_page` and each flush drain (`drain_dirty_ranks`). Measured (`micro_batch_mvcc_probe`, 16 writers, 8,192-endpoint feed): MVCC p99 7–67 ms against WAL's 179–835 ms at every batch size; the 75–95× verdict of the 100-row geo shape stands for that writer. The dirty set is volatile: a crash between commit and drain leaves stale keys until the endpoint is next written (`endpoint_rank::ensure` does not detect them). A failed window re-stages from its patch (`CacheSpec::restage_patch`); `Coalesced<K, P>` no longer carries a duplicate source row. Partitioned N-channel drain was deferred — zero conflicts at every measured batch size.

**Import upserts:** `upsert_endpoints_bulk` and `upsert_endpoint_group_links_bulk` are multi-row (chunked at `IMPORT_STATEMENT_ROWS` = `LINK_STATEMENT_ROWS` = 400); `upsert_protocols_bulk` is still one typed upsert per row and is the largest surviving import cost at a measured 117 us/row. Raw SQL writers that touch an embed-enum column must go through a tested `as_db_label` (`HostType::as_db_label`) — the stored spelling is the derive's `snake_case` ident, which is neither `Debug` nor the wire form, and a wrong one fails silently.
`LEAS_TURSO_CONCURRENT_WRITES=1` opts them into Turso MVCC; existing WAL
files remain WAL, existing MVCC files retain MVCC, and intentional schema wipes
remove `-wal`, `-shm`, and `-log` sidecars before recreation. The engine cannot
convert a WAL-header file in place. `Database::uses_concurrent_writes()` is the
per-handle authority; batch completion skips the incompatible WAL passive
checkpoint for MVCC handles. Real-feed contention evidence remains a benchmark
gate, not a default-enable claim.

Schema, indexes, invariants and flows are documented in **`docs/reference/database.md`**
(with diagrams); this section is the crate-level summary. The rule for — and the
complete inventory of — the hand-written SQL the typed path cannot express is
**`docs/reference/database-manual-sql.md`** (typed path first; every exception has a
recorded cause and measurement there).

**Models** (defined via `#[derive(toasty::Model)]` in `models_toasty.rs`, 10 tables):
- `Endpoint` — server config; dedup key `stable_hash(host, port)` or `stable_hash("undefined", config_uid)`; `resolved_at` is the DNS-attempt stamp the resolution TTL gates on (the addresses themselves are `EndpointIp`'s)
- `EndpointIp` — one row per resolved address of a DNS endpoint, PK `(endpoint_id, ip_key)`; `ip_key` is the address in a sortable packed encoding (family byte then big-endian octets), so B-tree byte order IS address order (ADR 0005)
- `Protocol` — `#key id` = the identity uid (host/port excluded), plus `sig` for the grouping key; transport/security embeds; `config: Deferred<Json<ProtocolConfig>>`
- `ProfileStats` — per `(protocol_id, endpoint_id)` pair: latency/speed/error/traffic; `last_seen_at` indexed (retention + staleness windows)
- `EndpointRank` — the materialized ordering keys the Profiles page is ordered by (ADR 0003); `rank_weight` (a raw `BLOB NOT NULL`, added by `ALTER TABLE` so no schema-tag bump) holds the static config weight, and `endpoint_rank_test_v2` is the covering index that carries it
- `EndpointGroup` — many-to-many Endpoint↔Group membership
- `Group`, `RoutingRule`, `DnsSetting`, `RouteProbes`

All timestamps are epoch-SECOND integers (`to_epoch`/`from_epoch`/`now_epoch` are the conversion points); `#[auto]` is deliberately absent from them, because on an integer column toasty's auto strategy is `Increment`, not "now". Scheduler task state is NOT a column: it is runtime-only (see "Task gate" below).

**Schema management**: `crate::schema` is the migration runner (ADR 0012). `PRAGMA user_version` is a CURSOR seeded at `SCHEMA_VERSION`; a current file is a no-op, a fresh file applies the seed, a supported older version applies the pending steps, and only an UNKNOWN cursor is `IncompatibleSchema` (which `open` answers with the pre-alpha wipe). `push_schema` still emits `CREATE TABLE` without `IF NOT EXISTS`, but it runs ONLY on the fresh path now. Hand-written DDL lives in `schema/ddl.rs`; the migration list is its single owner.
