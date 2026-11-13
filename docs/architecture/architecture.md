# leas architecture

How the workspace is put together: which crates exist, what each one owns, where the process boundaries are, what `AppState` and `CoreEvent` carry, which screens exist, and how a batch ping runs end to end. It does not cover keybindings and workflows (see [`../guides/tui-manual.md`](../guides/tui-manual.md)), the reasons behind a choice (see [`decisions.md`](decisions.md)), or the database schema (see [`../reference/database.md`](../reference/database.md)).

## Workspace layout

`Cargo.toml` declares `members = ["crates/*"]`, resolver 3, edition 2024, rust-version `1.99.1`, workspace version `0.1.0`. Fifteen crates exist:

`leas`, `leas-config`, `leas-core`, `leas-db`, `leas-dns`, `leas-geoip`, `leas-hakari`, `leas-host-features`, `leas-hotpath`, `leas-memtrace`, `leas-native`, `leas-oracles`, `leas-proto`, `leas-route`, `leas-tls`. (`leas-oracles` is dev-only and excluded from `default-members`; `leas-hotpath` is a dev benchmark pair of binaries, also absent from `default-members`. `leas-memtrace` is a library and a default member, so its unit tests run in the normal suite; it is also the optional `mem-trace` allocator of the `leas` binary — see [`decisions.md`](decisions.md) §30.)

## Crate dependency graph

Edges are runtime dependencies from each `crates/*/Cargo.toml`. `leas-hakari` is omitted: every member depends on it (see below).

```text
leas (binary)
  ├── leas-core            ping adapters, speed tests, heed logs (native-shared glue)
  │     └── leas-proto     typed configs, per-kind binary identity
  ├── leas-native          in-process backend: tunnels, inbounds, telemetry
  │     ├── leas-proto     typed ProtocolConfig / EndpointEssentials
  │     ├── leas-tls       TLS 1.3 + 1.2-fallback client engine, REALITY
  │     └── leas-route     first-match routing engine for the local inbound
  ├── leas-db              toasty models, schema cursor, page query, write-behind, export
  │     └── leas-proto     typed configs embedded in model rows
  ├── leas-config          AppConfig, import/export, forms, subscription decoding
  │     └── leas-proto     share-URL parsing and protocol types
  ├── leas-proto            protocol configs, share URLs, Clash YAML, identity hashing
  ├── leas-route            routing engine primitives and codecs
  │     ├── leas-dns       optional, feature `dns`
  │     └── leas-geoip     optional, feature `geoip`
  ├── leas-dns              DNSCrypt-stamp resolver
  ├── leas-geoip            geo data: GeoLite2, .dat, .srs
  ├── leas-host-features    SNI / exact-IP / CIDR whitelist membership
  └── leas-memtrace         optional, feature `mem-trace`: the process allocator +
                            per-module memory artifacts (also used by `leas-hotpath`)
```

Notes that the manifests enforce:

- `leas-route`'s `geoip` feature is on by default (geo token resolution needs it), and `leas` enables `dns` for the production `DnsSinkAdapter`; the `engine` test suites run with both. `leas-route`'s `leas-tls` edge is a dev-dependency for benches and tests.
- `leas-native` does not depend on `leas-core`; it takes typed configs straight from `leas-proto` and returns `leas-native` types.
- `leas-core` carries only native-shared glue: ping adapters, speed tests, the heed log store, `SysStats`/formatters and `ensure_tls_provider`. The oracle adapters (config builders, subprocess lifecycle, updater, gRPC stats client, `CoreType`, `core_mapping`) live in the dev-only `leas-oracles::oracle_adapters`; the client graph has no tonic/prost edge.
- `leas` depends on `leas-proto` and `leas-route` directly, in addition to the crates listed above.
- `leas-memtrace` is an optional dependency of `leas` (feature `mem-trace`, which implies `std-alloc` and swaps the default mimalloc allocator out) and a plain dependency of the dev-only `leas-hotpath`, whose `memtrace` bin drives real code paths under it.

`leas-hakari` is a cargo-hakari generated feature-unification crate. Every member depends on it; its own dependencies are never referenced from code and exist only to unify feature flags. Regenerate after a `Cargo.lock` change with `cargo hakari generate`; the `hakari-check` gate runs `cargo hakari generate --diff`, `cargo hakari manage-deps --dry-run` and `cargo hakari verify`, and `--dry-run` is what catches a member missing the dependency.

## Crate responsibilities

### leas (binary and library)

Entry point `crates/leas/src/main.rs` and the TUI library (`src/lib.rs` exports `ops`, `route_compile`, `state`, `types`, `ui`, `AppState`).

Startup order in `main`:

1. `install_tls_provider()` installs the ring `CryptoProvider` process-wide, before any TLS consumer (reqwest, QUIC ping, hickory DoH).
2. `AppConfig::load()` reads `~/.config/leas/config.json`.
3. `Database::open()` opens `~/.config/leas/data.db`; the directory is tightened to `0700` and the database plus `-wal`/`-shm` sidecars to `0600` on Unix, because the file holds cleartext proxy credentials. A failed open (another instance's lock, an IO error, a corrupt file) PROPAGATES and leaves the file untouched; only an unknown schema cursor wipes it.
4. `HeedLogStorage::new()` opens `~/.config/leas/logs.lmdb`; a `spawn_blocking` writer drains a bounded 4096-message channel in batches of up to 100 per heed transaction, polling every 200 ms so it can notice `shutdown_token` at quit.
5. `AppState::new()` builds the shared state, then `ui::run(&mut state)` owns the terminal and the event loop.

Module layout beyond the UI: `state.rs` (`AppState`), `types.rs` (`CoreEvent`, `AppMode`, pane enums, view types), `route_compile.rs` (routing-rule compilation into the native engine), `ops/` (every asynchronous action), `ui/` (rendering and key handling).

`ops/` modules:

| Module | Owns |
| --- | --- |
| `connect.rs` | `connect_to_profile`, `disconnect`, `resolve_runtime_core`, the subprocess session and its stats loops |
| `native_connect.rs` | `run_native_session`, the in-process arm of `connect_to_profile` |
| `ping.rs`, `ping/` | single and batch probes, the batch walk, plan scopes, fill-exit-IPs |
| `ping_native.rs` | the native probe runner, `ProbeClass`, failure classification |
| `events.rs` | `poll_core_events`, result application, throttled page reload |
| `scheduler.rs` | `TaskScheduler`, the per-link gate and DNS deferral |
| `job_scheduler.rs` | the user-visible task queue, `TaskKind`, terminal events |
| `enrich.rs` | background DNS, mmdb, whitelist and exit-IP enrichment |
| `profiles.rs`, `subscriptions.rs`, `settings.rs`, `settings` writes | profile mutations, subscription updates, settings persistence |
| `stream_import.rs`, `telegram.rs` | the one import pipeline (decoder, batches, write-behind) and its two sources: HTTP subscriptions and Telegram public channels |
| `compact.rs`, `purge.rs`, `updates.rs`, `export.rs`, `db_monitor.rs`, `speed_test.rs` | maintenance commands, retention, binary updates, export, DB monitoring, single-link speed tests |
| `clipboard.rs` | one process-lifetime `arboard::Clipboard` handle behind `LazyLock<Mutex<Option<Clipboard>>>` for every copy and paste site |

Export splits across three owners: `leas-db/src/export.rs` opens a dedicated Turso read connection and drains ordered rows, `ops/export.rs` owns scope policy and the clipboard/file sinks, `ui/export.rs` owns the popup. The single clipboard handle matters because `arboard::Clipboard` is the X11 selection owner on Linux; a per-call handle drops the serving window and the payload is lost without a clipboard manager.

### leas-core (library)

Native-shared session glue: `log_heed` (LMDB log store + `LogMessage`), `grpc_client`'s `SysStats` + `format_bytes`/`format_uptime`, `ping` (fast adapters and `FastPingManager`), `speed_test` (`TestType`, `speed_test`, `tcp_ping`, `udp_ping`, `udp_test`) and `ensure_tls_provider`. It has no subprocess, updater, gRPC client or `CoreType` surface.

- `ping` dials the endpoint directly (never a core); `speed_test`/UDP dial the connected native inbound.
- The gRPC Stats client (`StatsProvider`, `GrpcStatsClient`, `create_stats_provider`) and its tonic/prost codegen moved to the dev-only `leas-oracles::oracle_adapters`; `SysStats` stays here because native telemetry writes it.
- `CoreType` (`{Xray, SingBox, Auto, Native}`), `core_mapping`, `bin_manager`, `config_builder`, `process` and `updater` moved to `leas-oracles::oracle_adapters`. The client has no core choice; the protocol identity no longer carries one.

Share-URL parsing and client-config export live in `leas-config`, not here.

### leas-config (library)

`AppConfig` load/save (serde JSON), `import_export` (share-URL parse/export and per-batch `ValidationSummary`), `forms`, `permissive_json`, `duration_or_secs`, `base64_util`, `fast_perc`, `ip_provider`.

`subscription.rs` owns the streaming decoder: bytes to base64 or raw text, to lines, to share URLs. The pipeline is chunking-invariant: output depends only on the input bytes, never on how `StreamingDecoder::feed()` splits them. Encoding detection buffers a head until the decision is safe, base64 is normalized to one alphabet with whitespace dropped, line assembly runs on bytes so a multi-byte codepoint split across feeds is never replaced with `U+FFFD`, and a single line is capped at 256 KiB (an over-long line is cut at the last scheme start and an over-long URL is dropped and counted).

### leas-proto (library)

Single source of truth for protocol data: `proto_spec` (typed `ProtocolConfig`, `ProtocolKind`, `EndpointEssentials`, per-kind binary identity, `core_mapping` with `resolve_core`), `urlx` (share-URL schemes), `clash` (mihomo YAML), `domain`, `utils`.

Identity is a frozen binary wire format (`uid = sig ^ cred_hash`) over non-default fields only; changing its coverage re-keys stored rows. Share-URL and config semantics: [`../reference/protocols.md`](../reference/protocols.md).

### leas-db (library)

Typed persistence: `database.rs`, `models_toasty.rs`, `profiles_query.rs`, `endpoint_rank.rs`, `endpoint_ip.rs`, `write_behind.rs`, `export.rs`, `merge.rs`, `retry.rs`, `schema/`, and a local-only Turso driver fork in `driver/`.

- `SCHEMA_VERSION` is 19 and `schema::LATEST` re-exports it. `PRAGMA user_version` is a migration cursor, not a wipe tag: current is a no-op, a fresh file applies the seed, a supported older cursor applies steps, and only an unknown cursor is `IncompatibleSchema`. Hand-written DDL lives in `schema/ddl.rs`; the schema change procedure belongs to [`../reference/database.md`](../reference/database.md).
- Eleven typed tables: `endpoints`, `endpoint_ip`, `protocols`, `profile_stats`, `endpoint_groups`, `groups`, `routing_rules`, `dns_settings`, `route_probes`, `endpoint_rank`, `app_meta`.
- The driver fork routes each `Operation` by statement stability: inlined-literal bulk SQL goes to uncached `prepare`, engine-generated statements to `prepare_cached`. This is why the published driver's unbounded SQL-text statement cache is not in the build.
- `WriteBehind<T>` is the staged-write seam. `LinkSpec` covers `profile_stats` mutations and `CountrySpec` covers exit-country writes; `AppState` holds both drivers.
- Ordering keys are materialized in `endpoint_rank` and implemented once in Rust. Law: [`../reference/ordering-law.md`](../reference/ordering-law.md). Manual SQL inventory: [`../reference/database-manual-sql.md`](../reference/database-manual-sql.md).

### leas-native (library)

In-process backend: client tunnels, the local inbound, the session server, capability gate and telemetry. It defines no config model and never touches the database; `leas` passes resolved values in as `NativeConnectParams` (typed `ProtocolConfig` plus `EndpointEssentials`).

Composition order per link is `dial -> security -> transport upgrade -> protocol -> tunnel`, folded by `chain.rs`: TLS or REALITY wraps the stream outermost, ws/grpc/xhttp framing runs inside it, then the protocol speaks, then the tunnel is handed back. QUIC-family protocols replace dial plus security plus upgrade with one QUIC dial and must be the last link.

- `transport/` covers the TCP dial, ws/grpc/httpupgrade/xhttp/v2rayhttp framing, mKCP, QUIC, and the plugin framing under `transport/v2ray/`.
- `protocol/` holds 20 kind modules. `NATIVE_KINDS` is `[Vless, Vmess, Trojan, Hysteria2, Shadowsocks, Shadowsocks2022, AnyTls]`; the other modules either implement a narrower path or return `NativeError::NotImplemented` by name. `capability::kind_supported` is the config-blind gate, `capability::supported(kind, config)` the config-aware one used at connect time; both fail closed. AnyTLS is also a **session-multiplexed** family: `protocol/anytls/client.rs` pools one TLS session per link identity (newest idle first, 30 s reaper) and only the first chain link pools — a chained hop opens one stream on the session its upstream tunnel carries.
- `inbound/` binds the local server side: `Socks5Inbound`, `HttpInbound` and `MixedInbound`. The session server uses one `MixedInbound` listener for SOCKS5 and HTTP CONNECT, selected by the first byte; there are no separate socks and http listeners.
- `server/` holds `NativeCoreServer` and `ServerConfig`. `start()` compiles a proxy-all routing engine, binds that one mixed listener and spawns its accept loop. Teardown is cooperative over one `watch` channel: `stop()` closes live sockets, `shutdown()` also awaits the accept loops and is the only teardown that guarantees the ports are free when it returns; `Drop` signals and aborts but cannot await. Neither protocol face authenticates a client, so a non-loopback bind warns once.
- `telemetry.rs` is the event seam to the TUI: `Telemetry::new(cap)` returns the sink plus `NativeEvents`, with separate bounded log and trace queues so a log burst cannot starve trace rows. `TraceGuard` emits a `Closed` row on drop, so a cancelled leg still ends its row. Byte counters live in shared atomics, which is what makes traffic live rather than per-connection-final.
- The `leas-oracles` crate (dev-only, excluded from `default-members`) owns the real-core e2e suite: its `e2e/` module runs xray-core, sing-box and mihomo servers against the native client, and its `build.rs` fetches the pinned assets. Case counts and the verification tiers belong to [`../reference/native-core.md`](../reference/native-core.md).

Why the backend is in-process, its seams and open work: [`native-core-integration.md`](native-core-integration.md).

### leas-route (library)

First-match routing engine used by the native inbound: `Engine::decide_async` maps a connection (optionally after TLS/HTTP/QUIC sniffing) to `Decision::Direct`, `Block` or a tagged outbound. `Engine::build_with_geo` resolves `geoip:`, `geosite:` and sing-box `rule_set` references from a caller-supplied `GeoSource`, parsing each dataset **once** per build (`GeoCompiler::preload` collects every token from the rule set) and moving the parsed categories into the rules (`take_site`); domain and matcher strings are `CompactString`, so the inline-sized majority never reaches the allocator. Resolution is per token: a `geoip.dat` category serves its own codes, and a code the dataset does not carry falls back to the caller-supplied GeoLite2 country database — but only for two-letter country codes. With no dataset at all the country database serves every token; with neither, or with a code the fallback cannot represent, the build fails with a named error rather than leaving a rule that silently never matches. The app layer in front of it (`ops::geodata`) additionally derives a per-dataset category inventory and skips (with a WARN) a rule whose codes the selected dataset cannot serve, marking the row disabled in the pane — the engine then builds the remaining rules. Also owns the address primitives, the sing-box and xray rule compilers, the DNS sink seam and probe tracking. The `dns` and `geoip` features are default-on/consumer-enabled as noted above.

### leas-tls (library)

Ring-only TLS client engine: TLS 1.3 with a TLS 1.2 ECDHE+AEAD client path reached on a 1.2 ServerHello, declarative browser hello profiles, GREASE, JA3/JA4 codecs, ML-KEM-768, REALITY client provisioning, record framing and post-handshake policy (`KeyUpdate`, ticket drop). Verification modes are WebPKI roots, CA DER, `insecure` and `pin_sha256`. Roster fidelity: [`../reference/tls-fingerprint-roster.md`](../reference/tls-fingerprint-roster.md); crypto sites: [`../reference/crypto-dependencies.md`](../reference/crypto-dependencies.md).

### leas-dns, leas-geoip, leas-host-features (enrichment libraries)

These three are consumers of network data, not owners of state.

- `leas-dns` resolves through DNSCrypt stamps (DoH, DoT, DoQ) with hickory-resolver. `DnsResolver` performs the lookup; caching and TTL policy belong to the caller (`ops/enrich.rs`, `dns_cache_ttl_secs`).
- `leas-geoip` owns every geo artifact: country/city lookups from a GeoLite2-City database (`maxminddb`, small per-IP caches, sync `country_sync` for the router), the v2ray `.dat` reader (`geodata::dat`), the sing-box binary rule-set reader (`geodata::srs`), and the validated atomic downloader (`fetch_validated`).
- `leas-host-features` answers SNI, exact-IP and CIDR whitelist membership with `fastbloom`, downloading the whitelist files when missing.

## Runtime boundaries

One process, one tokio multi-thread runtime (`#[tokio::main]`). The TUI event loop (`ui::run`) owns the main task; every slow action runs in a spawned task and reports back through the `CoreEvent` channel. The log writer is the only `spawn_blocking` loop. Subprocess cores are child processes; the native core is a set of listeners and tasks inside this process.

Three runtime backends, two persisted:

| Backend | Runs | Started by | Data path |
| --- | --- | --- | --- |
| xray-core | child process | `RealCoreManager` | config file plus gRPC `StatsService` at `127.0.0.1:62789` |
| sing-box | child process | `RealCoreManager` | config file plus Clash API `/traffic` stream |
| native | in-process | `run_native_session` | `NativeCoreServer` listener plus `Telemetry` |

`resolve_runtime_core` in `ops/connect.rs` makes the per-connect choice: an explicit `Xray` or `SingBox` override wins; a kind outside `NATIVE_KINDS` keeps the link's stamped core; blocked proxy-all, an unloaded config or a capability refusal keeps the stamped core and records a reason; otherwise the link runs native. Nothing native is persisted, so the decision is recomputed on every connect.

One backend runs at a time. `disconnect` signals the running session over a oneshot and waits at most `DISCONNECT_TEARDOWN` (3 s); starting a new session first waits for the previous one for at most `PREV_SESSION_TEARDOWN` (5 s).

Stats cadence: the xray arm polls `query_stats` every 3 s and `get_sys_stats` every third tick (about 9 s); the native arm uses the same 3 s and 9 s cadence plus a 1 s sniffer snapshot; sing-box streams `/traffic` lines. All of them emit the same `StatsUpdate` and `SysStatsUpdate` events, so screens and persistence do not branch on the backend.

## AppState

`crates/leas/src/state.rs`. One struct, owned by the event loop and borrowed immutably by every render pass. Async work gets clones of the individual handles it needs, never `&mut AppState`.

| Concern | Fields | Notes |
| --- | --- | --- |
| Persistence | `db: Arc<Database>`, `link_stage: Arc<WriteBehind<LinkSpec>>` | staged link writes, one flush task |
| Config and theme | `config: AppConfig`, `theme: opaline::Theme`, `settings_form_snapshot` | `config.theme_name` is the slug the theme was loaded from |
| Shell | `focused_pane`, `pane1_tab`, `pane2_tab`, `pane2_height` | replaces the old single tab cycle; `pane2_height` 0 means the 16-row default |
| Profiles page | `endpoints`, `page_total`, `page_offset`, `filter_cache_valid`, `endpoints_gen`, `reload_gen`, `selected_index`, `selected_sub`, `multi_select` | `selected_index` indexes the loaded page, never the whole feed |
| Filters and view | `search_query`, `search_focused`, `purgatory_view`, `purgatory_ttl_secs`, `purgatory_retention_secs` | |
| Logs | `log_cache`, `log_scroll`, `log_select_anchor`, `log_viewport_rows`, `log_has_older`, `known_targets`, `selected_targets`, `heed_storage`, `last_seen_log_ns`, `log_sender_tx`, `core_log_tx` | watermark reconciles pushed lines with the heed poll |
| Connection | `connected_core`, `connected_protocol_id`, `connecting`, `connection_error`, `live_proxy`, `disconnect_tx`, `core_task_handle` | |
| Events | `core_event_rx`, `core_event_tx` | the `CoreEvent` channel |
| Testing | `scheduler: Arc<TaskScheduler>`, `testing_profiles`, `testing_details`, `speed_test_stop`, `batch_progress`, `maint_progress`, `fill_progress`, `batch` | keys are `(endpoint_id, protocol_id)` |
| Task queue | `task_queue`, `running_task`, `scheduler_paused`, `task_history`, `tasks_cursor` | process lifetime, never persisted |
| Live metrics | `system_stats`, `current_traffic_up`, `current_traffic_down`, `current_memory`, `native_activity`, `sniffer`, `last_test_tcp`, `last_test_real`, `last_test_speed` | |
| Enrichment | `endpoint_info`, `outbound_country_cache`, `geo_ip`, `dns_resolver`, `host_features`, `dns_cache_ttl_secs` | `endpoint_info` survives `reload_profiles`; country cache is a 512-entry LRU |
| Aggregates | `aggregates`, `aggregates_dirty`, `details_scroll` | Details panel counts, keyed by the current filter |
| Layout and mode | `mode`, `previous_mode`, `confirmation`, `clipboard`, `actions_compact`, `term_height`, `should_quit` | |
| Display cache | `display_rows_cache` | display rows rebuilt only when a fingerprint changes |
| Subscriptions, updates | `groups`, `updating_groups`, `update_status` | |
| Shutdown | `shutdown_token: Arc<AtomicBool>` | the one flag every background loop polls |

Session-only state stays in memory by design: `native_activity` is a ring of 2000 rows, `sniffer` holds the latest snapshot plus a 60-sample rate ring, `batches` and the task queue die with the process, and `scheduler` task ids are meaningful only inside the process that allocated them.

## CoreEvent

`crates/leas/src/types.rs`. One `tokio::sync::mpsc` channel carries work results from spawned tasks to the UI. The event loop drains it once per frame in `ops::events::poll_core_events`.

| Variants | Purpose |
| --- | --- |
| `Connected(CoreType)`, `Disconnected`, `Error(String)` | session lifecycle |
| `StatsError(String)` | non-fatal stats failure; keeps `connected_core` |
| `StatsUpdate {...}`, `SysStatsUpdate(SysStats)` | traffic deltas and system counters |
| `NativeTrace(TraceEvent)`, `SnifferSample(Box<SnifferSnapshot>)` | native per-connection trace and 1 s per-host snapshot |
| `LogLine {...}`, `TuiLog {...}` | core stderr lines and TUI tracing lines; `TuiLog` carries the event time and `persisted` so only persisted lines advance the heed watermark |
| `SubscriptionsUpdated {...}`, `ProfilesRowsReady {...}`, `RetentionPurged` | profile feed changes; `ProfilesRowsReady` carries a `generation` so a stale page is dropped |
| `SpeedTestResult {...}`, `TestTypeUpdate {...}`, `BatchEnded` | probe results, per-link running type, batch completion |
| `DnsResolveRequest {...}`, `EndpointInfoUpdated {...}`, `HostFeaturesLoaded(Arc<...>)` | enrichment requests and results |
| `DnsRetryTargets {...}`, `CompactFinished {...}`, `MaintenanceDone`, `ExportFinished {...}` | maintenance and export commands |
| `UpdateCheckResult`, `UpdateDownloadProgress`, `UpdateCompleted` | subprocess-core updates |
| `Route(RouteEvent)` | routing engine events from the native inbound |

`SnifferSample` is boxed because an inline `SmallVec` snapshot would dominate every event. Every result event that mutates a link is keyed by `(endpoint_id, protocol_id)`; `protocol_id` alone collides across endpoints that share a `Protocol` row.

## TUI screen map

`crates/leas/src/ui/`. The shell, verified in `ui/mod.rs::render` and `types.rs`:

- Pane 1 (top, `Min(6)` rows): tabs `Profiles`, `Sniffer`, `Logs`.
- Pane 2 (bottom, `pane2_height` rows, default 16): tabs `Details`, `Metrics`, `Tasks`. At one row or fewer it renders as a single borderless summary line.
- A one-line newest-log row between pane 2 and the status bar, dropped when pane 2 is compact.
- Status bar on the last row.
- A terminal under 20 rows always collapses pane 2 to the one-line bar. `actions_compact` holds the same collapse for the session.

Screen modes (`AddServer`, `EditServer`, `ImportUrl`, `BatchImport`, `Settings`) take the whole content area until they close; overlays (help, confirmation, speed-test menu, export popups, target picker) stack above whichever base is active.

| Module | Tab or mode | Content |
| --- | --- | --- |
| `profiles.rs` | Pane 1 `Profiles` | the 18-column endpoint grid, expansion into per-link rows, page scrollbar |
| `sniffer.rs` | Pane 1 `Sniffer` | per-host traffic for the live native session: two header lines, two mirrored sparklines on a shared scale, then the host table sorted by total |
| `logs.rs` | Pane 1 `Logs` | log viewer with source and target filters, selection and copy |
| `details.rs` | Pane 2 `Details` | selected server facts, selected link facts, database status; the link section scrolls with its own offset |
| `metrics.rs` | Pane 2 `Metrics` | session traffic, core system stats, and the native connection ring re-exported from `native_activity.rs` |
| `tasks.rs` | Pane 2 `Tasks` | running task progress bar, then the queued tasks earliest first |
| `settings.rs` | `Settings` mode | split pane: section tree and search on the left, form or group list on the right; 15 sections |
| `add_server.rs` | `AddServer`, `EditServer`, `ImportUrl`, `BatchImport` | protocol picker, typed form, import popups |
| `export.rs` | export modes | scope, destination and path popups |
| `status_bar.rs`, `theme.rs`, `widgets/` | shell | status line, theme role resolution, the reusable `DataTable` |

The Profiles grid, `GRID_COLUMNS` in `profiles.rs`, is 18 columns in this order: status glyph, Flag, Address, Port, White, separator, Protocol, Config, separator, Fast, Auth, Real, Stab, Streak, Speed, separator, Out, Exit. Fast and Auth sit before Real because they are the two facts known before a verdict. Stab and Streak sit after Real because they describe the same representative link. Width-aware dropping removes Exit, Out, White, Streak, Stab, Auth, Fast and Speed first, then shrinks Address toward a 12-cell floor; separators never drop. The scrollbar spans the SQL-filtered feed: `page_total` sizes the thumb and `page_offset + first_visible_row` positions it.

Rows come from the loaded page, hydrated by one `profiles_page` call. The Test cell renders the endpoint's representative link, the same link the ordering law stores its tier from, so cell and row band cannot disagree.

Keybindings, column semantics and workflows: [`../guides/tui-manual.md`](../guides/tui-manual.md).

## Batch ping flow

Two layers cooperate: `ops::job_scheduler` is the user-visible queue, and `ops::ping` is the probe pipeline.

### Queue

`job_scheduler::TaskSpec` freezes a `TaskKind`, a `PlanScope`, an optional selected `(endpoint_id, protocol_id)` and a label. `identity()` is `(kind, scope, endpoint)`, so the queue never holds the same task twice and a running task is never re-armed. `enqueue` appends; `drain` starts the head only when nothing is running and the queue is not paused; `stop` cancels the running task and pauses rather than clearing; `resume` continues; `discard_queue_on_quit` flushes history.

`TaskKind` values: `FastTest`, `RealTest`, `SpeedTest`, `UdpTest`, `SpeedTestBatch`, `FillExitIps`, `DnsRetry`, `Compact`, `MultiFastTest`, `MultiRealTest`. `dispatch` maps each to exactly one entry point, and `started` reads the progress slot the entry point sets to confirm the spawn took effect, so a silent refusal cannot wedge the queue.

A scoped batch checks `scope_is_empty` first with a one-row `profiles_page` over `PlanScope`; an unreadable scope counts as non-empty.

### Pipeline

Entry points in `ops/ping.rs`: `start_batch_ping` (fast only, whole feed), `start_batch_then_real_ping` and `start_batch_then_real_ping_scoped` (merged fast plus real), `start_endpoint_batch_ping` and `start_endpoint_batch_real_ping` (selected endpoint), `start_speed_test_batch`, `start_fill_exit_ips`. Every one funnels into `start_batch`, which refuses a second concurrent batch, clears `speed_test_stop`, resets the scheduler, and spawns `run_batch`.

`BatchParams` fixes the budgets before the walk starts: `fast_timeout` and `transport_timeout` both from `speed_test.tcp_timeout_secs`, `real_timeout` from `real_ping_timeout_secs`, retries from `real_ping_retries`, `real_concurrency` from `real_ping_concurrency` (default 100), page size `PROFILES_PAGE_SIZE` (200), the DNS deferral window from `TaskScheduler::dns_defer_secs`, and the DNS cache TTL.

`run_batch`:

1. Builds `BatchShared` and publishes it into `AppState` before the first probe, so an interrupted run can still report its classification through `interrupted_summary_line`.
2. Walks the plan as a page stream (`PlanWalk`). An explicit plan is one page; a feed walk pages through the tab's own query. Endpoint ids are frozen before any probe for every scope, including `All`, because the scope predicate reads `rank_bin`, which the batch itself changes as results land; offset paging over the live predicate would skip rows.
3. Dispatches each page as it loads. This is the difference between the first probe starting within one page and waiting for the whole plan: resolving every page first cost about 5.8 s of dead air on the 2026-09-17 reference feed (18,334 endpoints, about 92 pages at a measured 63 ms per page).
4. Waits for the fast, real and deferred counters to reach zero, joins every tracked task, then calls `finish_batch`, which flushes staged writes, applies the error sweep (`error_ttl_hours`) and emits `BatchEnded`.

`dispatch_page` does, per link: caches the protocol kind and the endpoint, sends at most one `DnsResolveRequest` per DNS endpoint and marks the lookup in flight in the same critical section, applies the config-blind `capability::kind_supported` gate and records an untestable marker, counts the link into the plan denominator, then schedules the fast half.

`dispatch_fast_link` passes `TaskScheduler::schedule`: `Started` spawns `run_task_chain`, `Queued` counts the link, `DnsDeferred` returns false and the caller owns a retry task, `QueueFull` skips the link and counts it. The batch never queues behind itself; the gate exists to keep one live task per link across concurrent producers.

The group-entry barrier applies to the deduplicating real phase: the plan keeps an endpoint's links contiguous, so the endpoint's first protocol is dispatched and its siblings are held until that verdict lands. An endpoint that succeeded drops the held siblings; an endpoint that did not releases them. There is no second check and no cancel-on-winner, so a sibling already in flight finishes and records its full result.

The fast half deduplicates by `(address, port)`: one TCP handshake per unique pair within a page, plus a batch-wide cache. It takes no concurrency permit of its own.

`after_fast_settle` is where a fast-only batch ends and a merged batch continues. The untestable marker is emitted first and outranks a measurement. A hard fast failure retires the link and writes the `[fast]` marker, except for a QUIC-plugin row whose TCP handshake cannot measure a QUIC server; that marker is retracted. With `real_phase` off, the method returns. With it on, `dispatch_real_probe` takes a `real_concurrency` permit, then consults `completed_endpoints` for the dedup setting, then schedules the real task.

The real probe is one connection with two independently budgeted stages: the transport stage (the dial, bounded by `transport_timeout`, and its span is the Fast metric) and the protocol plus probe stage (security handshake, transport upgrade, protocol handshake, target TLS, request, bounded by `real_timeout`). `ProbeError` carries `transport_span: Option<Duration>` and `auth_ack: AuthAck`, so a transport failure is distinguishable from a protocol failure by the field, not by the error class: both stages can report `ProbeClass::Timeout`, and a class test would retire a working server whose protocol stage hung.

### Results

Every result is a `CoreEvent::SpeedTestResult` carrying `endpoint_id`, `protocol_id`, `test_type`, `latency_ms`, `transport_ms`, `speed_bps`, `ip_info`, `error`, `purge`, `marker_kind` and `auth_ack`. `ops::events::apply_test_result` is the one mapping from result to row: it patches the link's typed columns in memory and stages the same patch through the write-behind driver. A `Cancelled` error persists nothing. Any other error writes the failure marker, keeps a stored real measurement, and clears the Fast span only when the transport stage itself failed, because a transport-stage failure contradicts that column.

When the affected row is on the loaded page, the handler re-sorts the owning endpoint's links by test priority and invalidates the page. During a batch the invalidation is throttled to one refetch per `RESULT_RELOAD_THROTTLE` (500 ms) and `BatchEnded` forces the final one. A refetch is one `profiles_page` plus page hydration on the UI task, measured at 23 ms against a 16 ms tick on the 7,486-endpoint reference feed.

Test priority is defined once, in the db crate: ascending `(tier, latency, -last_seen_at, id)` with tier 0 real-ok, 1 fast or UDP-ok, 2 untested, 3 real or name failure, 4 fast failure, 5 DNS unresolved, 6 purged. Fresh failures dominate stored successes because the marker is checked before the stored delay. `EndpointRow::representative_link_index` is the argmin the Test cell renders.

`speed_test_stop: Arc<AtomicBool>` is the shared stop flag. Setting it stops dispatch at the page boundary and cancels running probes; the batch still flushes and emits its terminal event, so a stopped run never leaves unpainted progress behind.

### Progress surfaces

`batch_progress` holds `BatchMeters`: plan pages plus the fast and real levels. `maint_progress` holds `MaintMeters` for DNS retry and Compact, and `fill_progress` holds `FillMeters` for the exit-IP fill. The status bar and the Details/Metrics/Tasks panes read the same slots, so their numbers cannot disagree. Each task kind sets exactly one slot, which is how `job_scheduler::started` detects a spawn.

## Connect path

`connect_to_profile(state, endpoint_id)` finds the row on the loaded page, takes its active link, resolves the runtime core, and starts the matching arm:

- Native: `run_native_session` verifies the config is loaded, derives the effective mixed port, builds `ServerConfig`, starts `NativeCoreServer`, emits `Connected`, forwards telemetry as `CoreEvent`s (traffic deltas, system stats, logs, per-connection traces, sniffer samples), then shuts down and emits `Disconnected` on the stop signal.
- Subprocess: `CoreManager::start` writes the config and spawns the binary, then the session task runs the backend-specific stats loop until `stop_rx` fires, kills the child and emits `Disconnected`.

Both arms end in the same `CoreEvent` shapes, so the UI, persistence and screens never branch on which backend served the session. Design rationale and seams: [`native-core-integration.md`](native-core-integration.md). Per-protocol capability: [`../reference/native-core.md`](../reference/native-core.md).
