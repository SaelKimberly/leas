# leas — Roadmap

## Phase 0 — Foundation (scaffolding) ✅

- ✅ Cargo workspace with 4 crates: leas (bin), leas-core (lib), leas-db (lib), leas-config (lib)
- ✅ SQLite schema (tables: profiles, groups, subscriptions, routing_rules, dns_settings, profile_extensions, server_stats)
- ✅ `profiles` table includes `core_type TEXT NOT NULL DEFAULT 'xray'` — selects proxy backend (xray / sing-box / auto)
- ✅ `groups` table includes `core_type TEXT` — optional per-group override for subscription servers
- ✅ **CoreType enum**: `Xray` | `SingBox` | `Auto` (Auto resolves via protocol-core mapping table)
- ✅ Protocol enum covers both backends: xray-native protocols + sing-box-only protocols (TUIC, Hysteria v1, Naïve, AnyTLS, ShadowTLS, Tor, SSH, Tailscale, ShadowsocksR, Redirect)
- ✅ Application config JSON file format (AppConfig struct with CoreConfig, GuiConfig, InboundConfig)
- ✅ Shared data models/enums (CoreType, Protocol, resolve_core, 7 model structs)
- ✅ Workspace builds with `cargo build`, tests pass with `cargo test`, clippy clean

## Phase 1 — TUI Shell ✅

- ✅ Ratatui main layout: tabbed panel structure (Profiles, Settings, Routing, DNS, Logs, Statistics)
- ✅ Profile list DataGrid with sortable columns (type, remarks, address, port, delay, speed, traffic, core)
- ✅ Group/subscription filter strip with live client-side search
- ✅ Status bar showing connection status + key hints (`[Tab] Next  [Ctrl+Q] Quit`)
- ✅ Tab navigation (Tab/Shift+Tab), profile list navigation (Up/Down/Home/End)
- ✅ Placeholder screens for Settings, Routing, DNS, Statistics
- ✅ DB query methods: get_all_profiles, get_profiles_by_group, get_all_groups, get_profile_extension, get_server_stats, get_all_profiles_with_details
- ✅ AppState with filtered/sorted profile list
- ✅ Keyboard shortcuts: q/Ctrl+C quit, / search, Esc clear filter, Tab cycle tabs

## Phase 2 — Profile CRUD ✅

- ✅ Add server forms per protocol (VMess, VLESS, Shadowsocks, SOCKS, HTTP, Trojan, WireGuard, Hysteria2, Hysteria v1, TUIC, Naïve, AnyTLS, ShadowTLS, Tor, SSH, Tailscale, Dokodemo-door, Custom)
- ✅ Core type selector per profile: auto-detect (default), force xray, force sing-box
- ✅ Edit/delete/clone/copy servers
- ✅ Share URL import (vmess://, vless://, ss://, trojan://, socks://, hysteria://, hysteria2://, tuic://, naive://, anytls://, shadowtls://, wireguard://, ssr://, http://) — all 14 protocols with fallback chain
- ✅ Multi-server selection operations
- ✅ Set default server, move/reorder servers
## Phase 3 — Core Integration

- ✅ **Dual-backend CoreManager** — `CoreManager` is a Rust trait (start/stop/is_running/running_core_type/sighup_reload/rewrite_config); `RealCoreManager` spawns xray or sing-box subprocesses (requires `log_tx: Sender<String>`), `MockCoreManager` is a test double with `Option<String>` error fields
- ✅ `CoreProcess` for xray-core (spawn `xray run -c <path>`)
- ✅ `SingBoxProcess` for sing-box (spawn `sing-box run -c <path>`)
- ✅ Config builder split: `config_builder_xray.rs` (xray-core JSON) + `config_builder_singbox.rs` (sing-box JSON)
- ✅ Protocol → Core auto-resolution: TUIC/Hysteria/Naïve/AnyTLS/ShadowTLS/Tor/SSH → sing-box; all others → xray-core
- ✅ gRPC API abstraction: `StatsProvider` trait for stats; xray uses native gRPC, sing-box uses experimental v2ray_api. Stats polling loop (3s interval) in connect_to_profile. Live Statistics tab with traffic and system stats.
- ✅ One-core-at-a-time: switching profiles between backends stops current core, starts the other
- ✅ Connect/disconnect flow
- ✅ Auto-detect xray and sing-box binary paths (PATH, configured paths)
- ✅ Process spawn/kill/restart lifecycle with health polling

## Phase 4 — Subscription Management ✅
-
- ✅ Add/edit/delete subscription groups
- ✅ Update all/group subscriptions (HTTP download + parse)
- ☐ Update via proxy
- ✅ Subscription format detection (base64, plain, v2rayN, sing-box) — streaming decoder with auto-encoding detection
- ✅ Scheduled auto-update

## Phase 5 — Speed Testing ✅

- ✅ TCP ping (connect timeout test)
- ✅ Real ping (HTTP request through proxy)
- ✅ Speed test (download test through proxy)
- ✅ UDP test
- ✅ Fast batch ping (all servers)
- ✅ Fast + real batch ping (all profiles), and its scoped variants: successful / new / successful+new / failed
- ✅ Sort by results, remove invalid servers
- ✅ Test result caching in SQLite
- ✅ Test cell reports the endpoint's representative link (delay band or failure marker), never a failed link's stale delay
- ✅ **Windows reliability (from a 796-link Fast + Real Ping run on a non-English Windows host)** — four defects the run's own log proved, each fixed with a regression test:
  - ✅ Fast-probe failure classification is TYPED, not text-matched (`IoFailure { kind, raw_code, text }` + pure `classify_io_failure`). Localized OS messages had put 332 unreachable endpoints in the soft class and sent them to the real level
  - ✅ Persisted failure text is bounded (`cap_error_text`) without losing the `(os error N)` code or truncating an `UNTESTABLE_PREFIX` marker
  - ✅ DNS lookups dedup by host with answer fan-out, in-flight lookups defer the gate, and the deferral window outlasts the resolver deadline (`deferred=0` against 196 failures before)
  - ✅ Logs tab reconciles its two producers through one event-time watermark and its poll no longer discards the window between reads
- ⏳ **QUIC on Windows (`WSAEMSGSIZE` / os error 10040)** — NOT fixed, needs a repro. quinn 0.11 exposes no public socket-buffer or GSO API, and a 1420-byte payload is far below any plausible send buffer, so the cause is unestablished. `socket2` is already in the lock if a repro justifies a direct dep

## Phase 6 — Settings Panel ✅
-
- ✅ Core type/settings, log level
- ✅ Inbound config (SOCKS, HTTP, mixed ports, sniffing)
- ✅ DNS settings (simple + advanced)
- ✅ Routing rules management (add/edit/delete/reorder)
- ✅ GUI settings (language (en/zh), theme, refresh interval)
- ✅ System proxy integration (set/unset HTTP_PROXY)
- ✅ TUN mode config
- ✅ Mux/fragment config
- ✅ Statistics toggle
:- ✅ Split-pane navigation (collapsible tree + form panel) — unified SettingsMode::Split replacing 10+ per-section form variants; Ctrl+W tree/form focus switching, SPLIT_SETTINGS_TREE const for easy section addition

## Phase 7 — Advanced Features

- ✅ Logs tab — wire core stdout/stderr pipeline to TUI display with live scrolling, color-coded log levels, and keyboard navigation (Up/Down/PgUp/PgDn/Home/End)
- ✅ Sing-box config builder completeness — config generation for all 17 outbound protocols (ShadowsocksR, Hysteria v1, Naive, AnyTLS, ShadowTLS, Tor, SSH, Tailscale, VMess, VLESS, Trojan, WireGuard) via 12 new protocol arms + build_tls helper + protocol code mapping
✅ WireGuard sing-box peer model — complete form fields for multi-peer arrays, pre-shared keys, allowed IPs
- ✅ Sub-healer profile model adoption — uid-based PK (sig ^ cred_hash), spec_blob (JSON-encoded ProtocolConfig, wrapped by the Proto identity container) replaces flat fields, Connection table for many-to-many Profile↔Group, bridge traits (ProfileLegacy/ProfileMut) for old parse/format compatibility, leas-proto crate with protocol config types. All 401 workspace tests pass.
- ✅ Export system — Profiles `Ctrl+E` scope/destination popup; direct Turso streaming export for Alive/Resolved/Active/Full; bounded file and clipboard sinks; exact subscription header and candidate-link count semantics; Resolved DNS→IP export preserves default SNI/authority and port specs.
- ✅ Advanced form fields — multiplex, V2Ray transport (WS/gRPC/QUIC/HTTPUpgrade), TLS options (ECH, uTLS fingerprint, Fragment) all added to protocol forms
- ✅ ProfileCore dedup — normalized schema (profile_cores + group_profiles) eliminates redundant storage for shared configs
- ✅ Version update check — GitHub releases API, download, install with .bak rollback, Updates settings form with per-core status
- ✅ Batch import — bulk import multiple share URLs at once via AppMode::BatchImport with scrollable results list
- ✅ Log source filtering — per-source toggle (core/TUI) via c/t keys in Logs tab, filter bar indicator
- ✅ Per-protocol core overrides — Settings → Protocol Core section with per-protocol Select:Auto/Xray/SingBox, 3-level resolution (profile→config→auto) in resolved_core() helper
- ✅ Group cycling shortcuts — [ / ] keys for next/previous group on Profiles tab, wraps with rem_euclid, skips graveyard
- ✅ Ctrl+G fallback — alternative connect key for terminals that can't distinguish Ctrl+Enter
- ✅ Group overlay fixes — sorted visual selection, Clear Group advertised, ALL-group mirror cleanup on delete
- ✅ Conditional Group column — shows profile origin group on "All" tab, hidden for specific groups, hidden at <107 col width
:- ✅ Speed test config — configurable ping URL, exit-IP provider (`IpProvider`, fixed set with automatic fallback), timeouts, batch page size via Settings > Speed Test form with persistent SpeedTestConfig
- ✅ Batch-then-real-ping — automatic real ping (with IP info) on fastest profiles after TCP batch, TestTypeUpdate event for emoji switching
- ✅ Profiles table redesign — connected indicator column (▶/space), IP info column, graveyard group filter, connected row highlight (TABLE_ROW_CONNECTED), selection preserved across sort column changes
- ✅ Log source validation toggle — V key on Logs tab toggles validation/subscription source logs visibility
- ✅ Graveyard orphan promotion — subscription_upsert_profiles promotes re-imported profiles from graveyard
- ✅ Keybinding harmonization — Ctrl+D disconnect, Ctrl+Shift+S copy share URL, docs/guides/tui-manual.md updated
- ✅ Heed-backed log storage — `logs` LMDB database with postcard-encoded LogMessage entries, `HeedLogStorage` in leas-core::log_heed, non-blocking TuiLogLayer via std::sync::mpsc channel, background batched heed writer (spawn_blocking, batch up to 100), MapFull→auto-resize (1 GB default, doubles up to 8 GB, atomic fail counter) with backoff retry — batches retried after successful resize, never dropped, async heed read wrappers (spawn_blocking), lazy log loading on first Logs tab access, and non-TLS LMDB read transactions so reader slots release with each transaction.
- ✅ Geo file auto-update — periodic download of geoip.dat/geosite.dat for both backends
- ✅ Log to file toggle — core log persistence with configurable path
- ✅ Certificate pinning UI — SHA-256 fingerprint or PEM upload per profile
- ✅ Default skip cert verify — global security toggle in Core settings
- ✅ Clear all stats — reset traffic counters per profile or globally
- ✅ Mux protocol selector — per-profile sing-box mux protocol choice

## Phase 8 — Polish & Release
-
- ✅ UI/UX fixes — 25+ items across 9 files: centered confirmation overlay with quit safety; inline form validation with error display; empty-state guidance when no profiles; blinking terminal cursor in search mode; actions panel collapses in non-profile tabs; consistent boolean `[X]`/`[ ]` and select `< value >` display; Home/End in group overlay; PgUp/PgDn in profiles list; inverted log scroll (Up=newer); Ctrl+A select-all/deselect-all; connection status indicator in tab bar; update indicator with yellow background; statistics screen refactored into 3 bordered sections; extract_form_fields helpers for form mode dedup

- ☐ i18n (en, zh, ru, fa)
- ✅ Theme system (dark/light/custom) — integrated ratatui-themes + ratatui-cheese crates, ThemeStyles + Palette pattern, palette_bridge bridge module, DataTable widget extraction, mouse support, tui-popup overlays
- ✅ Scrollbar support — themed scrollbar via tui-scrollbar 0.2 integrated into DataTable widget: Layout::horizontal split, GlyphSet::Unicode arrows, thumb/track styles via ThemeStyles::scrollbar_thumb/scrollbar_track, wired into logs and profiles screens; Profiles uses SQL-filtered total and feed-global viewport position without loading the full feed
- ☐ Responsive layout for terminal resize
- ☐ Error handling & recovery flows
- ☐ man page / --help
- ☐ CI/CD, packaging
✅ Performance optimization — add_log owned strings (saves 3 allocs/log), get_str closure (saves 5-17 allocs/settings save), parse_core_log_line eq_ignore_ascii_case (removes to_lowercase alloc), BatchImport mutable scroll (avoids Vec clone per keypress), TCP ping spawn no longer clones Vec<Profile>, updater Cow<OsStr> over to_string_lossy

## Phase 9 — v2rayN Parity

### Routing

- ☐ Proxy chain — front proxy (入口代理) + back proxy (落地代理) per subscription group, with tag-based outbound chaining
- ☐ Policy groups/balancers — Xray 4 types (random/leastPing/leastLoad/leastConn) + sing-box 1 type, alias-based node selection with nested groups
- ☐ Routing mode switcher — quick Rule/Global/Direct/Unchanged toggle in status bar
- ☐ Rule set sources — custom geosite/geoip URLs with auto-update per routing rule
- ☐ Routing rules import/export — JSON array clipboard operations
- ☐ Process-based routing — per-process split tunneling (v2rayN v7.23.0 feature)
- ☐ End fragment support — outbound fragment for CDN evasion

### Subscription

- ☐ Multi-URL subscriptions — optional extra URLs merged into one group
- ☐ Regex filtering — filter imported profiles by alias during subscription update
- ☐ Subscription conversion target — convert between core types on import (convert_target field exists, always None)
- ☐ SIP008 format — Shadowsocks SIP008 subscription format support
- ☐ SOCKS4/5 share link import — socks:// scheme with SOCKS4 auth fields

### Clash YAML

- ✅ Clash YAML proto_spec parsing — `clash/mod.rs` with 29 ClashProxy/ClashXxx serde structs, `try_from_clash`/`to_clash` on ProtoSpec trait, per-protocol implementations for all 17 protocols, dispatch macro, roundtrip tests passing
- ☐ Clash API proxies view — real-time proxy group selector TUI tab
- ☐ Clash API connections view — real-time active connection monitor TUI tab
- ☐ Clash API providers view — subscription provider management and health TUI tab
### Core Management

- ☐ Automatic server failover — health-check based fallback between profiles in a group
:- ✅ Batch test parameters — configurable concurrency (real_ping_concurrency via SpeedTestConfig), timeout, test URL per test type (timeouts + URLs done via SpeedTestConfig in Phase 7)
- ☐ PAC system proxy mode — PAC file generation with GFWList integration (HTTP proxy only currently)
- ☐ Multi-core simultaneous support — run xray-core and sing-box concurrently for different groups

### System Integration

- ☐ Auto startup — systemd user service / autostart desktop file / launchd plist
- ☐ Sudo password input — polkit/privileged operation support for TUN mode on Linux/macOS
- ☐ Global hotkey bindings — system-wide key combinations for common actions
- ☐ DBUS integration — system proxy set via networkmanager/gsetting D-Bus instead of env vars

### Config & Advanced

- ☐ Full config template editor — raw JSON editor for both xray-core and sing-box formats
- ☐ Config backup/restore — WebDAV cloud backup with scheduled auto-backup
- ☐ JSON config import/export — export full profile as JSON, import auto-detect format
- ☐ QR code display — render share URL as ANSI QR code in terminal

## Phase 10 — DNS & GeoIP

- ✅ leas-dns + leas-geoip crates adopted — DNSCrypt-stamp DNS resolution (DOH/DOT/DOQ via hickory-resolver 0.26) and GeoLite2-City IP → country/city lookup (maxminddb 0.32 — 0.32 removed the `simdutf8` feature outright, so the manifest carries no feature list). Panic-free async init, per-instance cache dirs, workspace style clean (fmt/clippy/tests). Not yet wired into TUI.
- ✅ Resolve actual IP addresses of DNS-based endpoints in TUI — background enrichment pipeline (`ops/enrich.rs`): `spawn_dns_resolve` (TTL-gated, `x` key forces), results shown in the expanded panel's `IPs:` line; DNS hosts get `[?]` + `🏁` until resolved. Hard deadlines: 10s DNSCrypt-list download timeout + 8s overall lookup timeout — failed lookups never hang and materialize TTL-gated entries so auto-retriggers don't re-run.
- ✅ Location Info (country flags) — inbound country flag column (`🏴` unknown) from mmdb + outbound (egress) IP/country from real-ping `ip_info`, both in the single-line row; outbound also in the panel sub-table. DNS results persist across launches via `endpoints.resolved_as`/`resolved_at` columns.

## Phase 11 — Host Features

- ✅ leas-host-features crate adopted — whitelist feature extraction ported from sub-healer: SNI/exact-IP/CIDR membership checks (fastbloom fast-negative guard + exact HashSet/interval verification, zero false positives, IPv4-only), download-if-missing from hxehex/russia-mobile-internet-whitelist, `get_host_features(&ServerName)` main API. Standalone, not yet wired into TUI.
- ✅ Whitelist features wired into TUI — IP/CIDR + SNI membership flags (`🏳️`) in the Profiles single-line row, refreshed on every launch by the whitelist pass (`HostFeaturesLoaded` event); features never persisted (track current files).

## Phase 12 — Profiles UI Redesign ✅

- ✅ 16-column single-line endpoint rows — named `Protocol Info` column (`protocol/transport/security`, replacing the endpoint-level Type cell), inbound country flag, Address, Feat whitelist flags (IP/SNI merged), Test delay, outbound IP+country; Remarks, Delay, Speed, Traffic, IP-info, top-level Last Seen dropped from the single line (Remarks wiped from TUI and DB; Last Seen lives only in the panel sub-table)
- ✅ Test column (2026-08) — active protocol's delay `[ 12 ]` colored by threshold (green <500ms, yellow ≥500ms, red ≥1000ms); red problem labels `[name]` (DNS unresolved), `[fast]`/`[real]` (every protocol of the endpoint unreachable for that test, per session-only per-endpoint ping rounds in `AppState.ping_status`, reset at batch start). Placed after the `}=>` arrow, before Outbound's `[` bracket
- ✅ Feat column — IP+SNI flag cells merged into one 4-wide column (`🏁` DNS unresolved, `🏳️` IP/CIDR + SNI whitelisted)
- ✅ Expandable rounded panel — `IPs:` line with `(x resolve)` hint + 11-column per-protocol sub-table (marker, hex id, last seen, last used, Protocol Type, config type, delay, speed, traffic, outbound, country), capped at 8 visible sub-rows with a window-scrolled view (window follows the selected variant, separator shows the visible range) so a many-protocol endpoint can never grow taller than the viewport; panel keeps a 1-line gap below so the bottom border never touches the next row; height-aware scrolling so expanded rows never strand the last profiles
- ✅ Expansion nav semantics — expand lands on first sub-row; `↑`/`↓` walk variants; `↑` at sub 0 → full row; `↓` at last sub-row → next profile; `↓` from full row of expanded endpoint → re-enter sub 0; collapsed endpoint moves on one `↓`
- ✅ Sub-table newest-first sort — each endpoint's protocols sorted by `last_seen_at` desc in `deserialize_endpoint_rows` (stable, ties keep insertion order); superseded by the test-priority sort in Phase 15
- ✅ Protocol pin via Enter — Enter on a sub-row sets `manual_protocol_override` (`set_protocol_default`), Enter on the endpoint row clears it (`set_active`); both patch the in-memory row so the UI switches without a reload
- ✅ Sub-row selection feedback — selected sub-row renders as a REVERSE highlight across the full panel-inner width (`ThemeStyles::panel_row_selected`: fg foreground + `bg Color::Reset` + bold): the expanded panel sits on the endpoint row's `surface` highlight, the selected sub-row drops back to the common background as a "notch". Theme-safe — the former accent `bg on_highlight` was near-white in Charm/light palettes (invisible light-on-light). Explicit `Color::Reset` required because ratatui `Cell::set_style` merges and a bg-less style leaves `surface` in place
- ✅ Uniform row background — zebra striping removed from the Profiles grid; unselected rows share one background, selection/connected keep their highlights
- ✅ DNS persistence across launches — `endpoints.resolved_as` (comma-joined IPs) + `resolved_at` (unix secs); schema v1→v3 migration (SCHEMA_VERSION 3, `ensure_column` + explicit transaction + `protocol_rows.endpoint_id` index)
- ✅ Endpoint-scoped ping batches — Fast/Real Ping on a collapsed multi-protocol endpoint row pings all its protocols; on a sub-row pings the exact protocol (`get_batch_for_real_ping(batch_id, wave, limit, dedup_endpoints)`)
- ✅ Last Used column — `protocol_rows.last_used_at` set on connect, shown in the panel sub-table
- ✅ `x` key — force DNS resolution of the selected endpoint
- ✅ Column/panel rework (2026-09-11) — endpoint-level Type column removed (the kind moved into the panel's Protocol Type column), single-row `Protocol Info` column added, row-number column widened to a six-digit slot (100000+ profiles), panel capped at 8 visible sub-rows with window scrolling + a visible-range label, and panel column offsets made authoritative so the intended inter-column gaps actually render

## Phase 13 — Hardening & Identity Refactor ✅

- ✅ Code review findings fixed (31/31, 5 critical) — single-codebase fixes: sing-box credential extraction, xray streamSettings synthesis, routing matcher validation, hysteria2 auth/pinSHA256, uid-0 collapse (PlaceholderConfig whole-body sig, never zero), typed sig/cred_hash retrofit (uid = sig ^ cred_hash; sig from semantic identity incl. security TYPE; cred_hash from credential values; no creds → uid == sig), transport host for ws/grpc/http, PortSpec overflow/coalesce, shared port allocator (CorePool::port_allocator) + batch active guard, pool mutex, udp_test timeouts, throughput fractional math, last_seen bump on connect, StatsUpdate protocol-id lookup, delete_group orphan cascade, edit view threshold, endpoint_id index (SCHEMA_VERSION 3), host-features merge guard, host-features/geoip/dns download deadlines + atomic writes + heal-on-corrupt, DataTable tall-row clipping, UI fixes (footer filtered row, Esc closes settings, copy URL, refresh_interval draw gate), log writer flush deadline, aarch64 xray asset (arm64-v8a), gRPC timeouts, heed resize backoff. 521 workspace tests pass.
- ✅ ProtoIdentity refactor — crate-private `ProtoIdentity` trait (compute_sig + compute_cred_hash) + `Proto` identity container (OnceLock<Identity> cache, Defer-less: empty lock IS the deferred state) replaces per-config sig_cache/cred_hash_cache fields and the impl_sig_cache! macro; `ProtoSpec: ProtoIdentity` sealed; `sig()/cred_hash()/uid()` inherent on `Proto`; spec_blob bytes unchanged (no DB migration).

## Phase 14 — Batch Ping Enhancement ✅

- ✅ Parallel Fast Ping — phase-1 pings a page concurrently via `run_page_pings` (one TCP ping per unique address:port, `buffer_unordered` capped by `fast_ping_concurrency` default 200, in-page owner/follower dedup + cross-page `fast_cache`); fast ping probes inbound only, so it is all-or-none per endpoint and the existing `[fast]`/`[real]` marker math stays valid
- ✅ Wave-scoped Real Ping dispatch — `get_batch_for_real_ping(batch_id, wave, limit, dedup_endpoints)` with occurrence ranks computed over ALL real sessions of the batch (status-independent, stable across dispatches); phase-2 consumer is a unified wake/drain pass loop (waves 1..N, `batch_page_size` chunks, 200ms coalescing, empty-wave termination); a failed protocol defers its endpoint's siblings to the next wave; `[real]` appears only after the endpoint's last candidate failed
- ✅ Skip/test-all after endpoint success — `real_ping_test_all_protocols` (default false = skip remaining protocols after one succeeds; true = test all); applies to all-visible batches; endpoint-scoped batches always test every protocol (`dedup=false`, and `cancel_stranded_real_pings` is gated on dedup so a success never cancels siblings)
- ✅ Group-failure halving retry + parallel readiness — stack-based page-halving on config-build/core-start/no-port-ready failures down to per-profile cores (missing binary not retryable); per-port SOCKS5 readiness waited in parallel (`join_all`), dead port = item-level failure
- ✅ Concurrency defaults — `real_ping_concurrency` 5 → 100, `fast_ping_concurrency` 200; `real_ping_window` (20) stays only as the phase-1 wake threshold
- ✅ Stopped tests don't fail rounds — `error == "Cancelled"` no longer inserts into the round's failed set, so stopping a batch never paints spurious `[fast]`/`[real]` labels
- ✅ Tests — 4 `run_page_pings` unit tests (parallel/cap/dedup/cached), DB wave-query test (stable ranks + dedup), integration dedup test updated

## Phase 15 — Test-Priority Sorting ✅

- ✅ Tier model + shared comparator — `EndpointRow::sort_protocols_by_test_priority` / `best_test_priority_key` in the db crate; ascending key `(tier, u64::MAX - weight, latency, -last_seen_at, id)`; tiers 0 real-ok, 1 fast/udp-ok, 2 untested, 3 real-err, 4 fast-err, 5 DNS-unresolved; fresh failure dominates stored success; main-table representative = best protocol (min key). **Superseded in the key by the static config weight (2026-10-01)**: tier still outranks weight, but inside a tier the weight outranks latency
- ✅ `delay_source` provenance — `profile_extensions.delay_source` column (SCHEMA_VERSION 4, `ensure_column` migration): 0 fast, 1 real, 2 udp; written by the `SpeedTestResult` handler (from `test_type`) and `batch_upsert_buffer` (from session `ping_type`); real-ok survives restarts
- ✅ Live sub-table re-sort — `SpeedTestResult` handler re-sorts the owning endpoint's protocols on TcpPing/RealPing results (success or failure; UDP never re-sorts); `selected_sub` remapped by protocol id (only when the result's endpoint is selected); `EndpointInfoUpdated` unresolved→resolved DNS flip re-sorts; `filter_cache_valid` invalidated
- ✅ Error events mutate nothing — `if error.is_none()` gate wraps the whole ext mutation + upsert; a cancelled/failed test never ranks an untested protocol as real-ok and never writes a `delay = 0` row
- ✅ Main-table Test sort — `SortColumn::Delay` renamed `SortColumn::Test`; comparator ranks endpoints by best protocol's test-priority key; reachable via `o`/`O` cycle and speed-test menu item 7; dead duplicate `compute_filtered_indices` (state.rs) and dead `batch_upsert_buffer` (state.rs) deleted
- ✅ Tests — 18 new: comparator unit tests (tiers, fresh-failure dominance, latency ordering, dns sink, best-key), migration + SELECT round-trip tests, events tests (re-sort + remap, failure demote, dns sink, flip, cancelled-no-rank, UDP no-re-sort), main-table sort tests (best-protocol tier, failure/dns sinks). 553 workspace tests pass

## Phase 16 — Log-Dump Hardening ✅

- ✅ Cipher-aware Shadowsocks core routing — `XRAY_SS_METHODS` (AEAD + 2022-blake3 + `aead_*` aliases, from `proxy/shadowsocks/config.proto` + `cipherFromString`) and `SINGBOX_SS_METHODS` (18 methods from sing-box docs) in `protocol_core_mapping.rs`; `resolve_core` takes `ss_method`; legacy ciphers (`aes-*-cfb`, `aes-*-ctr`, `rc4-md5`, `chacha20-ietf`, `xchacha20`, `none`) auto-route to sing-box (xray-core's `CipherType` enum lacks them). Fixes the 6 "unknown cipher method: aes-256-cfb" core-start failures
- ✅ Builder cipher validation + Shadowsocks2022 arms — xray.rs and singbox.rs both reject ciphers neither core supports via `BuildError::InvalidProfile` (invalid config never written; a forced core fails at build with a clear error, never a core crash on startup); `Protocol::Shadowsocks2022` now builds under protocol/type "shadowsocks" (was: "not supported" error)
- ✅ DB write-contention retry — `retry_on_busy`/`is_busy_error` in `leas-db/src/retry.rs` (backoff 20ms doubling, 1.28s cap), wired into `update_endpoint_resolution` + `batch_flush_ping_buffer`; the 850 "database is locked" lines (enrichment herd, 20 ms-bursts) no longer drop writes. `Database::conn()` sets `PRAGMA busy_timeout=5000` on every pooled acquisition (the `open()` pragma is per-connection and never reaches pool conns — measured where 462 lock failures still fired in 5 second-bursts); all 49 write call sites route through it, so writers queue instead of failing
- ✅ Enrich hostname validation — `is_resolvable_hostname` (ASCII labels, no `?`/`=`/`:`/`_`/spaces) skips plugin URLs (`host:port?plugin=...`) and Telegram-channel garbage before hickory lookup; invalid names recorded as TTL-gated failed attempts
- ✅ WS vhost deprecation — xray wsSettings emit top-level `host` instead of deprecated `headers.Host` (typed path in `leas-proto/src/proto_spec/common.rs` + legacy dotted path in `config_builder/xray.rs`); kills the 152 "host in headers is deprecated" core warnings
- ✅ Log hygiene — `TuiLogLayer` filter `trace,hickory_net::h2=error` (391 DoH h2 noise lines suppressed, everything else stays trace+); enrich "no records found" DNS warnings downgraded to debug
- ✅ Forms — Shadowsocks2022 method select: removed invalid `none`, added missing `2022-blake3-chacha20-poly1305`
- ✅ REALITY config validation — the xray builder rejects `security: "reality"` without `realitySettings.publicKey`/`serverName` (6× `REALITY: Empty "realitySettings"` core-start failures from legacy VLESS blobs with `security=reality` and no key material); sing-box reality block fixed to emit only `enabled`/`public_key`/`short_id` (the URL's `spx` was being written into `short_id`, corrupting it — sing-box has no `spider_x` outbound field)
- ✅ Tests — 24 new (routing 12, builder validation + 2022 4, retry 4, hostname 2, ws-host assertions 2, reality validation 2, singbox short_id 1). 575 workspace tests pass
- ✅ Host validation — `validate_host` rejects unspecified IP addresses (`0.0.0.0`/`::`) as a hard rule (not gated by `allow_private_ips`); bracketed-IPv6 forms (`[::]`, `[::1]`) now parse for all host checks (previously slipped past everything). Subscription summary counts them as host validation. 5 new tests — 580 workspace tests pass
## Phase 17 — Quality Gate ✅

- ✅ Gate target selector — `just quality-gate code|deps|all` (and `quality-gate-ci`): `code` = fmt-check/clippy/nextest (source checks), `deps` = hakari-check/deny/machete/outdated/audit (dependency checks), `all` default. Run source checks without dep audits and vice versa.
- ✅ Tooling configs — rustfmt.toml (edition 2024, max_width 100, Unix newlines), criterion.toml (`.benchmarks/` home; `cargo criterion` is the only bench launcher), .config/nextest.toml (`ci` profile), .cargo/audit.toml (vuln scan; 5 allowed informational warnings), deny.toml (licenses/bans/sources).
- ✅ cargo-hakari unified deps — `crates/leas-hakari/` (renamed from workspace-hack to match the `leas-*` crate convention); `.config/hakari.toml` targets the two toolchain triples; regenerate after any Cargo.lock change.
- ✅ Hakari gate coverage (2026-09-11) — `hakari-check` runs `cargo hakari generate --diff` + `cargo hakari manage-deps --dry-run` + `cargo hakari verify`; `verify` alone cannot see a stale workspace-hack or a member without the dependency, which is how `leas-route` had drifted — the only workspace member with no `leas-hakari` dep, so its features were never unified. Dependency added to route; all three checks green.
- ✅ cargo-machete (unused deps, hard-fail) — 16 genuinely unused deps removed; OUT_DIR/build.rs-generated deps (prost, tonic-prost, tonic-prost-build) and the documented tokio-rustls override ignored via `[package.metadata.cargo-machete]`; hakari crate's deps ignored by design (regeneration command in the manifest comment + AGENTS.md).
- ✅ cargo-outdated (version freshness, informational `--exit-code 0`) — 12 patch-level updates applied; 4 semver-major tracks applied (toasty 0.10, base64 0.23, brotli 8, sha2 0.11) with breakage verified — zero code changes required; residual outdated entries are graph-inherent dual-major pins in the generated hakari crate. *(Superseded by the 2026-09-28 pass below — kept as the record of that pass.)*
- ✅ Dependency refresh 2026-09-28 — every direct dep to its latest minor, and every 2+-crate dep hoisted to the root `[workspace.dependencies]` (14 hoisted: base64, base64-simd, bytes, flate2, lru, md-5, sha2, parking_lot, rcgen, tempfile, tokio-rustls, webpki-roots, x25519-dalek). **Nine semver-major bumps landed, all behaviour-neutral**: toasty 0.11, maxminddb 0.32, compact_str 0.10, brotli 9, zstd 0.14, yaml-rust2 0.13, rstest 0.27, ratatui-themes 0.3, dirs 7. No call site changed; the only source touches were a `cargo fmt` whitespace cleanup in `log_heed.rs` and a comment-only rstest version correction in three native e2e test files. The one behavioural fix: `heed` moved to `default-features = false`, because the LMDB store uses heed's native `U64BE`/`Bytes`/`Str`/`Unit` types and encodes by hand with postcard — its unused `serde-bincode` default was the sole reason `bincode` 1.3.3 (RUSTSEC-2025-0141) sat in the graph, which was the only red item on the deps gate. Residual dual-majors are all transitive, each now attributed to its REAL parent (AGENTS.md). Also recorded: `cargo deny check advisories` under-covers this tree and is not the advisory gate of record (AGENTS.md § Verification).
- ✅ CI hygiene — `.cargo/audit.toml` at `.cargo/` (cargo-audit has no `--config` flag and does not expand `~` in config paths); 1381 tests pass, clippy `-D warnings` clean, fmt clean.
- ✅ Clippy-allow audit (2026-08-27) — every `#[allow]/#![allow(clippy::...)]` in the workspace reviewed on Rust 1.98: 38 stale/fixable attributes removed and the source fixed instead (14 `manual_let_else` rewrites, 70 `must_use`/const fixes via `clippy --fix`, `option_if_let_else` → `map_or_else`, iterator loops replacing index loops, heap-allocated large arrays, vmess `Cipher` variants boxed for `large_enum_variant`, XUDP `open_udp_session` de-asynced with all call sites migrated, cast sites converted to checked arithmetic); 16 defensible keeps rewritten as two-line attrs with explicit `reason = "..."`. Clippy pedantic+nursery zero-warning workspace-wide; quality-gate code green.

## Phase 18 — Native SOCKS5 (client + UDP inbound) ✅

- ✅ SOCKS5 client handshake — `protocol/socks` replaces the placeholder: greeting → method selection → RFC 1929 sub-negotiation → CONNECT → reply, each step under `timeouts::PROTOCOL`, wired into `protocol::connect`. Credentials come from unvalidated share URLs, so an over-long one is `Socks5Error::CredentialTooLong`, never a panic; an empty username counts as absent (no `ULEN = 0` frame on the wire); `REP` is checked before `RSV` and a non-zero reply `RSV` is logged, not fatal (neither fast-socks5 nor xray validates it). The client's UDP side stays `NotImplemented`: SOCKS5 datagrams need a raw UDP socket, not the (possibly TLS-wrapped) stream this layer sits on.
- ✅ UDP ASSOCIATE in the inbound — `Socks5InboundConfig::udp` (default on) replaces the `0x07` refusal. One relay task per association routes EVERY datagram through the engine (`NetworkMask::UDP`), so an association may reach direct and proxy outbounds at once; `frag != 0` is discarded; reply headers reverse v4-mapped v6 addresses. The association pins to the control connection's peer address (an unpinned local process could otherwise hijack it), expires via `UDP_PIN_DEADLINE` when no datagram ever arrives, and ends on control-TCP EOF — the control read half is polled from the first iteration, so an associate-then-disconnect client cannot park the task and leak its two sockets.
- ✅ Splittable datagram carriers — `PacketTunnel::split() -> (PacketReader, PacketWriter)` with per-carrier halves (`vless::{PacketReader,PacketWriter}`, `vmess::udp::…`, `trojan::…`, `hysteria2::udp::{UdpReader,UdpWriter}`); each carrier now separates per-direction framing state from its transport (`VmessClientStream` = transport + `VmessRead`/`VmessWrite`; hysteria2 shares its h3 keepalive through an `Arc` so the session outlives either half), and vless/trojan frame readers resume a cancelled read from struct-held progress. `PacketTunnel::recv` spans several awaits for the stream carriers, so racing it in a `select!` desynchronised the tunnel; the proxy leg (`run_proxy_leg`) now owns the split tunnel with the reader in its own task. VLESS XUDP refuses to split (shared mux tunnel, no halves).
- ✅ Per-datagram failure isolation — a malformed header, unroutable destination, failed bind/send, refused per-packet destination or full proxy queue drops that datagram only; the leg's exit clears itself so a later datagram re-opens the tunnel after `PROXY_REOPEN_BACKOFF` (no permanent blackhole latch). Domain destinations resolve off the relay loop (spawned task for direct, inside the leg for proxy) so one DNS miss cannot stall the other flows or control-EOF detection; both upstream family sockets are bound together, so an `AAAA`-only name is reachable.
- ✅ Routing fidelity — the sniffer receives the WHOLE datagram, gated on `Engine::needs_sniff()`: a QUIC Initial is padded to ≥1200 bytes and the QUIC arm rejects a truncated packet, so the previous 512-byte prefix made `protocol: quic` rules unmatchable.
- ✅ Micro-optimizations — `TCP_NODELAY` on accepted inbound sockets, transport dials and direct outbound dials (Go cores set it by default); the greeting is read in two bulk reads instead of one per method byte; `reply_for` maps `io::ErrorKind` to RFC 1928 §6 codes (an unresolvable domain answers `0x04`, a refusal `0x05`, a local-firewall `EACCES` `0x02`) while dial errors keep both the kind and the target address.
- ✅ Tests — 494 native lib tests (from 442): UDP echo round-trip, fragment drop, block-drop with association survival, source pinning, multi-destination fan-out, teardown-without-a-datagram and control-EOF both proven by reply-port release, `unmap_v6`, every mapped `reply_for` kind, UDP header codec round-trip + malformed inputs, `Command` discriminants, greeting edge cases, exact client-handshake wire bytes (domain + IPv6 targets, RFC 1929 frame, `0xFF`/GSSAPI/over-long-credential refusals), and per-carrier split round-trip, concurrent write-during-pending-read, cancel-safety and EOF. Quality gate green (1698 nextest).

## Phase 19 — Secret Wiping (`zeroize`) ✅

- ✅ Crypto dependency features — the load-bearing half, invisible in source: `zeroize` is NOT a default feature of `aes` 0.9 / `aes-gcm` 0.11 / `chacha20poly1305` 0.11 / `ctr` 0.10 / `hmac` 0.13 / `sha2` 0.11 / `md-5` 0.11 / `blake2` 0.11, so every VMess/VLESS cipher instance was leaving its expanded round keys, ChaCha state and HMAC blocks in freed memory; and `zeroize` IS in `x25519-dalek`'s defaults, which `default-features = false` silently stripped, so the REALITY dual-agreement scalar and every `SharedSecret` were dropped unwiped. Both manifests now list the feature explicitly (verified via `cargo tree -e features`); zero code churn.
- ✅ TLS engine key material — `Zeroizing` on the whole TLS 1.3 key schedule (`hkdf_extract`, `hkdf_expand_label`, `derive_secret`, `handshake_secret`, `master_secret`, `finished_key`, the new `crypto::TrafficSecrets` pair alias), the TLS 1.2 PRF chain including every `A(i)` intermediate (`p_hash`/`prf`/`master_secret*`/`key_block`/`finished_verify_data`), `X25519KeyPair::agree`, `reality::auth::derive_auth_key`, and the hybrid `pq ‖ classical` IKM buffer. Wire-visible outputs (`transcript_hash`, `finished_mac`) stay plain.
- ✅ ML-KEM secrets — `mlkem::SharedSecret` is `#[derive(ZeroizeOnDrop)]` with hand-written length-only `Debug` (the derive printed a decapsulation key into any log line), and `mlkem::SecretKey` wraps RustCrypto's `DecapsulationKey`, which wipes itself on drop. (Original form, replaced 2026-09-18: liboqs never wiped its own `newtype_buffer!` `Vec<u8>`, so `encapsulate`/`decapsulate` took ownership via `into_vec()` into a `Zeroizing`.)
- ✅ Native protocol key material — VMess (`cmd_key`, `chacha20_key_32`, the AEAD-KDF's heap `msg`/`pad_key` buffers, and `Session` via `#[derive(ZeroizeOnDrop)]` covering all five key/IV fields with no call-site churn), VLESS `mlkem768x25519plus` (`nfs_key`, `united`), the trojan hex-SHA224 auth token (a replayable bearer credential), `Salamander.psk` (+ redacted `Debug`), and the SOCKS5 RFC 1929 credential frame.
- ✅ Documented non-goals — ring's `LessSafeKey`/`Prk`/`hmac::Tag` (opaque, no wipe hook — the derivation buffers on either side are the wipeable surface), AEAD write IVs (useless without the ring-held key), wire-visible values (nonces, salts, MACs, transcript hashes, public keys, `pin_sha256`, REALITY `short_id`), QUIC Initial keys in `leas-route::sniff` (derived from a public salt + DCID — any observer derives them), and the `leas-proto` config structs + `Socks5InboundConfig.auth` (the same bytes sit plaintext in SQLite and the generated core config JSON and live until process exit).
- ✅ Secret-exposure audit (non-zeroize) — the generated core config JSON is written into a `tempfile::TempDir`, which is created 0o700, so the 0o644 file inside is not reachable by other local users; secrets reach the core via that file path only, never argv; no `tracing` macro in the core/config/native/proto/tui crates interpolates a credential. The two real leak vectors found were the `Debug` derives on the ML-KEM secret types and on `Salamander`, both fixed.
- ✅ Verification — 1698 workspace tests pass unchanged (RFC 8448 key-schedule vectors, RFC 7748 X25519 known-answers, REALITY seal round-trip, hybrid-PQ handshake, Go-verified VMess vectors, trojan wire order), proving byte-identical crypto output; clippy pedantic+nursery clean (`type_complexity` on the traffic-secret pairs resolved with the `TrafficSecrets` alias, not an allow), fmt clean, hakari regenerated.

## Phase 20 — Native Core as Runtime Backend

- ✅ Runtime-only core selection — the in-process core (`leas-native`) is now a first-class backend, chosen AT CONNECT TIME and never persisted. Only the runtime enum moved: `leas_core::CoreType` gains `Native` (Display/`as_str`/`FromStr` `"native"`); the persisted `leas_proto::proto_spec::CoreType` stays `{Xray, SingBox}`, `resolve_core` still returns concrete values, and no native value ever reaches the DB or a generated core config — **no schema or persisted-enum change shipped**. Both reasons are load-bearing: `core_type` is a field of the identity-hashed `ProtocolEssentials`, so re-stamping it re-keys `ProtocolId` (= `ParsedProto::uid()`) and duplicates rows; and toasty renders the column as `TEXT ... CHECK ("core_type" IN ('xray','sing_box'))`, frozen in every already-created DB (the `PRAGMA user_version` tag is 6 and a mismatch makes `Database::open` DELETE the file — never a migration).
- ✅ Connect-time gate — `resolve_runtime_core(link_core, kind, forced, config, proxy_all_blocked)` (private in `ops/connect.rs`) owns the decision: native when the link's concrete core is `Xray`, the kind is one of the six native kinds (vless/vmess/trojan/hysteria2/shadowsocks/shadowsocks-2022, `capability::kind_supported`), no `protocol_core_overrides` entry forces xray/sing-box, and `capability::supported(kind, config)` passes on the LOADED config. A `native`/`auto` override asks for native (`asks_native`) and still faces the same gate — never silently native. Every refusal warns with host, kind, chosen core and rule/DNS counts (`REFUSED_KIND` / `REFUSED_PROXY_ALL` / `REFUSED_UNLOADED` / `REFUSED_CAPABILITY`). No new toggle shipped: `PROTOCOL_CORE_DEFS` (Settings → Protocol Core) and the per-profile core field still offer `Auto,Xray,SingBox`, and Auto resolution reaches native without one — spelling `native` in a `protocol_core_overrides` value is a config-file opt-in.
- ✅ Capability gates — `crates/leas-native/src/capability.rs` (`NATIVE_KINDS`, `kind_supported`, `supported`) defers every row native would serve worse than the subprocess: VLESS account `encryption` the connect path cannot dial (`mlkem_encryption_supported` runs the codec's own parser, so only an unknown/malformed scheme defers and never `mlkem768x25519plus` itself), non-vision VLESS flows, legacy VMess payload ciphers, non-zero `alter_id`, and mKCP `seed` / `header_type` including the share-link `path` seed carrier. A TLS fingerprint id is not a refusal (no roster row → engine default + approximated marker). Transports are matched POSITIVELY, so a new `TransportConfig` variant fails closed at compile time.
- ✅ VLESS `mlkem768x25519plus` account encryption works on the native core (2026-09-23) — the long-standing `pq-enc` "interop divergence" was NOT a wire bug: the reference server decoded our request and dialled the echo on every attempt, and the client received the full `200 OK` body. The record layer (`protocol/vless/encryption/mlkem.rs` `CommonConn::poll_read`) raised `UnexpectedEof` on a CLEAN end of stream at a record/padding-field boundary, so the probe's `read_to_end` discarded the completed response as `status 0 body ""`. It now mirrors Go's `io.ReadFull` rule (zero bytes into a field = clean `io.EOF`; partial = truncation), pinned by `eof_at_a_record_boundary_is_clean`, and the capability gate no longer defers the shape — Auto resolution picks the in-process core for a PQ account. Verified against the real Go `encryption.ServerInstance` in all three modes (`native`/`xorpub`/`random`) plus the `0rtt` window.
- ✅ `NativeCoreServer` — `leas-native/src/server/mod.rs`: `ServerConfig::new(socks, http, proxy, telemetry)` binds a SOCKS5 inbound (UDP ASSOCIATE on) plus an optional HTTP CONNECT inbound over a proxy-all engine. `stop()` is the watch-channel signal, `shutdown()` awaits the accept loops so the ports are released before the next `start` (no EADDRINUSE), `Drop` signals first and then aborts them, a failing HTTP bind unwinds the already-serving SOCKS listener, and a non-loopback bind warns that neither inbound authenticates its clients.
- ✅ HTTP CONNECT inbound — `inbound/http.rs`: bounded head scan (`MAX_HEAD_BYTES` 16 KiB, checked mid-line) that replays bytes the client pipelined behind the head into the tunnel (dropping them truncated the stream and stalled it), framed `400`/`403`/`407`/`431`/`501`/`502` refusals (`Connection: close` + `Content-Length` + a one-line reason), optional `Proxy-Authorization: Basic` compared by DECODING the client token (one indistinguishable 407 for missing/malformed/wrong), open-relay warning at bind, transient accept errors absorbed.
- ✅ Telemetry feed — `telemetry.rs`: `Telemetry` / `NativeEvents` with SEPARATE log and trace queues (traces drain first — the open/close pair matters more than the line), `TraceEvent::Opened`/`Closed` rows, `TraceGuard` emitting `Closed` even when the relay future is dropped mid-leg (inbound shutdown, task abort), `Counted<S>` wrapping each relayed stream to feed the shared byte atomics live, and per-window drop counts folded into one summary instead of one line per loss.
- ✅ Native session arm — `crates/leas/src/ops/native_connect.rs::run_native_session` replaces the subprocess arm for native sessions: binds the listeners, emits `CoreEvent::Connected(CoreType::Native)`, forwards telemetry on the EXISTING `StatsUpdate` / `SysStatsUpdate` / log shapes (so persistence and the Statistics screen behave identically; RSS from `/proc/self/status` `VmRSS`, which needs no page-size assumption) plus the new `CoreEvent::NativeTrace`, then `server.shutdown().await` + `Disconnected`.
- ✅ Native Activity tab — `Tab::NativeActivity` + `crates/leas/src/ui/native_activity.rs`: live per-connection trace rows from `AppState.native_activity` (`NativeActivityLog`, 2000-row session ring in `types.rs`, reset on each native `Connected`, still-open rows closed out on `Disconnected` so the counters stay exact), a `NATIVE_TRACE_BUDGET` of 512 traces per frame in `ops/events.rs`, window-then-format render and clamped scrolling.
- ✅ One-core-at-a-time now covers the in-process server (extends Phase 3) — `connect_to_profile` awaits the previous session task (`PREV_SESSION_TEARDOWN` 5 s, then abort) before binding its own listeners; `disconnect()` leaves a bounded waiter that gives the session `DISCONNECT_TEARDOWN` 3 s to run `server.shutdown()` + `Disconnected` instead of aborting it outright; `ui::run`'s exit path awaits that waiter before leaving the alternate screen.
- ✅ Two exit hangs fixed — the crossterm reader (`event::read()`) and the heed log batch writer (`std::sync::mpsc::recv()`) were `spawn_blocking` tasks that never returned, and `Runtime::drop` waits for in-flight blocking work, so quit parked forever. Both now poll in 200 ms slices (`IDLE_POLL`) against the canonical `AppState::shutdown_token`, which `main` stores unconditionally after `ui::run` returns and also from the panic hook (a panic unwinds past the normal store).
- ✅ Wiring — `leas` takes an unconditional path dependency on `leas-native`, whose tokio gains the `sync` feature; `cargo hakari verify` passes. Design brief: `docs/architecture/native-core-integration.md`; per-protocol matrix: `docs/reference/native-core.md`; keys and tab: `docs/guides/tui-manual.md`.
- ☐ Native real ping — real ping and speed test still need an xray or sing-box binary: the JSON config builders and the temp ping cores dispatch on the link's concrete `core_type`, so there is no native real-ping path and a native-only install fails real pings with `Binary not found`. Fast (TCP) ping is unaffected — it never spawned a core.
- ☐ Native routing + DNS — native is proxy-all, so any routing rule or non-default DNS setting demotes the connect to xray-core BEFORE `BuildParams` is built (the api flags follow the real core). Lifting this needs the routing engine and a DNS path wired into the native session.
- ☐ HTTP inbound surface — CONNECT-only (absolute-form/plain proxying answers `501`) and no user-facing auth: `HttpInboundConfig::auth` exists in the crate, but the profile model has no credential source, so the native session leaves it `None` and relies on the loopback bind.
- ☐ SOCKS5 UDP through a SOCKS5 outbound — `protocol/socks` has no `PacketTunnel` (`NotImplemented`: "socks5 udp (needs a raw UDP socket shape, not the stream tunnel)"), so a socks:// upstream carries TCP only. Inbound UDP ASSOCIATE over the five native proxy outbounds landed in Phase 18.
- ☐ Status-bar hints clipped (~25 columns, every tab) — pre-existing right-alignment miscount, not introduced here: `ui/status_bar.rs` sizes its filler from `str::len()` (bytes, not display columns) and inserts the update/download indicator spans AFTER that math, so the composed line overruns `area.width` and `Paragraph` truncates the tail of every documented hint row.

## Phase 21 — ProtocolId Identity Restore ✅

- ✅ Per-kind binary identity — production `ProtocolId` is now `ParsedProto::identity_once()` over the typed config fields (`proto_spec/identity.rs`: `ProtoIdentity::write_identity` → `IdentityWriter`), one traversal, zero allocation, no JSON serialization. `sig` hashes non-credential, non-default fields only (the "same way configured servers" grouping key); credentials go to a domain-separated second stream and yield `cred_hash = 0` when absent (then `uid == sig`); `uid = sig ^ cred_hash`, never zero. The canonical-JSON path (`canonical_triple`/`hash_bytes_sig`/`hash_bytes_cred`) and the test-only `Proto` identity container were deleted, along with the now-unused `utils::compute_cred_hash` — one owner, not two.
- ✅ Framing (a live collision class removed) — every field is written tag + explicit length; raw concatenation made `flow="ab",sni="c"` and `flow="a",sni="bc"` hash identically, silently merging distinct configs into one `Protocol` row. HashMaps (`headers`, `plugin_opts`, `torrc`) go through a key-sorted writer, `XHttpConfig::extra` through a canonical JSON walker (object keys sorted, small maps on the stack), `Vec`s through ordered lists.
- ✅ Defaults elided — a value equal to what `inject_to` emits when the field is absent produces the same identity as the absent form (`type=tcp`, `security=none`, VMess `scy=auto`, `insecure=false`, TUIC `bbr`/`native`/`h3`, kcp `mtu=1350`/`tti=20`/`header_type=none`, WireGuard `mtu=1420`, ShadowTLS `version=3`, SSH `user=root`). TLS-mandatory kinds (tuic/hysteria1/hysteria2/naive/anytls/shadowtls) additionally elide an inert TLS block, so `security=tls` and an absent `security=` no longer split.
- ✅ Parse-boundary discriminators kept — `ProtocolEssentials::write_identity` writes `proto_kind`, `config_type` and `core_type` before delegating, so no in-uid discriminator was dropped by the cutover. `proto_kind` is load-bearing: `Redirect`/`TProxy`/`Mixed` share one `PlaceholderConfig`, and the variant is only representable here.
- ✅ Per-kind defects fixed on the way (found by the audit) — `SsConfig` hashed a `HashMap` straight into the hasher (nondeterministic uid) and emitted `plugin_opts` in random order into the core config; `socks`/`http` had constant sigs (all non-credential state collided); trojan's REALITY `pbk`/`sid`/`spx` were in NEITHER stream (two reality servers with one password deduped to a single row) and now belong to `sig` as public server parameters; `tor`/`naive` hashed only their kind tag, `tailscale` only `control_url`; SSH hashed its default `user`; hy2/tuic/shadowtls/wg hashed builder defaults. Deliberately excluded from identity: `remarks`/`uuid_origin` (display/derived) and each config's duplicated `path` mirror.
- ✅ Format frozen + verified — `identity_format_is_frozen_for_every_kind` pins the exact `(sig, cred_hash, uid)` of one config for every dispatchable kind (22 goldens, incl. Clash-built tor/ssh/tailscale and the three placeholders), so a reorder/reframe fails loudly with a pointer to the required schema bump; `identity.rs` unit tests cover framing, map order, cred-isolation and the zero guards; endpoint tests cover default elision, credential-vs-sig separation and the three discriminators.
- ✅ Schema bump `user_version` 6 → 7 (deliberate wipe) — the new uids are unrelated to the v6 canonical-JSON values, so reusing a v6 file would re-key every protocol into a duplicate row and orphan its links. SQLite is recreated (LMDB logs survive). AGENTS.md decision 11 + decision 4, the retired context page and docs/architecture/architecture.md updated to the new mechanism.
- ✅ Bench row — `leas-proto/benches/identity.rs`, wired into `just bench micro`: 50–85 ns per `identity_once()` vs the 720–1070 ns measured for the canonical-JSON path, zero heap allocation (was two serializations + a `Value` tree per call).

## Phase 22 — DB ↔ TUI Deep Refactor ✅

- ✅ Page load to ONE statement — `Database::load_page_projection` joins endpoints ⋈ links ⋈ protocols with the page's ids inlined as integer literals (turso charges ~0.8 ms per BOUND parameter, so the typed path's ~600 binds were the whole cost) and decodes the display columns through toasty's own `Load` impls; the three deferred JSON carriers stay unloaded. 1,027 ms → 63 ms on the 7,656-endpoint reference feed, pinned by `page_projection_matches_the_orm_rows` against the typed `load_page_rows` (kept as the oracle).
- ✅ The SQL link order retired — `profile_link_order`/`order_links` disagreed with the decision-16 law for a DNS-unresolved endpoint (a live measurement sorted above a fresh failure; the law sinks every link of such an endpoint to tier 5). One implementation again: `RankLink::key`.
- ✅ Task state is runtime-only — `profile_stats.task_id`/`task_queue` dropped, `TaskScheduler` owns its own `states` map, and the `SchedulerDb` trait (with 3 impls + mock), `update_scheduler_state` and `sweep_orphans` are deleted. The gate has no database handle, so its per-transition read and the whole orphan-id class are gone at the type level; `complete(link, id, kind)` rejects a stale completion by explicit id.
- ✅ Write path *(retired by Phase 24)* — the flush drained to ONE coalesced patch per link and `apply_link_patches` wrote each existing row with a single literal `UPDATE` over the patch's groups, with one `VALUES`-CTE existence probe per 400-row chunk (no per-row SELECT, no bound parameters). The per-row statement was forced by the engine: turso has no `UPDATE … FROM (VALUES …)`. Phase 24 replaced it with one multi-row `INSERT … ON CONFLICT` per chunk — measured 29.0 → 10.0 ms per 512-patch window and 360 → 44.3 ms per 2 000 imported links.
- ✅ Import and bulk maintenance — `persist_parsed` writes the batch in one transaction through the bulk upserts; "remove failed servers" deletes through one `delete_endpoints` transaction; the routing-rule reorder is one transaction.
- ✅ Retention wired — `purge_expired` had no caller: a 10-minute task reclaims endpoints whose newest link aged past the retention window and reports `CoreEvent::RetentionPurged`, so the page re-reads.
- ✅ Durable-facts schema pass (`user_version` 8 → 9, deliberate wipe) — timestamps are epoch-second integers (deleting the fixed-width RFC3339 binder and the nanos parser; rank keys compare seconds), `protocols.cred_hash` and `endpoints.parent_id` plus the resolved-IP child-endpoint machinery are gone (`resolved_as`/`resolved_at` are the single owner), `last_seen_at` gained the index its predicates need, and the callerless query surface (`profiles_ids`, `profiles_link_pairs`, `profiles_failed_ids`, `profiles_enrich_seed_ids`, `profiles_count`, `LinkWriter::read`) was deleted. Note for the next agent: `#[auto]` on an integer timestamp column is `AutoStrategy::Increment`, not "now" — the writers stamp those columns.
- ✅ Measured record — `docs/aegis/specs/2026-09-14-db-tui-flow-audit.md` §7 (page cost, before/after) and §8 (phases 2–3, including the two plan deviations: the count cache dropped — 7.5 ms of a 63 ms load — and anchor-first re-anchoring rejected as 3× more expensive on the common path).

## Phase 23 — Endpoint Addresses + Turso Feature Audit ✅

- ✅ Resolved addresses are a table, not a JSON column (`user_version` 9 → 10, deliberate wipe) — `endpoint_ip(endpoint_id, ip_key)`, one row per address, replaces `endpoints.resolved_as`; `endpoints.resolved_at` stays as the DNS-attempt stamp the TTL gates on. `ip_key` is the address in a sortable packed encoding (a family byte — the `IpAddr` discriminant — then big-endian octets, 5 or 17 bytes), so B-tree byte order IS address order with IPv4 first. The set is deduped by the PK, queryable, and finally orderable — the property the JSON array never had. Consumers take `Vec<IpAddr>` end to end, so nothing parses or renders address text off the display path (ADR 0005).
- ✅ A new sort the old column could not express at all — `PageSort::Ip` orders endpoints by their lowest resolved address (sentinel `x'ff'` when there is none), wired into the `o` sort cycle and the header indicator, verified in the running TUI against a seeded feed.
- ✅ Every proposed Turso feature measured before it was designed around — `inet` cannot be ordered or indexed by the engine (no `OPERATOR '<'`: `ORDER BY`/`CREATE INDEX` are parse errors) and an operator-declared variant orders the TEXT (`10.0.0.1 < 9.0.0.1`); `smallint` needs STRICT, which toasty cannot emit (its column-type hatch reaches a *name* only, inert on a non-STRICT table); materialized views cannot express the page query (LEFT JOIN / LIMIT / window functions / scalar subqueries all refused) and cost 425 µs per write to maintain; `USING` index methods are `fts` + vector only; `array_agg` needs the experimental custom-types flag and returns an internal record payload; `likely`/`unlikely` are inert *and* hide predicates from index-seek detection; `ANALYZE` changes no plan here; MVCC `concurrent_writes` changes no reader latency (p50 27.0 → 27.6 ms). Full transcript: `docs/aegis/specs/2026-09-15-endpoint-ip-storage-design.md`.
- ✅ Reached the engine the way it is actually reachable — the driver's experimental flags verified through our own builder, with raw DDL for what toasty cannot emit; the verdicts hold on that route (validation goes live, ordering/indexing still refused), so none of them was a reachability artifact.
- ✅ Page path priced rather than assumed — one feed, one decode path: the address aggregate costs +3.3…+4.6 ms on an unresolved page (a floor) and +6.1 ms fully resolved; the two "obvious" restructures cost more (`rank_dns` join +7.7…+8.6 ms, a second id-inlined read +12.0…+13.6 ms), so the shipped shape stands.
- ✅ The file got **bigger**, and the record says so — +7.4% (4.03 → 4.33 MB at 6,528 addresses); the win is capability plus a bounded per-address cost, not bytes. The remaining lever (a materialized `endpoint_rank.rank_ip`: the IP sort 166.9 ms → 0.94 ms) is documented with its cost and deliberately not taken.
- ✅ Reference documentation — `docs/reference/database.md`: the schema, indexes, derived-state invariants, the six flows and the query map, with mermaid diagrams verified by rendering.

## Phase 24 — DB Performance Claims + Write-Path Batching ✅

- ✅ The expert reports' claims adjudicated against the engine, one by one — `docs/aegis/specs/2026-09-16-db-claim-verification.md` is the ledger for the external expert reports: what shipped, what the repo already does (materialized rank keys, inlined literals, batched rank refresh, prepared-statement caching), and what measurement rejected (MVCC, chunk widths 1 000–2 000, `cache_size`, expression indexes for search, `synchronous=FULL`, WAL pragmas that do not exist).
- ✅ Both remaining per-row write paths batched — `apply_link_patches` and `upsert_links_bulk` now emit ONE multi-row `INSERT … VALUES (…),(…) ON CONFLICT(protocol_id, endpoint_id) DO UPDATE …` per (400-row statement chunk, `ON CONFLICT` action), the action bucketed by the patch's column groups with `contains` and `DO NOTHING` when a patch carries none, so the group disjointness and the insert-on-missing contract are unchanged. Measured 29.0 ms → 10.0 ms per 512-patch window and 360 ms → 44.3 ms per 2 000 imported links; the retired existence probe and per-row `UPDATE` are gone (ADR 0002 amendment 4).
- ✅ The reason some SQL is hand-written is now a document, not folklore — `docs/reference/database-manual-sql.md` holds the rule (typed path first, raw SQL needs a recorded cause), the six causes, the per-site inventory with each site's measurement and the test that executes it, the Toasty blockers with their exact failures, the rejected alternatives, and the checklist for adding one. The stale "raw SQL is confined to PRAGMAs" claim in AGENTS.md decisions 4/21 and the `database.rs` bullet is corrected.
- ✅ MVCC mode re-evaluated for the write-wait workload — engine A/B proves disjoint writers avoid WAL's 5-second busy timeout, but five-run DB-API import+geo probe measured MVCC tax: total +32.0%, import p50 +47.0%, geo p50 +32.4%. MVCC remains opt-in (`LEAS_TURSO_CONCURRENT_WRITES=1`); default WAL stays. Existing WAL files cannot be converted in place by this engine; real-feed contention A/B remains open. (2026-10-08: the MVCC passive-checkpoint gap is FIXED — see ADR 0012 D-D.)
- ✅ The address carrier re-examined from a fresh angle and kept — `unhex(string_agg(hex(ip_key), ''))` (flag-free, `string_agg`/`hex`/`unhex`/`FILTER` are plain functions) decodes byte-identically to `group_concat(hex(ip_key), ',')` (277 == 277 addresses) but is equal in cost within noise, while the text parse it removes is 8–14 µs per page; slicing a split `(family, addr)` blob by a fixed width returns 367 addresses where 277 exist, so the packed single column stays.
- ✅ Baseline accuracy pass over the DB text — `AGENTS.md` decisions 4, 21 and 22 (the multi-row upsert shape, the raw-SQL rule with one owner, the retired per-row `UPDATE` clause), `docs/reference/database.md`'s query map and ping flow, ADR 0002 amendment 4 superseding amendments 1–2, plus the stale schema version, `resolved_as` and vanished-file references in the retired context page and docs/architecture/architecture.md (`groups.rs`, `ping/real/*`, a duplicated `settings.rs` bullet).
- ✅ Dependency hygiene on the same pass — `rustls` 0.23.43 → 0.23.45 (RUSTSEC-2026-0285), `cargo hakari generate` re-run per AGENTS.md and the generated hack crate's machete ignore list refreshed for the renamed dual-major `getrandom` keys it now carries. `just quality-gate` 8/8.

## Phase 25 — Crypto Dependency Hardening ✅

- ✅ ML-KEM is RustCrypto `ml-kem` 0.3.2, not liboqs — `oqs`/`oqs-sys` are gone, and with them liboqs' CMake + vendored C/C++ build. The wrapper keeps its public shape; `SecretKey` is now the 64-byte FIPS 203 keygen seed (RustCrypto's `DecapsulationKey` wipes itself on drop) and a `RingRng` adapter over `rand_core` 0.10 keeps ML-KEM key material on ring's CSPRNG instead of a second OS-RNG path. The swap is pinned by `mlkem768_seed_derivation_matches_liboqs_and_go_stdlib`: the encapsulation key for two fixed seeds was captured from the retired implementation and independently reproduced by Go 1.27.1 `crypto/mlkem` — byte-identical. Live proof: the hybrid `tls-pq` rows pass against real xray-core 26.3.27 and sing-box 1.13.16.
- ✅ xray's AES-CTR mask documented and pinned rather than dismantled — `ctr` stays (its hazmat banner is about unauthenticated *encryption*; this is a keystream mask whose integrity comes from the NFS AEAD and the `hash32` chain, and no RustCrypto API offers raw AES-CTR), now with the three oracles the self-consistent round-trips could not give: NIST SP 800-38A F.5.5 counter semantics, the `blake3.DeriveKey("VLESS")` + CTR composition, and the relay-chain keystream continuation offset — each against Go bytes.
- ✅ Dependency hygiene — `chacha20` un-yanked (0.10.1 → 0.10.2), `smartstring` → `compact_str` behind the existing `TinyText` alias, `postcard` defaults off (removes `heapless 0.7` / `atomic-polyfill`), and `subtle` replaces the hand-rolled constant-time compare. `cargo audit` went from 6 warnings to 3, and each remaining one carries a recorded reachability + re-evaluation trigger instead of being silenced.
- ✅ Governance — `#![forbid(unsafe_code)]` on both crypto crates (zero `unsafe` existed, so it costs nothing and closes the door), and `docs/reference/crypto-dependencies.md` as the authority for every non-default crypto site: cause, independent oracle, wire-compatibility statement, retirement trigger, plus the generator programs that reproduce the pinned vectors. Design spec, plan and ADR 0007 live in `docs/aegis/`.

## Phase 26 — Batch-Feed Scaling (per-link cost at feed scale) ✅

- ✅ Every per-link step of the Fast + Real flow priced before it was touched — `crates/leas/src/ops/ping/flow_cost.rs` (ignored perf lab: `cargo test -p leas --release --lib -- --ignored --nocapture flow_cost`, plus `LEAS_MEASURE_DB` for rows against a copy of a real feed). Every row is the MEDIAN of its samples, because the first sample of a section pays page-cache, statement compilation and pool setup that steady state never pays. Allocation COUNTS are unavailable in-process (`turso` installs a `#[global_allocator]` through its default `mimalloc` feature, and a second one is a compile error; `toasty-driver-turso` requests `turso` with defaults, so feature unification makes disabling it a `[patch.crates-io]` fork — not taken), so allocation figures are derived from the code path and backed by A/B timing of the allocation-free variant.
- ✅ The feed walk orders by endpoint id (`PageSort::Id`) — 3.9 ms per page raw and 3.0 ms in the walk, against 11.9 / 12.1 ms for the host order it used before; endpoint ids satisfy the walk's stability requirement (no write moves them) exactly as host text did. The tab keeps `Address` as its default sort; materializing `rank_host`/`rank_port` (which would make that 19–20 ms page index-driven, against 0.37–0.77 ms for the stored-key sorts) needs a schema tag — 13 is now taken by the 2026-09-23 early-data identity re-key, so 14 — and is deliberately not taken.
- ✅ Real probes load each `ProtocolId` once per batch — a `Protocol` row is shared by every endpoint carrying the same config (6,283 rows for 9,090 links on the reference feed) and the per-link reload measured 55–121 µs, i.e. 0.5–1.1 s of the plan's serial work. Read failures are not memoized.
- ✅ Result-driven page refetch bounded — per VISIBLE row and at most one per 500 ms while a batch runs, settled by `BatchEnded`. The refetch is a 22–25 ms page query + hydrate against a 16 ms tick, and a feed-wide run's results are ~98% off-page, so the unthrottled version kept the task that dispatches the probes reloading for the whole run.
- ✅ The write-behind flush trigger reads an `AtomicU64` instead of `DashMap::len()` (1.03–1.08 µs of `stage`'s 1.12 µs): `stage` 1,120 → 54 ns, `stage_result` 1,128 → 80 ns, with the counter pinned against the map through stage, coalescing, drain and both arms of a failed-window re-stage.
- ✅ The plan shares endpoints (`Arc<Endpoint>`, one clone per row rather than per link; `PlanLink` 472 → 336 B) and `dispatch_page` inserts per endpoint; `fast_probe` borrows the host instead of cloning it.
- ✅ Measured and deliberately NOT taken — a dedup key of `Arc<str>` (42 → 37 ns) or a prehashed `(u64,u16)` key (58 ns, *worse*); an index on `endpoints(host, port)` (the planner keeps the rank-driven plan plus a temp B-tree: 19.5 ms with the index, and forcing it 13.2 against 11.9 ms without); `CompactString` for `Endpoint.host` (94% of hosts fit the 24-byte inline form, but the site is one 26 ns clone per link and the type ripples through the toasty model).
- ✅ Recorded — ADR 0008 (decisions, rejected alternatives with their measurements, and the open items: the `Address` sort, `endpoint_rank::refresh` at ~22 µs per endpoint, and an intermittent exactly-3.09 s stall in the lab's in-memory batch that did not reproduce in isolation — `finish_batch` alone 35 ms, a cold `db.connection()` 153 µs, and two processes × four batches all 69–119 ms with `flushes=4 staged-left=0`).

## Phase 27 — Windows Compatibility

- ✅ One action per keypress on Windows — `handle_event` (`crates/leas/src/ui/mod.rs`) dispatched every `Event::Key`, and a Windows console reports a key-up record for every press, which crossterm maps to `KeyEventKind::Release` (`event/sys/windows/parse.rs`); every press therefore fired its action twice, and a paste doubled each character (no bracketed paste is enabled, so a paste arrives as per-character key records). The event boundary now dispatches `Press` only — mouse-synthesized keys were already `Press`, `Repeat` is unreachable without pushed keyboard-enhancement flags, and Unix terminals report `Press` alone, which is why the defect was Windows-only. Reproduced on the platform path by a crossterm probe built for `x86_64-pc-windows-gnu` and run under Wine: one keypress delivers `Press` + `Release`, a three-character paste six records and three actions.
- ✅ Cross-build recipe recorded (AGENTS.md § Verification) — `cargo zigbuild --target x86_64-pc-windows-gnu -p leas` needs `RUSTC` pointed at the rustup toolchain's `rustc` (a Homebrew rustc on PATH owns only the Linux std, and the `rustc-wrapper` hands sccache a bare `rustc` name it resolves from PATH) and a mingw-capable `windres` (`turso_sdk_kit`'s build script runs bare `windres`; Homebrew binutils cannot emit a PE resource, `llvm-windres` can). The target builds warning-free.
- ✅ Subprocess core discovery is Unix-shaped — `bin_manager.rs::find_binary` searched PATH through `which` (absent on Windows) and matched extensionless names (`xray`/`sing-box`, never `xray.exe`), so a subprocess backend could not be located there. `get_core_info` still holds the extensionless base names, and `bin_manager::exe_names` is now the single owner that spells them for the platform (`std::env::consts::EXE_SUFFIX`), used by the managed-directory check, the recursive search, the PATH lookup (`where` on Windows, `which` elsewhere) and by `updater`'s search inside an extracted archive, which had the same list hardcoded a second time. The drop-in archive path (`find_and_extract_archives`) also accepts sing-box's Windows `.zip`, not only the Linux `.tar.gz`. The in-process native backend remains unaffected. The platform spelling is covered by unit tests that run on either host; the Windows half is the msvc `nextest` job's to confirm.
- ✅ Backend updater is Linux-only — `updater.rs::release_asset_url` rejected every non-Linux OS and `asset_name` hardcoded `-linux-`, so Settings → Updates was dead on Windows. `asset_name` now takes the OS and arch as *inputs* (reading `std::env` inside made it untestable off Linux and turned "not implemented" into a runtime refusal), and names `Xray-windows-{64,arm64-v8a}.zip` / `sing-box-<version>-windows-{amd64,arm64}.zip` from the upstream tables: Xray-core's `.github/build/friendly-filenames.json` (`windows-amd64 → windows-64`) and sing-box's `build.yml` (`Compress-Archive` ZIPs). macOS keeps its refusal — `macos-64`/`darwin-arm64` exist upstream but no macOS target is claimed. The naming is now a `#[rstest]` table over (os, arch), so the Windows rows run on the Linux host too.
- ☐ Statistics memory row is blank on Windows — `ops/native_connect.rs::proc_rss_bytes` is Linux-only by design (0 elsewhere); `GetProcessMemoryInfo` would fill it. The `leas-db` `cache_routing` leak guard is Linux-only for the same reason: its bound is calibrated against `/proc/self/status` `VmRSS`, and a different probe would need its own calibration before it could assert anything.

## Phase 28 — DB Query Monitoring ✅

- ✅ In-process query monitor (`crates/leas/src/ops/db_monitor.rs`) — traces every Turso/toasty query keyed by `Database` method, with duration, retry count, success/failure, and a slowest-statement sample; ranked dump on demand via the `d` key on the Logs tab. Registry fold math (bounded circular sample window `SAMPLE_CAP=4096`, p50/p99, fail/retry rollup) is pure and unit-tested.
- ✅ Statement-level SQL is FREE from toasty 0.11's built-in per-query tracing (`toasty::query` events: `duration_ms`/`rows`/`error`/`db.statement`; DEBUG, WARN past `slow_statement_threshold` default 1s) — no driver fork. Retry count is NOT available there (one event per physical attempt) and comes from `retry_on_busy` recording the final count into the enclosing method span. The event shape is unchanged from 0.10 (verified in `toasty-core/src/driver/log.rs`), so the 0.10→0.11 bump needed no code change.
- ✅ Two-source aggregating `tracing::Layer` (`DbMonitorLayer`): `on_event` folds `toasty::query` metrics via the enclosing `db_method` span (`ctx.event_scope`), `on_close` folds the method's final `retries`. Every public `Database` method across `database.rs`, `profiles_query.rs`, `endpoint_rank.rs` carries `#[tracing::instrument(target = "db_method", …)]` (the literal target matches the Layer's `on_new_span` gate). Always-on (bounded ~1.3 MiB); histogram escalation noted if the per-statement lock ever shows in a profile.
- ✅ Informative slow-query line — `main.rs` `LogVisitor` now captures the `toasty::query` structured fields and renders `slow query [312.4ms]: <sql>` instead of the bare `slow query` (the reported subscription-update symptom: the old visitor kept only the `message` field).
- ✅ Spec/plan/verification in `docs/aegis/` (`2026-09-24-db-query-monitoring-*`); falsifier A (real toasty events attribute to a real `Database` method, no unattributed leakage) and falsifier B (`into_message` render) both unit-tested.

## Phase 29 — Clipboard Ownership ✅

- ✅ Clipboard writes stop silently no-opping — `Ctrl+E` export (every scope) and the three Logs copy paths reported success while the clipboard never changed on any desktop without a clipboard manager. `arboard::Clipboard` on Linux IS the X11 selection owner, so the create-set-drop in `ClipboardBuffer::finish` destroyed the serving window in `Drop`; the payload survived only if a manager won a hard 100 ms handover race, and `set_text` had already returned `Ok`. A single process-lifetime handle in `ops/clipboard.rs` now backs export, logs copy, paste and copy-URL; copy errors surface instead of being swallowed.
- ✅ Verified on a bare X server (`Xvfb`, no clipboard manager), the only environment where the defect is visible — 985,439 bytes delivered where the old code returned 0. A dev box WITH a manager reproduces the bug as a false success, so clipboard work must be checked there, not on the desktop. A display-less session returns `Err` per call and retries (infallible `LazyLock<Mutex<Option<..>>>` init: a panicking initializer would poison the cell for the rest of the process).
- ☐ `Database::open`'s recovery branch (`database.rs:250-264`) deletes the DB file on ANY `try_open_db` error, so a lock/contention failure — a second app instance against a live file — silently wipes a healthy database. It must distinguish real corruption from a transient open failure. (Observed 2026-09-29: a live 4.8 MB / 4,669-stat file reduced to 132 KB / 0 rows, schema and `user_version` intact, so the error branch and not a tag mismatch.)

## Phase 30 — Shadowsocks SIP003 plugins + VLESS TCP mux ✅ (except `mode=quic`)

- ✅ Typed, lossless SIP003 model (`proto_spec/ss_plugin.rs`) — `PluginSpec` replaces the old
  `plugin` + `plugin_opts` map pair; every wire key lands in a typed field or `extra`, and an
  unsupported spelling is PRESERVED (`Invalid(value)`) rather than rewritten to a default that
  would dial a server neither spelling describes. `SsConfig::plugin_opts` is **removed**, no shim.
- ✅ simple-obfs + v2ray-plugin framing, served natively (`transport/v2ray/`) — `obfs=http`,
  `obfs=tls` (a synthetic-TLS record writer, layouts pinned against real `sizeof`/`offsetof`), and
  `mode=websocket` (+`tls`, early data OFF). TLS stays outermost, so no chain phase is skipped.
- ✅ Plugin mux as the protocol phase (`transport/mux.rs` extracted from `protocol/vless/mux.rs` so
  both families share ONE codec; `protocol/ss/mux.rs` takes a per-session SS codec;
  `mux_session.rs` owns session/tunnel lifetime so a session id can never be duplicated).
- ✅ VLESS `mux` end to end — field, five parse forms, value-bearing identity, form fields
  (defaulted ABSENT so a form row and an imported row agree), Clash round trip. Usable spellings
  (`smux`/`yamux`/`h2mux`, unparseable values) are STORED and refused **by name** at `capability`,
  never at parse, so the row stays importable/exportable/`[untestable]`/purge-safe. Vision × mux
  is refused by name (Xray accepts vision only with its XUDP port-666 multiplexer).
- ✅ Batch pipeline fix (spec §8.1) — a datagram-mode row is no longer retired by a TCP fast
  failure it could never measure, in **either** batch kind, and that marker is retracted. The
  retraction re-stages the plan-time snapshot rather than blanking it, so a valid earlier marker
  survives. The single-ping fast path declines such a row outright.
- ✅ `outbound::dial` re-checks `capability` before opening a socket — it is the in-process surface
  the SOCKS5/HTTP inbound calls, and nothing on that path consulted the gate.
- ✅ Verification: tier-3b real-oracle rows against a live `v2ray-plugin`/`obfs-server`, plus a
  **structural** tier-3a differential against sing-box's in-process plugin client (raw-byte
  equality is not the claim — the WS key and the target session id must differ). Opt-in via
  `just plugin-bins`; a skip is not green.
- ✅ Schema tag 13 → 14 and `IDENTITY_VERSION` 1 → 2 — no column change, but every Shadowsocks and
  VLESS-mux uid re-keys, so the stored database is recreated on first launch. Stated in the release
  notes (`docs/aegis/2026-10-01-ss-plugin-release-notes.md`).
- ☐ **`mode=quic` — stopped at its own evidence gate, by design.** The client wire could not be
  pinned: the reference server (v2ray-plugin v1.3.2) embeds V2Ray 4.38.3, whose source is not in
  this repository, and three mutually incompatible QUIC wires are in-tree — so a guess would fail as
  an opaque handshake timeout. It is refused by name (`capability::QUIC_WIRE_UNPINNED`) BEFORE any
  dial, which also fixes the live defect it exposed: such a row used to open a TCP connection to a
  server answering on UDP/443. Unblocking needs the plugin's source or an upstream statement of its
  QUIC client's key/header/ALPN. Evidence: `docs/aegis/plans/2026-09-30-ss-plugin.md` (T22).
- ✅ Static config weight — a compiled, versioned prior over each link's transport/security discriminators (`proto_spec/weight.rs`), inserted into the decision-16 key inside the tier and materialized as `endpoint_rank.rank_weight` (raw BLOB column + `endpoint_rank_test_v2` covering index + `WEIGHT_VERSION` rebuild, no schema-tag bump); the `PlanScope::All` feed walk now orders by the law and freezes its ids before the first probe

## Phase 31 — Write contention, import integrity, DNS timing ✅

From the 2026-10-01 production run (74,014 endpoints / 145,268 links; 4,028-link Fast+Real
batch). Plan: `docs/aegis/plans/2026-10-02-write-contention-and-dns-timing-fixes.md` (15 tasks).

- ✅ **Timer floor + staleness deadline on the link writer** — the old loop wrote on a single
  staged row, so a 200 ms trickle committed 4,028 rows in **1,167** transactions; now **32** (52×).
  A single (non-batch) ping stages 1-3 groups, far below the floor, so `flush_soon()` wakes the
  task when the last one settles (a wake, never a UI-task commit).
- ✅ **Full jitter in `retry_on_busy`** — a fixed ladder is metastable; the callers that collide
  are the concurrent ones, so an un-jittered retry re-synchronises exactly what it was meant to
  break. Same attempt count and ceiling.
- ✅ **Import upserts are multi-row** for `endpoints` and `endpoint_groups` — those two families
  went **309,739 statements → 774**; the whole import is **~409,467 → ~100,500**, because
  `upsert_protocols_bulk` is deliberately NOT converted (deferred third family: its
  stored enum labels are the embed derive's `snake_case` idents and the JSON column encoding is
  unverified; it stays the next real win at a measured 117 µs/row).
- ✅ **Country writes are queued** — one owner, one transaction per drain, re-queue on failure.
  Per-host batching was a no-op (`waiters.len() ≈ 1`); the 88 aborts came from the old `break`.
- ✅ **A dropped import batch is reported** — it used to return `(0, …)` and leave the group `Ok`.
- ✅ **The purge scan left the write transaction** — it was holding the write lock for 3.1 s every
  10 minutes from a read-only full-table walk.
- ✅ **DNS deferral** — the permit wait is bounded by `DNS_LOOKUP_TIMEOUT` (report time is now a
  function of the timeout), the budget exceeds that bound, the poll backs off instead of spinning,
  and the clock resets when the state is re-armed.
- ✅ **Log fidelity** — the export pages heed instead of copying a 500-row cache (the 2026-10-01
  dump was 575 of 1,313 lines); the writer flushes in-flight on shutdown; the DNS-resolution
  `info!` line that was 79% of the persisted log is now `debug`.
- ✅ **Tracing fields split by destination** — `db.params` rides the session-only `detail` and can
  never reach `LogMessage`, because one bind is `protocols.config` (UUIDs, passwords).
- ✅ **Subscription failures say why** — a bounded `ValidationSummary` sample, classified by kind
  so a parse message cannot leak credentials into the persisted log.
- ✅ **Turso journal mode decided: WAL stays** — an A/B on synthetic feeds (no wipe of the real
  database) found MVCC 1.2-4.8x slower at 32 concurrent writers. See
  `docs/aegis/specs/2026-09-24-turso-mvcc-rollout-design.md` §12.
- ☐ **The `profiles_page` Active+Test cost is toasty's, not the plan's** — ~98 ms at 74k, flat in
  offset and flat in plan, against ~1.2 ms for the identical raw SQL. Neither `ANALYZE` nor a
  band-partial index changes it. The escalation is **keyset pagination**, which ADR 0001 and the
  band spec already name; not an index, not a statistics gap.
- ☐ **`upsert_protocols_bulk` is still one statement per row** — needs writer-side `as_db_label`
  for `TransportType`/`SecurityType`/`ProtocolKind` (each with a DB round-trip test) and the
  confirmed encoding of the two JSON blob columns.

## Phase 32 — Driver statement-cache leak (unbounded, text-keyed) ✅

- ✅ **Root cause found and measured** — `turso_sdk_kit`'s `TursoConnection.cached_statements` is an
  UNBOUNDED `HashMap` keyed by SQL text (no eviction), and `toasty-driver-turso` routes EVERY
  statement through `prepare_cached`. Our inlined-literal SQL (ids/values/timestamps — the C6 perf
  choice) is a new text per call, so each call compiled and retained an `Arc<PreparedProgram>`
  (~116–310 KiB) forever: `load_page_projection` with fresh ids grew **+123,580 KiB / 400 calls**,
  a varying `WriteBehind<LinkSpec>` window **+188,684 KiB / 200**. Text-keyed proven both ways (an
  IDENTICAL text saturates; a varying one climbs). No per-probe leak (engine + hyper-glue loops flat).
- ✅ **Reads fixed** — `load_page_projection` runs on the raw uncached `Database::direct`
  connection (`turso::Connection::query` uses `prepare`, not `prepare_cached`): **+123 MB → +8 MB**.
- ✅ **Writes fixed** — the crate now OWNS a local-only driver fork (`crates/leas-db/src/driver/`,
  from toasty `main` at its `turso = "0.8"` bump) whose `Connection::exec` routes `Operation::RawSql`
  (the inlined-literal bulk statements) through the UNCACHED `prepare` and `Insert`/`QuerySql` through
  `prepare_cached`: **+188 MB → plateau**. The old `SqlConn`/`RawConn` seam, `CacheSpec::RAW`,
  `write_window_raw`/`refresh_raw` and `Database::write_conn` are RETIRED — the bulk writers run on the
  pooled driver and keep their literal-inlining win. Contention stays retryable
  (`driver::error::classify_turso_error`), and a file-db link-window test pins the write path.
- ✅ **The import window is one transaction** — retired with the seam: every helper takes
  `&mut impl toasty::Executor`, so `SourceSpec::write_window`'s raw families and the typed
  `upsert_protocols_bulk` run on ONE pooled transaction, with the inlined-literal statements served
  by the fork's uncached `RawSql` route. See `docs/reference/database-manual-sql.md`.
