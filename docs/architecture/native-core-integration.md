# Native-core integration

Why the native backend runs in-process, where its seams are, how the shipped code deviates from the 2026-09-03 brief, and what is still open. Status: implemented 2026-09-03 at baseline `b2c1786ecd67be191912f0f1b020fab3f8753eae` (clean tree). This page does not own capability, protocol or transport coverage (that is [`reference/native-core.md`](../reference/native-core.md)), nor the durable rules (that is [`decisions.md`](decisions.md)), nor TUI usage and scenario evidence ([`../guides/tui-manual.md`](../guides/tui-manual.md), [`../guides/tui/`](../guides/tui/)).

## Why in-process

A profile the engine can serve connects with no core binary, no generated config file, no `find_binary`, no process spawn, no port-allocator probe and no readiness poll. The session is one `NativeCoreServer` inside the TUI process: it binds the mixed listener, dials the profile through `crates/leas-native/src/connect.rs`, and reports back through the same `CoreEvent` shapes the subprocess pollers emit.

The same engine is the probe: real ping dials the native tunnel (`crates/leas/src/ops/ping_native.rs` → `leas_native::probe::fetch`), so the test path has no core lifecycle either. ADR 0004.

The price is scope. The in-process core is proxy-all: one connected profile, no routing rules, no DNS server, no TUN, and seven protocol kinds (`NATIVE_KINDS` in `crates/leas-native/src/capability.rs`). Anything outside that runs the subprocess core, and the gate says so.

## Seams

Every claim below is a symbol in the tree, not a plan.

| Path | Seam |
| --- | --- |
| `crates/leas/src/ops/connect.rs` | `resolve_runtime_core` chooses the runtime core per connect; the task branches to `native_connect::run_native_session` before `ConfigBuilder`/`find_binary` are reached. `PREV_SESSION_TEARDOWN` (5 s) and `DISCONNECT_TEARDOWN` (3 s) bound the handover. |
| `crates/leas/src/ops/native_connect.rs` | `run_native_session`: binds the server, emits `Connected(Native)`, runs the telemetry adapter, emits `Disconnected`. Cadences: 3 s traffic deltas (same as the xray gRPC poller), ~9 s sys stats, 1 s Sniffer snapshot. |
| `crates/leas-native/src/server/mod.rs` | `NativeCoreServer` and `ServerConfig`: a proxy-all `leas-route` engine with one proxy outbound tagged `proxy`, one mixed listener, cooperative `stop`/`shutdown`. |
| `crates/leas-native/src/inbound/mixed.rs` | One listener for SOCKS5 and HTTP CONNECT, selected by the first byte. |
| `crates/leas-native/src/capability.rs` | `kind_supported`, `support_reason`, `supported`: the config-level gate. |
| `crates/leas-native/src/telemetry.rs` | `Telemetry`, `TraceEvent`, `SnifferSnapshot`, `HOST_TABLE_CAP` (1000). |
| `crates/leas/src/ops/ping_native.rs` | Real ping: one tunnel per attempt, one HTTP/1.1 request over it. |
| `crates/leas-core/src/core_type.rs` | `CoreType::Native` exists for runtime identity only (display, sort, statistics label). The proto enum has no such variant. |
| `crates/leas/src/ui/metrics.rs`, `crates/leas/src/ui/native_activity.rs` | Render the session: live connection rows, totals, and the `in-process (event feed)` API line. Scroll state is a module-local atomic. |

## Resolution rule

Native is asked for by a `protocol_core_overrides` value of `native` or `auto`, and by any link whose protocol kind and loaded config the engine can serve. It is granted only when `capability::supported` passes, the config is loaded, and no routing rules, DNS servers or DNS hosts exist (`proxy_all_blocked`). An `xray` or `sing-box` override vetoes native outright.

A refusal returns the link's concrete subprocess core and a reason string logged as a `warn` naming host, kind, rule count, DNS counts and the core that runs instead; an explicit native override earns a second "override NOT honored" line. The Profiles list shows the override (or the resolved subprocess core), so a connect-time native selection is visible in the logs, not in the list.

Nothing native-specific is persisted. The runtime choice is recomputed per connect because only there is the `ProtocolConfig` loaded, and `ConfigBuilder::build` dispatches on the resolved subprocess core, so a runtime core that disagreed with the build would feed one core's JSON to the other's binary.

## Telemetry adapter

| Native event | `CoreEvent` | Consumer |
| --- | --- | --- |
| `Traffic` | `StatsUpdate` | `apply_stats_delta`: day reset and `profile_stats` upsert, unchanged from the xray path |
| `Sys` | `SysStatsUpdate` | metrics pane |
| `Log` | `LogLine` | Logs tab, no `parse_core_log_line` (native lines are already structured) |
| `Trace` | `NativeTrace` | native activity ring buffer, capped at 2000 entries, session-only |
| `SnifferSample` | `SnifferSample` | Sniffer pane, session-only |

## Deviations from the brief

| Brief | Shipped |
| --- | --- |
| Proto `CoreType` gains `Auto` (item 5) | Reverted. The persisted string would violate the frozen `core_type` CHECK constraint on existing files, and `core_type` sits inside the identity hash, so re-stamping would orphan a row's stats. The decision is runtime-only (decision 4). |
| Native asked for by xray-stamped links only | Any link whose kind and config the engine serves asks for it, including `SingBox`-stamped rows such as legacy Shadowsocks ciphers. An `xray`/`sing-box` override still vetoes. |
| New `Tab::NativeActivity` plus a Statistics screen | One merged Metrics pane (`crates/leas/src/ui/metrics.rs`, which routes scrolling to `ui/native_activity.rs`); the panel shows `in-process (event feed)` where the subprocess API endpoint would be. |
| Activity scroll state on `AppState` | Module-local `AtomicUsize` in `ui/native_activity.rs`, matching the Logs-tab pattern. |
| A native server lifecycle test | Not added as a hermetic test. Coverage is the inbound trace test `relayed_leg_emits_trace_events_and_traffic` (`crates/leas-native/src/inbound/tests.rs`) plus the connect-branch suite. |
| Full trace rows for every leg | TCP CONNECT and HTTP CONNECT legs emit open/close/byte rows; UDP associations relay but are untraced, because byte accounting would need relay-loop surgery. |
| Real ping as an ephemeral native SOCKS server (item 7) | `ops/ping_native.rs` calls `leas_native::probe::fetch` directly: dial → TLS → one HTTP/1.1 request, ALPN pinned to `http/1.1`, target verified against Mozilla roots. Rows the engine cannot serve get a persisted `[real]` marker instead of a probe. |
| `build_multi` kept as a follow-up | Deleted; no caller existed. |

Tier-3 note, 2026-09-03: the vmess UDP row fails identically on the clean baseline against sing-box 1.13.16 (server logs `bad packet connection`, client sees a truncated response header). It is scoped to xray single-core in `crates/leas-native/tests/vmess.rs` with that reason in the comment. Current suite counts and the full matrix live in [`reference/native-core.md`](../reference/native-core.md) § E2E coverage.

## Open work items

1. **The proxy UDP leg is missing.** `inbound::outbound::proxy_params` never sets `params.udp`, and `protocol::vless::connect_udp` rejects `params.udp == None`, so a native session drops SOCKS5 UDP ASSOCIATE traffic through the proxy outbound. The capability gate is deliberately TCP-truthful about this (see `capability.rs`).
2. **UDP association trace rows.** Byte accounting for a relayed association needs the relay loop to count datagrams; until then the activity view shows TCP legs only.
3. **HTTP CONNECT e2e row.** The status-code surface, auth gate, 16 KiB head cap and pipelined-byte replay are covered by tier-1 tests in `crates/leas-native/src/inbound/http.rs`; no tier-3 row against a real core exists.
4. **Proxy credentials.** No profile field or UI surface exists, so the native inbounds run unauthenticated and rely on the loopback bind. A non-loopback `inbound.listen` therefore publishes an open proxy; `NativeCoreServer::start` warns once at bind time.
5. **Shadowsocks 2022 multi-user EIH.** Single-user PSK only: the typed `SsConfig` carries no identity field.
6. **Sys metrics are process-level approximations** (RSS plus uptime), not xray's Go runtime numbers, so the statistics section shows fewer fields for native.

## Risks

- The native core is the default runtime for its six kinds, reachable with no user action and no migration, so a regression surfaces on real profiles before the e2e suite sees it. Mitigations: the fail-closed gate, the loud downgrade warn, and the `xray`/`sing-box` override veto.
- A native session is unauthenticated by design (item 4). Treat a non-loopback bind as an open proxy.
- Display and runtime can differ: the list shows the resolved subprocess core while the gate runs native. Cosmetic; the connect log names the runtime core.

## Verification

- Hermetic: `cargo test -p leas-native --lib`.
- Real-core tiers and their commands: [`reference/native-core.md`](../reference/native-core.md) § Verification tiers.
- Workspace: `cargo test` plus `just quality-gate code`.
- Manual: import a link for each of the seven kinds, connect (no core selection needed), confirm live traffic in the Metrics pane and per-connection rows in the native activity section; kill the network mid-connection and confirm `Failed` rows; confirm SOCKS5 and HTTP CONNECT both work on the effective port, including with `mixed_port` set; set an `xray` entry in `protocol_core_overrides` and confirm the subprocess path is unchanged.
