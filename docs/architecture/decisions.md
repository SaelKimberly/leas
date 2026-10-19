# Durable design decisions

The invariants a change must respect. Detail lives in the sibling `reference/` pages; this page states the decision and points there. (Folded from the retired the retired context page and the agent-reference page.)

## Identity & schema

- **Typed schema, one file.** SQLite via `toasty` 0.11 over `turso` 0.8, through the crate's own local-only driver fork (`crates/leas-db/src/driver/`). 11 typed tables: `endpoints`, `endpoint_ip`, `protocols`, `profile_stats`, `endpoint_groups`, `groups`, `routing_rules`, `dns_settings`, `route_probes`, `endpoint_rank`, `app_meta`. Details: [`reference/database.md`](../reference/database.md).
- **The schema cursor is not a wipe tag.** `PRAGMA user_version` is a migration cursor (`crate::schema`, ADR 0012): a current file is a no-op, a fresh file applies the seed, a supported older version migrates, and only an unknown cursor wipes. **Never bump `SCHEMA_VERSION` to force a change**; raw DDL lives in `schema/ddl.rs`. Identity re-keys are their own data step.
- **Profile identity is a frozen binary wire format.** `uid = sig ^ cred_hash`, computed by the per-kind writer in `leas-proto/src/proto_spec/identity.rs` over non-default, explicitly-set fields only. Endpoints (host/port) never participate; credentials are domain-separated (`cred_hash = 0` when there are none, so `uid == sig`). Every field is tag+length framed and the write order is frozen. Changing what identity covers re-keys stored rows — see the checklist in [`reference/database.md`](../reference/database.md) / `AGENTS.md`.

## Backends

- **Three runtime backends, two persisted.** `CoreManager` abstracts the xray-core and sing-box **subprocesses**; `leas-native` is the third and runs **in-process** (no binary, no config file, no gRPC). Persisted `core_type` stays `{Xray, SingBox}`; the native choice is **runtime-only**, recomputed per connect by `resolve_runtime_core` in `ops/connect.rs` and never written to the DB or a generated config (ADR 0004).
- **Protocol-core auto-resolution.** TUIC, Hysteria v1, Naïve, AnyTLS, ShadowTLS, Tor, SSH, Tailscale, ShadowsocksR, Redirect → sing-box; everything else → xray-core. Shadowsocks/2022 is cipher-aware (`XRAY_SS_METHODS`/`SINGBOX_SS_METHODS`): legacy ciphers → sing-box. A forced core that cannot build the cipher fails at build time.
- **One core at a time.** Only one backend runs per session — including the in-process server, whose listeners live in this process. Teardown windows: `PREV_SESSION_TEARDOWN` (5 s), `DISCONNECT_TEARDOWN` (3 s).
- **Native capability gate fails closed.** `capability::supported(kind, config)` decides whether native may serve a row; a refusal is a *result* (`UNTESTABLE_PREFIX` marker), never a silent downgrade.

## Ordering & the Profiles page

- **One ordering law, materialized.** The link key is `(bin, stab_bin, u64::MAX - weight, -last_seen_at, protocol_id)`; the endpoint key is `(band, bin, stab_bin, u64::MAX - weight, domain, sub_domain, addr, endpoint_id)`. Implemented ONCE in Rust (`endpoint_rank::RankLink::key`); SQL stores the keys and never re-derives the order. Full write-up: [`reference/ordering-law.md`](../reference/ordering-law.md), ADR 0003.
- **The Profiles tab is a SQL page** (`PROFILES_PAGE_SIZE = 200`), hydrated in one statement; ordering/filter/count are SQL. ADR 0001.
- **`profile_stats` writes are write-behind.** `ops/link_writer.rs` owns every mutation, staged by column group (RESULT / PURGE / TRAFFIC) and flushed as one multi-row upsert window. ADR 0002, decision 22.
- **Test-cell truth.** The Test column describes the endpoint's *representative* link (argmin of the link key), not `active_link()`.

## Enrichment & networking

- **Background enrichment never blocks the UI.** DNS/mmdb/whitelist work runs in spawned tasks reporting via `CoreEvent::EndpointInfoUpdated`, merged by field group. DNS lookups dedup by HOST and fan the answer out to every waiter; failed lookups are TTL-gated via `scheduler.mark_dns_failure`.
- **Country writes are queued** — one owner, one transaction per drain (`WriteBehind<CountrySpec>`, 15 s staleness deadline).
- **Every network path has a hard deadline.** A hang is a bug.
- **Import feed ceilings are configuration** (`AppConfig.import`, `0` = unbounded; defaults equal the previously hard-coded values).
- **IPv6 answers are enabled by default; DNS stamp transport stays IPv4-only.** DNS lookups pass `allow_ipv6=true` (`ops/enrich.rs`) — the answer-family property of the server being dialed. The DNSCrypt resolver-list parser (`parse_dnscrypt_lines` → `sdns_to_nsc`) is deliberately `allow_ipv6=false`: a stamp is the client's transport to the DNS server itself, and admitting the 467 IPv6-only published stamps made every pool lookup crawl unreachable v6 dials on hosts without an IPv6 route (~10 s per lookup, over the enrich 8 s deadline). The host-features whitelist (`leas-host-features`) remains IPv4-only by design — the upstream data files (`ipwhitelist.txt`, `cidrwhitelist.txt`) contain only IPv4 entries.
- **The subscription decoder is chunking-invariant.** `StreamingDecoder` output
  depends only on the input bytes, never on how they are split across `feed()`
  calls: encoding detection buffers a head until it is decisive, base64 is
  normalized to one alphabet (whitespace dropped, so MIME-wrapped and URL-safe
  input decode alike), and line assembly runs on bytes so a line ends only at
  its `\n`. A single line is capped (`MAX_LINE`); a longer one is cut at the
  last scheme start, and a single over-long URL is dropped and counted, never
  silently truncated.

## Native core & TLS

- **Xray composition order:** `dial → security → transport upgrade → protocol → tunnel`. TLS is outermost; ws/grpc framing runs inside it. `LinkContext` is the per-link policy surface every phase reads.
- **TLS fingerprint engine is ring-only** (`leas-tls`): TLS 1.3 + a 1.2 fallback, declarative browser-hello profiles, WebPKI verification (`insecure`/`pin_sha256` trust modes only — never a blanket skip). REALITY reuses the same hello machinery. Both crypto crates are `#![forbid(unsafe_code)]`.
- **Secrets are wiped** (`zeroize` on owned key buffers; the `zeroize` *feature* must stay listed on every crypto dep that touches keys). Non-default crypto sites and advisories: [`reference/crypto-dependencies.md`](../reference/crypto-dependencies.md), ADR 0007.
- **Verification tiers:** tier 1 offline (hermetic, the CI gate); tier 2 live grader; tier 3 real-core e2e (feature + `LEAS_CORE_BIN_DIR`); plus a manual perf-lab tier — the timing/planner probes behind `--features perf-lab`, `#[ignore]`d and never in the gate. No implicit network in the usual test run.

## Reference repositories (read-only)

`thirdparty/Xray-core` (primary Go core), `thirdparty/sing-box` (secondary Go backend), `thirdparty/v2rayN` (C# client — a *reference implementation* for protocol/URL formats, no longer a parity target), `thirdparty/shoes`, `thirdparty/leaf`, `thirdparty/shadowsocks-rust`, plus `v2rayNG`, `mihomo`, `quirktiva`, `v2ray-core-legacy`.

## Source-file map

The per-crate map is in [`architecture.md`](architecture.md) (crate dependency graph + responsibilities); the TUI's `ops/`/`ui/` module split is in `AGENTS.md` § Structure. Per-task recipes ("adding a protocol form", "adding a Clash conversion", …) live with their owning `reference/` page.
