# Database

The TUI's persistent state is **one SQLite file** — `data.db` under the config
directory (`dirs::config_dir()/leas/`, e.g. `~/.config/leas/data.db`) —
opened through `toasty` 0.10 on the `toasty-driver-turso` backend (an
in-process, async SQLite-compatible engine). Nothing else is persisted except
the log store (LMDB, `logs.lmdb/`) and the geo mmdb.

`crates/leas-db` owns it: `models_toasty.rs` declares every table,
`database.rs` holds every write/read method, `profiles_query.rs` holds the one
raw-SQL page engine, and `endpoint_rank.rs` / `endpoint_ip.rs` own the two
derived-state tables.

| | |
| --- | --- |
| Tables | 11 (listed below; `app_meta` is the key/value stamp table) |
| Schema tag | `PRAGMA user_version = 18` |
| Migrations | `crate::schema` — `PRAGMA user_version` is a CURSOR. A current file is a no-op, a fresh file applies the seed, a supported older version applies the pending steps, and only an UNKNOWN cursor deletes and recreates the file (see [Changing the schema](#changing-the-schema)) |
| Raw SQL | `profiles_query.rs` (the page), `endpoint_rank.rs` and `endpoint_ip.rs` (their index DDL plus the id-inlined reads/writes), and the bulk patch statements (ADR 0001, ADR 0003); `PRAGMA`s are the other standing exception, described under [Connection settings](#connection-settings) |

## Entity map

```mermaid
erDiagram
    endpoints ||--o{ endpoint_ip : "address set (ADR 0005)"
    endpoints ||--o{ profile_stats : "per-protocol state"
    endpoints ||--o{ endpoint_groups : "membership"
    groups ||--o{ endpoint_groups : "membership"
    protocols ||--o{ profile_stats : "config"
    endpoints ||--o| endpoint_rank : "ordering keys (ADR 0003)"
    groups ||--o{ routing_rules : "scoped rules"

    endpoints {
        BIGINT id PK "stable_hash(name, port)"
        TEXT domain "eTLD+1; empty for an IP/exotic host (db-rewamp D2)"
        TEXT sub_domain "labels left of the domain; empty otherwise"
        INTEGER port "primary port"
        TEXT ports "JSON array (multi-port specs)"
        TEXT last_source "hash of the source subscription"
        BIGINT manual_protocol_override "FK protocols.id, NULL = auto"
        BIGINT resolved_at "DNS attempt stamp (TTL gate)"
        BIGINT created_at "epoch seconds"
    }
    endpoint_ip {
        BIGINT endpoint_id PK
        BLOB ip_key PK "packed address, sortable"
        TEXT country "ISO-3166 alpha-2, NULL until looked up"
    }
    protocols {
        BIGINT id PK "uid = sig ^ cred_hash"
        BIGINT sig "non-credential half / grouping key"
        TEXT proto_kind "27 protocol kinds"
        TEXT transport_type "tcp|ws|grpc|http|quic|kcp|http_upgrade|x_http"
        TEXT security_type "none|tls|reality"
        TEXT security_sni "SNI (tls + reality)"
        TEXT security_fp "fingerprint"
        BOOLEAN security_insecure
        TEXT config "JSON ProtocolConfig"
        BIGINT created_at
    }
    profile_stats {
        BIGINT protocol_id PK "FK protocols.id"
        BIGINT endpoint_id PK "FK endpoints.id"
        BIGINT last_used_at
        BIGINT last_seen_at "staleness + retention"
        TEXT latency "real|fast, NULL = untested"
        INTEGER latency_delay "ms"
        TEXT latency_ip "exit IP of a real ping"
        BIGINT speed_bps
        BOOLEAN error "failure marker flag"
        TEXT error_kind "real|fast|name"
        TEXT error_text
        TEXT purge_reason "reality_fallback|certificate_mismatch|…, NULL = live (ADR 0006)"
        BIGINT stab_mask "stability ring: last STAB_WINDOW=16 real outcomes, bit i = i-th OLDEST, 1 = success"
        BIGINT stab_len "live samples in the ring, 0..=16 (bits [len,64) are always zero)"
        BIGINT traffic_today_up
        BIGINT traffic_today_down
        BIGINT traffic_total_up
        BIGINT traffic_total_down
        BIGINT created_at
        BIGINT updated_at
        INTEGER version "optimistic concurrency"
    }
    endpoint_groups {
        BIGINT endpoint_id PK
        TEXT group_id PK
        BIGINT last_seen_at "per-source confirmation"
        INTEGER sort_order
    }
    groups {
        TEXT id PK "uuid"
        TEXT name
        TEXT url "subscription URL"
        BOOLEAN enabled
        TEXT user_agent
        TEXT convert_target "clash"
        INTEGER sort_order
        BIGINT last_refreshed
        TEXT status "ok|error|never"
        TEXT error_message
        BIGINT refresh_interval "minutes"
    }
    routing_rules {
        TEXT id PK
        TEXT group_id "NULL = global"
        INTEGER type "opaque"
        TEXT domain_matcher
        TEXT domains "JSON array"
        TEXT ips "JSON array"
        TEXT inbound_tags "JSON array"
        TEXT ports "JSON array"
        TEXT source_ports "JSON array"
        TEXT network
        TEXT protocols "JSON array"
        TEXT domain_strategy
        TEXT outbound_tag
        TEXT balancer_tag
        TEXT rule_set_file
        TEXT rule_set_url
        INTEGER sort_order
    }
    dns_settings {
        TEXT id PK
        TEXT name
        TEXT servers "JSON array"
        TEXT hosts "JSON array"
        TEXT query_strategy "use_ip|use_ipv4|use_ipv6"
        BOOLEAN disable_cache
        BOOLEAN disable_fallback
        TEXT client_ip
        BIGINT cache_ttl_secs
    }
    route_probes {
        TEXT id PK "singleton: 'global'"
        TEXT hosts "JSON array"
    }
    endpoint_rank {
        BIGINT endpoint_id PK
        BIGINT rank_bin "D11 bins: 0..5 real<50..>=1000, 6..11 fast, 12 untested, 13 real-err, 14 fast-err, 15 dns-err, 16 purged — the representative link's LAST outcome"
        BIGINT rank_stab "0..7 real-probe success rate of the representative link (4 = neutral); ordered inside the bin, BEFORE rank_weight"
        BIGINT rank_proven "1 when some live unpurged link's ring holds a success — the Successful scope's membership, NOT the representative's bin"
        BLOB rank_weight "static config weight (8 big-endian bytes, NOT NULL); ordered AFTER rank_stab"
        TEXT rank_domain "registrable domain (eTLD+1), empty for an IP/exotic host (D2)"
        TEXT rank_sub_domain "labels left of the domain"
        BLOB rank_addr "packed IP-literal key, empty for a DNS host (the address tiebreak)"
        BIGINT rank_newest_seen "view windows"
    }
```

`toasty` emits **no SQL `REFERENCES`**: the arrows above are ownership, not
constraints. Deletion order is explicit in the deletion owners
(`delete_endpoints`, `purge_expired`) — child rows first, in one transaction.
Cardinality note: every arrow out of `endpoints` and into `endpoint_rank` is
*optional*, because a linkless endpoint is a legal row — it has no
`profile_stats` links, so nothing to order — and `compute_rank` returns `None`
for it (it is the `min()?` over the links), `repair_missing` only fills
endpoints that have links, and `prune` drops the key of an endpoint whose links
went away.

## Tables

### Identity and addresses

**`endpoints`** — one row per `host:port`. `id` is a stable hash
(`stable_hash(name, port)`, where `name` is the canonical DNS name
(`sub_domain.domain`) or the IP literal; exotic kinds hash `("", port)`, which
is why `domain` can be empty). The host kind is DERIVED (db-rewamp D2/D10): a
non-empty `domain` is a DNS name whose addresses live in `endpoint_ip`; an
empty `domain` is an IP-literal or exotic host whose literal (if any) is the
single `endpoint_ip` row — its dial target has no other home. `ports` carries a
multi-port spec (JSON array, empty when the single `port` is the whole spec).

**`endpoint_ip`** — a DNS endpoint's resolved addresses, **one row per address**
(ADR 0005). `country` is the address's ISO-3166 alpha-2 code (`country.iso_code`
from the mmdb), written once by the geo step (the page seed batches a page's
writes into one transaction) and read back by the enrichment
seed — a launch whose addresses all carry one renders the flags without an mmdb
walk (or the 60 MB download). It is the *only* persisted geo fact; the
whitelist features and the exit-IP country stay per-launch (decision 13). The PK `(endpoint_id, ip_key)` makes the set deduped; `ip_key` is
the address itself in a sortable packed encoding — a family byte (`4` = IPv4,
`6` = IPv6, the `IpAddr` discriminant) then the big-endian octets, 5 or 17
bytes, so B-tree byte order *is* address order with IPv4 first. The text form
exists only at the display edge (`crate::endpoint_ip::ip_of` → `IpAddr`).
`endpoints.resolved_at` is a *different* fact: the stamp of the last lookup
attempt, which the resolution TTL reads — a failed lookup stamps it and leaves
the address set empty, and that empty set is what the tier-5 band means.

### Config

**`protocols`** — one row per distinct protocol configuration. `id` is the
identity uid `sig ^ cred_hash` (`leas-proto`'s per-kind binary writer over
non-default, explicitly-set fields only); `sig` is kept because it is the
"same way configured servers" grouping key. Host and port are **not** part of
the identity, so one protocol serves many endpoints. `config` holds the full
typed `ProtocolConfig` as JSON (the single owner — the former `transport_data`/`security_data` copies were dropped, db-rewamp D8); the
nested transport/security configs, and the scalar columns beside them
(`transport_type`, `security_type`/`sni`/`fp`/`insecure`) are the display
projections the page reads without touching the JSON. Changing what the identity
covers re-keys every row — it is a data reset, never a migration (decision 11).

**`profile_stats`** — the per-`(protocol, endpoint)` pair state: everything a
test measures and everything traffic counts, plus the one durable VERDICT
(`purge_reason`, ADR 0006). The verdict is not a measurement marker: `error` is
swept by `error_ttl_hours`, `purge_reason` only moves when a real probe earns one
or a data-carrying success clears one, and it is written by its own column group
so no other writer can rewrite it from a stale snapshot. The three embeds are flattened
into columns, so one "row" in mermaid is `latency`+`latency_delay`+`latency_ip`,
`error`+`error_kind`+`error_text`, and the four `traffic_*` counters.
`#[version]` makes typed single-row updates optimistic-concurrency safe; the
bulk patch path bumps it manually. Writers are disjoint by column group
(`LinkGroups::RESULT` vs `TRAFFIC`) so a ping result and the stats poller can
never clobber each other (decision 22).

### Grouping

**`groups`** — a subscription/group: URL, refresh interval, last status. A
group is *not* a container that owns endpoints; membership is the many-to-many
link below, and an endpoint may belong to none (the All view shows it).

**`endpoint_groups`** — the many-to-many membership link, carrying the
per-source confirmation stamp (`last_seen_at`, refreshed by every import from
that source) and an optional display order.

### Routing, DNS, probing

**`routing_rules`** — the routing table's rows, ordered by `sort_order`; the
list-valued columns are JSON arrays of text (note `ports`, the one
`Vec<u16>`). `group_id` scopes a rule to a subscription's endpoints; `NULL`
means global. `type` is an opaque integer carried for the form only.

**`dns_settings`** — the DNS configuration rows (`servers`/`hosts` are JSON
arrays; `cache_ttl_secs` is the TUI-side resolution cache TTL).

**`route_probes`** — a single row (`id = 'global'`) holding the hostnames the
routing engine must resolve.

### Derived state

**`endpoint_rank`** — the materialized per-endpoint ordering keys (ADR 0003;
full write-up: `docs/reference/ordering-law.md`). Each row is the decision-16 law
evaluated for one endpoint over its links; the page's default order is an index
scan of `endpoint_rank_key_v2`, which is why the Profiles tab stays fast at any
offset. The values are computed **in Rust** by `endpoint_rank::RankLink::key` —
the single implementation of the law, shared with the panel's link order — and
never re-derived in SQL. `rank_bin` is the representative link's coarse delay
band (real `<50..≥1000` = 0–5, fast = 6–11, untested 12, error 13/14, DNS
unresolved 15, purged 16); `rank_newest_seen` answers the Active/Purgatory
window. `rank_stab` is the representative link's real-probe success rate
(`0..7`, `4` neutral) from a ring of its last 16 real outcomes, and
`rank_proven` is the endpoint's `Successful` membership (any live unpurged link
with a success in its ring) — the two are separate facts because a proven
endpoint's representative can be an untested sibling (spec
`2026-10-09-stab-bin-design`, `docs/reference/ordering-law.md` §6.1). `rank_weight` is the
static config weight (spec
`2026-10-01-static-config-weight-design`): a compiled prior over the link's
transport/security discriminators, stored as 8 big-endian bytes so SQL's memcmp
order IS the comparator's order. It is a RAW `NOT NULL` column (the model has no
seat for one, and declaring it there would need schema tag 15 = a data wipe), it
is NOT re-set by `write`'s follow-up `UPDATE` because it is Rust-computed rather
than SQL-derived, and `NOT NULL` is load-bearing: `profiles_anchor` binds every
ordering term's value back into a comparison, so one NULL weight is a query
ERROR, not a mis-sort.

## Indexes

| Index | Table / columns | Serves |
| --- | --- | --- |
| *(PK autoindex)* | `endpoints(id)` | every by-id lookup, all hydration |
| *(PK autoindex)* | `endpoint_ip(endpoint_id, ip_key)` | the address set of an endpoint (prefix seek), PK uniqueness |
| `endpoint_ip_by_key` *(raw)* | `endpoint_ip(ip_key, endpoint_id)` | address-ordered scans, `min(ip_key)` per endpoint, range lookups by address |
| *(PK autoindex)* | `profile_stats(protocol_id, endpoint_id)` | pair lookups, the link upserts' `ON CONFLICT` target |
| `index_profile_stats_by_endpoint_id` | `profile_stats(endpoint_id)` | the page's per-endpoint link reads. (`protocol_id` — the FIRST PK column — deliberately carries NO secondary index: the PK autoindex serves its prefix seek, and a redundant index costs every write, db-rewamp §3.2) |
| `index_profile_stats_by_last_seen_at` | `profile_stats(last_seen_at)` | retention cutoff, staleness windows |
| *(PK autoindex)* | `endpoint_groups(endpoint_id, group_id)` | membership lookups AND an endpoint's groups (`endpoint_id` is the PK prefix, db-rewamp §3.2) |
| `index_endpoint_groups_by_group_id` | `endpoint_groups(group_id)` | a group's endpoints (the query; `group_id` is the second PK column, so the autoindex cannot serve it) |
| *(PK autoindex)* | `endpoint_rank(endpoint_id)` | rank-row writes/lookups |
| `endpoint_rank_key_v2` *(raw)* | `endpoint_rank(band, rank_bin, rank_stab, rank_weight DESC, rank_domain, rank_sub_domain, rank_addr, endpoint_id, rank_proven)` | the default page order — a covering index, so the page is an index scan. `rank_proven` is TRAILING (placing it between `band` and the order terms filesorts), so every scope filters inline on an index scan with no sorter. **A NEW NAME, never an edit in place**: `CREATE INDEX IF NOT EXISTS` makes a changed column list a silent no-op on an existing database. It supersedes `endpoint_rank_key`, which the same DDL list drops |
| `rank_weight_meta` *(raw)* | `rank_weight_meta(id, weight_version)` | one row: the version of every INPUT to the stored keys — the compiled weight tables AND the stability thresholds (`KEY_INPUTS_VERSION`). A mismatch at open recomputes every key — the ONLY trigger that can replace the `ADD COLUMN` defaults materialized for pre-existing rows |
| `endpoint_rank_band_window` *(raw)* | `endpoint_rank(band, rank_newest_seen)` | the directional reband sweep (`band=0 AND rank_newest_seen < ?`) |

The two raw sets exist because toasty's `#[index]` is single-column and cannot
express a mixed-direction composite. They are created with
`CREATE INDEX IF NOT EXISTS` at every open, so they are additive and
idempotent. `endpoint_ip` deliberately carries **no** `#[index]` on
`endpoint_id`: it is the composite PK's first column, so the autoindex already
serves that prefix (unlike `profile_stats.endpoint_id`, which is the *second*
PK column and therefore needs its own index).

## Derived state and who maintains it

Two tables are derived, and a write that changes their inputs **must** refresh
them, or the page silently lists a stale position:

- `endpoint_rank` follows every link change: `upsert_link`,
  `upsert_links_bulk` (inside the caller's transaction), `apply_link_patches`
  (after commit), `update_last_used`, `update_endpoint_resolution`,
  `set_manual_override`, `restore_endpoint`, `clear_all_stats` (wholesale
  `backfill_all`), and the error-TTL sweep. `repair_missing` runs at open and
  is exposed as `Database::repair_endpoint_ranks`; `prune` runs inside the
  deletion transactions.
- `endpoint_ip` is rewritten as a set by its single writer,
  `update_endpoint_resolution` (delete-then-insert, deduped by key), in the
  same transaction as the endpoint's `resolved_at` and the rank refresh. The
  rewrite **carries the countries of the addresses that survive it** — a
  re-resolution must not discard a lookup that already happened.
  `set_endpoint_ip_country` is the geo step's write: it updates the row, or
  creates it when the lookup won the race against the address write. The page
  seed flushes through `set_endpoint_ip_countries` — the same per-row statements
  inside ONE transaction for the page, because a connection + commit per endpoint
  contended with the import's own 500-URL chunk commits (`database is locked` →
  `retry_on_busy`).
  Deletions go through `endpoint_ip::delete_for` inside the same transaction as
  the endpoint rows.

## Connection settings

Every pooled connection is acquired through `Database::conn()`, which sets
`PRAGMA busy_timeout=5000` and `PRAGMA synchronous=NORMAL`; `open()` additionally
sets `journal_mode=WAL` and `foreign_keys=ON`. `busy_timeout` and `synchronous`
are per-connection pragmas: setting them once at open never reaches
pool-created connections, which is what produced the historical
"database is locked" storms. WAL + `synchronous=NORMAL` is the deliberate
durability trade (commits are not individually fsynced); the default `FULL`
costs ~4.2 ms per commit and a ping batch issues tens of thousands of them.

## MVCC mode and the micro-batch write-behind (2026-10-20)

MVCC stays opt-in (`LEAS_TURSO_CONCURRENT_WRITES=1`, fresh files only). What
the migration changed is how the write-behind driver behaves when it IS on:

- **Micro-batch window.** `WriteBehind::new` clamps the default 512-row window
  to 32 rows on an MVCC database (`DEFAULT_FLUSH_ROWS_MVCC`). Measured
  (`micro_batch_mvcc_probe`, 16 writers × 256 updates/writer, 8,192-endpoint
  feed): at batch 16 MVCC p99 is **12 ms against WAL's 631 ms**; at every
  size the WAL arm carries 330–835 ms tail stalls that MVCC never shows.
  Scope: this win is measured on the hand-rolled profile_stats probe shape
  only. The geo writer's 75–95× verdict on its own 100-row batched shape
  (`2026-10-20-turso-0.9-access-design.md` §7.1) was NOT re-measured and
  stands for that writer.
- **Rank refresh leaves the transaction.** Under MVCC, `LinkSpec::refresh`
  is skipped in the window transaction; the touched endpoints are marked in
  `Database::dirty_ranks` (IN-MEMORY) on commit, and both `profiles_page` and
  `WriteBehind::flush` drain the set. **Durability boundary:** a crash between
  a link-patch commit and the next drain leaves stale stored keys that reopen
  does NOT repair — `endpoint_rank::ensure` backfills missing rows and
  recomputes on a weight-version change only. A stale row persists until that
  endpoint is next written. WAL keeps the atomic in-tx refresh and has no such
  window. A fresh import keeps the in-tx refresh either way: a new endpoint
  has no rank row yet, and deferring it would blind the page.
- **Writer partitioning deferred.** The plan's N-channel partitioned drain was
  NOT built: the probe measured zero conflicts at every batch size, and the
  column-group design already keeps `last_seen_at` out of the RESULT patch.
  `WriteBehind::run` remains the single-owner flush loop.
- **Failure path.** A failed window is re-staged from the patch
  (`CacheSpec::restage_patch`) — the drained triple no longer carries a
  duplicate source-row clone (`Coalesced<K, P>`), so the staged heap cost is
  one row, not two.
- **`stage()` stays synchronous.** `push`/`stage` remain non-awaiting
  `DashMap` inserts (ADR 0002); nothing about the MVCC path changes the UI
  task's contract.

## Flows

### Open (and schema creation)

```mermaid
flowchart TD
    A[Database::open path] --> B{file exists and is 0 bytes?}
    B -- yes --> C[delete it]
    B -- no --> D[build Db with the 10 models]
    C --> D
    D --> E{open failed?}
    E -- yes --> F[delete the file, rebuild]
    E -- no --> G[read PRAGMA user_version]
    F --> G
    G --> H{"cursor vs LATEST (18)"}
    H -- "== 18" --> J["ensure raw DDL (idempotent)"]
    H -- "== 0" --> I["push_schema + raw DDL, set cursor 18"]
    H -- "unknown" --> W["IncompatibleSchema: wipe and rebuild"]
    I --> K[PRAGMAs: WAL, busy_timeout, NORMAL, foreign_keys]
    J --> K
    W --> K
    K --> L[default group if none]
    L --> M["endpoint_rank::ensure: backfill or repair (DATA; the DDL lives in crate::schema)"]
    M --> O[ready]
```

### Import / subscription refresh

```mermaid
sequenceDiagram
    participant S as Subscription
    participant P as persist_parsed / stream_import
    participant T as transaction
    participant D as data.db
    S->>P: fetch + parse (ParsedProto)
    P->>T: begin
    T->>D: upsert_endpoints_bulk (identity fields only)
    T->>D: upsert_protocols_bulk (config, transport, security)
    T->>D: upsert_links_bulk — SOURCE columns only
    Note over T,D: on UPDATE the link writes last_seen_at<br/>(the SOURCE column) — the RESULT and TRAFFIC columns<br/>are written ON CREATE only, so a refresh cannot wipe a measurement
    T->>D: endpoint_rank::refresh (inside the transaction)
    T->>D: group links (last_seen_at per source)
    T->>T: commit
    P->>P: CoreEvent::SubscriptionsUpdated → page reload
```

### Profiles page load

```mermaid
sequenceDiagram
    participant U as UI task
    participant W as LinkWriter
    participant Q as profiles_query
    participant D as data.db
    U->>W: flush()
    Note over U,W: staged results must be durable BEFORE the sweep,<br/>which writes the same error columns
    U->>Q: clear_expired_errors (optional TTL sweep, then rank refresh)
    U->>Q: profiles_page(req)
    Q->>D: SELECT COUNT(*) over endpoint_rank + predicates
    Q->>D: SELECT k.endpoint_id ORDER BY stored keys LIMIT/OFFSET
    D-->>Q: 200 ids
    U->>Q: load_page_projection(ids)
    Q->>D: ONE statement — endpoints JOIN profile_stats LEFT JOIN protocols,<br/>ids inlined as literals, addresses via group_concat(hex(ip_key))
    D-->>Q: rows
    Q->>Q: assemble EndpointRow: group links by endpoint, sort by the<br/>decision-16 law, pick the display link
    Q-->>U: page rows + PageMeta{ids, total, offset}
```

Why one statement and inlined ids: turso charges ~0.8 ms per *bound*
parameter, so the typed hydration (three `IN (...)` reads, ~600 binds) cost
488 ms per page against 49.6 ms for the same rows from one inlined statement
(ADR 0001). The typed path (`load_page_rows`) survives as the parity oracle.

### Ping result (batch and single)

```mermaid
sequenceDiagram
    participant G as TaskScheduler (runtime only)
    participant B as BatchShared / event handler
    participant W as LinkWriter
    participant D as data.db
    G->>B: task settles (protocol_id, endpoint_id)
    B->>B: apply_test_result → latency/error (RESULT group)
    B->>W: stage(link, RESULT) — no await
    Note over W: the pending map is authoritative —<br/>stage() never touches the DB
    W->>D: on flush_interval/flush_rows: ONE transaction of<br/>multi-row upserts + one rank refresh per touched endpoint
    Note over W,D: a failed window re-stages itself AND every window after it
```

### DNS enrichment

```mermaid
sequenceDiagram
    participant E as ops/enrich.rs
    participant H as hickory resolver
    participant V as poll_core_events
    participant D as data.db
    E->>H: resolve(host) — TTL-gated, hard deadline
    H-->>E: addresses (or a failure)
    E->>V: CoreEvent::EndpointInfoUpdated{endpoint_id, info}
    V->>V: merge by field group (resolution / whitelist / outbound)<br/>— concurrent events must not clobber each other
    V->>D: update_endpoint_resolution(eid, Vec<IpAddr>, at) — ONE transaction:
    D->>D: endpoints.resolved_at = at
    D->>D: endpoint_ip: delete the old set, insert the new (deduped by key)
    D->>D: endpoint_rank::refresh — the endpoint may leave/enter the DNS band
```

### Connect

```mermaid
flowchart LR
    A[selected endpoint + protocol] --> B[load_protocol_with_config]
    B --> C[core_mapping::resolve_core<br/>kind + override + ss method]
    C --> D{native capable?}
    D -- yes --> E[NativeCoreServer in-process]
    D -- no --> F[subprocess: xray-core / sing-box]
    B -.->|reads the deferred JSON| G[protocols.config]
```

## Query map

| Call | Statement | Notes |
| --- | --- | --- |
| `profiles_page` | count + ordered ids | drives from `endpoint_rank`; the default order is a covering-index scan |
| `profiles_anchor` | count of rows sorting before a key tuple | used to re-anchor the window after a re-sort moved the selection |
| `load_page_projection` | one hydration statement, ids inlined | the page's rows (display columns only; the three deferred JSON carriers stay unloaded) |
| `load_page_rows` | typed `in_list` reads + in-memory join | the reference implementation the projection is pinned against |
| `update_endpoint_resolution` | `UPDATE endpoints` + `endpoint_ip` set rewrite + rank refresh | one transaction, retried on write contention |
| `apply_link_patches` | one multi-row upsert per (chunk, group shape) | the write-behind flush path; 512-patch window ~10.0 ms vs ~29.0 ms for the retired per-row `UPDATE` + existence probe (ADR 0002 amendment 4) |
| `endpoint_rank::refresh` / `backfill_all` / `repair_missing` | raw, id-inlined reads + a bulk upsert | never binds ids (~0.8 ms each) |
| `upsert_links_bulk` | one multi-row upsert per chunk, SOURCE columns on conflict | the import path; 2,000 links ~44 ms vs ~360 ms for the per-row typed upsert (ADR 0002 amendment 4) |

## Changing the schema

1. **Add a column or table** to `models_toasty.rs` (or raw DDL at open for tables
   toasty cannot express — currently only the two index sets).
2. **Add a migration step** in `crates/leas-db/src/schema/` and bump
   `LATEST`/`SCHEMA_VERSION` (they must agree; a test pins it). An existing file
   at the previous version then applies the step instead of being deleted. The
   cursor SEEDS at 18, so the first change after that is 19.
   **Only a cursor naming an unknown schema wipes** — a pre-migration or foreign
   file — and `open` reports that as `IncompatibleSchema` before recreating. The
   project is pre-alpha and treats the database as re-importable fixture data,
   but a wipe must now be a deliberate choice, not the default path for a column
   addition.
3. **If the change touches identity** (any field a protocol's `write_identity`
   writes), bump `IDENTITY_VERSION` in `leas-proto` and re-pin the identity
   goldens — but do **NOT** bump `SCHEMA_VERSION` for it: the schema did not
   change, and a cursor bump would report a perfectly compatible file as
   `IncompatibleSchema` and wipe an already-imported feed.
   **A re-key has NO detector today.** There is no `app_meta.identity_version`
   reader/writer and no re-key step in `crate::schema` (the spec's §5.1
   `Step::Rebuild` was never built), so nothing compares stored uids against
   `IDENTITY_VERSION`: a re-key leaves every stored uid stale and the next import
   inserts a SECOND `Protocol` row per config under the new uids, breaking
   identity dedup SILENTLY. Until that machinery exists, ship the reset yourself —
   a hand-written reset entry in `leas-db/src/schema/ddl.rs` guarded by your
   own marker, or an `IncompatibleSchema`-style wipe. This mirrors AGENTS.md
   decision 11.

   **Format vs value — the rule above is about the FORMAT.** What the writer
   writes (tags, order, which values are elided) decides the version. A change
   that only alters a stored **value** for a subset of configs is a different
   case: the format and the goldens are untouched, so no `IDENTITY_VERSION` bump
   and no wipe. Only the configs whose value actually differs re-key, and their
   old rows age out through Purgatory (7 d) to `purge_expired` (30 d) instead of
   being deleted. `specs/2026-09-23-ws-path-canonicalization-design.md` §4.3 is
   the worked example: a canonicalized transport path, where the format held and
   the version tag did not move.
4. **Raw SQL stays exceptional.** Add it only where the engine's cost model
   forces it (the page, the id-inlined rank reads, the bulk patch writes), keep
   it parameterised-or-integer-inlined, keep it read-only where possible, and
   add a statement-vs-schema drift test.

## Known limits

- The page load carries a measured **+3.8 ms (unresolved page) to +6.1 ms
  (fully-resolved page)** over the previous JSON column, and the file is ~7.5%
  larger on a 1–3-address feed — the price of the address set being relational.
  Both alternatives (reading the flag from `rank_dns`, or reading addresses in
  a second statement) measured *worse*; the remaining lever is a materialized
  `endpoint_rank.rank_ip` key (166.9 ms → 0.94 ms for the IP sort), deliberately
  not taken. See `docs/aegis/specs/2026-09-15-endpoint-ip-storage-design.md`.
- The IP sort is not index-driven (a correlated `min(ip_key)` per row): ~166 ms
  per fetch, in the same band as the pre-existing Address/Port sorts.
- `endpoint_ip.ip_key` cannot be produced or ordered by the engine's own `inet`
  type: it is declared without `OPERATOR '<'`, so `ORDER BY`/`CREATE INDEX` on
  such a column are parse errors, and an operator-declared variant orders the
  text (`10.0.0.1 < 9.0.0.1`). Hence the packed key.
