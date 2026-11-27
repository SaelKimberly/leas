//! Every hand-written DDL statement in the crate, in one place.
//!
//! The rule (`docs/database-manual-sql.md` §1) is that the typed toasty path
//! is the default and raw SQL needs a recorded cause. This module is where the
//! DDL half of that list LIVES, so "which indexes exist" is one file rather
//! than a scatter of `ensure` functions. Each statement below carries its cause
//! from `docs/database-manual-sql.md` §2.
//!
//! # Why the tables are not here yet
//!
//! A toasty model's table is emitted by `push_schema` from the model
//! definition, and that emission IS the schema of record until the typed layer
//! is retired (`docs/aegis/specs/2026-10-08-db-adapter-and-migrations-design.md`
//! §6.1, stage S7). Re-writing those `CREATE TABLE` statements by hand here
//! would create a second spelling of the same fact with no reader forcing them
//! to agree, so the v18 migration calls `push_schema` for the tables and this
//! file for everything toasty cannot express. When S7 lands, the tables move
//! here and `push_schema` stops being called.
//!
//! # The raw half
//!
//! Two capability gaps of toasty's `#[index]` (single-column only, no
//! mixed-direction composite) force hand-written `CREATE INDEX`; the rest are
//! derived-state tables and columns on `endpoint_rank` that are deliberately
//! NOT model fields, so adding them costs no schema-tag bump and no wipe.

/// `endpoint_ip`'s covering index: the address-ordered read path
/// (`PageSort::Ip`'s `min(ip_key)` and the IP/CIDR search range).
///
/// Cause C2 — the sort wants `(ip_key, endpoint_id)` together. A field-level
/// `#[index]` is one column; a struct-level `#[index(name = "endpoint_ip_by_key",
/// ip_key, endpoint_id)]` can express this order (it exists at toasty 0.11 and
/// predates 0.10), but the raw statement is kept on purpose: `ensure_raw_ddl`
/// re-applies it on every open, so it heals a database that lost the index,
/// while `push_schema` would create it only at cursor 0. Additive, so it is
/// re-run safely.
pub const ENDPOINT_IP_BY_KEY: &str =
    "CREATE INDEX IF NOT EXISTS endpoint_ip_by_key ON endpoint_ip (ip_key, endpoint_id)";

/// The Test order (decision 16): the default sort, and the one the tab scrolls
/// under.
///
/// Cause C2 — a composite whose last-but-one term is DESCENDING is outside
/// `#[index]`. This index is what makes a page an index scan (~1 ms) instead of
/// a sort over every endpoint (~240 ms). **A NEW NAME, never an edit in place**:
/// `IF NOT EXISTS` makes a changed column list a silent no-op on every database
/// that already has the old index, which would keep serving the new `ORDER BY`
/// and drop the page back to the filesort.
///
/// `endpoint_rank_key_v2` supersedes `endpoint_rank_key` (docs
/// `2026-10-09-stab-bin-design` §6.3): `rank_stab` joins the order terms after
/// `rank_bin`, and `rank_proven` rides LAST as a covering column so the four
/// scopes filter inline on an index scan instead of needing a second index.
pub const ENDPOINT_RANK_KEY_V2: &str = "CREATE INDEX IF NOT EXISTS endpoint_rank_key_v2 ON endpoint_rank(\
     band, rank_bin, rank_stab, rank_weight DESC, rank_domain, rank_sub_domain, rank_addr, \
     endpoint_id, rank_proven)";

/// The v18 index name, retired by `endpoint_rank_key_v2`. Kept as a statement
/// so an existing database drops it instead of carrying a dead index on every
/// rank refresh.
pub const ENDPOINT_RANK_KEY_DROP: &str = "DROP INDEX IF EXISTS endpoint_rank_key";

/// The directional reband sweep seeks `band < 2 AND rank_newest_seen < ?`.
pub const ENDPOINT_RANK_BAND_WINDOW: &str =
    "CREATE INDEX IF NOT EXISTS endpoint_rank_band_window ON endpoint_rank(band, rank_newest_seen)";

/// One-row stamp for the compiled weight tables. A table of opinions that lives
/// in code has no other way to know it is out of date.
pub const RANK_WEIGHT_META: &str = "CREATE TABLE IF NOT EXISTS rank_weight_meta \
     (id INTEGER PRIMARY KEY CHECK (id = 0), weight_version INTEGER NOT NULL)";

/// `profile_stats`'s stability ring columns (`stab_mask`, `stab_len`).
///
/// **TYPED, unlike the `endpoint_rank` raw columns.** They are declared on the
/// `ProfileStats` model, because `decode_projected_link` builds a
/// `ProfileStats` from the page projection and the panel renders the ratio from
/// them — a non-model column would have no home in the decoded row. These
/// ALTERs exist only for databases whose `profile_stats` table was created
/// before the fields were declared (`push_schema` runs only at cursor 0, so a
/// declared field never re-creates an existing table).
///
/// `NOT NULL DEFAULT 0` is what makes the column legal for pre-existing rows;
/// `0/0` reads as `stab_bin = STAB_NEUTRAL` (warm-up), which is the correct
/// "no estimate" value.
pub const STAB_ADD_COLUMNS: &[&str] = &[
    "ALTER TABLE profile_stats ADD COLUMN stab_mask INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE profile_stats ADD COLUMN stab_len INTEGER NOT NULL DEFAULT 0",
];

/// `endpoint_rank`'s two RAW columns, added with `ALTER TABLE`.
///
/// Both are deliberately NOT toasty model fields — they are derived columns on
/// a derived table, so declaring them would mean a schema-tag bump and (under
/// the old tag world) a wipe of a large enriched feed. They cannot be part of
/// `CREATE TABLE` for the same reason.
///
/// `ALTER TABLE ... ADD COLUMN` is NOT idempotent: it errors on a column that
/// already exists. There is no `IF NOT EXISTS` form on this engine, so the
/// runner applies these and TOLERATES the duplicate-column error — the same
/// behaviour the pre-migration `ensure_in` had. `rank_weight` is `NOT NULL
/// DEFAULT`, which is what makes the column legal for pre-existing rows (and
/// why a NULL weight in the anchor query would otherwise error).
///
/// The stab columns are a DIFFERENT case: they are typed model fields
/// (`EndpointRank::stab`/`proven`), so the "declaring them would need a bump"
/// rationale above does NOT apply to them — the runner-era truth is that
/// `push_schema` runs only at cursor 0, so a declared field costs no bump and
/// no wipe. They are listed here so an EXISTING table gains them; a fresh file
/// gets them from `CREATE TABLE`.
pub const ENDPOINT_RANK_ADD_COLUMNS: &[&str] = &[
    "ALTER TABLE endpoint_rank ADD COLUMN band INTEGER",
    "ALTER TABLE endpoint_rank ADD COLUMN rank_weight BLOB \
     NOT NULL DEFAULT x'0000000000000000'",
    "ALTER TABLE endpoint_rank ADD COLUMN rank_stab INTEGER NOT NULL DEFAULT 4",
    "ALTER TABLE endpoint_rank ADD COLUMN rank_proven INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE endpoint_rank ADD COLUMN rank_alive INTEGER NOT NULL DEFAULT 0",
];

/// Prefix indexes for the feed search (issue 019).
///
/// The search's `LIKE 'prefix%'` terms ran over the whole rank table on every
/// keystroke. Additive and idempotent, so `ensure_raw_ddl` re-applies them with
/// no cursor bump.
pub const ENDPOINT_RANK_PREFIX_INDEXES: &[&str] = &[
    "CREATE INDEX IF NOT EXISTS endpoint_rank_domain ON endpoint_rank (rank_domain)",
    "CREATE INDEX IF NOT EXISTS endpoint_rank_sub_domain ON endpoint_rank (rank_sub_domain)",
];

/// Indexes and tables created AFTER the ALTERs above (the covering index names
/// `band`, so it cannot run before the column exists). All idempotent.
pub const V18_AFTER_ALTERS: &[&str] = &[
    ENDPOINT_IP_BY_KEY,
    ENDPOINT_RANK_KEY_V2,
    ENDPOINT_RANK_KEY_DROP,
    ENDPOINT_RANK_BAND_WINDOW,
    RANK_WEIGHT_META,
];

/// **Migration 19** — the latency reshape (spec
/// `2026-10-21-merged-test-pipeline-design` D5, ADR 0016).
///
/// The `Latency` embed was an ENUM: one shared `latency_delay` column plus an
/// exclusive `latency` discriminator, so a row could hold a real delay OR a
/// fast delay, never both. The merged probe produces both in one pass, so
/// the row now carries `latency_real_delay` and `latency_fast_delay`
/// independently, plus the auth flag — and the discriminator is gone.
///
/// The ORDER matters:
///
/// 1. the fast column is added FIRST, and the data step copies a `'fast'`
///    row's delay into it — the v18 shape stored the delay ONCE, in
///    `latency_delay`, and the discriminator said which kind it was;
/// 2. a `'fast'` row's `latency_delay` is CLEARED: it is a TRANSPORT span,
///    not a real measurement, and the new shape keeps the two apart;
/// 3. the RENAME then turns the remaining `latency_delay` (the real rows'
///    delays) into `latency_real_delay`;
/// 4. the DROP goes last — after it, the discriminator's rows are gone and
///    the two delay columns are the whole provenance.
///
/// **These statements are NOT idempotent.** `RENAME COLUMN` and
/// `DROP COLUMN` fail with "no such column" on a second application, and this
/// engine has no `IF NOT EXISTS` form for either. They are safe **only
/// because the migration cursor gates them** — the step runs when
/// `cursor < 19` and the cursor advances in the same transaction. This is why
/// the statements live in the step list (`schema::steps`) and NOT in
/// `ensure_raw_ddl`, which re-runs on every open and has no version to gate
/// on.
pub const V19_LATENCY_RESHAPE: &[&str] = &[
    "ALTER TABLE profile_stats ADD COLUMN latency_fast_delay INTEGER",
    "ALTER TABLE profile_stats ADD COLUMN latency_auth INTEGER",
    // The data step: a 'fast' row's delay is a TRANSPORT span, so it belongs
    // in the fast column. It must run before the discriminator is dropped.
    "UPDATE profile_stats SET latency_fast_delay = latency_delay \
     WHERE latency = 'fast'",
    // ...and the SAME delay leaves the real column: a fast-only row has no
    // real measurement, and the new shape keeps the two apart.
    "UPDATE profile_stats SET latency_delay = NULL WHERE latency = 'fast'",
    "ALTER TABLE profile_stats RENAME COLUMN latency_delay TO latency_real_delay",
    "ALTER TABLE profile_stats DROP COLUMN latency",
];

/// v20: the country ruleset a routing row belongs to (`cn`/`ir`/`ru`).
///
/// Nullable on purpose: rows written before the ruleset model carry `NULL`,
/// and the pane treats them as belonging to whichever country's custom set is
/// active until an edit stamps them.
pub const V20_ROUTING_RULESET: &[&str] = &["ALTER TABLE routing_rules ADD COLUMN ruleset TEXT"];

/// v21: the credential purge reason (spec `2026-09-17-purge-reason-design.md`,
/// amendment 2026-11-18 D8/D9).
///
/// SQLite cannot widen a `CHECK` in place, so the table is rebuilt: the new
/// shape (8-value `purge_reason` CHECK, `error_kind` CHECK and composite PK
/// unchanged) is created under a temporary name, the rows are copied by an
/// explicit column list, the old table is dropped, the new one renamed, and
/// the two secondary indexes are recreated under the names `push_schema`
/// emits. PK values are copied verbatim — no re-key, no row loss.
///
/// The non-idempotence is safe because the cursor gates the step (see
/// `steps.rs`).
pub const V21_CREDENTIAL_PURGE: &[&str] = &[
    "CREATE TABLE profile_stats_v21 (\"protocol_id\" BIGINT NOT NULL, \"endpoint_id\" BIGINT NOT NULL, \"last_used_at\" BIGINT, \"last_seen_at\" BIGINT NOT NULL, \"latency_real_delay\" INTEGER, \"latency_fast_delay\" INTEGER, \"latency_ip\" TEXT, \"latency_auth\" BIGINT, \"speed_bps\" BIGINT, \"error\" BOOLEAN, \"error_kind\" TEXT CHECK (\"error_kind\" IN ('real', 'fast', 'name')), \"error_text\" TEXT, \"purge_reason\" TEXT CHECK (\"purge_reason\" IN ('reality_fallback', 'certificate_mismatch', 'certificate_expired', 'not_tls', 'config_invalid', 'transport_rejected', 'origin_unreachable', 'credential_rejected')), \"stab_mask\" BIGINT NOT NULL, \"stab_len\" BIGINT NOT NULL, \"traffic_today_up\" BIGINT NOT NULL, \"traffic_today_down\" BIGINT NOT NULL, \"traffic_total_up\" BIGINT NOT NULL, \"traffic_total_down\" BIGINT NOT NULL, \"created_at\" BIGINT NOT NULL, \"updated_at\" BIGINT NOT NULL, \"version\" INTEGER NOT NULL, PRIMARY KEY (\"protocol_id\", \"endpoint_id\"))",
    "INSERT INTO profile_stats_v21 (\"protocol_id\", \"endpoint_id\", \"last_used_at\", \"last_seen_at\", \"latency_real_delay\", \"latency_fast_delay\", \"latency_ip\", \"latency_auth\", \"speed_bps\", \"error\", \"error_kind\", \"error_text\", \"purge_reason\", \"stab_mask\", \"stab_len\", \"traffic_today_up\", \"traffic_today_down\", \"traffic_total_up\", \"traffic_total_down\", \"created_at\", \"updated_at\", \"version\") SELECT \"protocol_id\", \"endpoint_id\", \"last_used_at\", \"last_seen_at\", \"latency_real_delay\", \"latency_fast_delay\", \"latency_ip\", \"latency_auth\", \"speed_bps\", \"error\", \"error_kind\", \"error_text\", \"purge_reason\", \"stab_mask\", \"stab_len\", \"traffic_today_up\", \"traffic_today_down\", \"traffic_total_up\", \"traffic_total_down\", \"created_at\", \"updated_at\", \"version\" FROM profile_stats",
    "DROP TABLE profile_stats",
    "ALTER TABLE profile_stats_v21 RENAME TO profile_stats",
    "CREATE INDEX \"index_profile_stats_by_endpoint_id\" ON \"profile_stats\" (\"endpoint_id\")",
    "CREATE INDEX \"index_profile_stats_by_last_seen_at\" ON \"profile_stats\" (\"last_seen_at\")",
];

/// v22: the failure stage × cause pair (spec `2026-11-19-probe-truth-and-ingest-boundary`,
/// S1).
///
/// SQLite cannot add a CHECK in place, so the table is rebuilt exactly as v21
/// rebuilt it: explicit column copy, indexes recreated under the names
/// `push_schema` emits. The two new columns sit AFTER `error_text` (the embed's
/// own order) and are nullable TOGETHER (the pair CHECK), so every pre-22 row
/// migrates as "class unknown" instead of a guess.
///
/// The non-idempotence is safe because the cursor gates the step.
pub const V22_STAGE_CAUSE: &[&str] = &[
    "CREATE TABLE profile_stats_v22 (\"protocol_id\" BIGINT NOT NULL, \"endpoint_id\" BIGINT NOT NULL, \"last_used_at\" BIGINT, \"last_seen_at\" BIGINT NOT NULL, \"latency_real_delay\" INTEGER, \"latency_fast_delay\" INTEGER, \"latency_ip\" TEXT, \"latency_auth\" BIGINT, \"speed_bps\" BIGINT, \"error\" BOOLEAN, \"error_kind\" TEXT CHECK (\"error_kind\" IN ('real', 'fast', 'name')), \"error_text\" TEXT, \"error_stage\" TEXT, \"error_cause\" TEXT, \"purge_reason\" TEXT CHECK (\"purge_reason\" IN ('reality_fallback', 'certificate_mismatch', 'certificate_expired', 'not_tls', 'config_invalid', 'transport_rejected', 'origin_unreachable', 'credential_rejected')), \"stab_mask\" BIGINT NOT NULL, \"stab_len\" BIGINT NOT NULL, \"traffic_today_up\" BIGINT NOT NULL, \"traffic_today_down\" BIGINT NOT NULL, \"traffic_total_up\" BIGINT NOT NULL, \"traffic_total_down\" BIGINT NOT NULL, \"created_at\" BIGINT NOT NULL, \"updated_at\" BIGINT NOT NULL, \"version\" INTEGER NOT NULL, PRIMARY KEY (\"protocol_id\", \"endpoint_id\"), CHECK ((\"error_stage\" IS NULL) = (\"error_cause\" IS NULL)))",
    "INSERT INTO profile_stats_v22 (\"protocol_id\", \"endpoint_id\", \"last_used_at\", \"last_seen_at\", \"latency_real_delay\", \"latency_fast_delay\", \"latency_ip\", \"latency_auth\", \"speed_bps\", \"error\", \"error_kind\", \"error_text\", \"error_stage\", \"error_cause\", \"purge_reason\", \"stab_mask\", \"stab_len\", \"traffic_today_up\", \"traffic_today_down\", \"traffic_total_up\", \"traffic_total_down\", \"created_at\", \"updated_at\", \"version\") SELECT \"protocol_id\", \"endpoint_id\", \"last_used_at\", \"last_seen_at\", \"latency_real_delay\", \"latency_fast_delay\", \"latency_ip\", \"latency_auth\", \"speed_bps\", \"error\", \"error_kind\", \"error_text\", NULL, NULL, \"purge_reason\", \"stab_mask\", \"stab_len\", \"traffic_today_up\", \"traffic_today_down\", \"traffic_total_up\", \"traffic_total_down\", \"created_at\", \"updated_at\", \"version\" FROM profile_stats",
    "DROP TABLE profile_stats",
    "ALTER TABLE profile_stats_v22 RENAME TO profile_stats",
    "CREATE INDEX \"index_profile_stats_by_endpoint_id\" ON \"profile_stats\" (\"endpoint_id\")",
    "CREATE INDEX \"index_profile_stats_by_last_seen_at\" ON \"profile_stats\" (\"last_seen_at\")",
];

/// v23: DNS sources, resolvers, links, and the pool knobs (spec
/// `2026-11-20-dns-resolvers`, D14).
///
/// Additive: three tables and two nullable `dns_settings` columns. The cursor
/// gates the step; the indexes live in [`V23_DNS_INDEXES`] because
/// `push_schema` does not emit a composite/unique index for a non-key field.
pub const V23_DNS_SOURCES: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS dns_sources (\"id\" TEXT NOT NULL PRIMARY KEY, \"name\" TEXT, \"url\" TEXT NOT NULL, \"enabled\" BOOLEAN NOT NULL, \"user_agent\" TEXT, \"sort_order\" INTEGER, \"last_refreshed\" BIGINT, \"status\" TEXT, \"error_message\" TEXT, \"refresh_interval\" BIGINT)",
    "CREATE TABLE IF NOT EXISTS dns_resolvers (\"stamp\" TEXT NOT NULL PRIMARY KEY, \"protocol\" TEXT NOT NULL, \"host\" TEXT NOT NULL, \"port\" BIGINT NOT NULL, \"latency_ms\" BIGINT, \"status\" TEXT NOT NULL, \"error\" TEXT, \"checked_at\" BIGINT, \"enabled\" BOOLEAN NOT NULL)",
    "CREATE TABLE IF NOT EXISTS dns_source_resolvers (\"source_id\" TEXT NOT NULL, \"stamp\" TEXT NOT NULL, PRIMARY KEY (\"source_id\", \"stamp\"))",
];

/// The two `dns_settings` columns, added through `ensure_raw_ddl`'s
/// duplicate-column tolerance (the `STAB_ADD_COLUMNS` rule).
///
/// A file stamped older that already carries them (a test fixture, or a
/// half-applied open) must not fail the migration.
pub const V23_DNS_ADD_COLUMNS: &[&str] = &[
    "ALTER TABLE dns_settings ADD COLUMN \"resolver_pool_size\" BIGINT",
    "ALTER TABLE dns_settings ADD COLUMN \"resolver_test_domain\" TEXT",
];

/// Indexes v23 needs on both a migrated and a fresh file. Idempotent; run by
/// `ensure_raw_ddl` after every migrate (and on every open).
pub const V23_DNS_INDEXES: &[&str] = &[
    "CREATE UNIQUE INDEX IF NOT EXISTS \"index_dns_sources_by_url\" ON \"dns_sources\" (\"url\")",
    "CREATE INDEX IF NOT EXISTS \"index_dns_resolvers_pool\" ON \"dns_resolvers\" (\"enabled\", \"status\", \"latency_ms\")",
    "CREATE INDEX IF NOT EXISTS \"index_dns_source_resolvers_by_stamp\" ON \"dns_source_resolvers\" (\"stamp\")",
];

/// The stage × cause pair invariant for a FRESH database.
///
/// A migrated file gets it from [`V22_STAGE_CAUSE`]'s table CHECK; `push_schema`
/// emits only what the model declares and the model cannot declare a table
/// constraint, so a fresh install would otherwise accept a half pair at the
/// same `SCHEMA_VERSION`. Two triggers, idempotent, run by `ensure_raw_ddl`
/// on every open — a file that already has the CHECK pays one no-op each.
pub const PAIR_GUARD: &[&str] = &[
    "CREATE TRIGGER IF NOT EXISTS profile_stats_pair_ins BEFORE INSERT ON profile_stats \
     WHEN (NEW.error_stage IS NULL) <> (NEW.error_cause IS NULL) \
     BEGIN SELECT RAISE(ABORT, 'error_stage and error_cause must be set together'); END",
    "CREATE TRIGGER IF NOT EXISTS profile_stats_pair_upd BEFORE UPDATE ON profile_stats \
     WHEN (NEW.error_stage IS NULL) <> (NEW.error_cause IS NULL) \
     BEGIN SELECT RAISE(ABORT, 'error_stage and error_cause must be set together'); END",
];
