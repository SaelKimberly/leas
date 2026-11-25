use std::io::Read;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;

use toasty::Executor;
use toasty::stmt::IntoStatement;
use toasty_core::driver::operation::TransactionMode;
use toasty_core::stmt::Value;

use crate::error::{DatabaseError, Result};
use crate::models_toasty::{
    AppMeta, DnsResolver, DnsSetting, DnsSource, DnsSourceResolver, Endpoint, EndpointGroup,
    EndpointId, EndpointIp, EndpointRank, EndpointRow, Group, GroupStatus, Latency, ProfileStats,
    Protocol, ProtocolId, ResolverStatus, RouteProbes, RoutingRule, TrafficStats, now_epoch,
};
use crate::retry_on_busy;
use rapidhash::{HashMapExt as _, RapidHashMap};

/// One parsed resolver, as a source refresh writes it. The app converts a
/// `leas_dns::Candidate` into this shape — `leas-db` does not depend on the DNS
/// transport.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsCandidateRow {
    pub stamp: String,
    pub protocol: String,
    pub host: String,
    pub port: u16,
}

// ── Database handle ─────────────────────────────────────────────────────

// Tag for databases created by this 7-table schema. toasty 0.9's
// push_schema emits CREATE TABLE without IF NOT EXISTS, so it can
// only run on a database that has no tables yet; the tag lets reopen
// skip it. Any other tag is a pre-T8 9-table database (incompatible
// with the typed models) and is recreated from scratch.
//
// 7 = per-kind binary identity (`Protocol.id = uid`, see
// `leas-proto::proto_spec::identity`). v6 rows carry uids hashed
// from canonical JSON, which are unrelated to the new values, so
// reusing a v6 file would re-key every protocol into a duplicate row
// and orphan its links. The bump WIPES the file by design.
//
// 8 = `endpoint_rank` (ADR 0003) as a first-class table. This project
// is pre-alpha, so a new table arrives by the same wipe rather than by
// migration machinery: a v7 file is discarded and rebuilt with the
// table present. The stored keys are derived state — a feed is
// re-imported, and the keys rebuild from its links.
//
// 9 = the durable-facts pass: `profile_stats` loses `task_id` /
// `task_queue` (the scheduler's state is runtime-only — an id is only
// meaningful inside the process that allocated it), the timestamps
// become epoch seconds, `protocols.cred_hash` and `endpoints.parent_id`
// go (both derivable: the uid is recomputed from the config, a DNS
// endpoint's resolutions live in `resolved_as`), and the two indexes
// the purge / failed-sweep predicates need are added. Same contract as
// every bump: a v8 file is WIPED, never migrated.
//
// 10 = resolved addresses become a table: the JSON-array
// `endpoints.resolved_as` column is replaced by `endpoint_ip`, one row
// per address with a sortable key. A v9 file is WIPED (the addresses it
// holds cannot be moved: the old column is gone, and the enrichment
// pipeline re-resolves on the next pass).
//
// 11 = `endpoint_ip` carries the address's ISO-3166 country, written
// once by the mmdb lookup, so a later launch renders the flag without
// the database. A v10 file is WIPED (a column cannot be added to a
// pushed table here; the countries are re-derived on the next pass).
//
// 12 = `profile_stats.purge_reason` (spec 2026-09-17-purge-reason):
// the typed, permanent verdict a real probe's evidence writes and only
// a data-carrying success clears. A v11 file is WIPED (a column cannot
// be added to a pushed table here; the verdicts are re-derived by the
// next Real run, and the reference classification is kept beside the
// dataset copy the design spec names).
//
// 14 = the SIP003 plugin field became a typed, lossless `PluginSpec`.
// No COLUMN changes — the JSON column carries the new shape — but the
// identity format changed with it (`IDENTITY_VERSION` 1 → 2), so every
// stored uid re-keys. A v13 file would still open and every row would
// simply be a stale uid with no config behind it, so the file is wiped
// for the clean re-import. The user accepted the wipe (pre-alpha,
// 2026-09-30).
//
// 15 = the DB-rewamp column drops + identity re-key: `protocols`
// loses `transport_data`/`security_data`, `profile_stats` loses
// `core_type`/`config_type` and `endpoint_rank` loses `rank_config`,
// and `IDENTITY_VERSION` 2 → 3 (the `config_type` term left the
// identity). A v14 file keeps the dropped columns as NOT NULL while the
// model no longer has them — every import INSERT would fail — so the
// file is wiped for the clean re-import. Subsequent rewamp slices
// (the host/identity model, the binned law) bump again.
//
// 16 = `app_meta(key, value)` as a typed model (PSL stamp).
//
// 17 = `endpoint_rank` reshaped to the BINNED law (db-rewamp D11): `rank_bin`/
// `rank_domain`/`rank_sub_domain`/`rank_addr` replace `rank_dns`/`rank_tier`/
// `rank_latency`/`rank_seen`/`rank_protocol`/`rank_display_seen`/`rank_speed`/
// `rank_traffic`; one covering index `endpoint_rank_key`.
//
// 18 = `endpoints.host`/`host_type` dropped (db-rewamp D2/D10): the identity
// input is the derived `(domain, sub_domain)` split, and every address lives in
// `endpoint_ip` (an IP-literal endpoint's dial target has no other home).
//
// 19 = the latency row carries TWO delays and an auth flag (spec
// `2026-10-21-merged-test-pipeline-design` D4/D5, ADR 0016): the `Latency`
// embed became a struct, so `latency_delay` is split into
// `latency_real_delay` (the full probe's span) and `latency_fast_delay` (the
// transport span), `latency_auth` was added, and the `latency` discriminator
// was DROPPED — a row's provenance is now carried by which delay column is
// populated. This is the crate's FIRST real migration step: a version-18
// database migrates in place, and only an unknown cursor still wipes.
//
// 20 = `routing_rules.ruleset` (country ruleset, spec
// `2026-11-11-country-rulesets-design` D3): nullable, so a pre-ruleset row
// stays readable and is treated as custom under every country.
//
// 21 = `PurgeReason::CredentialRejected`: SQLite cannot widen a CHECK in
// place, so the step rebuilds `profile_stats` (spec `2026-09-17-purge-reason`
// amendment, D8/D9).
pub const SCHEMA_VERSION: i64 = 23;

/// One resolved address of an endpoint, with the ISO-3166 alpha-2 country the
/// geo step wrote (`None` until it does).
///
/// A named alias because the signature appears in three places and the tuple
/// spelling is unreadable inline.
pub type ResolvedAddress = (std::net::IpAddr, Option<String>);

pub struct Database {
    db: toasty::Db,
    concurrent_writes: bool,
    path: Option<PathBuf>,
    export_lock: Arc<tokio::sync::Mutex<()>>,
    /// A LONG-LIVED direct turso connection (db-rewamp T13), created ONCE at
    /// open and used for the page's id+count reads, which bypass toasty's
    /// execution layer (~108 ms → ~1 ms on the 74k feed). `None` for an
    /// in-memory database, where the toasty path is used. The export reader
    /// opens its own per-call connection instead: it is a one-off.
    pub(crate) direct: Option<Arc<tokio::sync::Mutex<turso::Connection>>>,
    /// Dirty endpoints whose ordering keys need refresh before page loads.
    /// Allows concurrent write transactions to omit in-tx rank refresh.
    pub(crate) dirty_ranks: Arc<dashmap::DashSet<EndpointId>>,
}

/// Which mutable column groups a [`LinkPatch`] writes.
///
/// The groups exist so the two independent writers of a `profile_stats` row —
/// ping results and the scheduler gate — cannot clobber each other's columns
/// when their patches coalesce in the same flush.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LinkGroups(u8);

impl LinkGroups {
    /// `latency` + `speed_bps` + `error` (ping results, error TTL sweeps).
    pub const RESULT: Self = Self(0b001);
    /// `purge_reason` (the real probe's verdict).
    ///
    /// Its own bit, not part of RESULT: [`link_patch_conflict_sql`] writes a
    /// FIXED column set from each patch's *snapshot*, so riding RESULT would
    /// let a phase-1 fast half — whose snapshot is the plan-time row — rewrite
    /// a verdict it never classified. That is the clobber shape these groups
    /// exist to prevent (ADR 0002), and the classifier is the only producer.
    pub const PURGE: Self = Self(0b010);
    /// `traffic_*` (the gRPC stats poller).
    pub const TRAFFIC: Self = Self(0b100);
    /// `stab_mask` + `stab_len` (the stability ring, spec
    /// `2026-10-09-stab-bin-design`).
    ///
    /// Its own bit for the same reason as [`Self::PURGE`]:
    /// [`link_patch_conflict_sql`] writes a fixed column set from each patch's
    /// snapshot, so riding RESULT would let a fast-only result — whose snapshot
    /// never sampled the ring — rewrite the counters. Only the producers that
    /// actually append a sample set this bit.
    pub const STAB: Self = Self(0b1000);
    /// `last_seen_at` (the approval stamp of a data-carrying success).
    ///
    /// Its own bit for the same reason as [`Self::PURGE`]: the fixed-column-set
    /// rule, so a fast half staging a plan-time snapshot cannot rewrite the
    /// stamp. The write is monotone (`MAX`), because the import writer also
    /// owns this column and both values mean "seen recently".
    pub const SEEN: Self = Self(0b1_0000);
    /// Every group.
    ///
    /// Every group can change a STORED ORDERING KEY — the rank columns derive
    /// from a link's `error`/`latency`/`last_seen_at`/`speed_bps`/`traffic`/
    /// `purge_reason`/`stab_mask`/`stab_len` — so every patch refreshes its
    /// endpoint's keys. (The scheduler's task state used to be a third group;
    /// it is runtime-only now and never reaches this table.)
    pub const ALL: Self = Self(0b1_1111);

    /// Whether `other`'s groups are all present in `self`.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// Whether any group is shared.
    #[must_use]
    pub const fn intersects(self, other: Self) -> bool {
        self.0 & other.0 != 0
    }

    /// OR of two groups.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

/// One row's pending write: the mutable state plus the groups that changed.
#[derive(Debug, Clone)]
pub struct LinkPatch {
    /// Row identity and the new values of the patched groups.
    pub link: ProfileStats,
    /// Groups to write; unset groups keep their persisted values.
    pub groups: LinkGroups,
}

// ── Constructors ────────────────────────────────────────────────────────
const CONCURRENT_WRITES_ENV: &str = "LEAS_TURSO_CONCURRENT_WRITES";
fn concurrent_writes_enabled() -> bool {
    concurrent_writes_from_env(std::env::var(CONCURRENT_WRITES_ENV).ok().as_deref())
}

fn concurrent_writes_from_env(value: Option<&str>) -> bool {
    value.is_some_and(|value| value == "1" || value.eq_ignore_ascii_case("true"))
}

fn file_journal_mode(path: &Path) -> std::io::Result<Option<u8>> {
    if !path.exists() || std::fs::metadata(path)?.len() < 20 {
        return Ok(None);
    }
    let mut file = std::fs::File::open(path)?;
    let mut header = [0_u8; 20];
    file.read_exact(&mut header)?;
    Ok(Some(header[19]))
}

fn should_use_mvcc(path: &Path, requested_mvcc: bool) -> Result<bool> {
    match file_journal_mode(path)? {
        Some(255) => Ok(true),
        Some(2) => {
            if requested_mvcc {
                tracing::warn!(
                    path = %path.display(),
                    "existing WAL database stays in WAL mode; this engine cannot convert a WAL file to MVCC in place"
                );
            }
            Ok(false)
        }
        Some(_) => Ok(false),
        None => Ok(requested_mvcc),
    }
}

/// Open the long-lived direct reader connection (db-rewamp T13). Mirrors the
/// driver's journal mode so a WAL/MVCC file is read consistently.
async fn open_direct_conn(path: &str, concurrent_writes: bool) -> Result<turso::Connection> {
    let db = turso::Builder::new_local(path)
        .build()
        .await
        .map_err(crate::export::turso_error)?;
    let conn = db.connect().map_err(crate::export::turso_error)?;
    // The builder handle is only needed to open the connection.
    drop(db);
    let journal = if concurrent_writes { "mvcc" } else { "wal" };
    let _ = conn
        .pragma_update("journal_mode", format!("'{journal}'"))
        .await;
    // The per-connection settings `conn()` applies to every pooled connection:
    // the raw link writer runs on THIS connection (its inlined-literal upsert
    // would otherwise grow the driver's unbounded statement cache), and a
    // concurrent writer must queue behind the lock holder rather than fail
    // instantly, exactly as the pooled writers do.
    let _ = conn.pragma_update("busy_timeout", "5000").await;
    let _ = conn.pragma_update("synchronous", "NORMAL").await;
    let _ = conn.pragma_update("foreign_keys", "ON").await;
    Ok(conn)
}

fn file_driver(path: &str, concurrent_writes: bool) -> crate::driver::Turso {
    let driver = crate::driver::Turso::file(path);
    if concurrent_writes {
        // The checkpoint flag MUST accompany the MVCC opt-in. NOT because the
        // log would grow without bound — the engine AUTO-checkpoints MVCC on the
        // commit path once its logical log passes ~4.12 MB
        // (`should_checkpoint()`, DEFAULT_LOG_CHECKPOINT_THRESHOLD, compared
        // against a BYTE offset) — but because of the MODE that checkpoint takes:
        // with the flag unset it is `CheckpointMode::Truncate`, which blocks both
        // readers and writers for the whole checkpoint; with it set it is
        // `Passive`, a non-blocking drain. So the flag trades a periodic
        // whole-database stall for a background one. (It is also what lets our
        // own batch-end `PRAGMA wal_checkpoint(PASSIVE)` run at all under MVCC —
        // without it the engine refuses that statement.)
        driver
            .concurrent_writes()
            .experimental_mvcc_passive_checkpoint(true)
    } else {
        driver
    }
}

fn remove_stale_mvcc_log_for_wal(path: &Path) -> std::io::Result<()> {
    if !path.exists() {
        return Ok(());
    }
    let log_path = std::path::PathBuf::from(format!("{}-log", path.display()));
    if !log_path.exists() {
        return Ok(());
    }
    let mut file = std::fs::File::open(path)?;
    let mut header = [0_u8; 20];
    file.read_exact(&mut header)?;
    if header[18] == 2 && header[19] == 2 {
        std::fs::remove_file(log_path)?;
    }
    Ok(())
}
fn remove_all_db_sidecars(path: &Path) -> std::io::Result<()> {
    for suffix in ["-wal", "-shm", "-log"] {
        let sidecar = std::path::PathBuf::from(format!("{}{suffix}", path.display()));
        if sidecar.exists() {
            std::fs::remove_file(sidecar)?;
        }
    }
    Ok(())
}

async fn configure_journal_mode(
    conn: &mut impl toasty::Executor,
    concurrent_writes: bool,
) -> Result<()> {
    let mode = if concurrent_writes { "mvcc" } else { "wal" };
    toasty::sql::query(format!("PRAGMA journal_mode='{mode}'"))
        .exec(conn)
        .await?;
    Ok(())
}

impl Database {
    /// Opens an existing database, or creates one. A failed open propagates and
    /// leaves the file alone; only an explicitly incompatible schema is wiped.
    pub async fn open(path: impl AsRef<Path>) -> Result<Self> {
        Self::open_with_concurrent_writes(path, concurrent_writes_enabled()).await
    }

    #[allow(
        clippy::significant_drop_tightening,
        reason = "the Turso driver temporaries are consumed by try_open_db in the very next statement; clippy attributes their drop to the whole fn through the generic await"
    )]
    pub async fn open_with_concurrent_writes(
        path: impl AsRef<Path>,
        requested_mvcc: bool,
    ) -> Result<Self> {
        let path_str = path
            .as_ref()
            .to_str()
            .ok_or_else(|| DatabaseError::Generic("invalid db path".into()))?;

        // If file is empty (0 bytes), delete so toasty can create it fresh
        if Path::new(path_str).exists() && std::fs::metadata(path_str)?.len() == 0 {
            std::fs::remove_file(path_str)?;
        }
        remove_stale_mvcc_log_for_wal(Path::new(path_str))?;
        let mut concurrent_writes = should_use_mvcc(Path::new(path_str), requested_mvcc)?;

        let driver = file_driver(path_str, concurrent_writes);
        let mut db = match Self::try_open_db(driver).await {
            Ok(db) => db,
            Err(e) => {
                // This branch used to DELETE the database and recreate it. Any
                // transient failure then became silent data loss: a second
                // instance opening a live file (writer lock held) hit it on
                // 2026-11-10 and wiped a 12 MB feed. A failed open now
                // propagates; the only wipe left is the explicit
                // `IncompatibleSchema` verdict below, which AGENTS decision 4
                // documents.
                tracing::error!(
                    path = %path_str,
                    error = %e,
                    "database open failed; the file was left untouched"
                );
                return Err(e);
            }
        };

        let mut conn = db.connection().await?;

        // The schema's single owner (see `crate::schema`). It replaces the old
        // `user_version` tag, whose only outcomes were "run push_schema" or
        // "delete the file": a supported older version now MIGRATES, and only a
        // file whose cursor names an UNKNOWN schema takes the documented wipe.
        match crate::schema::migrate(&db, &mut conn).await {
            Ok(()) => {}
            Err(crate::error::DatabaseError::IncompatibleSchema(version)) => {
                // A foreign or pre-migration file: unreadable by this code.
                // The pre-alpha policy is a wipe (AGENTS decision 4), now an
                // EXPLICIT verdict rather than an inferred `CREATE TABLE`
                // failure.
                tracing::warn!(
                    version,
                    latest = crate::schema::LATEST,
                    "incompatible DB schema, recreating from scratch"
                );
                drop(conn);
                if Path::new(path_str).exists() {
                    remove_stale_mvcc_log_for_wal(Path::new(path_str))?;
                    std::fs::remove_file(path_str)?;
                }
                remove_all_db_sidecars(Path::new(path_str))?;
                concurrent_writes = requested_mvcc;
                let driver = file_driver(path_str, concurrent_writes);
                db = Self::try_open_db(driver).await?;
                let mut fresh = db.connection().await?;
                crate::schema::migrate(&db, &mut fresh).await?;
                conn = fresh;
            }
            Err(e) => return Err(e),
        }

        configure_journal_mode(&mut conn, concurrent_writes).await?;

        Self::init_default_groups(&mut conn).await?;
        // The ordering keys' DDL now lives in `crate::schema` (run by
        // `migrate` above). What remains here is the DATA work: backfill an
        // empty table, heal absent rows, and recompute keys when the compiled
        // weight tables changed. A database that predates it pays once, here.
        if std::env::var("LEAS_SKIP_RANK_ENSURE").is_err()
            && let Err(e) = crate::endpoint_rank::ensure(&mut conn).await
        {
            tracing::warn!(target: "leas_db", "endpoint_rank: {e}");
        }
        let direct = match open_direct_conn(path_str, concurrent_writes).await {
            Ok(c) => Some(Arc::new(tokio::sync::Mutex::new(c))),
            Err(e) => {
                tracing::warn!(target: "leas_db", "direct reader unavailable: {e}");
                None
            }
        };
        let db = Self {
            db,
            concurrent_writes,
            path: Some(PathBuf::from(path_str)),
            export_lock: Arc::new(tokio::sync::Mutex::new(())),
            direct,
            dirty_ranks: Arc::new(dashmap::DashSet::new()),
        };
        // One-time: retire the stored shapes no codec can dial (S5). A failure
        // here must not block the open — the next open retries, and the marker
        // only advances when the work committed.
        if std::env::var("LEAS_SKIP_INVALID_PURGE").is_err()
            && let Err(e) = db.purge_invalid_shapes_once().await
        {
            tracing::warn!(target: "leas_db", "invalid-shape purge: {e}");
        }
        Ok(db)
    }

    /// One-time retirement of the stored rows the ingest gate now refuses
    /// (spec `2026-11-19-probe-truth-and-ingest-boundary` S5).
    ///
    /// A shape no shipped codec can dial — a `flow` with no TLS/REALITY layer,
    /// or an `ss` "method" that is not a cipher — is not a deprecated variant
    /// (ADR 0018 D-C): it is an invalid config. New imports are refused before
    /// they reach the store; this step gives the rows that arrived earlier the
    /// verdict their shape earns (`config_invalid`), so Purgatory's TTL retires
    /// them instead of the probe budget testing them forever.
    ///
    /// Marker-gated (`app_meta.invalid_shapes_purged`): the scan runs once per
    /// database, never on a normal open. Rows are classified with the SAME
    /// validators the ingest gate uses, never by a second JSON reading here.
    async fn purge_invalid_shapes_once(&self) -> Result<()> {
        const MARKER: &str = "invalid_shapes_purged";
        // Version 2 added the unrepresentable transport host (the audit's
        // `invalid uri character` class). An existing DB stamped 1 re-runs
        // the scan once; the key stays the same, so no schema change.
        // Version 3 added the Hysteria2 obfs shape (unknown name / missing
        // password). An existing DB stamped 1 or 2 re-runs the scan once; the
        // key stays the same, so no schema change.
        const MARKER_VERSION: i64 = 3;
        let mut conn = self.conn().await?;
        if crate::schema::rekey::marker_value(&mut conn, MARKER).await? >= MARKER_VERSION {
            return Ok(());
        }
        let rows = toasty::sql::query(
            "SELECT ps.endpoint_id, ps.protocol_id, p.config FROM profile_stats ps \
             JOIN protocols p ON p.id = ps.protocol_id WHERE ps.purge_reason IS NULL",
        )
        .exec(&mut conn)
        .await?;
        let mut hits: Vec<(i64, i64)> = Vec::new();
        for row in &rows {
            let toasty_core::stmt::Value::Record(fields) = row else {
                continue;
            };
            let (
                Some(toasty_core::stmt::Value::I64(endpoint)),
                Some(toasty_core::stmt::Value::I64(protocol)),
                Some(toasty_core::stmt::Value::String(config)),
            ) = (fields.first(), fields.get(1), fields.get(2))
            else {
                continue;
            };
            let Ok(parsed) = serde_json::from_str::<leas_proto::proto_spec::ProtocolConfig>(config)
            else {
                continue;
            };
            if !leas_proto::proto_spec::is_undialable_shape(&parsed) {
                continue;
            }
            hits.push((*protocol, *endpoint));
        }
        if hits.is_empty() {
            crate::schema::rekey::stamp_marker(&mut conn, MARKER, MARKER_VERSION).await?;
            return Ok(());
        }
        let mut endpoints: Vec<EndpointId> = Vec::new();
        for chunk in hits.chunks(400) {
            let list = chunk
                .iter()
                .map(|(p, e)| format!("({p},{e})"))
                .collect::<Vec<_>>()
                .join(",");
            toasty::sql::query(format!(
                "UPDATE profile_stats SET purge_reason = 'config_invalid', updated_at = {} \
                 WHERE (protocol_id, endpoint_id) IN ({list})",
                crate::models_toasty::now_epoch()
            ))
            .exec(&mut conn)
            .await?;
            endpoints.extend(chunk.iter().map(|(_, e)| EndpointId::new(*e)));
        }
        drop(conn);
        let _ = self.refresh_endpoint_ranks(&endpoints).await;
        let mut conn = self.conn().await?;
        crate::schema::rekey::stamp_marker(&mut conn, MARKER, MARKER_VERSION).await?;
        Ok(())
    }

    /// One-time clear of the `not testable by the native engine: …` verdicts
    /// when the native engine gains a shape (audit §D4). The caller owns the
    /// revision (`leas-native::capability::SUPPORT_REVISION`): this crate
    /// cannot see the capability table, so it cannot derive the version.
    ///
    /// Marker-gated (`app_meta.capability_version`). Only a live row whose
    /// error is the untestable marker is cleared; a real probe failure and a
    /// purge verdict are facts about the link and stay. The cleared endpoint
    /// ranks are refreshed because a real-error tier change moves them.
    pub async fn clear_stale_capability_verdicts(&self, version: i64) -> Result<()> {
        const MARKER: &str = "capability_version";
        let mut conn = self.conn().await?;
        if crate::schema::rekey::marker_value(&mut conn, MARKER).await? >= version {
            return Ok(());
        }
        let pattern = format!("{}%", crate::UNTESTABLE_PREFIX);
        let rows = toasty::sql::query(format!(
            "SELECT DISTINCT endpoint_id FROM profile_stats WHERE error_kind = 'real' \
             AND error_text LIKE {} AND purge_reason IS NULL",
            sql_lit(&pattern)
        ))
        .exec(&mut conn)
        .await?;
        let ids: Vec<i64> = rows
            .iter()
            .filter_map(|row| match row {
                toasty_core::stmt::Value::Record(f) => match f.first() {
                    Some(toasty_core::stmt::Value::I64(id)) => Some(*id),
                    _ => None,
                },
                _ => None,
            })
            .collect();
        let mut endpoints: Vec<EndpointId> = Vec::new();
        for chunk in ids.chunks(400) {
            let list = chunk
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(",");
            toasty::sql::query(format!(
                "UPDATE profile_stats SET error = NULL, error_kind = NULL, \
                 error_text = NULL, error_stage = NULL, error_cause = NULL, \
                 updated_at = {} WHERE endpoint_id IN ({list}) AND error_kind = 'real' \
                 AND error_text LIKE {} AND purge_reason IS NULL",
                crate::models_toasty::now_epoch(),
                sql_lit(&pattern)
            ))
            .exec(&mut conn)
            .await?;
            endpoints.extend(chunk.iter().map(|id| EndpointId::new(*id)));
        }
        drop(conn);
        if !endpoints.is_empty() {
            let _ = self.refresh_endpoint_ranks(&endpoints).await;
        }
        let mut conn = self.conn().await?;
        crate::schema::rekey::stamp_marker(&mut conn, MARKER, version).await?;
        Ok(())
    }

    /// True when this handle reads the page through the long-lived direct
    /// turso connection (T13) — a file-backed database. False for an in-memory
    /// one, which uses the toasty execution path.
    #[must_use]
    pub const fn uses_direct_reader(&self) -> bool {
        self.direct.is_some()
    }
    /// Mark endpoints as needing their ordering keys recomputed.
    pub fn mark_endpoint_ranks_dirty(&self, endpoint_ids: &[EndpointId]) {
        for id in endpoint_ids {
            self.dirty_ranks.insert(*id);
        }
    }

    /// Number of endpoints currently pending rank recalculation.
    #[must_use]
    pub fn dirty_rank_count(&self) -> usize {
        self.dirty_ranks.len()
    }

    /// Drain and recompute stored keys for all dirty endpoints.
    ///
    /// Ids are removed up front so a re-mark landing during the refresh
    /// survives; on refresh FAILURE they are re-inserted, or those endpoints
    /// would never be refreshed again (busy exhaustion is real — the refresh
    /// retries 5×, then gives up).
    #[tracing::instrument(target = "db_method", skip_all, fields(retries = tracing::field::Empty))]
    pub async fn drain_dirty_ranks(&self) -> Result<usize> {
        if self.dirty_ranks.is_empty() {
            return Ok(0);
        }
        let ids: Vec<EndpointId> = self.dirty_ranks.iter().map(|entry| *entry).collect();
        if ids.is_empty() {
            return Ok(0);
        }
        for id in &ids {
            self.dirty_ranks.remove(id);
        }
        match self.refresh_endpoint_ranks(&ids).await {
            Ok(n) => Ok(n),
            Err(err) => {
                for id in &ids {
                    self.dirty_ranks.insert(*id);
                }
                Err(err)
            }
        }
    }

    /// Open a toasty DB by constructing builder. Separate for recovery logic.
    async fn try_open_db(driver: crate::driver::Turso) -> Result<toasty::Db> {
        let db = toasty::Db::builder()
            // Bind values on the `toasty::query` event. The monitoring spec
            // names this knob (`:21`, `:23`); it was referenced nowhere in the
            // tree. SAFETY: params reach only the SESSION-ONLY `detail`
            // channel — `LogVisitor::split` keeps them out of `LogMessage`, so
            // a bind carrying `protocols.config` (UUIDs, passwords) is never
            // persisted to heed, which is non-goal 10 of that spec.
            .log_statement_params(true)
            .models(toasty::models!(
                Endpoint,
                Protocol,
                ProfileStats,
                EndpointGroup,
                Group,
                RoutingRule,
                DnsSetting,
                DnsSource,
                DnsResolver,
                DnsSourceResolver,
                RouteProbes,
                AppMeta,
                EndpointRank,
                EndpointIp
            ))
            .build(driver)
            .await?;
        Ok(db)
    }

    /// Acquire a pooled connection.
    ///
    /// The `SQLite` per-connection settings the pooled connections need
    /// (`busy_timeout` 5 s, `synchronous=NORMAL`, `foreign_keys=ON`) are
    /// applied once per physical connection by the driver's pool create hook.
    /// Without the busy-wait, concurrent writers (enrichment resolutions,
    /// ping-buffer flushes) fail instantly with "database is locked" instead of
    /// queuing behind the lock holder — the 850-line "database is locked" class
    /// in the dumps.
    async fn conn(&self) -> Result<toasty::Connection> {
        // The 2026-11-24 audit's 806/812 s statements were unattributable:
        // toasty's `QueryLog` times the exec but says nothing about the pool
        // checkout, which is where a single-writer WAL backlog is paid.
        let started = std::time::Instant::now();
        // Report BEFORE propagating: a checkout that waited and then failed is
        // the most pathological case, and `?` below would hide it.
        let conn = self.db.connection().await;
        crate::driver::conn_timing::report_checkout(started.elapsed());
        let conn = conn?;
        // The per-connection settings (`busy_timeout`, `synchronous`,
        // `foreign_keys`) are applied ONCE per physical connection by the
        // driver's pool create hook (`driver/mod.rs::connect`). They used to be
        // re-issued here on every checkout — two statements, measured 20–33 µs
        // per database call — after the first checkout already set them.
        Ok(conn)
    }

    /// Public pooled-connection accessor for callers building typed
    /// create/update statements (Task 10 writes; integration tests).
    pub async fn connection(&self) -> Result<toasty::Connection> {
        self.conn().await
    }
    /// Whether this database handle was opened with Turso MVCC transactions.
    #[must_use]
    pub const fn uses_concurrent_writes(&self) -> bool {
        self.concurrent_writes
    }

    /// Acquire the process-local export gate for a complete streaming export.
    pub async fn export_guard(&self) -> tokio::sync::OwnedMutexGuard<()> {
        self.export_lock.clone().lock_owned().await
    }
    pub(crate) fn export_path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    pub async fn in_memory() -> Result<Self> {
        let driver = crate::driver::Turso::in_memory();
        let db = toasty::Db::builder()
            .models(toasty::models!(
                Endpoint,
                Protocol,
                ProfileStats,
                EndpointGroup,
                Group,
                RoutingRule,
                DnsSetting,
                DnsSource,
                DnsResolver,
                DnsSourceResolver,
                RouteProbes,
                AppMeta,
                EndpointRank,
                EndpointIp
            ))
            .build(driver)
            .await?;

        let mut conn = db.connection().await?;
        // Same single schema owner as the file path (see `crate::schema`): on an
        // in-memory database the cursor is always 0, so this creates the tables
        // and the raw DDL exactly once.
        crate::schema::migrate(&db, &mut conn).await?;

        Self::init_default_groups(&mut conn).await?;
        // The ordering keys' DDL now lives in `crate::schema` (run by
        // `migrate` above). What remains here is the DATA work: backfill an
        // empty table, heal absent rows, and recompute keys when the compiled
        // weight tables changed. A database that predates it pays once, here.
        if std::env::var("LEAS_SKIP_RANK_ENSURE").is_err()
            && let Err(e) = crate::endpoint_rank::ensure(&mut conn).await
        {
            tracing::warn!(target: "leas_db", "endpoint_rank: {e}");
        }
        Ok(Self {
            db,
            concurrent_writes: false,
            path: None,
            export_lock: Arc::new(tokio::sync::Mutex::new(())),
            direct: None,
            dirty_ranks: Arc::new(dashmap::DashSet::new()),
        })
    }

    async fn init_default_groups(conn: &mut impl toasty::Executor) -> Result<()> {
        let count = Group::all().count().exec(conn).await?;
        if count == 0 {
            Group::create()
                .id(uuid::Uuid::new_v4().to_string())
                .name(Some("Default".to_string()))
                .enabled(true)
                .sort_order(Some(0))
                .into_statement()
                .exec(conn)
                .await?;
        }
        Ok(())
    }
}

/// Rows per literal statement chunk in the link writers
/// ([`Database::apply_link_patches`], [`upsert_links_bulk`]) — a
/// statement-size bound, not a predicate-depth one: both writers emit one
/// multi-row upsert per chunk, whose width does not change its expression depth
/// (measured 2026-09-16: 400 / 1,000 / 2,000 rows per statement are equal
/// within noise — 11.1 / 10.6 / 10.6 ms for a 512-patch window), so this
/// number is free to move.
const LINK_STATEMENT_ROWS: usize = 400;

/// Endpoints per transaction in [`Database::update_endpoint_resolutions`].
/// One transaction carries the `resolved_at` update, the address-set rewrite
/// (one delete + a country read + one insert per surviving address) and one
/// rank refresh for the chunk — bounded enough that the plan read can
/// interleave, wide enough to collapse the flush's per-endpoint commits.
const RESOLUTION_CHUNK: usize = 64;

/// A SQL TEXT literal: single quotes doubled, so a stored error message can
/// never terminate the literal. The values come from our own rows, never from
/// user input at this layer.
#[must_use]
pub fn sql_lit(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for ch in s.chars() {
        if ch == '\'' {
            out.push('\'');
        }
        out.push(ch);
    }
    out.push('\'');
    out
}

/// A SQL TEXT literal for a nullable column (`NULL` when absent).
fn sql_opt_lit(s: Option<&str>) -> String {
    s.map_or_else(|| "NULL".to_string(), sql_lit)
}

/// A SQL integer literal for a nullable column.
fn sql_opt_num(n: Option<i64>) -> String {
    n.map_or_else(|| "NULL".to_string(), |n| n.to_string())
}

const LINK_COMPARE_KEYS: &str = "protocol_id, endpoint_id";

/// The `INSERT … VALUES (…),(…)` prefix both link writers share; a caller
/// appends its tuples and then the `ON CONFLICT` action. The column order IS
/// the order [`link_values_sql`] emits.
const LINK_UPSERT_PREFIX: &str = "INSERT INTO profile_stats (protocol_id, endpoint_id, \
     last_used_at, last_seen_at, latency_real_delay, latency_fast_delay, latency_ip, \
     latency_auth, speed_bps, \
     error, error_kind, error_text, error_stage, error_cause, purge_reason, \
     traffic_today_up, traffic_today_down, \
     traffic_total_up, traffic_total_down, created_at, updated_at, version, \
     stab_mask, stab_len) VALUES ";

/// The whole-snapshot SQL tuple for one link.
///
/// SQL literals rather than binds: turso charges ~0.8 ms per bound parameter
/// (200 ids = 174 ms against 9.7 ms for the same statement with literals), and a
/// chunk carries 20 columns per row.
fn link_values_sql(link: &ProfileStats, now: i64) -> String {
    use std::fmt::Write as _;

    let mut sql = String::with_capacity(160);
    let _ = write!(
        sql,
        "({}, {}, NULL, {}, ",
        link.protocol_id.get(),
        link.endpoint_id.get(),
        link.last_seen_at
    );
    // The four measurement columns. There is no discriminator any more: a
    // row's provenance is carried by WHICH delay column is populated
    // (schema 19, spec D4).
    let _ = write!(
        sql,
        "{}, {}, {}, {}",
        sql_opt_num(link.latency.real_delay.map(i64::from)),
        sql_opt_num(link.latency.fast_delay.map(i64::from)),
        sql_opt_lit(link.latency.ip.as_deref()),
        sql_opt_num(link.latency.auth),
    );
    let _ = write!(sql, ", {}, ", sql_opt_num(link.speed_bps));
    match &link.error {
        Some(error) => {
            let _ = write!(
                sql,
                "1, {}, {}, {}, {}",
                sql_lit(error_kind_str(error.kind)),
                sql_lit(&error.text),
                sql_opt_lit(error.stage.map(failure_stage_str)),
                sql_opt_lit(error.cause.map(failure_cause_str))
            );
        }
        None => sql.push_str("NULL, NULL, NULL, NULL, NULL"),
    }
    let _ = write!(
        sql,
        ", {}",
        sql_opt_lit(link.purge_reason.map(purge_reason_str))
    );
    let _ = write!(
        sql,
        ", {}, {}, {}, {}, {}, {}, 1, {}, {})",
        link.traffic.today_up,
        link.traffic.today_down,
        link.traffic.total_up,
        link.traffic.total_down,
        now,
        now,
        link.stab_mask,
        link.stab_len
    );
    sql
}

/// The `ON CONFLICT (protocol_id, endpoint_id) …` action for one patch's column
/// groups.
///
/// An existing row is written with exactly the patch's groups, so a column
/// another writer owns (`last_used_at`) or another group owns keeps its
/// persisted value — the disjointness [`LinkGroups`] exists for. A patch that
/// carries no group at all only creates a missing row (`DO NOTHING`).
fn link_patch_conflict_sql(groups: LinkGroups) -> String {
    let (has_result, has_purge, has_traffic, has_stab, has_seen) = (
        groups.contains(LinkGroups::RESULT),
        groups.contains(LinkGroups::PURGE),
        groups.contains(LinkGroups::TRAFFIC),
        groups.contains(LinkGroups::STAB),
        groups.contains(LinkGroups::SEEN),
    );
    let mut sets: Vec<&str> = Vec::with_capacity(17);
    if has_result {
        sets.extend_from_slice(&[
            "latency_real_delay = excluded.latency_real_delay",
            "latency_fast_delay = excluded.latency_fast_delay",
            "latency_ip = excluded.latency_ip",
            "latency_auth = excluded.latency_auth",
            "speed_bps = excluded.speed_bps",
            "error = excluded.error",
            "error_kind = excluded.error_kind",
            "error_text = excluded.error_text",
            "error_stage = excluded.error_stage",
            "error_cause = excluded.error_cause",
        ]);
    }
    if has_purge {
        sets.push("purge_reason = excluded.purge_reason");
    }
    if has_traffic {
        sets.extend_from_slice(&[
            "traffic_today_up = excluded.traffic_today_up",
            "traffic_today_down = excluded.traffic_today_down",
            "traffic_total_up = excluded.traffic_total_up",
            "traffic_total_down = excluded.traffic_total_down",
        ]);
    }
    if has_stab {
        sets.extend_from_slice(&[
            "stab_mask = excluded.stab_mask",
            "stab_len = excluded.stab_len",
        ]);
    }
    if has_seen {
        // `MAX`, not assignment: the import writer owns the same column with an
        // unconditional SET, so a patch staged from an older snapshot must not
        // move the stamp backwards.
        sets.push("last_seen_at = MAX(excluded.last_seen_at, last_seen_at)");
    }
    if sets.is_empty() {
        return format!(" ON CONFLICT({LINK_COMPARE_KEYS}) DO NOTHING");
    }
    sets.push("updated_at = excluded.updated_at");
    // `version` is the row's own optimistic-concurrency counter, so it only
    // ever moves forward — the values tuple's `1` applies to a fresh row.
    sets.push("version = version + 1");
    format!(
        " ON CONFLICT({LINK_COMPARE_KEYS}) DO UPDATE SET {}",
        sets.join(", ")
    )
}

/// The `ON CONFLICT` action of the import/refresh writer: SOURCE columns only.
///
/// The caller's snapshot comes from a fresh parse, so writing the RESULT columns
/// (`latency*`, `speed_bps`, `error*`) or the TRAFFIC counters on update
/// silently wipes the measurements and counters the ping pipeline and the stats
/// poller own — the whole-row shape this replaced did exactly that
/// (2026-09-15: an import refresh running beside a Fast+Real batch destroyed
/// every fast latency it had just written). `last_used_at` is likewise never
/// touched here (its owner is [`Database::update_last_used`]).
const LINK_SOURCE_CONFLICT_SQL: &str = " ON CONFLICT(protocol_id, endpoint_id) DO UPDATE SET \
     last_seen_at = excluded.last_seen_at, updated_at = excluded.updated_at";

/// One multi-row upsert statement for a set of rows whose conflict action is
/// uniform.
async fn exec_link_upsert(
    tx: &mut impl toasty::Executor,
    rows: &[ProfileStats],
    conflict: &str,
    now: i64,
) -> Result<()> {
    for chunk in rows.chunks(LINK_STATEMENT_ROWS) {
        let mut sql = String::with_capacity(chunk.len() * 160 + LINK_UPSERT_PREFIX.len());
        sql.push_str(LINK_UPSERT_PREFIX);
        for (i, link) in chunk.iter().enumerate() {
            if i > 0 {
                sql.push(',');
            }
            sql.push_str(&link_values_sql(link, now));
        }
        sql.push_str(conflict);
        toasty::sql::statement(sql).exec(tx).await?;
    }
    Ok(())
}

/// The `CHECK`-constrained storage text of a [`ProfileErr`] variant. An
/// exhaustive match, so a new variant cannot be forgotten; a wrong string is
/// rejected by the column's CHECK constraint rather than stored.
pub(crate) const fn error_kind_str(kind: crate::models_toasty::ProfileErr) -> &'static str {
    match kind {
        crate::models_toasty::ProfileErr::Real => "real",
        crate::models_toasty::ProfileErr::Fast => "fast",
        crate::models_toasty::ProfileErr::Name => "name",
    }
}

/// The storage text of a [`FailureStage`](crate::models_toasty::FailureStage).
///
/// Unlike `error_kind`, the pair columns carry NO value CHECK (the pair trigger
/// only enforces both-or-none), so a wrong spelling would store silently. The
/// SQL round-trip test (`link_upsert_persists_the_failure_pair`) reads the row
/// back through the typed embed, whose decode is the guard.
pub(crate) const fn failure_stage_str(stage: crate::models_toasty::FailureStage) -> &'static str {
    use crate::models_toasty::FailureStage as S;
    match stage {
        S::Dial => "dial",
        S::Transport => "transport",
        S::Protocol => "protocol",
        S::Target => "target",
    }
}

/// The storage text of a [`FailureCause`](crate::models_toasty::FailureCause);
/// see [`failure_stage_str`] for why there is no CHECK to catch a typo.
pub(crate) const fn failure_cause_str(cause: crate::models_toasty::FailureCause) -> &'static str {
    use crate::models_toasty::FailureCause as C;
    match cause {
        C::Timeout => "timeout",
        C::Refused => "refused",
        C::NoRoute => "no_route",
        C::Nxdomain => "nxdomain",
        C::Alert => "alert",
        C::Status => "status",
        C::Framing => "framing",
        C::Config => "config",
        C::Io => "io",
    }
}

/// The `CHECK`-constrained storage text of a [`PurgeReason`] variant, spelled
/// the way toasty's derive renders it (`snake_case`, verified by the column-shape
/// probe of 2026-09-17). A wrong spelling is refused by the column CHECK, and
/// `apply_link_patches_isolates_column_groups` (tests/integration.rs) executes
/// this statement and proves the group it belongs to.
const fn purge_reason_str(reason: crate::models_toasty::PurgeReason) -> &'static str {
    use crate::models_toasty::PurgeReason;
    match reason {
        PurgeReason::RealityFallback => "reality_fallback",
        PurgeReason::CertificateMismatch => "certificate_mismatch",
        PurgeReason::CertificateExpired => "certificate_expired",
        PurgeReason::NotTls => "not_tls",
        PurgeReason::ConfigInvalid => "config_invalid",
        PurgeReason::TransportRejected => "transport_rejected",
        PurgeReason::OriginUnreachable => "origin_unreachable",
        PurgeReason::CredentialRejected => "credential_rejected",
    }
}

impl Database {
    /// Read a value from the typed `app_meta` key/value table, `None` when the key
    /// is absent.
    #[tracing::instrument(target = "db_method", skip_all, fields(retries = tracing::field::Empty))]
    pub async fn meta_get(&self, key: &str) -> Result<Option<String>> {
        let mut conn = self.conn().await?;
        let row = AppMeta::filter_by_key(key.to_owned())
            .first()
            .exec(&mut conn)
            .await?;
        Ok(row.map(|m| m.value))
    }

    /// Upsert a value into `app_meta`.
    #[tracing::instrument(target = "db_method", skip_all, fields(retries = tracing::field::Empty))]
    pub async fn meta_set(&self, key: &str, value: &str) -> Result<()> {
        let mut conn = self.conn().await?;
        AppMeta::upsert_by_key(key.to_owned())
            .value(value.to_owned())
            .exec(&mut conn)
            .await?;
        Ok(())
    }
}

/// Extract the first INTEGER column of the first row (used for PRAGMA reads).
pub(crate) fn first_i64(rows: &[Value]) -> Option<i64> {
    rows.first().and_then(|v| {
        if let Value::Record(fields) = v {
            fields.first().and_then(|f| match f {
                Value::I64(n) => Some(*n),
                _ => None,
            })
        } else {
            None
        }
    })
}

// ── Read queries (public API) ───────────────────────────────────────────

impl Database {
    /// Single endpoint by id with all links and protocols.
    #[tracing::instrument(target = "db_method", skip_all, fields(retries = tracing::field::Empty))]
    pub async fn get_endpoint(&self, id: EndpointId) -> Result<Option<EndpointRow>> {
        let mut conn = self.conn().await?;
        let endpoint = Endpoint::filter_by_id(id).first().exec(&mut conn).await?;
        let Some(endpoint) = endpoint else {
            return Ok(None);
        };
        let mut rows = self.load_endpoint_rows(vec![endpoint], &mut conn).await?;
        Ok(rows.pop())
    }

    /// Look up endpoint row by link protocol id (p.id not e.id).
    #[tracing::instrument(target = "db_method", skip_all, fields(retries = tracing::field::Empty))]
    pub async fn get_endpoint_by_protocol_id(
        &self,
        protocol_id: ProtocolId,
    ) -> Result<Option<EndpointRow>> {
        let mut conn = self.conn().await?;
        let link = ProfileStats::filter(ProfileStats::fields().protocol_id().eq(protocol_id))
            .first()
            .exec(&mut conn)
            .await?;
        let Some(link) = link else {
            return Ok(None);
        };
        let endpoint = Endpoint::filter_by_id(link.endpoint_id)
            .first()
            .exec(&mut conn)
            .await?;
        let Some(endpoint) = endpoint else {
            return Ok(None);
        };
        let mut rows = self.load_endpoint_rows(vec![endpoint], &mut conn).await?;
        Ok(rows.pop())
    }

    /// One `profile_stats` row by its composite key.
    ///
    /// The scheduler gate's `refresh` for a plain `Database` backend (the
    /// write-behind writer answers from its staged map instead).
    #[tracing::instrument(target = "db_method", skip_all, fields(retries = tracing::field::Empty))]
    pub async fn read_link_row(
        &self,
        protocol_id: ProtocolId,
        endpoint_id: EndpointId,
    ) -> Result<Option<ProfileStats>> {
        let mut conn = self.conn().await?;
        Ok(
            ProfileStats::filter_by_protocol_id_and_endpoint_id(protocol_id, endpoint_id)
                .first()
                .exec(&mut conn)
                .await?,
        )
    }

    #[tracing::instrument(target = "db_method", skip_all, fields(retries = tracing::field::Empty))]
    pub async fn get_all_groups(&self) -> Result<Vec<Group>> {
        let mut conn = self.conn().await?;
        let groups: Vec<Group> = Group::all()
            .order_by(Group::fields().sort_order().asc())
            .exec(&mut conn)
            .await?;
        Ok(groups)
    }

    /// Members per group, one row per `endpoint_groups` link: the Sources
    /// tab's `Endpoints` column. The typed model has no COUNT aggregate, so
    /// the links are loaded and folded in memory — the caller refreshes this
    /// once per tab entry, not per row.
    pub async fn get_group_member_counts(&self) -> Result<RapidHashMap<String, usize>> {
        let mut conn = self.conn().await?;
        // COUNT(*) per group in SQL. The typed form loaded EVERY membership row
        // — one row per (endpoint, group), tens of thousands — through the
        // decode layer to count them in Rust; `index_endpoint_groups_by_group_id`
        // serves this as a covering scan of the group column.
        let rows =
            toasty::sql::query("SELECT group_id, COUNT(*) FROM endpoint_groups GROUP BY group_id")
                .exec(&mut conn)
                .await?;
        let mut counts: RapidHashMap<String, usize> = RapidHashMap::new();
        for row in &rows {
            let toasty_core::stmt::Value::Record(record) = row else {
                continue;
            };
            let Some(toasty_core::stmt::Value::String(group_id)) = record.fields.first() else {
                continue;
            };
            let Some(toasty_core::stmt::Value::I64(count)) = record.fields.get(1) else {
                continue;
            };
            counts.insert(group_id.clone(), usize::try_from(*count).unwrap_or(0));
        }
        Ok(counts)
    }

    /// Groups enabled with a non-empty url whose refresh window has elapsed:
    /// `last_refreshed IS NULL` or `last_refreshed + refresh_interval minutes
    /// < now` (`refresh_interval` defaults to 1440 minutes, matching the old
    /// subscription update interval). Ordered by `sort_order`.
    #[tracing::instrument(target = "db_method", skip_all, fields(retries = tracing::field::Empty))]
    pub async fn get_groups_due_update(&self) -> Result<Vec<Group>> {
        let mut conn = self.conn().await?;
        let candidates: Vec<Group> = Group::filter(Group::fields().enabled().eq(true))
            .filter(Group::fields().url().is_some())
            .order_by(Group::fields().sort_order().asc())
            .exec(&mut conn)
            .await?;
        let now = now_epoch();
        let mut due = Vec::new();
        for group in candidates {
            if group.url.as_deref().is_none_or(str::is_empty) {
                continue;
            }
            match group.last_refreshed {
                None => due.push(group),
                Some(last) => {
                    let interval = group.refresh_interval.unwrap_or(1440) * 60;
                    if last.saturating_add(interval) < now {
                        due.push(group);
                    }
                }
            }
        }
        Ok(due)
    }

    #[tracing::instrument(target = "db_method", skip_all, fields(retries = tracing::field::Empty))]
    pub async fn get_all_routing_rules(&self) -> Result<Vec<RoutingRule>> {
        let mut conn = self.conn().await?;
        let rules: Vec<RoutingRule> = RoutingRule::all()
            .order_by(RoutingRule::fields().sort_order().asc())
            .exec(&mut conn)
            .await?;
        Ok(rules)
    }

    /// The (single) DNS settings row, if any.
    #[tracing::instrument(target = "db_method", skip_all, fields(retries = tracing::field::Empty))]
    pub async fn get_dns_settings(&self) -> Result<Option<DnsSetting>> {
        let mut conn = self.conn().await?;
        let settings: Vec<DnsSetting> = DnsSetting::all().exec(&mut conn).await?;
        Ok(settings.into_iter().next())
    }

    /// Assemble the page's rows in the page's order, typed.
    ///
    /// The reference implementation of the page's row shape: the ordering is
    /// the decision-16 law ([`EndpointRow::sort_links_by_test_priority`], the
    /// single source — SQL never re-derives it) and the page order is the
    /// caller's `ids`. [`Self::load_page_projection`] returns the same rows
    /// from one statement; the parity test in `tests/profiles_query.rs` pins
    /// the two together, and this path stays as their oracle.
    #[tracing::instrument(target = "db_method", skip_all, fields(retries = tracing::field::Empty))]
    pub async fn load_page_rows(
        &self,
        ids: &[EndpointId],
        include_purged: bool,
    ) -> Result<Vec<EndpointRow>> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let mut conn = self.conn().await?;
        let endpoints: Vec<Endpoint> =
            Endpoint::filter(toasty::stmt::in_list(Endpoint::fields().id(), ids.to_vec()))
                .exec(&mut conn)
                .await?;
        let mut rows = self.load_endpoint_rows(endpoints, &mut conn).await?;
        drop(conn);

        // The same Active-view filter the projection applies in SQL, so the two
        // page readers stay interchangeable (their parity test pins it).
        // `load_endpoint_rows` itself stays unfiltered: the single-endpoint
        // lookups must still see a purged link — that is how it gets re-proved.
        if !include_purged {
            for row in &mut rows {
                row.links.retain(|l| l.purge_reason.is_none());
                row.select_best_measured_link();
            }
        }

        // Page order, not id order: the caller's sequence IS the display order.
        let mut by_id: RapidHashMap<EndpointId, EndpointRow> =
            rows.into_iter().map(|row| (row.endpoint.id, row)).collect();
        Ok(ids.iter().filter_map(|id| by_id.remove(id)).collect())
    }

    /// Assemble [`EndpointRow`]s for a small endpoint set (the single-endpoint
    /// lookups [`Self::get_endpoint`] / [`Self::get_endpoint_by_protocol_id`]
    /// — the tab loads go through [`Self::load_tab_rows`] instead).
    ///
    /// Loads the page's links with one `endpoint_id IN (...)` statement; the
    /// set is ≤1 endpoint here, so the row-value expansion cost that makes
    /// `in_list` untenable at 10k+ ids (see [`Self::load_tab_rows`]) never
    /// applies. Protocols are joined in memory (bounded by distinct configs).
    async fn load_endpoint_rows(
        &self,
        endpoints: Vec<Endpoint>,
        conn: &mut toasty::Connection,
    ) -> Result<Vec<EndpointRow>> {
        if endpoints.is_empty() {
            return Ok(Vec::new());
        }
        let ids: Vec<EndpointId> = endpoints.iter().map(|e| e.id).collect();
        // Newtype embed paths expose only `.eq()`; build the IN filter through
        // `stmt::in_list` (the field struct implements `IntoExpr<EndpointId>`).
        let links: Vec<ProfileStats> = ProfileStats::filter(toasty::stmt::in_list(
            ProfileStats::fields().endpoint_id(),
            ids.clone(),
        ))
        .exec(conn)
        .await?;
        // Only the protocols THIS page's links reference. The whole-table read
        // (6,111 rows here) decoded every `Protocol` model per page load —
        // ~0.47 s of the ~2.2 s a page-boundary move cost at 7.7k endpoints —
        // and the page only ever looks up the few ids its own links carry.
        let mut protocol_ids: Vec<ProtocolId> = links.iter().map(|l| l.protocol_id).collect();
        protocol_ids.sort_unstable();
        protocol_ids.dedup();
        let protocols: Vec<Protocol> = if protocol_ids.is_empty() {
            Vec::new()
        } else {
            Protocol::filter(toasty::stmt::in_list(Protocol::fields().id(), protocol_ids))
                .exec(conn)
                .await?
        };
        let protocol_by_id: RapidHashMap<ProtocolId, Protocol> =
            protocols.into_iter().map(|p| (p.id, p)).collect();

        let mut by_endpoint: RapidHashMap<EndpointId, Vec<ProfileStats>> = RapidHashMap::new();
        for link in links {
            by_endpoint.entry(link.endpoint_id).or_default().push(link);
        }
        // The address set is a table of its own now: one id-inlined read for
        // the whole set, exactly like the links above.
        let mut resolved = crate::endpoint_ip::load(conn, &ids).await?;

        let mut rows = Vec::with_capacity(endpoints.len());
        for endpoint in endpoints {
            let links = by_endpoint.remove(&endpoint.id).unwrap_or_default();
            let protocols = links
                .iter()
                .filter_map(|l| {
                    protocol_by_id
                        .get(&l.protocol_id)
                        .map(|p| (p.id, p.clone()))
                })
                .collect();
            let resolved_ips = resolved.remove(&endpoint.id).unwrap_or_default();
            let dns_unresolved = crate::endpoint_rank::dns_unresolved_endpoint(
                endpoint.domain.as_str(),
                !resolved_ips.is_empty(),
            );
            let mut row = EndpointRow {
                endpoint,
                links,
                protocols,
                resolved_ips,
                selected_protocol: 0,
                expanded: false,
            };
            row.sort_links_by_test_priority(dns_unresolved);
            // Single-row display follows the best measured link (survives
            // restarts via the persisted latency columns); the sub-table
            // keeps test-priority order.
            row.select_best_measured_link();
            rows.push(row);
        }
        // Deterministic page order (the newtype id path cannot be ordered in SQL).
        rows.sort_by_key(|r| r.endpoint.id);
        Ok(rows)
    }
}

// ── Write methods (public API) ─────────────────────────────────────────

impl Database {
    // ── Upserts (idempotent, natural-key dedup) ──────────────────────────

    /// Insert or update one endpoint by id.
    ///
    /// Replaces the endpoint's identity fields (`host`, `host_type`, `port`,
    /// `ports`, `last_source`). The resolution state (the `endpoint_ip`
    /// address set and `endpoints.resolved_at`) and the manual protocol
    /// override are owned by their dedicated writes
    /// ([`Self::update_endpoint_resolution`], [`Self::set_manual_override`])
    /// and are preserved on update — this matches the old subscription path,
    /// which never clobbered an existing endpoint's resolution state
    /// (INSERT OR IGNORE).
    #[tracing::instrument(target = "db_method", skip_all, fields(retries = tracing::field::Empty))]
    pub async fn upsert_endpoint(&self, e: &Endpoint) -> Result<()> {
        let db = self;
        let endpoint = e.clone();
        retry_on_busy(
            move || {
                let endpoint = endpoint.clone();
                async move {
                    let mut conn = db.conn().await?;
                    Endpoint::upsert_by_id(endpoint.id)
                        .domain(endpoint.domain.clone())
                        .sub_domain(endpoint.sub_domain.clone())
                        .port(endpoint.port)
                        .ports(endpoint.ports.clone())
                        .last_source(endpoint.last_source.clone())
                        .on_create(|create| create.created_at(now_epoch()))
                        .exec(&mut conn)
                        .await?;
                    Ok(())
                }
            },
            5,
        )
        .await
    }

    /// Insert or update one protocol row by id.
    ///
    /// The `config` deferred JSON column is read via `.get()`, which panics when
    /// unloaded — a default read path (including the crate's own
    /// `load_endpoint_rows`, which never includes deferred data) yields an
    /// unloaded `Protocol`. Callers must pass a freshly-built struct or one
    /// loaded with the deferred data included; an unloaded struct is rejected
    /// with an error instead of panicking.
    #[tracing::instrument(target = "db_method", skip_all, fields(retries = tracing::field::Empty))]
    pub async fn upsert_protocol(&self, p: &Protocol) -> Result<()> {
        if p.config.is_unloaded() {
            return Err(DatabaseError::Generic(
                "upsert_protocol: deferred config not loaded (rebuild the Protocol or load it with config included)"
                    .into(),
            ));
        }
        let db = self;
        let protocol = p.clone();
        retry_on_busy(
            move || {
                let protocol = protocol.clone();
                async move {
                    let mut conn = db.conn().await?;
                    Protocol::upsert_by_id(protocol.id)
                        .sig(protocol.sig)
                        .proto_kind(protocol.proto_kind)
                        .transport(protocol.transport.clone())
                        .security(protocol.security.clone())
                        .config(protocol.config.get().0.clone())
                        .on_create(|create| create.created_at(now_epoch()))
                        .exec(&mut conn)
                        .await?;
                    Ok(())
                }
            },
            5,
        )
        .await
    }

    /// Insert or update one per-pair link row by its composite key
    /// `(protocol_id, endpoint_id)`.
    ///
    /// Replaces the link's source- and result-state fields (`core_type`,
    /// `last_seen_at`, `latency`, `speed_bps`, `error`,
    /// `traffic`). The activity timestamp (`last_used_at`) is owned by
    /// [`Self::update_last_used`] and is preserved on update.
    #[tracing::instrument(target = "db_method", skip_all, fields(retries = tracing::field::Empty))]
    pub async fn upsert_link(&self, s: &ProfileStats) -> Result<()> {
        let db = self;
        let link = s.clone();
        retry_on_busy(
            move || {
                let link = link.clone();
                async move {
                    let endpoint_id = link.endpoint_id;
                    let mut conn = db.conn().await?;
                    ProfileStats::upsert_by_protocol_id_and_endpoint_id(
                        link.protocol_id,
                        link.endpoint_id,
                    )
                    .last_seen_at(link.last_seen_at)
                    .latency(link.latency.clone())
                    .speed_bps(link.speed_bps)
                    .error(link.error.clone())
                    .purge_reason(link.purge_reason)
                    .stab_mask(link.stab_mask)
                    .stab_len(link.stab_len)
                    .traffic(link.traffic)
                    .updated_at(now_epoch())
                    .on_create(|create| create.created_at(now_epoch()))
                    .exec(&mut conn)
                    .await?;
                    crate::endpoint_rank::refresh(&mut conn, &[endpoint_id]).await?;
                    Ok(())
                }
            },
            5,
        )
        .await
    }

    /// Apply one patch per row inside a single transaction.
    ///
    /// Each patch carries only the column *groups* that changed (see
    /// [`LinkGroups`]), and the groups decide the statement's `ON CONFLICT`
    /// action, so the two independent writers of a `profile_stats` row — ping
    /// results and the traffic poller — cannot clobber each other's columns:
    /// the groups make the writers disjoint instead of merely sequential.
    ///
    /// One multi-row upsert per (chunk, group shape) replaces one existence
    /// probe plus one `UPDATE` per row: turso has no
    /// `UPDATE … FROM (VALUES …)` (measured 2026-09-16: parse error), so the
    /// per-row form was one statement per link. Measured on a 512-patch window
    /// over the reference feed: 29.0 ms → 10.6 ms.
    ///
    /// One transaction per batch replaces one commit per row — the write-behind
    /// link writer calls this from its flush task, never from the UI task. A row
    /// deleted mid-batch is re-created by its own patch (an upsert inserts what
    /// it cannot update), which is the contract the callers rely on.
    #[tracing::instrument(target = "db_method", skip_all, fields(retries = tracing::field::Empty))]
    pub async fn apply_link_patches(&self, patches: &[LinkPatch]) -> Result<usize> {
        if patches.is_empty() {
            return Ok(0);
        }
        // The result writer is the one path whose loss is DATA (a 400-row
        // chunk of probe results), and the 2026-11-20 run lost 226 of them at
        // the old five attempts while background DNS writes held the busy
        // timeout (spec 2026-11-23 T6 / F4). More attempts here, not globally:
        // a background scan may give up sooner than a test result.
        retry_on_busy(|| self.apply_link_patches_once(patches), 8).await
    }

    /// The write half of [`Self::apply_link_patches_once`], scoped to a
    /// transaction the CALLER opened and will commit.
    ///
    /// Split out for [`crate::write_behind::LinkSpec`]: the write-behind driver
    /// owns its transaction (and its retry), so the upsert loop has to be
    /// callable on a borrowed executor rather than opening one of its own.
    /// `now` is the stamp the rows are written with, for the same reason — the
    /// caller's clock is the driver's.
    pub(crate) async fn apply_link_patches_tx(
        tx: &mut impl toasty::Executor,
        patches: &[LinkPatch],
        now: i64,
    ) -> Result<usize> {
        if patches.is_empty() {
            return Ok(0);
        }
        // The `ON CONFLICT` action is per-STATEMENT, so the patches are bucketed
        // by the action they need rather than by their exact bit pattern —
        // `contains` is what decides the columns written, exactly as the
        // per-row form did. The bucket is the presence vector over EVERY group
        // bit (`LinkGroups::ALL`, not a hand-copied 4-bit list: a new group
        // otherwise folds into bucket 0 and its patch is silently skipped by the
        // `DO NOTHING` action — which is what `SEEN` did on 2026-11-20).
        for bucket in 0u8..=LinkGroups::ALL.0 {
            let shape: Vec<&LinkPatch> = patches
                .iter()
                .filter(|p| p.groups == LinkGroups(bucket))
                .collect();
            if shape.is_empty() {
                continue;
            }
            let conflict = link_patch_conflict_sql(LinkGroups(bucket));
            for chunk in shape.chunks(LINK_STATEMENT_ROWS) {
                let mut sql = String::with_capacity(chunk.len() * 160 + LINK_UPSERT_PREFIX.len());
                sql.push_str(LINK_UPSERT_PREFIX);
                for (i, patch) in chunk.iter().enumerate() {
                    if i > 0 {
                        sql.push(',');
                    }
                    sql.push_str(&link_values_sql(&patch.link, now));
                }
                sql.push_str(&conflict);
                toasty::sql::statement(sql).exec(tx).await?;
            }
        }

        Ok(patches.len())
    }

    async fn apply_link_patches_once(&self, patches: &[LinkPatch]) -> Result<usize> {
        if patches.is_empty() {
            return Ok(0);
        }
        let mut conn = self.conn().await?;
        let now = now_epoch();

        let mut touched: Vec<EndpointId> = patches.iter().map(|p| p.link.endpoint_id).collect();
        touched.sort_unstable();
        touched.dedup();

        let mut tx = conn.transaction().await?;
        Self::apply_link_patches_tx(&mut tx, patches, now).await?;
        // The upsert INSERTS a row whose endpoint was deleted mid-batch (its
        // contract), so the orphan must be removed in the SAME transaction —
        // the purge-time sweep cannot see a link that lands after it ran
        // (review, 2026-11-23).
        Self::sweep_orphan_links_for(&mut tx, &touched).await?;
        tx.commit().await?;

        // Derived state: the patched endpoints' ordering keys follow their
        // links. Done after the commit (the page is read later, never here).
        if let Err(e) = crate::endpoint_rank::refresh(&mut conn, &touched).await {
            tracing::warn!(target: "leas_db", "endpoint_rank refresh: {e}");
        }
        Ok(patches.len())
    }

    /// Insert or update one endpoint↔group link by its composite key
    /// `(endpoint_id, group_id)`.
    #[tracing::instrument(target = "db_method", skip_all, fields(retries = tracing::field::Empty))]
    pub async fn upsert_endpoint_group_link(&self, eg: &EndpointGroup) -> Result<()> {
        let db = self;
        let edge = eg.clone();
        retry_on_busy(
            move || {
                let edge = edge.clone();
                async move {
                    let mut conn = db.conn().await?;
                    EndpointGroup::upsert_by_endpoint_id_and_group_id(
                        edge.endpoint_id,
                        edge.group_id.clone(),
                    )
                    .last_seen_at(edge.last_seen_at)
                    .sort_order(edge.sort_order)
                    .exec(&mut conn)
                    .await?;
                    Ok(())
                }
            },
            5,
        )
        .await
    }

    /// Insert or update one group by id (replaces `insert_group` +
    /// `update_group`).
    pub async fn upsert_group(&self, g: &Group) -> Result<()> {
        let db = self;
        let group = g.clone();
        retry_on_busy(
            move || {
                let group = group.clone();
                async move {
                    let mut conn = db.conn().await?;
                    Group::upsert_by_id(group.id.clone())
                        .name(group.name.clone())
                        .url(group.url.clone())
                        .enabled(group.enabled)
                        .user_agent(group.user_agent.clone())
                        .convert_target(group.convert_target)
                        .sort_order(group.sort_order)
                        .last_refreshed(group.last_refreshed)
                        .status(group.status)
                        .error_message(group.error_message.clone())
                        .refresh_interval(group.refresh_interval)
                        .exec(&mut conn)
                        .await?;
                    Ok(())
                }
            },
            5,
        )
        .await
    }

    // ── Activity ─────────────────────────────────────────────────────────

    /// Record the USER'S INTENT to use a link: sets `last_used_at` only.
    ///
    /// `last_seen_at` is the liveness clock ("the source listed it, or the
    /// client proved it"), and connect initiation is not proof — the tunnel
    /// may never come up. The proof write is [`Self::record_link_alive`],
    /// issued when the session reports `Connected` (spec 2026-11-23 T11).
    #[tracing::instrument(target = "db_method", skip_all, fields(retries = tracing::field::Empty))]
    pub async fn update_last_used(
        &self,
        protocol_id: ProtocolId,
        endpoint_id: EndpointId,
        at: i64,
    ) -> Result<()> {
        let db = self;
        retry_on_busy(
            move || async move {
                let mut conn = db.conn().await?;
                ProfileStats::filter_by_protocol_id_and_endpoint_id(protocol_id, endpoint_id)
                    .update()
                    .last_used_at(Some(at))
                    .exec(&mut conn)
                    .await?;
                Ok(())
            },
            5,
        )
        .await
    }

    /// Record CLIENT PROOF that a link is alive: a session built on it, or a
    /// data-carrying probe result. Moves `last_seen_at` (the purge/band
    /// clock) and refreshes the derived ordering keys.
    ///
    /// The stamp is written with the plain typed update rather than
    /// `LinkGroups::SEEN`'s raw `MAX`; a connect proof racing a probe result
    /// can move the value by the seconds between them, which changes no
    /// decision the clock feeds.
    #[tracing::instrument(target = "db_method", skip_all, fields(retries = tracing::field::Empty))]
    pub async fn record_link_alive(
        &self,
        protocol_id: ProtocolId,
        endpoint_id: EndpointId,
        at: i64,
    ) -> Result<()> {
        let db = self;
        retry_on_busy(
            move || async move {
                let mut conn = db.conn().await?;
                ProfileStats::filter_by_protocol_id_and_endpoint_id(protocol_id, endpoint_id)
                    .update()
                    .last_seen_at(at)
                    .exec(&mut conn)
                    .await?;
                crate::endpoint_rank::refresh(&mut conn, &[endpoint_id]).await?;
                Ok(())
            },
            5,
        )
        .await
    }

    /// Persist the DNS resolution of an endpoint host: its address set
    /// (`endpoint_ip`) and `resolved_at`. Survives launches so the TUI does not
    /// re-resolve DNS hosts on startup. Retried on write contention (the
    /// enrichment pipeline resolves many endpoints concurrently), as the old
    /// code did.
    ///
    /// The address set and the endpoint's rank keys move together: "has an
    /// address" IS part of the ordering law (decision 16 tier 5), so an
    /// endpoint leaves — or enters — the DNS-unresolved band here.
    #[tracing::instrument(target = "db_method", skip_all, fields(retries = tracing::field::Empty))]
    pub async fn update_endpoint_resolution(
        &self,
        endpoint_id: EndpointId,
        ips: Vec<std::net::IpAddr>,
        at: i64,
    ) -> Result<()> {
        let db = self;
        retry_on_busy(
            move || {
                let ips = ips.clone();
                async move {
                    let mut conn = db.conn().await?;
                    let mut tx = conn.transaction().await?;
                    Endpoint::filter_by_id(endpoint_id)
                        .update()
                        .resolved_at(Some(at))
                        .exec(&mut tx)
                        .await?;
                    crate::endpoint_ip::replace(&mut tx, endpoint_id, &ips).await?;
                    crate::endpoint_rank::refresh(&mut tx, &[endpoint_id]).await?;
                    tx.commit().await?;
                    Ok(())
                }
            },
            5,
        )
        .await
    }

    /// Write a batch of DNS resolutions: `resolved_at`, the address set, and
    /// the rank keys of every endpoint in one transaction per
    /// [`RESOLUTION_CHUNK`] rows.
    ///
    /// The per-endpoint form is one transaction EACH, and the enrichment
    /// flush calls it once per endpoint — 65 k endpoints × several statements
    /// was the import's write volume against the same single-writer WAL the
    /// UI reads through (2026-11-24 audit G2). Chunked so one statement
    /// cannot hold the connection for a whole page of resolutions.
    ///
    /// Re-running a chunk after a busy retry is idempotent: `resolved_at` is
    /// absolute and [`crate::endpoint_ip::replace`] replaces the set.
    ///
    /// A failing chunk does NOT abort the rest (the per-endpoint loop it
    /// replaces isolated failures per endpoint): each chunk commits on its
    /// own, a failed one is logged, and one error is returned once the batch
    /// is done so the caller still sees the failure — the first BUSY error if
    /// any chunk hit one (so the retry ladder retries the batch), else the
    /// first error.
    ///
    /// # Errors
    ///
    /// [`DatabaseError`] (first busy, else first) when any chunk fails; the
    /// other chunks' rows stay committed.
    #[tracing::instrument(target = "db_method", skip_all, fields(retries = tracing::field::Empty))]
    pub async fn update_endpoint_resolutions(
        &self,
        rows: &[(EndpointId, Vec<std::net::IpAddr>, i64)],
    ) -> Result<()> {
        if rows.is_empty() {
            return Ok(());
        }
        let db = self;
        let rows = rows.to_vec();
        retry_on_busy(
            move || {
                let rows = rows.clone();
                async move {
                    let mut first_err: Option<DatabaseError> = None;
                    let mut busy_err: Option<DatabaseError> = None;
                    for chunk in rows.chunks(RESOLUTION_CHUNK) {
                        // Check the connection out per chunk, not per batch: a
                        // long flush must not hold one pooled connection for
                        // its whole run while the plan read waits.
                        let result = match db.conn().await {
                            Ok(mut conn) => Self::write_resolution_chunk(&mut conn, chunk).await,
                            Err(err) => Err(err),
                        };
                        if let Err(err) = result {
                            tracing::warn!(
                                target: "leas_db",
                                "resolution chunk of {} endpoint(s) failed: {err}",
                                chunk.len()
                            );
                            // A busy error is what the ladder retries, so it
                            // must win over an earlier non-busy one: returning
                            // the non-busy error would skip the retry and drop
                            // every contended chunk in this batch.
                            if crate::is_busy_error(&err) {
                                busy_err.get_or_insert(err);
                            } else {
                                first_err.get_or_insert(err);
                            }
                        }
                    }
                    busy_err.or(first_err).map_or(Ok(()), Err)
                }
            },
            5,
        )
        .await
    }

    /// One chunk of [`Self::update_endpoint_resolutions`] in its own
    /// transaction: the stamp, the address set, and the rank keys move
    /// together, or none of them do.
    async fn write_resolution_chunk(
        conn: &mut toasty::Connection,
        chunk: &[(EndpointId, Vec<std::net::IpAddr>, i64)],
    ) -> Result<()> {
        let mut tx = conn.transaction().await?;
        let mut ids = Vec::with_capacity(chunk.len());
        for (endpoint_id, ips, at) in chunk {
            Endpoint::filter_by_id(*endpoint_id)
                .update()
                .resolved_at(Some(*at))
                .exec(&mut tx)
                .await?;
            crate::endpoint_ip::replace(&mut tx, *endpoint_id, ips).await?;
            ids.push(*endpoint_id);
        }
        crate::endpoint_rank::refresh(&mut tx, &ids).await?;
        tx.commit().await?;
        Ok(())
    }

    /// The persisted resolved addresses of `ids` with their stored countries.
    ///
    /// The enrichment seed's read: an address that already carries a country
    /// needs no mmdb walk.
    ///
    /// # Errors
    ///
    /// [`DatabaseError`] when the read fails.
    #[tracing::instrument(target = "db_method", skip_all, fields(retries = tracing::field::Empty))]
    pub async fn endpoint_resolutions(
        &self,
        ids: &[EndpointId],
    ) -> Result<std::collections::HashMap<EndpointId, Vec<ResolvedAddress>>> {
        let mut conn = self.conn().await?;
        crate::endpoint_ip::load_resolved(&mut conn, ids).await
    }

    /// Record the country of one resolved address (the mmdb lookup's write).
    ///
    /// # Errors
    ///
    /// [`DatabaseError`] when the write fails.
    #[tracing::instrument(target = "db_method", skip_all, fields(retries = tracing::field::Empty))]
    pub async fn set_endpoint_ip_country(
        &self,
        endpoint_id: EndpointId,
        ip: std::net::IpAddr,
        iso: &str,
    ) -> Result<()> {
        let db = self;
        let iso = iso.to_string();
        retry_on_busy(
            move || {
                let iso = iso.clone();
                async move {
                    let mut conn = db.conn().await?;
                    let mut tx = conn.transaction().await?;
                    crate::endpoint_ip::set_countries_bulk(
                        &mut tx,
                        &[(endpoint_id, ip, iso.clone())],
                    )
                    .await?;
                    tx.commit().await?;
                    Ok(())
                }
            },
            5,
        )
        .await
    }

    /// Persist resolved-address countries for a whole page in ONE transaction.
    ///
    /// `set_endpoint_ip_country` takes its own connection and commit per call
    /// (~4.2 ms per FULL commit, `docs/database.md`), and the import's 500-URL
    /// chunk commits contend with it (`database is locked` → `retry_on_busy`).
    /// The page seed writes a page at a time instead.
    ///
    /// # Errors
    ///
    /// [`DatabaseError`] when the write fails.
    #[tracing::instrument(target = "db_method", skip_all, fields(retries = tracing::field::Empty))]
    pub async fn set_endpoint_ip_countries(
        &self,
        rows: &[(EndpointId, std::net::IpAddr, String)],
    ) -> Result<()> {
        if rows.is_empty() {
            return Ok(());
        }
        let db = self;
        retry_on_busy(
            move || async move {
                let mut conn = db.conn().await?;
                let mut tx = conn.transaction().await?;
                set_endpoint_ip_countries_once(&mut tx, rows).await?;
                tx.commit().await?;
                Ok(())
            },
            5,
        )
        .await
    }

    /// Set or clear (`None`) the manual protocol override of an endpoint — the old `set_protocol_override` + `clear_protocol_override` merged.
    #[tracing::instrument(target = "db_method", skip_all, fields(retries = tracing::field::Empty))]
    pub async fn set_manual_override(
        &self,
        endpoint_id: EndpointId,
        protocol_id: Option<ProtocolId>,
    ) -> Result<()> {
        let db = self;
        retry_on_busy(
            move || async move {
                let mut conn = db.conn().await?;
                Endpoint::filter_by_id(endpoint_id)
                    .update()
                    .manual_protocol_override(protocol_id)
                    .exec(&mut conn)
                    .await?;
                crate::endpoint_rank::refresh(&mut conn, &[endpoint_id]).await?;
                Ok(())
            },
            5,
        )
        .await
    }

    // ── Purge / delete ───────────────────────────────────────────────────

    /// Rows per keyset page of the never-observed sweep. A page is short enough
    /// that one statement cannot hold a pool connection for minutes behind a
    /// batch's writers (the 2026-11-20 run measured 143.7 s on the unpaged
    /// form against a 0.36 s cold cost).
    const SWEEP_PAGE: usize = 10_000;

    /// The keyset-paged candidate scan behind [`Self::purge_expired`].
    async fn never_observed_candidates(
        conn: &mut toasty::Connection,
        cutoff: i64,
    ) -> Result<Vec<EndpointId>> {
        Self::never_observed_candidates_paged(conn, cutoff, Self::SWEEP_PAGE).await
    }

    /// `page` is a parameter so the test can force several pages with a small
    /// fixture; production always passes [`Self::SWEEP_PAGE`].
    async fn never_observed_candidates_paged(
        conn: &mut toasty::Connection,
        cutoff: i64,
        page: usize,
    ) -> Result<Vec<EndpointId>> {
        debug_assert!(page > 0);
        let mut out: Vec<EndpointId> = Vec::new();
        let mut last = i64::MIN;
        loop {
            let rows = toasty::sql::query(format!(
                "SELECT e.id FROM endpoints e WHERE e.id > {last} AND NOT EXISTS \
                 (SELECT 1 FROM profile_stats p WHERE p.endpoint_id = e.id \
                 AND p.last_seen_at >= {cutoff}) \
                 ORDER BY e.id LIMIT {page}"
            ))
            .exec(&mut *conn)
            .await?;
            let before = out.len();
            for row in &rows {
                let id = match row {
                    toasty_core::stmt::Value::Record(r) => r.fields.first(),
                    _ => None,
                };
                if let Some(toasty_core::stmt::Value::I64(id)) = id {
                    out.push(EndpointId::new(*id));
                    last = *id;
                }
            }
            if out.len() - before < page {
                break;
            }
            // A page that parsed no id would otherwise re-query the same key
            // forever (this schema always returns I64, but the guard costs
            // nothing and turns a malformed row into a stop rather than a spin).
            if out.len() == before {
                break;
            }
        }
        Ok(out)
    }

    /// Purge endpoints where EVERY link's `last_seen_at < cutoff` — the old
    /// `COALESCE(MAX(p.last_seen_at), 0) < cutoff` predicate, including
    /// linkless endpoints (`links().all(...)` is vacuously true for them).
    /// Returns the number of deleted endpoints.
    ///
    /// Cascade, in one transaction: the endpoints' `endpoint_groups` links,
    /// their `profile_stats` links, then the endpoints themselves, then
    /// orphan `protocol` rows (those left with zero links).
    #[tracing::instrument(target = "db_method", skip_all, fields(retries = tracing::field::Empty))]
    pub async fn purge_expired(&self, cutoff: i64) -> Result<usize> {
        retry_on_busy(|| self.purge_expired_once(cutoff), 5).await
    }

    async fn purge_expired_once(&self, cutoff: i64) -> Result<usize> {
        let mut conn = self.conn().await?;

        // The CANDIDATE scan runs OUTSIDE the transaction.
        //
        // It used to run inside one, which turned a read-only full-table walk
        // into a write-lock hold: the 2026-10-01 run measured this statement at
        // **3,098 ms** on 74,014 endpoints, so every other writer in the process
        // waited behind a three-second "read". The scan is now a plain read.
        //
        // Race, and why it is safe: an endpoint that gains a link between the
        // scan and the delete would be deleted with a live link. The re-check
        // below closes that inside the transaction.
        //
        // All-links staleness: an endpoint whose EVERY link is older than the
        // cutoff (De-Morgan of the old `.all(last_seen < cutoff)`; vacuously
        // true for a linkless endpoint, so orphans are reclaimed too). This is
        // deliberately NOT the page's live-only `band`: a fresh-but-purged link
        // (a subscription re-listed it) must keep its endpoint alive, which a
        // live-only `rank_newest_seen` would not (ADR 0006 / view-band spec
        // §3.5). Raw because toasty's `.all()` quantifier compiled to a
        // whole-table projection (145 ms, dump-3.log); this is an indexed
        // NOT EXISTS on `profile_stats.last_seen_at`.
        //
        // Keyset-paged (2026-11-20): the statement measured 143.7 s inside a
        // batch while the same file answers it in 0.36 s cold, i.e. the cost is
        // a pool connection held behind writers, not the scan. A short page
        // releases the connection between chunks; the candidate set is
        // identical because `e.id` is the PK and the walk is ordered.
        let candidates = Self::never_observed_candidates(&mut conn, cutoff).await?;
        if candidates.is_empty() {
            return Ok(0);
        }

        // Re-check under the write transaction, then cascade.
        let mut tx = conn.transaction().await?;
        // Ids are inlined as literals, the convention every other raw statement
        // in this crate uses (a bound parameter per id costs ~0.8 ms).
        let id_list = candidates
            .iter()
            .map(|id| id.get().to_string())
            .collect::<Vec<_>>()
            .join(",");
        let live = toasty::sql::query(format!(
            "SELECT e.id FROM endpoints e WHERE e.id IN ({id_list}) AND NOT EXISTS \
             (SELECT 1 FROM profile_stats p WHERE p.endpoint_id = e.id \
             AND p.last_seen_at >= {cutoff})"
        ))
        .exec(&mut tx)
        .await?;
        let ids: Vec<EndpointId> = live
            .iter()
            .filter_map(|row| match row {
                toasty_core::stmt::Value::Record(r) => r.fields.first().cloned(),
                _ => None,
            })
            .filter_map(|v| match v {
                toasty_core::stmt::Value::I64(id) => Some(EndpointId::new(id)),
                _ => None,
            })
            .collect();
        let count = ids.len();

        if count > 0 {
            EndpointGroup::filter(toasty::stmt::in_list(
                EndpointGroup::fields().endpoint_id(),
                ids.clone(),
            ))
            .delete()
            .exec(&mut tx)
            .await?;
            ProfileStats::filter(toasty::stmt::in_list(
                ProfileStats::fields().endpoint_id(),
                ids.clone(),
            ))
            .delete()
            .exec(&mut tx)
            .await?;
            // No foreign key exists (docs/reference/database.md), so an
            // orphan link would survive the cascade forever. Sweep BEFORE the
            // protocol cascade: a protocol whose only link is swept here must
            // be collected by the same pass (review, 2026-11-23).
            toasty::sql::statement(
                "DELETE FROM profile_stats WHERE NOT EXISTS \
                 (SELECT 1 FROM endpoints e WHERE e.id = profile_stats.endpoint_id)",
            )
            .exec(&mut tx)
            .await?;
            Self::purge_orphan_protocols(&mut tx).await?;
            crate::endpoint_ip::delete_for(&mut tx, &ids).await?;
            Endpoint::filter(toasty::stmt::in_list(Endpoint::fields().id(), ids.clone()))
                .delete()
                .exec(&mut tx)
                .await?;
            // The page drives from `endpoint_rank`: drop the keys of the rows
            // whose links just went away, or the tab would list them again.
            crate::endpoint_rank::prune(&mut tx, &ids).await?;
        }

        tx.commit().await?;
        Ok(count)
    }

    /// Delete an endpoint and cascade: its `profile_stats` links, its
    /// `endpoint_groups` links, the endpoint row, then orphan `protocol`
    /// rows (those whose last link just died). One transaction.
    #[tracing::instrument(target = "db_method", skip_all, fields(retries = tracing::field::Empty))]
    pub async fn delete_endpoint(&self, endpoint_id: EndpointId) -> Result<()> {
        self.delete_endpoints(&[endpoint_id]).await.map(|_| ())
    }

    /// Delete several endpoints and cascade, in ONE transaction.
    ///
    /// The per-endpoint path ([`Self::delete_endpoint`]) opens a transaction,
    /// scans for orphan protocols and prunes rank keys per endpoint; a bulk
    /// delete ("remove failed servers" over a whole page) did all of that N
    /// times. Returns the number of endpoints deleted.
    #[tracing::instrument(target = "db_method", skip_all, fields(retries = tracing::field::Empty))]
    pub async fn delete_endpoints(&self, endpoint_ids: &[EndpointId]) -> Result<usize> {
        if endpoint_ids.is_empty() {
            return Ok(0);
        }
        retry_on_busy(|| self.delete_endpoints_once(endpoint_ids), 5).await
    }

    async fn delete_endpoints_once(&self, endpoint_ids: &[EndpointId]) -> Result<usize> {
        if endpoint_ids.is_empty() {
            return Ok(0);
        }
        let mut conn = self.conn().await?;
        let mut tx = conn.transaction().await?;

        EndpointGroup::filter(toasty::stmt::in_list(
            EndpointGroup::fields().endpoint_id(),
            endpoint_ids.to_vec(),
        ))
        .delete()
        .exec(&mut tx)
        .await?;
        ProfileStats::filter(toasty::stmt::in_list(
            ProfileStats::fields().endpoint_id(),
            endpoint_ids.to_vec(),
        ))
        .delete()
        .exec(&mut tx)
        .await?;
        Self::purge_orphan_protocols(&mut tx).await?;
        crate::endpoint_ip::delete_for(&mut tx, endpoint_ids).await?;
        Endpoint::filter(toasty::stmt::in_list(
            Endpoint::fields().id(),
            endpoint_ids.to_vec(),
        ))
        .delete()
        .exec(&mut tx)
        .await?;
        // A link staged for one of these endpoints between the two deletes
        // would orphan here; the delete path runs the same anti-join as the
        // purge (review, 2026-11-23).
        toasty::sql::statement(
            "DELETE FROM profile_stats WHERE NOT EXISTS \
             (SELECT 1 FROM endpoints e WHERE e.id = profile_stats.endpoint_id)",
        )
        .exec(&mut tx)
        .await?;
        Self::purge_orphan_protocols(&mut tx).await?;
        crate::endpoint_rank::prune(&mut tx, endpoint_ids).await?;
        tx.commit().await?;
        Ok(endpoint_ids.len())
    }

    /// Remove all endpoint↔group links for `group_id` (the old `clear_group`),
    /// returning the number of links removed. Endpoints and their links stay.
    #[tracing::instrument(target = "db_method", skip_all, fields(retries = tracing::field::Empty))]
    pub async fn clear_group_endpoints(&self, group_id: &str) -> Result<usize> {
        let db = self;
        let group_id = group_id.to_owned();
        retry_on_busy(
            move || {
                let group_id = group_id.clone();
                async move {
                    let mut conn = db.conn().await?;
                    let rows: Vec<EndpointGroup> =
                        EndpointGroup::filter(EndpointGroup::fields().group_id().eq(&group_id))
                            .exec(&mut conn)
                            .await?;
                    let count = rows.len();
                    EndpointGroup::filter(EndpointGroup::fields().group_id().eq(&group_id))
                        .delete()
                        .exec(&mut conn)
                        .await?;
                    Ok(count)
                }
            },
            5,
        )
        .await
    }

    /// Delete a group: its `endpoint_groups` links, then the group row.
    /// One transaction.
    ///
    /// Note: the old `delete_group` also purged endpoints of this group that
    /// no longer belonged to ANY group. The typed model keeps group-less
    /// endpoints (the All view shows them, and `clear_group_endpoints`
    /// unlinks without deleting) — endpoint cleanup is left to
    /// [`Self::purge_expired`] by staleness, so deleting a group never
    /// silently destroys endpoints.
    #[tracing::instrument(target = "db_method", skip_all, fields(retries = tracing::field::Empty))]
    pub async fn delete_group(&self, group_id: &str) -> Result<()> {
        retry_on_busy(|| self.delete_group_once(group_id), 5).await
    }

    async fn delete_group_once(&self, group_id: &str) -> Result<()> {
        let mut conn = self.conn().await?;
        let mut tx = conn.transaction().await?;

        EndpointGroup::filter(EndpointGroup::fields().group_id().eq(group_id))
            .delete()
            .exec(&mut tx)
            .await?;
        Group::filter_by_id(group_id.to_string())
            .delete()
            .exec(&mut tx)
            .await?;

        tx.commit().await?;
        Ok(())
    }

    // ── DNS sources and resolvers ───────────────────────────────────────

    /// Inserts `source` when the table is empty (the built-in seed). Returns
    /// whether it inserted.
    pub async fn seed_dns_source_if_empty(&self, source: &DnsSource) -> Result<bool> {
        let db = self;
        let source = source.clone();
        retry_on_busy(
            move || {
                let source = source.clone();
                async move {
                    let mut conn = db.conn().await?;
                    let existing: Vec<DnsSource> = DnsSource::all().exec(&mut conn).await?;
                    if !existing.is_empty() {
                        return Ok(false);
                    }
                    DnsSource::create()
                        .id(source.id.clone())
                        .name(source.name.clone())
                        .url(source.url.clone())
                        .enabled(source.enabled)
                        .user_agent(source.user_agent.clone())
                        .sort_order(source.sort_order)
                        .last_refreshed(source.last_refreshed)
                        .status(source.status)
                        .error_message(source.error_message.clone())
                        .refresh_interval(source.refresh_interval)
                        .exec(&mut conn)
                        .await?;
                    Ok(true)
                }
            },
            5,
        )
        .await
    }

    /// All DNS sources, in display order.
    pub async fn list_dns_sources(&self) -> Result<Vec<DnsSource>> {
        let mut conn = self.conn().await?;
        Ok(DnsSource::all()
            .order_by(DnsSource::fields().sort_order().asc())
            .exec(&mut conn)
            .await?)
    }

    pub async fn upsert_dns_source(&self, source: &DnsSource) -> Result<()> {
        let db = self;
        let source = source.clone();
        retry_on_busy(
            move || {
                let source = source.clone();
                async move {
                    let mut conn = db.conn().await?;
                    DnsSource::upsert_by_id(source.id.clone())
                        .name(source.name.clone())
                        .url(source.url.clone())
                        .enabled(source.enabled)
                        .user_agent(source.user_agent.clone())
                        .sort_order(source.sort_order)
                        .last_refreshed(source.last_refreshed)
                        .status(source.status)
                        .error_message(source.error_message.clone())
                        .refresh_interval(source.refresh_interval)
                        .exec(&mut conn)
                        .await?;
                    Ok(())
                }
            },
            5,
        )
        .await
    }

    /// Records a refresh outcome on an EXISTING source. Update-only: a source
    /// deleted while the fetch ran is not re-created by the status write.
    pub async fn update_dns_source_status(
        &self,
        source_id: &str,
        last_refreshed: i64,
        status: GroupStatus,
        error: Option<String>,
    ) -> Result<()> {
        let db = self;
        let source_id = source_id.to_string();
        retry_on_busy(
            move || {
                let source_id = source_id.clone();
                let error = error.clone();
                async move {
                    let mut conn = db.conn().await?;
                    DnsSource::filter_by_id(source_id)
                        .update()
                        .last_refreshed(Some(last_refreshed))
                        .status(Some(status))
                        .error_message(error)
                        .exec(&mut conn)
                        .await?;
                    Ok(())
                }
            },
            5,
        )
        .await
    }

    /// Deletes a source and its links; a resolver another source still lists
    /// survives, a resolver with no link left is removed.
    pub async fn delete_dns_source(&self, source_id: &str) -> Result<()> {
        retry_on_busy(|| self.delete_dns_source_once(source_id), 5).await
    }

    async fn delete_dns_source_once(&self, source_id: &str) -> Result<()> {
        let mut conn = self.conn().await?;
        let mut tx = conn.transaction().await?;
        DnsSourceResolver::filter_by_source_id(source_id.to_string())
            .delete()
            .exec(&mut tx)
            .await?;
        DnsSource::filter_by_id(source_id.to_string())
            .delete()
            .exec(&mut tx)
            .await?;
        tx.commit().await?;
        Self::sweep_orphan_resolvers(&mut conn).await
    }

    /// Applies one source's parsed candidates.
    ///
    /// A resolver is unique by stamp and its measurement columns are never
    /// written here, so refreshing a source costs no retest (spec D4). Links
    /// are added before removed, so a crash cannot leave a resolver unlinked.
    pub async fn refresh_source_links(
        &self,
        source_id: &str,
        candidates: &[DnsCandidateRow],
    ) -> Result<()> {
        let db = self;
        let source_id = source_id.to_string();
        let candidates = candidates.to_vec();
        retry_on_busy(
            move || {
                let source_id = source_id.clone();
                let candidates = candidates.clone();
                async move {
                    let mut conn = db.conn().await?;
                    // One Immediate transaction: resolver inserts, the link
                    // rewrite and the orphan sweep are one unit, so two
                    // overlapping refreshes serialize instead of deleting each
                    // other's just-inserted resolver between the insert and its
                    // link.
                    let mut tx = conn
                        .transaction_builder()
                        .mode(TransactionMode::Immediate)
                        .begin()
                        .await?;
                    // A source deleted while its fetch ran must not be
                    // resurrected by its links.
                    let exists = DnsSource::filter_by_id(source_id.clone())
                        .first()
                        .exec(&mut tx)
                        .await?
                        .is_some();
                    if !exists {
                        tx.commit().await?;
                        return Ok(());
                    }
                    let existing: Vec<DnsResolver> = DnsResolver::all().exec(&mut tx).await?;
                    let mut known: std::collections::HashMap<String, DnsResolver> = existing
                        .into_iter()
                        .map(|row| (row.stamp.clone(), row))
                        .collect();
                    for candidate in &candidates {
                        if let Some(stored) = known.remove(&candidate.stamp) {
                            // A parser change can move the display endpoint; the
                            // measurement stands until the next test (D4).
                            if stored.protocol != candidate.protocol
                                || stored.host != candidate.host
                                || stored.port != i64::from(candidate.port)
                            {
                                DnsResolver::filter_by_stamp(candidate.stamp.clone())
                                    .update()
                                    .protocol(candidate.protocol.clone())
                                    .host(candidate.host.clone())
                                    .port(i64::from(candidate.port))
                                    .exec(&mut tx)
                                    .await?;
                            }
                            continue;
                        }
                        DnsResolver::create()
                            .stamp(candidate.stamp.clone())
                            .protocol(candidate.protocol.clone())
                            .host(candidate.host.clone())
                            .port(i64::from(candidate.port))
                            .latency_ms(None)
                            .status(ResolverStatus::Unchecked)
                            .error(None)
                            .checked_at(None)
                            .enabled(true)
                            .exec(&mut tx)
                            .await?;
                    }
                    let links: Vec<DnsSourceResolver> =
                        DnsSourceResolver::filter_by_source_id(source_id.clone())
                            .exec(&mut tx)
                            .await?;
                    let old: std::collections::HashSet<String> =
                        links.into_iter().map(|link| link.stamp).collect();
                    let wanted: std::collections::HashSet<&str> =
                        candidates.iter().map(|c| c.stamp.as_str()).collect();
                    for candidate in &candidates {
                        if !old.contains(&candidate.stamp) {
                            DnsSourceResolver::create()
                                .source_id(source_id.clone())
                                .stamp(candidate.stamp.clone())
                                .exec(&mut tx)
                                .await?;
                        }
                    }
                    for stamp in &old {
                        if !wanted.contains(stamp.as_str()) {
                            DnsSourceResolver::filter_by_source_id_and_stamp(
                                source_id.clone(),
                                stamp.clone(),
                            )
                            .delete()
                            .exec(&mut tx)
                            .await?;
                        }
                    }
                    Self::sweep_orphan_resolvers(&mut tx).await?;
                    tx.commit().await?;
                    Ok(())
                }
            },
            5,
        )
        .await
    }

    /// Deletes resolvers no source links to. Called after a link set changes;
    /// takes an executor so it runs inside the refresh's transaction.
    async fn sweep_orphan_resolvers(conn: &mut impl toasty::Executor) -> Result<()> {
        let links: Vec<DnsSourceResolver> = DnsSourceResolver::all().exec(&mut *conn).await?;
        let live: std::collections::HashSet<String> =
            links.into_iter().map(|link| link.stamp).collect();
        let resolvers: Vec<DnsResolver> = DnsResolver::all().exec(&mut *conn).await?;
        for resolver in resolvers {
            if !live.contains(&resolver.stamp) {
                DnsResolver::filter_by_stamp(resolver.stamp)
                    .delete()
                    .exec(&mut *conn)
                    .await?;
            }
        }
        Ok(())
    }

    /// Every listed resolver (the DNS tab's rows).
    pub async fn list_dns_resolvers(&self) -> Result<Vec<DnsResolver>> {
        let mut conn = self.conn().await?;
        Ok(DnsResolver::all().exec(&mut conn).await?)
    }

    pub async fn set_dns_resolver_enabled(&self, stamp: &str, enabled: bool) -> Result<()> {
        let db = self;
        let stamp = stamp.to_string();
        retry_on_busy(
            move || {
                let stamp = stamp.clone();
                async move {
                    let mut conn = db.conn().await?;
                    DnsResolver::filter_by_stamp(stamp)
                        .update()
                        .enabled(enabled)
                        .exec(&mut conn)
                        .await?;
                    Ok(())
                }
            },
            5,
        )
        .await
    }

    /// The live pool: enabled resolvers that answered the last test, fastest
    /// first, limited to `limit`.
    pub async fn dns_pool(&self, limit: usize) -> Result<Vec<DnsResolver>> {
        let mut conn = self.conn().await?;
        let mut rows: Vec<DnsResolver> = DnsResolver::all().exec(&mut conn).await?;
        rows.retain(|row| {
            row.enabled && row.status == ResolverStatus::Ok && row.latency_ms.is_some()
        });
        rows.sort_by(|a, b| {
            a.latency_ms
                .cmp(&b.latency_ms)
                .then_with(|| a.stamp.cmp(&b.stamp))
        });
        rows.truncate(limit);
        Ok(rows)
    }

    /// Writes one test run: `(stamp, latency_ms, error)`. A `None` latency is
    /// a failed measurement and stores the error class.
    pub async fn apply_dns_test_results(
        &self,
        results: &[(String, Option<u32>, Option<String>)],
    ) -> Result<()> {
        let db = self;
        let results = results.to_vec();
        retry_on_busy(
            move || {
                let results = results.clone();
                async move {
                    let mut conn = db.conn().await?;
                    let at = now_epoch();
                    for (stamp, latency, error) in &results {
                        let status = if latency.is_some() {
                            ResolverStatus::Ok
                        } else {
                            ResolverStatus::Error
                        };
                        DnsResolver::filter_by_stamp(stamp.clone())
                            .update()
                            .latency_ms(latency.map(i64::from))
                            .status(status)
                            .error(error.clone())
                            .checked_at(Some(at))
                            .exec(&mut conn)
                            .await?;
                    }
                    Ok(())
                }
            },
            5,
        )
        .await
    }

    // ── Stats / restore ─────────────────────────────────────────────────

    /// Zero traffic (`today_up/down`, `total_up/down`) and clear
    /// `latency`, `speed_bps`, and `error` on EVERY `profile_stats` row
    /// (query-based update, one statement; the old `clear_all_stats` wiped
    /// server stats + extensions' delay/speed).
    #[tracing::instrument(target = "db_method", skip_all, fields(retries = tracing::field::Empty))]
    pub async fn clear_all_stats(&self) -> Result<()> {
        let db = self;
        retry_on_busy(
            move || async move {
                let mut conn = db.conn().await?;
                ProfileStats::all()
                    .update()
                    .traffic(TrafficStats {
                        today_up: 0,
                        today_down: 0,
                        total_up: 0,
                        total_down: 0,
                    })
                    .latency(Latency::default())
                    .error(None)
                    .speed_bps(None)
                    // The stability ring goes with the measurements: "clear all
                    // stats" that left it behind would keep every wiped link
                    // proven (spec `2026-10-09-stab-bin-design` §7.5).
                    .stab_mask(0)
                    .stab_len(0)
                    .exec(&mut conn)
                    .await?;
                crate::endpoint_rank::backfill_all(&mut conn).await?;
                Ok(())
            },
            5,
        )
        .await
    }

    /// Restore a stale endpoint by setting `last_seen_at = now` on all its
    /// links (old `restore_endpoint`).
    #[tracing::instrument(target = "db_method", skip_all, fields(retries = tracing::field::Empty))]
    pub async fn restore_endpoint(&self, endpoint_id: EndpointId) -> Result<()> {
        let db = self;
        retry_on_busy(
            move || async move {
                let now = now_epoch();
                let mut conn = db.conn().await?;
                ProfileStats::filter(ProfileStats::fields().endpoint_id().eq(endpoint_id))
                    .update()
                    .last_seen_at(now)
                    .exec(&mut conn)
                    .await?;
                crate::endpoint_rank::refresh(&mut conn, &[endpoint_id]).await?;
                Ok(())
            },
            5,
        )
        .await
    }
}

impl Database {
    /// The endpoints whose links carry a failure marker older than `cutoff` —
    /// the error-TTL sweep's id set.
    ///
    /// A projection, not a model load: the caller only needs `endpoint_id` to
    /// refresh the ordering keys, and decoding every link row to keep one
    /// integer cost 25.9 ms against 9.0 ms for this at 74k rows / 14.8k swept
    /// links (`docs/research/2026-11-16-turso-0.9-delta.md` §7).
    /// How many DISTINCT exit IPs the stored successes name (spec
    /// `2026-11-19-probe-truth` S6).
    ///
    /// The corpus is links, not servers: one endpoint's several links share a
    /// host, and one server's several ports share an exit. The page's own
    /// aggregates count endpoints, so this is the only number that says "how
    /// many servers actually work".
    ///
    /// Raw SQL cause (`docs/reference/database-manual-sql.md`): `COUNT(DISTINCT
    /// latency_ip)` is an aggregate over a column no typed projection exposes,
    /// and the page's aggregate is per-endpoint (it joins `endpoint_rank`), so
    /// the question cannot be asked of it.
    pub async fn distinct_exit_ips(&self) -> Result<u64> {
        let mut conn = self.conn().await?;
        let rows = toasty::sql::query(
            "SELECT COUNT(DISTINCT latency_ip) FROM profile_stats \
             WHERE latency_ip IS NOT NULL AND latency_ip <> ''",
        )
        .exec(&mut conn)
        .await?;
        Ok(rows
            .first()
            .and_then(|row| match row {
                toasty_core::stmt::Value::Record(record) => record.fields.first(),
                _ => None,
            })
            .and_then(|value| match value {
                toasty_core::stmt::Value::I64(n) => u64::try_from(*n).ok(),
                _ => None,
            })
            .unwrap_or(0))
    }

    /// Clear the DNS-derived failure marker on every link of `endpoint_ids`
    /// (spec `2026-11-19-probe-truth-and-ingest-boundary` S4).
    ///
    /// A resolved host is a *retry state*, not a verdict: the marker it carried
    /// ("the name does not resolve") is stale the moment an address exists, so
    /// the link must fall back to "not tested" (bin 12) rather than stay sunk
    /// below every untested row.
    ///
    /// Raw SQL cause (`docs/reference/database-manual-sql.md`): the marker is
    /// an EMBED (`error_kind`/`error_text`/`error_stage`/`error_cause`), and
    /// toasty exposes no filter over an embed's field, so "kind = name" cannot
    /// be written through the typed path. The UPDATE is endpoint-scoped and
    /// touches ONLY the name class: a real marker, a measurement and a purge
    /// verdict are left exactly as they were.
    ///
    /// The caller owes a `refresh_endpoint_ranks` for the same ids — the page
    /// reads the derived keys, not this table.
    pub async fn clear_name_markers(&self, endpoint_ids: &[EndpointId]) -> Result<()> {
        if endpoint_ids.is_empty() {
            return Ok(());
        }
        // This is a write the events handler fires per `NamesResolved` event,
        // so it lands in exactly the burst a batch's flushes are also writing
        // (2026-11-20: 62 `database is locked` failures in 10 s). The UPDATE is
        // idempotent, so retrying the whole chunk loop is safe — the same shape
        // `refresh_endpoint_ranks` uses.
        let db = self;
        let ids = endpoint_ids.to_vec();
        crate::retry_on_busy(
            move || {
                let ids = ids.clone();
                async move {
                    let mut conn = db.conn().await?;
                    let now = crate::models_toasty::now_epoch();
                    for chunk in ids.chunks(500) {
                        let list = chunk
                            .iter()
                            .map(|id| id.get().to_string())
                            .collect::<Vec<_>>()
                            .join(",");
                        toasty::sql::query(format!(
                            "UPDATE profile_stats SET error = NULL, error_kind = NULL, error_text = NULL, \
                             error_stage = NULL, error_cause = NULL, updated_at = {now} \
                             WHERE error_kind = 'name' AND endpoint_id IN ({list})"
                        ))
                        .exec(&mut conn)
                        .await?;
                    }
                    Ok(())
                }
            },
            5,
        )
        .await
    }

    pub async fn endpoint_ids_with_errors_before(&self, cutoff: i64) -> Result<Vec<EndpointId>> {
        let mut conn = self.conn().await?;
        let rows = toasty::sql::query(format!(
            "SELECT endpoint_id FROM profile_stats \
             WHERE error IS NOT NULL AND updated_at < {cutoff}"
        ))
        .exec(&mut conn)
        .await?;
        Ok(rows
            .iter()
            .filter_map(|row| match row {
                toasty_core::stmt::Value::Record(record) => record.fields.first(),
                _ => None,
            })
            .filter_map(|v| match v {
                toasty_core::stmt::Value::I64(id) => Some(EndpointId::new(*id)),
                _ => None,
            })
            .collect())
    }

    /// Delete `Protocol` rows with no remaining `profile_stats` links — the
    /// shared protocol table's orphan cleanup (the old per-row model had no
    /// shared table to clean). Runs inside the caller's transaction.
    ///
    /// **One statement, raw, and `NOT EXISTS` on purpose.** The typed form
    /// (`links().all(FALSE)`) lowers to `id NOT IN (SELECT protocol_id FROM
    /// profile_stats)`, which turso 0.9.0-pre.5 serves as a per-row subquery
    /// loop: measured at 74k protocols it costs **5.37 s**, against **23 ms**
    /// for this anti-join (and 29 ms for the DELETE), in every journal mode —
    /// `docs/research/2026-11-16-turso-0.9-delta.md` §3. The purge runs once
    /// per merged endpoint inside the merge transaction, where that 5 s is
    /// what the 2026-11-16 production dump's 556 s compact pass was made of.
    /// The same convention as `purge_expired_once`'s candidate scan.
    /// Remove links whose endpoint no longer exists, for the endpoints a
    /// flush touched. Same anti-join as the purge; ids inlined like every
    /// other raw statement here.
    async fn sweep_orphan_links_for(
        tx: &mut dyn toasty::Executor,
        ids: &[EndpointId],
    ) -> Result<()> {
        if ids.is_empty() {
            return Ok(());
        }
        let list = ids
            .iter()
            .map(|id| id.get().to_string())
            .collect::<Vec<_>>()
            .join(",");
        toasty::sql::statement(format!(
            "DELETE FROM profile_stats WHERE endpoint_id IN ({list}) AND NOT EXISTS \
             (SELECT 1 FROM endpoints e WHERE e.id = profile_stats.endpoint_id)"
        ))
        .exec(&mut *tx)
        .await?;
        Ok(())
    }

    pub(crate) async fn purge_orphan_protocols(tx: &mut dyn toasty::Executor) -> Result<()> {
        toasty::sql::statement(
            "DELETE FROM protocols WHERE NOT EXISTS \
             (SELECT 1 FROM profile_stats p WHERE p.protocol_id = protocols.id)",
        )
        .exec(&mut *tx)
        .await?;
        Ok(())
    }
}
// ── Route probes (singleton settings row) ───────────────────────────────

impl Database {
    /// The global probe-hostname list; an absent row yields an empty vec.
    #[tracing::instrument(target = "db_method", skip_all, fields(retries = tracing::field::Empty))]
    pub async fn get_route_probes(&self) -> Result<Vec<String>> {
        let mut conn = self.conn().await?;
        let rows: Vec<RouteProbes> = RouteProbes::all().exec(&mut conn).await?;
        Ok(rows.into_iter().next().map_or_default(|r| r.hosts))
    }

    /// Replace the global probe-hostname list (singleton `id == "global"`).
    /// Deduped case-insensitively, first spelling kept — same policy as
    /// merge's probe union.
    #[tracing::instrument(target = "db_method", skip_all, fields(retries = tracing::field::Empty))]
    pub async fn upsert_route_probes(&self, hosts: Vec<String>) -> Result<()> {
        let db = self;
        let mut seen = std::collections::HashSet::new();
        let deduped: Vec<String> = hosts
            .into_iter()
            .filter(|h| seen.insert(h.to_lowercase()))
            .collect();
        retry_on_busy(
            move || {
                let deduped = deduped.clone();
                async move {
                    let mut conn = db.conn().await?;
                    RouteProbes::upsert_by_id("global".to_string())
                        .hosts(deduped)
                        .exec(&mut conn)
                        .await?;
                    Ok(())
                }
            },
            5,
        )
        .await
    }
}
// ── Bulk upserts (subscription import) ───────────────────────────────
//
// Executor-taking free functions rather than `Database` methods: the caller
// owns the transaction, so a whole batch (endpoints + protocols + links +
// group links) commits as ONE transaction — one fsync per batch instead of
// four, and a crash mid-batch never leaves half a batch stored. Field lists
// are copied verbatim from the single-row methods above — the bulk path must
// never drift from them.

/// Rows per multi-row statement on the import path. `LINK_STATEMENT_ROWS`
/// (400) is the measured value for the link writer; these tables are narrower,
/// so they use the same chunk size rather than inventing a second constant.
const IMPORT_STATEMENT_ROWS: usize = LINK_STATEMENT_ROWS;

/// Insert-or-update many endpoints on the caller's executor (usually a
/// `&mut Transaction`). Empty slice is a no-op.
///
/// One multi-row statement per chunk instead of one typed upsert per row. The
/// 2026-10-01 import issued **105,147 statements** for this one family;
/// chunked at 400 that is ~263.
///
/// The column set is copied verbatim from the typed single-row builder below —
/// the bulk path must never drift from it. `manual_protocol_override` and
/// `resolved_at` are deliberately NOT written here either: the typed writer
/// leaves them alone, and an import must not clear an operator's override or
/// stamp a resolution the resolver owns.
#[tracing::instrument(target = "db_method", skip_all, fields(retries = tracing::field::Empty))]
pub async fn upsert_endpoints_bulk(tx: &mut impl toasty::Executor, eps: &[Endpoint]) -> Result<()> {
    use std::fmt::Write as _;
    if eps.is_empty() {
        return Ok(());
    }
    let created = now_epoch();
    for chunk in eps.chunks(IMPORT_STATEMENT_ROWS) {
        let mut sql = String::with_capacity(chunk.len() * 96 + 96);
        sql.push_str(
            "INSERT INTO \"endpoints\" (\"id\", \"domain\", \"sub_domain\", \"port\", \"ports\", \
             \"last_source\", \"created_at\") VALUES ",
        );
        for (i, e) in chunk.iter().enumerate() {
            if i > 0 {
                sql.push(',');
            }
            let _ = write!(
                sql,
                "({}, {}, {}, {}, {}, {}, {})",
                e.id.get(),
                sql_lit(&e.domain),
                sql_lit(&e.sub_domain),
                e.port,
                sql_lit(&blob_lit(&e.ports)),
                e.last_source
                    .as_deref()
                    .map_or_else(|| "NULL".to_owned(), sql_lit),
                created
            );
        }
        sql.push_str(
            " ON CONFLICT(\"id\") DO UPDATE SET \"domain\" = excluded.\"domain\", \
             \"sub_domain\" = excluded.\"sub_domain\", \"port\" = excluded.\"port\", \
             \"ports\" = excluded.\"ports\", \"last_source\" = excluded.\"last_source\"",
        );
        toasty::sql::statement(sql).exec(tx).await?;
    }
    Ok(())
}

/// The `ports` column's stored text: an array of `u16` as JSON, matching what
/// the typed upsert writes. A blank list is `[]`, not `NULL`.
fn blob_lit(ports: &[u16]) -> String {
    if ports.is_empty() {
        return "[]".to_owned();
    }
    let mut out = String::with_capacity(ports.len() * 6 + 2);
    out.push('[');
    for (i, p) in ports.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str(&p.to_string());
    }
    out.push(']');
    out
}

/// Insert-or-update many protocols on the caller's executor. Empty slice is a
/// no-op. Same deferred-unloaded guard as `Database::upsert_protocol`.
#[tracing::instrument(target = "db_method", skip_all, fields(retries = tracing::field::Empty))]
pub async fn upsert_protocols_bulk(tx: &mut impl Executor, ps: &[Protocol]) -> Result<()> {
    use std::fmt::Write as _;
    for p in ps {
        if p.config.is_unloaded() {
            return Err(DatabaseError::Generic(
                "upsert_protocols_bulk: deferred config not loaded (rebuild the Protocol or load it with config included)"
                    .into(),
            ));
        }
    }
    // One 400-row statement per chunk, not one typed upsert per protocol.
    // Measured on a realistic VLESS payload (a ~400 B config plus the embed
    // columns): 20 000 protocols cost 658-713 ms as typed single-row upserts
    // against 125-155 ms this way — `docs/research/2026-11-16-turso-0.9-delta.md`
    // §5. The column list, the enum labels (`as_db_label`, the toasty embed
    // spelling — never the wire `as_str`), the INTEGER flag and the config
    // JSON are the exact forms the typed writer stores; the test
    // `protocols_bulk_matches_the_typed_writer` pins that equality.
    let created = now_epoch();
    for chunk in ps.chunks(IMPORT_STATEMENT_ROWS) {
        let mut sql = String::with_capacity(chunk.len() * 320 + 320);
        sql.push_str(
            "INSERT INTO protocols (id, sig, proto_kind, transport_type, security_type, \
             security_sni, security_fp, security_insecure, config, created_at) VALUES ",
        );
        for (i, p) in chunk.iter().enumerate() {
            if i > 0 {
                sql.push(',');
            }
            let config = serde_json::to_string(&p.config.get().0).map_err(|e| {
                DatabaseError::Generic(format!("upsert_protocols_bulk: config json: {e}"))
            })?;
            let _ = write!(
                sql,
                "({}, {}, {}, {}, {}, {}, {}, {}, {}, {created})",
                p.id.get(),
                p.sig,
                sql_lit(p.proto_kind.as_db_label()),
                sql_lit(p.transport.r#type.as_db_label()),
                sql_lit(p.security.r#type.as_str()),
                p.security
                    .sni
                    .as_deref()
                    .map_or_else(|| "NULL".to_owned(), sql_lit),
                p.security
                    .fp
                    .as_deref()
                    .map_or_else(|| "NULL".to_owned(), sql_lit),
                p.security
                    .insecure
                    .map_or_else(|| "NULL".to_owned(), |b| i64::from(b).to_string()),
                sql_lit(&config),
            );
        }
        // The typed upsert's conflict action: every field this writer owns
        // EXCEPT `created_at`, which `on_create` stamps once.
        sql.push_str(
            " ON CONFLICT(id) DO UPDATE SET sig = excluded.sig, \
             proto_kind = excluded.proto_kind, transport_type = excluded.transport_type, \
             security_type = excluded.security_type, security_sni = excluded.security_sni, \
             security_fp = excluded.security_fp, \
             security_insecure = excluded.security_insecure, config = excluded.config",
        );
        toasty::sql::statement(sql).exec(&mut *tx).await?;
    }
    Ok(())
}

/// Insert-or-update many per-pair link rows on the caller's executor — the
/// subscription/import path, and the one writer restricted to the SOURCE
/// columns.
///
/// Empty slice is a no-op. An **update** writes identity/config provenance only
/// (`last_seen_at`, `updated_at`); the RESULT
/// columns (`latency*`, `speed_bps`, `error*`) and the TRAFFIC counters are
/// written **on create only** (they ride the `VALUES` tuple, which a conflicting
/// row's `DO UPDATE` never reads). The caller's snapshot comes from a fresh
/// parse, so writing those columns on update silently wipes the measurements and
/// counters the ping pipeline and the stats poller own — the whole-row shape
/// this replaced did exactly that (2026-09-15: an import refresh running beside
/// a Fast+Real batch destroyed every fast latency it had just written).
/// `last_used_at` is likewise never touched here (its owner is
/// [`Database::update_last_used`]).
#[tracing::instrument(target = "db_method", skip_all, fields(retries = tracing::field::Empty))]
pub async fn upsert_links_bulk(
    tx: &mut impl toasty::Executor,
    links: &[ProfileStats],
) -> Result<()> {
    // One multi-row upsert per chunk instead of one typed upsert per row
    // (measured 2026-09-16 over the reference feed: 2,000 links 360 ms → 48 ms).
    exec_link_upsert(tx, links, LINK_SOURCE_CONFLICT_SQL, now_epoch()).await?;
    // Derived state: the stored ordering keys follow the links, so every
    // link writer refreshes the endpoints it touched — here, inside the
    // caller's transaction, which makes the key update atomic with the write.
    // Kept in BOTH journal modes: a fresh import's endpoints have no rank row
    // yet, so deferring would blind the page until a drain.
    let mut touched: Vec<EndpointId> = links.iter().map(|l| l.endpoint_id).collect();
    touched.sort_unstable_by_key(|id| id.get());
    touched.dedup();
    if touched.is_empty() {
        return Ok(());
    }
    crate::endpoint_rank::refresh(tx, &touched).await?;
    Ok(())
}

/// The statement half of [`Database::set_endpoint_ip_countries`], on the
/// caller's executor.
///
/// Split out for [`crate::write_behind::CountrySpec`]: the write-behind driver
/// opens its OWN transaction and owns the commit, so a call that opened a
/// second connection (and retried it) inside the driver's tx would deadlock on
/// itself. Every other one-shot caller keeps the public wrapper.
// No `db_method` span here, matching `apply_link_patches_once`: the public
// wrapper already carries one, and the driver calls this from INSIDE its own
// flush — a second, shorter span would be the one `DbMonitor` attributes the
// write to.
pub async fn set_endpoint_ip_countries_once(
    tx: &mut impl Executor,
    rows: &[(EndpointId, std::net::IpAddr, String)],
) -> Result<()> {
    crate::endpoint_ip::set_countries_bulk(tx, rows).await
}

/// Insert-or-update many endpoint↔group links on the caller's executor.
/// Empty slice is a no-op.
///
/// Multi-row per chunk. This was the single largest family on the import path —
/// **204,592 statements** in the 2026-10-01 run, half the total — because a
/// 500-URL batch touches one endpoint once per protocol, and every one of those
/// was its own statement. Chunked at 400 that is ~511.
#[tracing::instrument(target = "db_method", skip_all, fields(retries = tracing::field::Empty))]
pub async fn upsert_endpoint_group_links_bulk(
    tx: &mut impl toasty::Executor,
    egs: &[EndpointGroup],
) -> Result<()> {
    use std::fmt::Write as _;
    if egs.is_empty() {
        return Ok(());
    }
    for chunk in egs.chunks(IMPORT_STATEMENT_ROWS) {
        let mut sql = String::with_capacity(chunk.len() * 72 + 96);
        sql.push_str(
            "INSERT INTO \"endpoint_groups\" (\"endpoint_id\", \"group_id\", \"last_seen_at\", \
             \"sort_order\") VALUES ",
        );
        for (i, eg) in chunk.iter().enumerate() {
            if i > 0 {
                sql.push(',');
            }
            let _ = write!(
                sql,
                "({}, {}, {}, {})",
                eg.endpoint_id.get(),
                sql_lit(&eg.group_id),
                eg.last_seen_at,
                eg.sort_order
                    .map_or_else(|| "NULL".to_owned(), |o| o.to_string()),
            );
        }
        sql.push_str(
            " ON CONFLICT(\"endpoint_id\", \"group_id\") DO UPDATE SET \
             \"last_seen_at\" = excluded.\"last_seen_at\", \
             \"sort_order\" = excluded.\"sort_order\"",
        );
        toasty::sql::statement(sql).exec(tx).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::is_busy_error;
    use crate::models_toasty::HostType;
    use crate::models_toasty::{Latency, Security, TrafficStats, Transport};
    use leas_proto::proto_spec::common::TransportConfig;
    use toasty::{Deferred, Json};

    /// The generic `app_meta` store: point read, upsert, absent key.
    #[tokio::test]
    async fn app_meta_round_trips_and_upserts() {
        let db = Database::in_memory().await.expect("db");
        assert_eq!(db.meta_get("missing").await.expect("get"), None);
        db.meta_set("psl_version", "2026-01-01T00:00:00Z")
            .await
            .expect("set");
        assert_eq!(
            db.meta_get("psl_version").await.expect("get"),
            Some("2026-01-01T00:00:00Z".to_string())
        );
        db.meta_set("psl_version", "2027-02-02T00:00:00Z")
            .await
            .expect("upsert");
        assert_eq!(
            db.meta_get("psl_version").await.expect("get"),
            Some("2027-02-02T00:00:00Z".to_string())
        );
    }
    use leas_proto::proto_spec::{
        ProtocolConfig, ProtocolKind, SecurityConfig, SecurityType, TransportType, VlessConfig,
    };

    #[test]
    fn concurrent_writes_is_opt_in() {
        assert!(!concurrent_writes_from_env(None));
        assert!(concurrent_writes_from_env(Some("1")));
        assert!(concurrent_writes_from_env(Some("true")));
        assert!(!concurrent_writes_from_env(Some("0")));
        assert!(!concurrent_writes_from_env(Some("false")));
    }
    /// The raw multi-row import writers must be indistinguishable from the
    /// typed ones: the row has to come back with the SAME `host_type` label,
    /// the same `ports` text, and the same group membership. A wrong enum
    /// label does not fail the write — it silently mis-classifies the endpoint.
    #[tokio::test]
    async fn multi_row_import_writers_round_trip_through_a_real_database() {
        let db = Database::in_memory().await.expect("db");
        let mut conn = db.connection().await.expect("conn");

        for (i, ht) in [
            HostType::Ipv4,
            HostType::Ipv6,
            HostType::Dns,
            HostType::Undefined,
        ]
        .into_iter()
        .enumerate()
        {
            let id = 900 + i64::try_from(i).expect("host-kind index fits");
            upsert_endpoints_bulk(
                &mut conn,
                &[Endpoint {
                    id: EndpointId::new(id),
                    domain: Endpoint::derive_domain(&format!("h{i}.example"), ht).0,
                    sub_domain: Endpoint::derive_domain(&format!("h{i}.example"), ht).1,
                    port: 443 + u16::try_from(i).expect("host-kind index fits"),
                    ports: if i == 0 { vec![] } else { vec![80, 443] },
                    last_source: None,
                    manual_protocol_override: None,
                    resolved_at: None,
                    created_at: 0,
                    links: Deferred::default(),
                    group_links: Deferred::default(),
                }],
            )
            .await
            .expect("endpoints bulk");
            upsert_endpoint_group_links_bulk(
                &mut conn,
                &[crate::models_toasty::EndpointGroup {
                    endpoint_id: EndpointId::new(id),
                    group_id: "grp-1".to_owned(),
                    last_seen_at: 42,
                    sort_order: None,
                    endpoint: Deferred::default(),
                    group: Deferred::default(),
                }],
            )
            .await
            .expect("group links bulk");
        }

        // Read the LABELS back as text, which is what a wrong writer would get
        // wrong — not through the typed loader, which would hide it.
        for (i, ht) in [
            HostType::Ipv4,
            HostType::Ipv6,
            HostType::Dns,
            HostType::Undefined,
        ]
        .into_iter()
        .enumerate()
        {
            let id = 900 + i64::try_from(i).expect("host-kind index fits");
            let rows = toasty::sql::query(format!(
                "SELECT domain, ports FROM endpoints WHERE id = {id}"
            ))
            .exec(&mut conn)
            .await
            .expect("read endpoint");
            let record = match &rows[0] {
                toasty_core::stmt::Value::Record(r) => r,
                other => panic!("expected a record, got {other:?}"),
            };
            let label = match &record.fields[0] {
                toasty_core::stmt::Value::String(s) => s.as_str(),
                other => panic!("domain must round-trip as TEXT, got {other:?}"),
            };
            // `domain` is the name for a DNS host, empty for an IP/exotic one
            // (db-rewamp D2/D10) — the stored text IS the identity's domain part.
            let expected = if matches!(ht, HostType::Dns) {
                format!("h{i}.example")
            } else {
                String::new()
            };
            assert_eq!(label, expected, "the stored domain must match the split");
            let groups = toasty::sql::query(format!(
                "SELECT COUNT(*) FROM endpoint_groups WHERE endpoint_id = {id} AND group_id = 'grp-1' AND last_seen_at = 42"
            ))
            .exec(&mut conn)
            .await
            .expect("read group link");
            let count = match &groups[0] {
                toasty_core::stmt::Value::Record(r) => match r.fields.first() {
                    Some(toasty_core::stmt::Value::I64(n)) => *n,
                    other => panic!("expected a count, got {other:?}"),
                },
                other => panic!("expected a record, got {other:?}"),
            };
            assert_eq!(count, 1, "the group link must be stored for endpoint {id}");
        }
    }

    /// An upsert must be an UPSERT: the second write replaces the mutable
    /// columns and leaves the ones the import does not own.
    #[tokio::test]
    async fn multi_row_endpoint_upsert_replaces_and_preserves() {
        let db = Database::in_memory().await.expect("db");
        let mut conn = db.connection().await.expect("conn");
        let mut ep = Endpoint {
            id: EndpointId::new(1),
            domain: Endpoint::derive_domain("old.example", HostType::Ipv4).0,
            sub_domain: Endpoint::derive_domain("old.example", HostType::Ipv4).1,
            port: 1,
            ports: Vec::new(),
            last_source: None,
            manual_protocol_override: None,
            resolved_at: None,
            created_at: 0,
            links: Deferred::default(),
            group_links: Deferred::default(),
        };
        upsert_endpoints_bulk(&mut conn, std::slice::from_ref(&ep))
            .await
            .expect("first");
        // Ownership the import must NOT clear.
        toasty::sql::statement(
            "UPDATE endpoints SET manual_protocol_override = 77, resolved_at = 1234 WHERE id = 1",
        )
        .exec(&mut conn)
        .await
        .expect("set owned columns");
        ep.domain = "new.example".to_owned();
        ep.sub_domain = String::new();
        ep.port = 2;
        upsert_endpoints_bulk(&mut conn, &[ep])
            .await
            .expect("second");

        let rows = toasty::sql::query(
            "SELECT domain, port, manual_protocol_override, resolved_at FROM endpoints WHERE id = 1",
        )
        .exec(&mut conn)
        .await
        .expect("read");
        let r = match &rows[0] {
            toasty_core::stmt::Value::Record(r) => r,
            other => panic!("expected a record, got {other:?}"),
        };
        // `host`/`group_id` are TEXT, `port` is an integer column — read each
        // with its own type rather than assuming.
        let text = |i: usize| -> String {
            match &r.fields[i] {
                toasty_core::stmt::Value::String(s) => s.clone(),
                other => panic!("column {i}: expected text, got {other:?}"),
            }
        };
        let int = |i: usize| -> i64 {
            match &r.fields[i] {
                toasty_core::stmt::Value::I64(n) => *n,
                other => panic!("column {i}: expected an integer, got {other:?}"),
            }
        };
        assert_eq!(text(0), "new.example", "domain must be replaced");
        assert_eq!(int(1), 2, "port must be replaced");
        assert_eq!(int(2), 77, "manual_protocol_override must survive");
        assert_eq!(int(3), 1234, "resolved_at must survive");
    }

    #[tokio::test]
    async fn in_memory_stays_wal_for_schema_lifecycle() {
        let db = Database::in_memory().await.expect("in-memory db");
        let mut conn = db.connection().await.expect("connection");
        let rows = toasty::sql::query("PRAGMA journal_mode")
            .exec(&mut conn)
            .await
            .expect("journal mode");
        let mode = rows.first().and_then(|value| match value {
            toasty::stmt::Value::Record(fields) => fields.first().and_then(|field| match field {
                toasty::stmt::Value::String(mode) => Some(mode.as_str()),
                _ => None,
            }),
            _ => None,
        });
        assert_eq!(mode, Some("wal"));
    }
    /// The MVCC checkpoint MUST work on the REAL `Database::open` path.
    ///
    /// This is the ONLY guard on the fix in `file_driver`: it enables
    /// `experimental_mvcc_passive_checkpoint` alongside the MVCC opt-in. Without
    /// it the engine refuses `PRAGMA wal_checkpoint(PASSIVE)` with
    /// `PASSIVE checkpoint requires experimental_mvcc_passive_checkpoint`, and every
    /// auto-checkpoint takes the blocking `Truncate` mode instead of `Passive`.
    ///
    /// It opens a real MVCC handle and runs the statement, so it FAILS if the
    /// flag is dropped from `file_driver` — which
    /// `ping::tests::checkpoint_runs_under_both_journal_modes` cannot do (that
    /// one only asserts a gate predicate whose body is a constant `true`).
    #[tokio::test]
    async fn mvcc_checkpoint_succeeds_on_the_open_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("mvcc-ckpt.db");
        let db = Database::open_with_concurrent_writes(&path, true)
            .await
            .expect("open mvcc");
        assert!(db.uses_concurrent_writes());
        let mut conn = db.connection().await.expect("conn");
        for n in 0..200 {
            toasty::sql::statement(format!(
                "INSERT INTO endpoints (id, created_at, domain, sub_domain, port, ports) \
                 VALUES ({n}, 0, 'ck.example', 'ck.example', 443, '[]')"
            ))
            .exec(&mut conn)
            .await
            .expect("insert");
        }
        let rows = toasty::sql::query("PRAGMA wal_checkpoint(PASSIVE)")
            .exec(&mut conn)
            .await
            .expect("MVCC must accept the passive checkpoint (file_driver sets the flag)");
        assert!(!rows.is_empty(), "the checkpoint returns its status row");
    }

    /// The GEO write path under several concurrency topologies — the A/B
    ///
    /// `set_endpoint_ip_countries` is the writer the flow-cost lab's mix arm
    /// reported failing under MVCC and not WAL. Its failures are split by
    /// `is_busy_error`: a spent retry budget is `exhausted`, anything else is
    /// `hard_err` — the distinction that matters, because a `Constraint` is not
    /// retryable at ANY budget and would otherwise read as exhaustion.
    ///
    /// Measured after the `ON CONFLICT` fix: `exhausted=0 hard_err=0` in EVERY
    /// arm, WAL and MVCC, including 16 writers on shared rows — i.e. the residue
    /// the lab showed was the `set_country` TOCTOU, not contention.
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    #[cfg(feature = "perf-lab")]
    #[ignore = "timing probe; prints a table, asserts nothing (run with --features perf-lab -- --ignored)"]
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_possible_wrap,
        clippy::cast_sign_loss,
        reason = "probe arithmetic over a tiny fixed endpoint pool"
    )]
    async fn geo_under_mvcc_probe() {
        #[allow(clippy::too_many_arguments)]
        async fn arm(
            label: &str,
            mvcc: bool,
            writers: usize,
            rows: usize,
            shared: bool,
            vary: bool,
        ) {
            let dir = tempfile::tempdir().expect("tempdir");
            let path = dir.path().join("geo.db");
            let db = Arc::new(
                Database::open_with_concurrent_writes(&path, mvcc)
                    .await
                    .expect("open"),
            );
            {
                let mut conn = db.connection().await.expect("conn");
                // A pool big enough for the DISJOINT arm to be genuinely
                // disjoint: 16 writers x 24 txns x 8 rows = 3072 distinct ids.
                for id in 1..=4096 {
                    seed_endpoint(&mut conn, id, id, "geo.example", HostType::Dns, 443, 1).await;
                }
            }
            // Split the outcome three ways: `retry_on_busy` returns Err for BOTH
            // a spent retry budget (a busy error) and a hard error it never
            // retried — conflating them is how a Constraint gets misread as
            // exhaustion.
            let (ok, exhausted, hard_err) = (
                Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            );
            let t0 = std::time::Instant::now();
            let mut set = tokio::task::JoinSet::new();
            for w in 0..writers {
                let db = Arc::clone(&db);
                let ok = Arc::clone(&ok);
                let exhausted = Arc::clone(&exhausted);
                let hard_err = Arc::clone(&hard_err);
                set.spawn(async move {
                    for r in 0..24usize {
                        // `shared` = every writer touches the SAME endpoint ids
                        // (the mix arm's 16x duplication); else disjoint.
                        let batch: Vec<_> = (0..rows)
                            .map(|i| {
                                // DISJOINT means each writer owns a distinct id
                                // BLOCK: never `% 64`, which would make every
                                // batch span all rows.
                                let id = if shared {
                                    (i % 8) as i64 + 1
                                } else {
                                    ((w * 24 + r) * rows + i) as i64 + 1
                                };
                                (
                                    EndpointId::new(id),
                                    std::net::IpAddr::from([
                                        10,
                                        0,
                                        (id / 256) as u8,
                                        (id % 256) as u8,
                                    ]),
                                    if vary {
                                        format!("D{w}")
                                    } else {
                                        "DE".to_string()
                                    },
                                )
                            })
                            .collect();
                        match db.set_endpoint_ip_countries(&batch).await {
                            Ok(()) => {
                                ok.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            }
                            Err(e) => {
                                if crate::is_busy_error(&e) {
                                    exhausted.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                } else {
                                    hard_err.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                }
                                if exhausted.load(std::sync::atomic::Ordering::Relaxed)
                                    + hard_err.load(std::sync::atomic::Ordering::Relaxed)
                                    == 1
                                {
                                    println!("GEO ERR: {e}");
                                }
                            }
                        }
                    }
                });
            }
            while set.join_next().await.is_some() {}
            println!(
                "GEOPROBE {label:<10} mvcc={mvcc:<5} writers={writers:<3} rows={rows:<3} shared={shared:<5} vary={vary:<5} wall={:>8.2?} ok={:<4} exhausted={} hard_err={}",
                t0.elapsed(),
                ok.load(std::sync::atomic::Ordering::Relaxed),
                exhausted.load(std::sync::atomic::Ordering::Relaxed),
                hard_err.load(std::sync::atomic::Ordering::Relaxed),
            );
        }
        // Production geometry: the geo drain is ONE owner (the WriteBehind
        // driver), overlapped only by a page seed. So the interesting rows are
        // LOW writer counts, not the lab's 16x.
        for mvcc in [false, true] {
            arm("prod-1w", mvcc, 1, 8, false, false).await;
            arm("prod-2w", mvcc, 2, 8, false, false).await;
            // PRODUCTION TOPOLOGY: TWO owners on the SAME rows. `vary=false` is
            // the seed/drain agreeing (a no-op UPDATE); `vary=true` is a
            // re-resolution racing a stale queued value — last-writer-wins must
            // still hold without a hard error.
            arm("prod-2w-same", mvcc, 2, 8, true, false).await;
            arm("prod-2w-vary", mvcc, 2, 8, true, true).await;
            arm("lab-16w", mvcc, 16, 8, false, false).await;
            arm("overlap", mvcc, 16, 8, true, false).await;
        }
    }

    /// Concurrent single-ping-shaped transactions under `retry_on_busy`, MVCC vs
    /// WAL, counting successes and RETRY EXHAUSTION.
    ///
    /// This answers the question the MVCC-default decision turns on: MVCC
    /// surfaces a same-row conflict at the SECOND write statement (or at COMMIT)
    /// rather than blocking, so the question is not "does it conflict" but
    /// "does the retry budget absorb it". `retry_exhausted` is the number that
    /// matters — a non-zero value means a lost write with MVCC as the default.
    ///
    /// It deliberately mirrors PRODUCTION's retry budget: ONE `retry_on_busy`
    /// (5 attempts) around the tx-scoped write, NOT the public
    /// `apply_link_patches` (which adds its own 5-attempt wrap — nesting them
    /// would measure a 25-attempt budget the app never uses).
    ///
    /// Measured at 32 writers x 60 transactions, several runs: **`retry_exhausted
    /// = 0` on the DISJOINT rows**, WAL and MVCC alike, with MVCC the faster arm
    /// in most runs (84-195 ms vs WAL's 192-775 ms) but not all — the run-to-run
    /// spread exceeds the difference, so treat the wall times as parity. On the
    /// single-row arm MVCC is consistently slower (291-532 ms vs 227-385 ms) and
    /// exhausts at most 1 of 1920, which `WriteBehind::flush` re-stages.
    ///
    /// The production shape is the DISJOINT one: a link's PK is
    /// `(protocol_id, endpoint_id)` and the write-behind coalesces a link's
    /// groups into ONE patch before writing.
    ///
    /// Ignored: timing-based, so it is a probe, not a gate; run it with
    /// `--ignored --nocapture`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    #[cfg(feature = "perf-lab")]
    #[ignore = "timing probe; prints a table, asserts nothing (run with --features perf-lab -- --ignored)"]
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_possible_wrap,
        reason = "probe arithmetic over a tiny fixed endpoint count"
    )]
    async fn mvcc_load_probe() {
        const WRITERS: usize = 32;
        const PER: usize = 60;

        async fn arm(label: &str, mvcc: bool, contending: bool) {
            let dir = tempfile::tempdir().expect("tempdir");
            let path = dir.path().join("load.db");
            let db = Arc::new(
                Database::open_with_concurrent_writes(&path, mvcc)
                    .await
                    .expect("open"),
            );
            assert_eq!(db.uses_concurrent_writes(), mvcc);
            {
                let mut conn = db.connection().await.expect("conn");
                // `seed_endpoint` also writes the link; give each endpoint its
                // own protocol id so the fixture does not re-insert protocol 1.
                // 32 writers x 60 txn = 1920 distinct ids for the disjoint arm.
                for id in 1..=2048 {
                    seed_endpoint(&mut conn, id, id, "load.example", HostType::Dns, 443, 1).await;
                }
            }
            let ok = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let exhausted = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let t0 = std::time::Instant::now();
            let mut set = tokio::task::JoinSet::new();
            for writer_ix in 0..WRITERS {
                let db = Arc::clone(&db);
                let ok = Arc::clone(&ok);
                let exhausted = Arc::clone(&exhausted);
                set.spawn(async move {
                    for i in 0..PER {
                        let id = if contending {
                            (i % 2) as i64 + 1
                        } else {
                            // GENUINELY disjoint: `% 64` (the first version)
                            // made every writer span all 64 rows, so the
                            // "disjoint" arm was fully overlapping and its
                            // "MVCC faster on disjoint rows" reading was an
                            // artifact of that.
                            (writer_ix * PER + i) as i64 + 1
                        };
                        let mut row = ProfileStats {
                            protocol_id: ProtocolId::new(id),
                            endpoint_id: EndpointId::new(id),
                            last_used_at: None,
                            last_seen_at: 1,
                            latency: Latency::fast((i % 900) as i32),
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
                            created_at: 0,
                            updated_at: 0,
                            version: 1,
                            protocol: toasty::Deferred::default(),
                            endpoint: toasty::Deferred::default(),
                        };
                        row.latency = Latency::fast((i % 900) as i32);
                        let row_patch = LinkPatch {
                            link: row,
                            groups: LinkGroups::RESULT,
                        };
                        // Mirror PRODUCTION exactly: `WriteBehind::flush` wraps
                        // ONE `retry_on_busy` around the tx-scoped write, which
                        // itself does not retry. Calling the public
                        // `apply_link_patches` here would wrap it TWICE (5x5 = 25
                        // attempts), which is not the budget the app uses.
                        let handle = Arc::clone(&db);
                        let row_patch = row_patch.clone();
                        let r = crate::retry_on_busy(
                            || async {
                                let mut conn = handle.connection().await?;
                                let mut tx = conn.transaction().await?;
                                let written = Database::apply_link_patches_tx(
                                    &mut tx,
                                    std::slice::from_ref(&row_patch),
                                    now_epoch(),
                                )
                                .await?;
                                tx.commit().await?;
                                Ok(written)
                            },
                            5,
                        )
                        .await;
                        if r.is_ok() {
                            ok.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        } else {
                            exhausted.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        }
                    }
                });
            }
            while set.join_next().await.is_some() {}
            println!(
                "PROBE {label:<10} mvcc={mvcc:<5} contend={contending:<5} wall={:>8.2?} ok={:<4} retry_exhausted={}",
                t0.elapsed(),
                ok.load(std::sync::atomic::Ordering::Relaxed),
                exhausted.load(std::sync::atomic::Ordering::Relaxed),
            );
        }
        for mvcc in [false, true] {
            arm("disjoint", mvcc, false).await;
            arm("contend", mvcc, true).await;
        }
    }
    /// Micro-batch concurrency probe (T1): compare WAL vs MVCC across batch
    /// sizes (1, 16, 32, 64, 128, 512) with 16 disjoint writers over
    /// a fixed pre-seeded feed, measuring both with and without rank refresh.
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    #[cfg(feature = "perf-lab")]
    #[ignore = "timing probe; prints a table, asserts nothing (run with --features perf-lab -- --ignored)"]
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_possible_wrap,
        reason = "probe arithmetic over fixed endpoint counts"
    )]
    async fn micro_batch_mvcc_probe() {
        const PRESEEDED_ENDPOINTS: usize = 8192;
        const TOTAL_UPDATES_PER_WRITER: usize = 256;

        async fn run_bench(mvcc: bool, with_rank_refresh: bool, writers: usize, batch_size: usize) {
            let dir = tempfile::tempdir().expect("tempdir");
            let path = dir.path().join("micro.db");
            let db = Arc::new(
                Database::open_with_concurrent_writes(&path, mvcc)
                    .await
                    .expect("open"),
            );
            {
                let mut conn = db.connection().await.expect("conn");
                for id in 1..=(PRESEEDED_ENDPOINTS as i64) {
                    seed_endpoint(&mut conn, id, id, "micro.example", HostType::Dns, 443, 1).await;
                }
            }

            let ok = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let exhausted = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let batches_per_writer = TOTAL_UPDATES_PER_WRITER / batch_size;
            let latencies = Arc::new(tokio::sync::Mutex::new(Vec::with_capacity(
                writers * batches_per_writer,
            )));
            let t0 = std::time::Instant::now();
            let mut set = tokio::task::JoinSet::new();

            for writer_ix in 0..writers {
                let db = Arc::clone(&db);
                let ok = Arc::clone(&ok);
                let exhausted = Arc::clone(&exhausted);
                let latencies = Arc::clone(&latencies);
                set.spawn(async move {
                    for b in 0..batches_per_writer {
                        let mut patches = Vec::with_capacity(batch_size);
                        let mut touched_eids = Vec::with_capacity(batch_size);
                        for r in 0..batch_size {
                            // Disjoint slice over preseeded endpoints
                            let raw_ix =
                                (writer_ix * TOTAL_UPDATES_PER_WRITER + b * batch_size + r)
                                    % PRESEEDED_ENDPOINTS;
                            let id = raw_ix as i64 + 1;
                            let eid = EndpointId::new(id);
                            touched_eids.push(eid);
                            let mut row = ProfileStats {
                                protocol_id: ProtocolId::new(id),
                                endpoint_id: eid,
                                last_used_at: None,
                                last_seen_at: 1,
                                latency: Latency::fast(((r + b) % 900) as i32),
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
                                created_at: 0,
                                updated_at: 0,
                                version: 1,
                                protocol: toasty::Deferred::default(),
                                endpoint: toasty::Deferred::default(),
                            };
                            row.latency = Latency::fast(((r + b) % 900) as i32);
                            patches.push(LinkPatch {
                                link: row,
                                groups: LinkGroups::RESULT,
                            });
                        }

                        let handle = Arc::clone(&db);
                        let tb0 = std::time::Instant::now();
                        let r = crate::retry_on_busy(
                            || {
                                let handle = Arc::clone(&handle);
                                let patches = patches.clone();
                                let touched_eids = touched_eids.clone();
                                async move {
                                    let mut conn = handle.connection().await?;
                                    let mut tx = conn.transaction().await?;
                                    let written = Database::apply_link_patches_tx(
                                        &mut tx,
                                        &patches,
                                        now_epoch(),
                                    )
                                    .await?;
                                    if with_rank_refresh {
                                        crate::endpoint_rank::refresh(&mut tx, &touched_eids)
                                            .await?;
                                    }
                                    tx.commit().await?;
                                    Ok(written)
                                }
                            },
                            5,
                        )
                        .await;

                        let dur_us = tb0.elapsed().as_micros();
                        latencies.lock().await.push(dur_us);

                        if r.is_ok() {
                            ok.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        } else {
                            exhausted.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        }
                    }
                });
            }
            while set.join_next().await.is_some() {}
            let total_dur = t0.elapsed();
            let mut lats = latencies.lock().await.clone();
            lats.sort_unstable();
            let p50 = lats[lats.len() / 2];
            let p95 = lats[(lats.len() * 95) / 100];
            let p99 = lats[(lats.len() * 99) / 100];
            println!(
                "MICROBENCH mode={:<4} rank_ref={:<5} bsize={:<3} wall={:>8.2?} ok={:<4} exhaust={} p50={:>6}µs p95={:>6}µs p99={:>6}µs",
                if mvcc { "MVCC" } else { "WAL" },
                with_rank_refresh,
                batch_size,
                total_dur,
                ok.load(std::sync::atomic::Ordering::Relaxed),
                exhausted.load(std::sync::atomic::Ordering::Relaxed),
                p50,
                p95,
                p99,
            );
        }

        println!("\n=== MICRO BATCH PROBE: 16 writers, WITH rank refresh ===");
        for batch_size in [1, 16, 32, 64, 128, 256] {
            run_bench(false, true, 16, batch_size).await;
            run_bench(true, true, 16, batch_size).await;
        }

        // Production geometry: the geo drain is ONE owner (the WriteBehind
        // driver), overlapped only by a page seed — the interesting rows are
        // LOW writer counts, not the lab's 16x (database.rs probe precedent).
        println!("\n=== MICRO BATCH PROBE: LOW writer counts (1/2/4), batch 32, rank in-tx ===");
        for writers in [1, 2, 4] {
            run_bench(false, true, writers, 32).await;
            run_bench(true, true, writers, 32).await;
        }

        println!(
            "\n=== MICRO BATCH PROBE: 16 writers, WITHOUT rank refresh (Phase 2 decoupling premise) ==="
        );
        for batch_size in [1, 16, 32, 64, 128, 256] {
            run_bench(false, false, 16, batch_size).await;
            run_bench(true, false, 16, batch_size).await;
        }
    }

    #[tokio::test]
    async fn mvcc_conflict_replays_without_losing_update() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db = Database::open_with_concurrent_writes(dir.path().join("mvcc.db"), true)
            .await
            .expect("file db");
        assert!(db.uses_concurrent_writes());
        let mut setup = db.connection().await.expect("setup connection");
        toasty::sql::query(
            "CREATE TABLE retry_probe (id INTEGER PRIMARY KEY, value TEXT NOT NULL)",
        )
        .exec(&mut setup)
        .await
        .expect("create probe table");
        toasty::sql::query("INSERT INTO retry_probe(id, value) VALUES (1, 'initial')")
            .exec(&mut setup)
            .await
            .expect("seed probe row");

        let mut first = db.connection().await.expect("first connection");
        let mut second = db.connection().await.expect("second connection");
        let mut first_tx = first.transaction().await.expect("first transaction");
        let mut second_tx = second.transaction().await.expect("second transaction");
        toasty::sql::query("UPDATE retry_probe SET value = 'first' WHERE id = 1")
            .exec(&mut first_tx)
            .await
            .expect("first update");
        let second_update =
            toasty::sql::query("UPDATE retry_probe SET value = 'second' WHERE id = 1")
                .exec(&mut second_tx)
                .await;
        let second_error = second_update.expect_err("same-row MVCC update must conflict");
        assert!(is_busy_error(&DatabaseError::Toasty(second_error)));
        first_tx.commit().await.expect("first commit");

        retry_on_busy(
            || async {
                let mut conn = db.connection().await?;
                let mut tx = conn.transaction().await?;
                toasty::sql::query("UPDATE retry_probe SET value = 'retry' WHERE id = 1")
                    .exec(&mut tx)
                    .await?;
                tx.commit().await?;
                Ok(())
            },
            5,
        )
        .await
        .expect("retry update");

        let rows = toasty::sql::query("SELECT value FROM retry_probe WHERE id = 1")
            .exec(&mut setup)
            .await
            .expect("read retried value");
        let value = rows.first().and_then(|value| match value {
            toasty::stmt::Value::Record(fields) => fields.first().and_then(|field| match field {
                toasty::stmt::Value::String(value) => Some(value.as_str()),
                _ => None,
            }),
            _ => None,
        });
        assert_eq!(value, Some("retry"));
    }
    fn ts(secs: i64) -> i64 {
        secs
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

    fn vless_config() -> ProtocolConfig {
        ProtocolConfig::Vless(VlessConfig {
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

    fn zero_traffic() -> TrafficStats {
        TrafficStats {
            today_up: 0,
            today_down: 0,
            total_up: 0,
            total_down: 0,
        }
    }

    /// Insert one endpoint with one protocol and one link at `last_seen`.
    use crate::models_toasty::PurgatoryView;

    /// A one-shot page request for the view predicates.
    fn req(view: PurgatoryView, active: i64) -> crate::profiles_query::PageRequest {
        crate::profiles_query::PageRequest {
            view,
            active_threshold: active,
            scope: crate::profiles_query::PlanScope::All,
            search: None,
            group_id: None,
            sort: crate::profiles_query::PageSort::Test,
            ascending: true,
            offset: 0,
            limit: 10_000,
        }
    }

    /// Endpoint ids in page order.
    async fn ids(db: &Database, req: &crate::profiles_query::PageRequest) -> Vec<i64> {
        db.profiles_page(req)
            .await
            .expect("page")
            .ids
            .iter()
            .map(|id| id.get())
            .collect()
    }

    /// The page's assembled rows.
    async fn rows_of(
        db: &Database,
        req: &crate::profiles_query::PageRequest,
    ) -> Vec<crate::models_toasty::EndpointRow> {
        let meta = db.profiles_page(req).await.expect("page");
        db.load_page_rows(&meta.ids, true).await.expect("rows")
    }

    async fn seed_endpoint(
        conn: &mut toasty::Connection,
        endpoint_id: i64,
        protocol_id: i64,
        host: &str,
        host_type: HostType,
        port: u16,
        last_seen: i64,
    ) {
        toasty::create!(Endpoint {
            created_at: 0,
            id: EndpointId::new(endpoint_id),
            domain: Endpoint::derive_domain(host, host_type).0,
            sub_domain: Endpoint::derive_domain(host, host_type).1,
            port,
            ports: Vec::<u16>::new(),
        })
        .exec(conn)
        .await
        .expect("create endpoint");
        seed_link(conn, endpoint_id, protocol_id, last_seen).await;
    }

    /// Insert one additional protocol + link for an existing endpoint.
    async fn seed_link(
        conn: &mut toasty::Connection,
        endpoint_id: i64,
        protocol_id: i64,
        last_seen: i64,
    ) {
        toasty::create!(Protocol {
            created_at: 0,
            id: ProtocolId::new(protocol_id),
            sig: protocol_id,
            proto_kind: ProtocolKind::Vless,
            transport: tcp_transport(),
            security: no_security(),
            config: Deferred::from(Json(vless_config())),
        })
        .exec(conn)
        .await
        .expect("create protocol");

        toasty::create!(ProfileStats {
            created_at: 0,
            updated_at: 0,
            protocol_id: ProtocolId::new(protocol_id),
            endpoint_id: EndpointId::new(endpoint_id),
            last_seen_at: ts(last_seen),
            stab_mask: 0,
            stab_len: 0,
            traffic: zero_traffic(),
            latency: Latency::default(),
        })
        .exec(conn)
        .await
        .expect("create link");
    }

    /// S6: the page counts endpoints; this counts SERVERS. Two links behind
    /// one exit IP are one server, and a blank IP is not a server at all.
    #[tokio::test]
    async fn distinct_exit_ips_counts_servers_not_links() {
        let db = Database::in_memory().await.expect("in-memory db");
        let mut conn = db.connection().await.expect("connection");
        let now = crate::models_toasty::now_epoch();
        for (ep, pid, ip) in [
            (1, 1001, "203.0.113.7"),
            (2, 1002, "203.0.113.7"),
            (3, 1003, "198.51.100.9"),
            (4, 1004, ""),
        ] {
            seed_endpoint(
                &mut conn,
                ep,
                pid,
                &format!("10.0.1.{ep}"),
                HostType::Ipv4,
                443,
                now,
            )
            .await;
            toasty::sql::query(format!(
                "UPDATE profile_stats SET latency_ip = '{ip}' WHERE endpoint_id = {ep}"
            ))
            .exec(&mut conn)
            .await
            .expect("seed exit ip");
        }
        assert_eq!(
            db.distinct_exit_ips().await.expect("count"),
            2,
            "two distinct addresses, however many links name them"
        );
    }

    /// A capability upgrade invalidates the persisted "not testable" verdict
    /// once: the marker gates the clear, an ordinary failure and a purge
    /// verdict survive, and the same revision does not re-clear a fresh marker.
    #[tokio::test]
    async fn stale_capability_verdicts_clear_once() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("capability.db");
        let now = crate::models_toasty::now_epoch();
        {
            let db = Database::open(&path).await.expect("fresh open");
            let mut conn = db.connection().await.expect("connection");
            for (ep, pid) in [(1, 1001), (2, 2001), (3, 3001)] {
                toasty::create!(Endpoint {
                    created_at: 0,
                    id: EndpointId::new(ep),
                    domain: Endpoint::derive_domain(&format!("10.0.3.{ep}"), HostType::Ipv4).0,
                    sub_domain: Endpoint::derive_domain(&format!("10.0.3.{ep}"), HostType::Ipv4).1,
                    port: 443,
                    ports: Vec::<u16>::new(),
                })
                .exec(&mut conn)
                .await
                .expect("create endpoint");
                toasty::create!(Protocol {
                    created_at: 0,
                    id: ProtocolId::new(pid),
                    sig: pid,
                    proto_kind: ProtocolKind::Vless,
                    transport: tcp_transport(),
                    security: no_security(),
                    config: Deferred::from(Json(
                        serde_json::from_value(serde_json::json!({
                            "schema": "Vless",
                            "uuid": "6202b230-417c-4d8e-b624-0f71afa9c75d",
                            "transport": {"type": "tcp"}
                        }))
                        .expect("config"),
                    )),
                })
                .exec(&mut conn)
                .await
                .expect("create protocol");
                toasty::create!(ProfileStats {
                    created_at: 0,
                    updated_at: 0,
                    protocol_id: ProtocolId::new(pid),
                    endpoint_id: EndpointId::new(ep),
                    last_seen_at: ts(now),
                    stab_mask: 0,
                    stab_len: 0,
                    traffic: zero_traffic(),
                    latency: Latency::default(),
                })
                .exec(&mut conn)
                .await
                .expect("create link");
            }
            for (ep, text, purge) in [
                (
                    1,
                    "not testable by the native engine: old gap",
                    None::<&str>,
                ),
                (
                    2,
                    "not testable by the native engine: old gap",
                    Some("config_invalid"),
                ),
                (3, "transport error: ws: 500", None),
            ] {
                let purge_sql = purge.map_or_else(|| "NULL".to_owned(), sql_lit);
                toasty::sql::query(format!(
                    "UPDATE profile_stats SET error = 1, error_kind = 'real', \
                     error_text = {}, purge_reason = {purge_sql} WHERE endpoint_id = {ep}",
                    sql_lit(text)
                ))
                .exec(&mut conn)
                .await
                .expect("seed verdict");
            }
        }

        let db = Database::open(&path).await.expect("reopen");
        db.clear_stale_capability_verdicts(1).await.expect("clear");
        let mut conn = db.connection().await.expect("connection");
        let texts = capability_texts(&mut conn).await;
        assert_eq!(texts[&1], None, "the stale marker must be cleared");
        let rows = toasty::sql::query(
            "SELECT error, error_kind, error_text, error_stage, error_cause \
             FROM profile_stats WHERE endpoint_id = 1",
        )
        .exec(&mut conn)
        .await
        .expect("read cleared columns");
        for row in &rows {
            let toasty_core::stmt::Value::Record(f) = row else {
                continue;
            };
            for (i, value) in f.iter().take(5).enumerate() {
                assert!(
                    matches!(value, toasty_core::stmt::Value::Null),
                    "cleared column {i} must be NULL, got {value:?}"
                );
            }
        }
        assert_eq!(
            texts[&2].as_deref(),
            Some("not testable by the native engine: old gap"),
            "a purge verdict outranks the capability marker"
        );
        assert_eq!(
            texts[&3].as_deref(),
            Some("transport error: ws: 500"),
            "a real failure is not a capability verdict"
        );
        let rows =
            toasty::sql::query("SELECT value FROM app_meta WHERE key = 'capability_version'")
                .exec(&mut conn)
                .await
                .expect("marker");
        let mut marker: Option<String> = None;
        for row in &rows {
            if let toasty_core::stmt::Value::Record(f) = row
                && let Some(toasty_core::stmt::Value::String(v)) = f.first()
            {
                marker = Some(v.clone());
            }
        }
        assert_eq!(marker.as_deref(), Some("1"));

        // The marker gates a second run: a marker written after the upgrade is
        // a current verdict, not a stale one.
        toasty::sql::query(
            "UPDATE profile_stats SET error = 1, error_kind = 'real', \
             error_text = 'not testable by the native engine: later' WHERE endpoint_id = 1",
        )
        .exec(&mut conn)
        .await
        .expect("seed post-upgrade marker");
        drop(conn);
        db.clear_stale_capability_verdicts(1)
            .await
            .expect("second clear");
        let mut conn = db.connection().await.expect("connection");
        assert_eq!(
            capability_texts(&mut conn).await[&1].as_deref(),
            Some("not testable by the native engine: later"),
            "the same revision must not re-clear"
        );
    }

    async fn capability_texts(
        conn: &mut toasty::Connection,
    ) -> std::collections::BTreeMap<i64, Option<String>> {
        let rows = toasty::sql::query(
            "SELECT endpoint_id, error_text FROM profile_stats ORDER BY endpoint_id",
        )
        .exec(conn)
        .await
        .expect("read verdicts");
        let mut out = std::collections::BTreeMap::new();
        for row in &rows {
            let toasty_core::stmt::Value::Record(f) = row else {
                continue;
            };
            let Some(toasty_core::stmt::Value::I64(id)) = f.first() else {
                continue;
            };
            out.insert(
                *id,
                match f.get(1) {
                    Some(toasty_core::stmt::Value::String(s)) => Some(s.clone()),
                    _ => None,
                },
            );
        }
        out
    }

    /// S5: the stored shapes no codec can dial get `config_invalid` exactly
    /// once, through the same predicate the ingest gate uses, and a valid row
    /// keeps its NULL verdict.
    #[tokio::test]
    async fn invalid_shapes_are_retired_once() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("shapes.db");
        let now = crate::models_toasty::now_epoch();
        {
            let db = Database::open(&path).await.expect("fresh open");
            let mut conn = db.connection().await.expect("connection");
            for (ep, pid, config) in [
                // VLESS flow with no TLS/REALITY layer: undialable.
                (
                    1,
                    1001,
                    serde_json::json!({"schema": "Vless", "uuid": "6202b230-417c-4d8e-b624-0f71afa9c75d", "transport": {"type": "tcp"}, "flow": "xtls-rprx-direct"}),
                ),
                // `ss` "method" that is not a cipher: undialable.
                (
                    2,
                    2001,
                    serde_json::json!({"schema": "Ss", "method": "null", "password": "null"}),
                ),
                // Plain VLESS: valid, must stay live.
                (
                    3,
                    3001,
                    serde_json::json!({"schema": "Vless", "uuid": "6202b230-417c-4d8e-b624-0f71afa9c75d", "transport": {"type": "tcp"}}),
                ),
                // A transport host no HTTP request can carry (audit §D3).
                (
                    4,
                    4001,
                    serde_json::json!({"schema": "Vless", "uuid": "6202b230-417c-4d8e-b624-0f71afa9c75d", "transport": {"type": "ws", "host": "RFDJCK.سیسی.wOrLd"}}),
                ),
                // A space PATH is dialable (the request builder encodes it):
                // it must NOT take the config_invalid verdict.
                (
                    5,
                    5001,
                    serde_json::json!({"schema": "Vless", "uuid": "6202b230-417c-4d8e-b624-0f71afa9c75d", "transport": {"type": "ws", "path": "/?ed=2560 PuLaFreeBOT", "host": "example.com"}}),
                ),
                // Hysteria2 with an unknown obfs name: nothing dials it.
                (
                    6,
                    6001,
                    serde_json::json!({"schema": "Hysteria2", "auth": "pw", "obfs": "xplus", "obfs_password": "obfs-secret"}),
                ),
                // Gecko with a valid password (and repaired default sizes):
                // dialable, must stay live.
                (
                    7,
                    7001,
                    serde_json::json!({"schema": "Hysteria2", "auth": "pw", "obfs": "gecko", "obfs_password": "gecko-secret", "obfs_min_packet_size": 2000, "obfs_max_packet_size": 1}),
                ),
            ] {
                // The endpoint only: this fixture owns the protocol row (it
                // carries the shape under test), so `seed_endpoint` would
                // create a second protocol with the same id.
                toasty::create!(Endpoint {
                    created_at: 0,
                    id: EndpointId::new(ep),
                    domain: Endpoint::derive_domain(&format!("10.0.2.{ep}"), HostType::Ipv4).0,
                    sub_domain: Endpoint::derive_domain(&format!("10.0.2.{ep}"), HostType::Ipv4).1,
                    port: 443,
                    ports: Vec::<u16>::new(),
                })
                .exec(&mut conn)
                .await
                .expect("create endpoint");
                toasty::create!(Protocol {
                    created_at: 0,
                    id: ProtocolId::new(pid),
                    sig: pid,
                    proto_kind: match config["schema"].as_str() {
                        Some("Ss") => ProtocolKind::Shadowsocks,
                        Some("Hysteria2") => ProtocolKind::Hysteria2,
                        _ => ProtocolKind::Vless,
                    },
                    transport: tcp_transport(),
                    security: no_security(),
                    config: Deferred::from(Json(serde_json::from_value(config).expect("config"))),
                })
                .exec(&mut conn)
                .await
                .expect("create protocol");
                toasty::create!(ProfileStats {
                    created_at: 0,
                    updated_at: 0,
                    protocol_id: ProtocolId::new(pid),
                    endpoint_id: EndpointId::new(ep),
                    last_seen_at: ts(now),
                    stab_mask: 0,
                    stab_len: 0,
                    traffic: zero_traffic(),
                    latency: Latency::default(),
                })
                .exec(&mut conn)
                .await
                .expect("create link");
            }
        }

        // Model "rows imported before this build": the first open stamped the
        // step (no rows existed yet), so clear the marker and reopen.
        {
            let db = Database::open(&path).await.expect("seed-state open");
            let mut conn = db.connection().await.expect("connection");
            // An existing DB from before the Hysteria2 obfs rule: stamped 2.
            // The step must treat it as stale and re-scan.
            toasty::sql::query(
                "INSERT INTO app_meta (key, value) VALUES ('invalid_shapes_purged', '2') \
                 ON CONFLICT(key) DO UPDATE SET value = '2'",
            )
            .exec(&mut conn)
            .await
            .expect("seed stale marker");
        }

        // Reopen: the one-time step runs and stamps.
        let db = Database::open(&path).await.expect("migrating reopen");
        let mut conn = db.connection().await.expect("connection");
        for (ep, want) in [
            (1, Some("config_invalid")),
            (2, Some("config_invalid")),
            (3, None),
            (4, Some("config_invalid")),
            (5, None),
            (6, Some("config_invalid")),
            (7, None),
        ] {
            let rows = toasty::sql::query(
                "SELECT endpoint_id, purge_reason FROM profile_stats ORDER BY endpoint_id",
            )
            .exec(&mut conn)
            .await
            .expect("read verdicts");
            let mut got: Option<String> = None;
            for row in &rows {
                let toasty_core::stmt::Value::Record(f) = row else {
                    continue;
                };
                if let (Some(toasty_core::stmt::Value::I64(id)), kind) = (f.first(), f.get(1))
                    && *id == ep
                {
                    got = match kind {
                        Some(toasty_core::stmt::Value::String(s)) => Some(s.clone()),
                        _ => None,
                    };
                }
            }
            assert_eq!(
                got.as_deref(),
                want,
                "endpoint {ep}: the invalid-shape verdict"
            );
        }
        drop(conn);

        // Second open: the marker makes it a no-op (re-stamp, no rewrite).
        let db = Database::open(&path).await.expect("second reopen");
        let mut conn = db.connection().await.expect("connection");
        let rows =
            toasty::sql::query("SELECT value FROM app_meta WHERE key = 'invalid_shapes_purged'")
                .exec(&mut conn)
                .await
                .expect("marker");
        let stamped = rows.first().and_then(|row| {
            let toasty_core::stmt::Value::Record(f) = row else {
                return None;
            };
            match f.first() {
                Some(toasty_core::stmt::Value::String(s)) => Some(s.clone()),
                _ => None,
            }
        });
        assert_eq!(
            stamped.as_deref(),
            Some("3"),
            "the step stamps the version that makes a second open a no-op"
        );
    }

    /// S4: a resolved host drops its name-class marker, and ONLY that. A real
    /// marker and a purge verdict are statements about the config, not about
    /// DNS, so they stay exactly as they were.
    #[tokio::test]
    async fn clearing_name_markers_leaves_real_markers_and_purges_alone() {
        let db = Database::in_memory().await.expect("in-memory db");
        let mut conn = db.connection().await.expect("connection");
        let now = crate::models_toasty::now_epoch();
        for (ep, pid) in [(1, 1001), (2, 1002), (3, 1003)] {
            seed_endpoint(
                &mut conn,
                ep,
                pid,
                &format!("10.0.0.{ep}"),
                HostType::Ipv4,
                443,
                now,
            )
            .await;
        }
        // One name marker, one real marker, one name marker on a purged row.
        for (ep, kind, purge) in [
            (1, "name", None),
            (2, "real", None),
            (3, "name", Some("config_invalid")),
        ] {
            toasty::sql::query(format!(
                "UPDATE profile_stats SET error = 1, error_kind = '{kind}', \
                 error_text = 'marker', purge_reason = {} WHERE endpoint_id = {ep}",
                purge.map_or_else(|| "NULL".to_string(), |r| format!("'{r}'"))
            ))
            .exec(&mut conn)
            .await
            .expect("seed marker");
        }

        let ids = [EndpointId::new(1), EndpointId::new(2), EndpointId::new(3)];
        db.clear_name_markers(&ids).await.expect("clear");

        // A purged row's name marker is cleared too: the marker is a DNS
        // statement, the verdict is the retirement. What must survive on row 3
        // is `purge_reason`, asserted below.
        for (ep, want_kind) in [(1, None), (2, Some("real")), (3, None)] {
            let rows = toasty::sql::query(format!(
                "SELECT error_kind FROM profile_stats WHERE endpoint_id = {ep}"
            ))
            .exec(&mut conn)
            .await
            .expect("read back");
            let got = rows.first().and_then(|v| match v {
                toasty_core::stmt::Value::Record(record) => record.fields.first(),
                _ => None,
            });
            match want_kind {
                None => assert!(
                    matches!(got, Some(toasty_core::stmt::Value::Null) | None),
                    "endpoint {ep}: a resolved name must clear the marker"
                ),
                Some(kind) => assert_eq!(
                    got,
                    Some(&toasty_core::stmt::Value::String(kind.to_string())),
                    "endpoint {ep}: the {kind} marker must stay"
                ),
            }
        }
        // The purged row keeps its verdict.
        let rows =
            toasty::sql::query("SELECT purge_reason FROM profile_stats WHERE endpoint_id = 3")
                .exec(&mut conn)
                .await
                .expect("read purge");
        assert!(
            matches!(
                rows.first().and_then(|v| match v {
                    toasty_core::stmt::Value::Record(record) => record.fields.first(),
                    _ => None,
                }),
                Some(toasty_core::stmt::Value::String(reason)) if reason == "config_invalid"
            ),
            "a verdict is not DNS-derived and must survive the clear"
        );
    }

    #[tokio::test]
    async fn active_and_stale_windows() {
        let db = Database::in_memory().await.expect("in-memory db");
        let mut conn = db.connection().await.expect("connection");
        // Band membership is materialized against `now − ttl` (default 7d) at
        // refresh time, so the fixture uses real-clock-relative timestamps: one
        // fresh endpoint and one older than the ttl.
        let now = crate::models_toasty::now_epoch();
        seed_endpoint(&mut conn, 1, 1001, "5.6.7.8", HostType::Ipv4, 443, now).await;
        seed_endpoint(
            &mut conn,
            2,
            2001,
            "9.10.11.12",
            HostType::Ipv4,
            80,
            now - 8 * 86_400,
        )
        .await;

        // The fixture seeded with raw writes: make the stored keys follow.
        db.repair_endpoint_ranks().await.expect("ranks");

        // Active: only the fresh endpoint (the `active` arg is now advisory —
        // membership is the stored `band`).
        let active = req(PurgatoryView::Active, now - 7 * 86_400);
        assert_eq!(ids(&db, &active).await, vec![1]);

        // Stale: only the older-than-ttl endpoint.
        let stale = req(PurgatoryView::Purgatory, now - 7 * 86_400);
        assert_eq!(ids(&db, &stale).await, vec![2]);

        // Count matches the stale view.
        assert_eq!(db.profiles_page(&stale).await.expect("count").total, 1);
    }

    #[tokio::test]
    async fn rows_are_assembled_with_links_and_protocols() {
        let db = Database::in_memory().await.expect("in-memory db");
        let mut conn = db.connection().await.expect("connection");
        seed_endpoint(&mut conn, 1, 1001, "1.2.3.4", HostType::Ipv4, 443, 10).await;
        seed_link(&mut conn, 1, 1002, 20).await;

        // The fixture seeded with raw writes: make the stored keys follow.
        db.repair_endpoint_ranks().await.expect("ranks");

        let rows = rows_of(&db, &req(PurgatoryView::All, ts(0))).await;
        assert_eq!(rows.len(), 1);
        let row = &rows[0];
        assert_eq!(row.endpoint.id, EndpointId::new(1));
        assert_eq!(row.links.len(), 2, "both links present");
        assert_eq!(row.protocols.len(), 2, "protocols map built from links");
        assert!(
            row.protocols.contains_key(&ProtocolId::new(1001)),
            "protocol 1001 included"
        );
        assert!(
            row.protocols.contains_key(&ProtocolId::new(1002)),
            "protocol 1002 included"
        );
        // Newest link first (untested tier, recency order).
        assert_eq!(row.links[0].protocol_id, ProtocolId::new(1002));
        assert_eq!(row.links[1].protocol_id, ProtocolId::new(1001));

        // active_protocol resolves through the map.
        let (link, proto) = row.active_protocol().expect("active protocol");
        assert_eq!(link.protocol_id, ProtocolId::new(1002));
        assert_eq!(proto.proto_kind, ProtocolKind::Vless);
    }

    #[tokio::test]
    async fn group_filter_and_links() {
        let db = Database::in_memory().await.expect("in-memory db");
        let mut conn = db.connection().await.expect("connection");
        seed_endpoint(&mut conn, 1, 1001, "192.168.1.1", HostType::Ipv4, 8080, 100).await;

        // Link endpoint 1 to two groups.
        toasty::create!(EndpointGroup {
            endpoint_id: EndpointId::new(1),
            group_id: "source-a".to_string(),
            last_seen_at: ts(100),
        })
        .exec(&mut conn)
        .await
        .expect("link group a");
        toasty::create!(EndpointGroup {
            endpoint_id: EndpointId::new(1),
            group_id: "source-b".to_string(),
            last_seen_at: ts(100),
        })
        .exec(&mut conn)
        .await
        .expect("link group b");

        let group = |id: &str| crate::profiles_query::PageRequest {
            group_id: Some(id.to_string()),
            ..req(PurgatoryView::All, ts(0))
        };
        // The fixture seeded with raw writes: make the stored keys follow.
        db.repair_endpoint_ranks().await.expect("ranks");
        assert_eq!(ids(&db, &group("source-a")).await, vec![1]);
        assert_eq!(ids(&db, &group("source-b")).await, vec![1]);
        assert!(
            ids(&db, &group("source-c")).await.is_empty(),
            "unlinked group matches nothing"
        );
    }

    #[tokio::test]
    async fn get_endpoint_by_id_and_protocol() {
        let db = Database::in_memory().await.expect("in-memory db");
        let mut conn = db.connection().await.expect("connection");
        seed_endpoint(&mut conn, 7, 3001, "10.0.0.1", HostType::Ipv4, 53, 100).await;

        let row = db.get_endpoint(EndpointId::new(7)).await.expect("get");
        assert!(
            row.as_ref().expect("row").endpoint.domain.is_empty(),
            "a literal IP host has no domain"
        );
        assert_eq!(row.unwrap().links.len(), 1);

        let by_proto = db
            .get_endpoint_by_protocol_id(ProtocolId::new(3001))
            .await
            .expect("by protocol");
        assert_eq!(by_proto.expect("row").endpoint.id, EndpointId::new(7));

        assert!(
            db.get_endpoint(EndpointId::new(999))
                .await
                .expect("missing")
                .is_none()
        );
        assert!(
            db.get_endpoint_by_protocol_id(ProtocolId::new(9999))
                .await
                .expect("missing")
                .is_none()
        );
    }

    /// A DNS endpoint the PROBE REACHED is not "unresolved" — the probe
    /// dials the name and the OS resolves it, without persisting the
    /// resolution. So a measured link on a DNS host with no address rows keeps
    /// its MEASUREMENT's band.
    ///
    /// Before the correction the band said 15 ("DNS unresolved") for such a
    /// link — and band 15 sits BELOW every real-error band (13), so a working
    /// server sorted below the failures. That is the ordering law inverted,
    /// and it is what the 2026-10-22 report saw.
    #[tokio::test]
    async fn a_measured_dns_link_is_not_sunk_to_the_dns_band() {
        let db = Database::in_memory().await.expect("in-memory db");
        let mut conn = db.connection().await.expect("connection");

        toasty::create!(Endpoint {
            created_at: 0,
            id: EndpointId::new(1),
            domain: Endpoint::derive_domain("unresolved.example", HostType::Dns).0,
            sub_domain: Endpoint::derive_domain("unresolved.example", HostType::Dns).1,
            port: 443,
            ports: Vec::<u16>::new(),
            // no address rows -> the address set is empty
        })
        .exec(&mut conn)
        .await
        .expect("endpoint");

        for (pid, last_seen) in [(1001, 1), (1002, 2)] {
            toasty::create!(Protocol {
                created_at: 0,
                id: ProtocolId::new(pid),
                sig: pid,
                proto_kind: ProtocolKind::Vless,
                transport: tcp_transport(),
                security: no_security(),
                config: Deferred::from(Json(vless_config())),
            })
            .exec(&mut conn)
            .await
            .expect("protocol");
            toasty::create!(ProfileStats {
                created_at: 0,
                updated_at: 0,
                protocol_id: ProtocolId::new(pid),
                endpoint_id: EndpointId::new(1),
                last_seen_at: ts(last_seen),
                latency: Latency::real_with_ip(10, None),
                stab_mask: 0,
                stab_len: 0,
                traffic: zero_traffic(),
            })
            .exec(&mut conn)
            .await
            .expect("link");
        }

        // The fixture seeded with raw writes: make the stored keys follow.
        db.repair_endpoint_ranks().await.expect("ranks");

        let rows = rows_of(&db, &req(PurgatoryView::All, ts(0))).await;
        let row = &rows[0];
        // The MEASURED links keep the real bands (0..=5): a 10 ms real delay
        // is bin 0. Recency decides between the two.
        assert_eq!(row.links[0].protocol_id, ProtocolId::new(1002));
        assert_eq!(row.links[1].protocol_id, ProtocolId::new(1001));
        assert_eq!(
            row.best_test_priority_key(true).unwrap().0,
            0,
            "a measured DNS link keeps its real band — it is not 'unresolved'"
        );
    }

    #[tokio::test]
    async fn open_reopen_preserves_data() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("reopen.db");

        let db = Database::open(&path).await.expect("open");
        let mut conn = db.connection().await.expect("connection");
        toasty::create!(Endpoint {
            created_at: 0,
            id: EndpointId::new(77),
            domain: Endpoint::derive_domain("1.1.1.1", HostType::Ipv4).0,
            sub_domain: Endpoint::derive_domain("1.1.1.1", HostType::Ipv4).1,
            port: 443,
            ports: Vec::<u16>::new(),
        })
        .exec(&mut conn)
        .await
        .expect("create endpoint");
        drop(conn);
        drop(db);

        // Reopen must NOT wipe: the schema tag skips push_schema.
        let db2 = Database::open(&path).await.expect("reopen");
        let mut conn = db2.connection().await.expect("connection");
        let endpoint = Endpoint::filter_by_id(EndpointId::new(77))
            .first()
            .exec(&mut conn)
            .await
            .expect("read");
        assert_eq!(endpoint.expect("endpoint").domain, "");
    }

    /// A file the engine cannot open must NOT be deleted.
    ///
    /// The old recovery branch wiped and recreated the file on ANY open
    /// failure, which destroyed a live 12 MB feed when a second instance
    /// opened it (2026-11-10 incident). The only wipe left is the explicit
    /// incompatible-schema verdict; a corrupt file must surface as an error
    /// with its bytes intact.
    #[tokio::test]
    async fn a_failed_open_leaves_the_file_untouched() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("garbage.db");
        let garbage = b"this is not a sqlite database".to_vec();
        std::fs::write(&path, &garbage).expect("write garbage");

        let opened = Database::open(&path).await;
        assert!(opened.is_err(), "a corrupt file must fail to open");
        drop(opened);

        assert_eq!(
            std::fs::read(&path).expect("read back"),
            garbage,
            "a failed open must leave the file bytes untouched"
        );
    }

    #[tokio::test]
    async fn open_recreates_incompatible_schema() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("pre8.db");

        // Build a database with a pre-T8 `endpoints` table (old 9-table
        // shape) — push_schema cannot run on it.
        {
            let driver = crate::driver::Turso::file(&path);
            let db = toasty::Db::builder()
                .models(toasty::models!(ScratchOnly))
                .build(driver)
                .await
                .expect("build db");
            db.push_schema().await.expect("push schema");
            let mut conn = db.connection().await.expect("connection");
            toasty::sql::statement("CREATE TABLE endpoints (id INTEGER PRIMARY KEY, host TEXT)")
                .exec(&mut conn)
                .await
                .expect("old endpoints table");
        }

        let db = Database::open(&path).await.expect("open recreates schema");
        let mut conn = db.connection().await.expect("connection");
        let rows = toasty::sql::query(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'profile_stats'",
        )
        .exec(&mut conn)
        .await
        .expect("check new table");
        assert_eq!(
            first_i64(&rows).expect("count"),
            1,
            "open() must recreate with the 7-table schema"
        );
    }
    /// Create a database file already in WAL mode, tagged with the CURRENT
    /// schema version so the reopen under test takes the "existing WAL file"
    /// path rather than the wipe path. A hardcoded older tag turns this into a
    /// different test the moment the tag moves — which is exactly what happened
    /// when it was pinned to 13.
    ///
    /// Its own function so the connection and the database are released on
    /// return: the reopen below needs the file free, and the caller reads far
    /// more naturally than an inline scope.
    ///
    /// `significant_drop_tightening` is silenced here rather than obeyed: it
    /// reports the `driver` temporary as "dropped at the end of its contained
    /// scope", but `driver` is MOVED into `try_open_db` and no such temporary
    /// survives — and both handles are already dropped explicitly on the last
    /// two lines, which is the whole of the lint's intent.
    #[allow(clippy::significant_drop_tightening)]
    async fn seed_wal_file(path: &std::path::Path) {
        let driver = crate::driver::Turso::file(path);
        let db = Database::try_open_db(driver).await.expect("initial db");
        db.push_schema().await.expect("initial schema");
        let mut conn = db.connection().await.expect("initial connection");
        toasty::sql::query("PRAGMA journal_mode='wal'")
            .exec(&mut conn)
            .await
            .expect("set WAL");
        toasty::sql::query(format!("PRAGMA user_version = {SCHEMA_VERSION}"))
            .exec(&mut conn)
            .await
            .expect("set schema tag");
        // The caller reopens this path immediately, so both handles are released
        // HERE rather than wherever the compiler happens to end the function.
        drop(conn);
        drop(db);
    }

    #[tokio::test]
    async fn existing_wal_file_stays_wal_and_reopens() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("wal.db");
        seed_wal_file(&path).await;
        let db = Database::open(&path).await.expect("reopen WAL db");
        assert!(!db.uses_concurrent_writes());
        let mut conn = db.connection().await.expect("WAL connection");
        let rows = toasty::sql::query("PRAGMA journal_mode")
            .exec(&mut conn)
            .await
            .expect("read mode");
        let mode = rows.first().and_then(|value| match value {
            toasty::stmt::Value::Record(fields) => fields.first().and_then(|field| match field {
                toasty::stmt::Value::String(mode) => Some(mode.as_str()),
                _ => None,
            }),
            _ => None,
        });
        assert_eq!(mode, Some("wal"));
    }
    #[tokio::test]
    async fn mvcc_schema_wipe_removes_log_sidecar() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("mvcc-stale.db");
        {
            let db = Database::open_with_concurrent_writes(&path, true)
                .await
                .expect("initial MVCC db");
            let mut conn = db.connection().await.expect("connection");
            toasty::sql::query("PRAGMA user_version=8")
                .exec(&mut conn)
                .await
                .expect("set stale tag");
        }
        let db = Database::open_with_concurrent_writes(&path, true)
            .await
            .expect("recreate MVCC db");
        assert!(db.uses_concurrent_writes());
    }

    #[derive(Debug, toasty::Model)]
    struct ScratchOnly {
        #[key]
        id: i64,
    }

    #[tokio::test]
    async fn groups_due_update_respects_refresh_interval() {
        let db = Database::in_memory().await.expect("in-memory db");
        let mut conn = db.connection().await.expect("connection");
        let now = jiff::Timestamp::now();
        let hour_ago = now
            .checked_sub(jiff::Span::new().hours(1))
            .expect("subtract");

        // Due: never refreshed.
        toasty::create!(Group {
            id: "g-never".to_string(),
            name: Some("never".to_string()),
            url: Some("https://example.com/sub".to_string()),
            enabled: true,
        })
        .exec(&mut conn)
        .await
        .expect("group");

        // Due: refreshed 1h ago with a 30-minute interval (default is 1440).
        toasty::create!(Group {
            id: "g-due".to_string(),
            name: Some("due".to_string()),
            url: Some("https://example.com/sub2".to_string()),
            enabled: true,
            refresh_interval: Some(30),
            last_refreshed: Some(hour_ago.as_second()),
        })
        .exec(&mut conn)
        .await
        .expect("group");

        // Not due: refreshed now.
        toasty::create!(Group {
            id: "g-fresh".to_string(),
            name: Some("fresh".to_string()),
            url: Some("https://example.com/sub3".to_string()),
            enabled: true,
            last_refreshed: Some(now.as_second()),
        })
        .exec(&mut conn)
        .await
        .expect("group");

        // Not due: disabled.
        toasty::create!(Group {
            id: "g-off".to_string(),
            name: Some("off".to_string()),
            url: Some("https://example.com/sub4".to_string()),
            enabled: false,
        })
        .exec(&mut conn)
        .await
        .expect("group");

        // Not due: no url.
        toasty::create!(Group {
            id: "g-nourl".to_string(),
            name: Some("nourl".to_string()),
            url: None,
            enabled: true,
        })
        .exec(&mut conn)
        .await
        .expect("group");

        let due = db.get_groups_due_update().await.expect("due");
        let mut due_ids: Vec<&str> = due.iter().map(|g| g.id.as_str()).collect();
        due_ids.sort_unstable();
        assert_eq!(due_ids, vec!["g-due", "g-never"]);
    }

    #[tokio::test]
    async fn dns_settings_and_routing_rules_roundtrip() {
        let db = Database::in_memory().await.expect("in-memory db");
        let mut conn = db.connection().await.expect("connection");

        assert!(db.get_dns_settings().await.expect("empty").is_none());

        toasty::create!(DnsSetting {
            id: "dns-1".to_string(),
            name: Some("main".to_string()),
            servers: ["1.1.1.1".to_string()],
            hosts: Vec::<String>::new(),
            disable_cache: true,
            disable_fallback: false,
        })
        .exec(&mut conn)
        .await
        .expect("dns setting");

        let dns = db.get_dns_settings().await.expect("dns").expect("row");
        assert_eq!(dns.servers, vec!["1.1.1.1".to_string()]);
        assert!(dns.disable_cache);

        toasty::create!(RoutingRule {
            id: "rule-1".to_string(),
            r#type: 0,
            domains: ["example.com".to_string()],
            ips: Vec::<String>::new(),
            inbound_tags: Vec::<String>::new(),
            ports: [443],
            source_ports: Vec::<u16>::new(),
            protocols: Vec::<String>::new(),
            sort_order: Some(2),
        })
        .exec(&mut conn)
        .await
        .expect("routing rule");

        let rules = db.get_all_routing_rules().await.expect("rules");
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].domains, vec!["example.com".to_string()]);
        assert_eq!(rules[0].ports, vec![443]);
    }

    #[tokio::test]
    async fn route_probes_roundtrip_and_dedupe() {
        let db = Database::in_memory().await.expect("in-memory db");

        // Absent row ⇒ empty vec, not an error.
        assert_eq!(db.get_route_probes().await.expect("absent").len(), 0);

        // Create path: case-insensitive dedupe keeps the first spelling.
        db.upsert_route_probes(vec![
            "A.example.com".to_string(),
            "b.Example.com".to_string(),
            "a.EXAMPLE.com".to_string(),
        ])
        .await
        .expect("upsert create");
        assert_eq!(
            db.get_route_probes().await.expect("probes"),
            vec!["A.example.com".to_string(), "b.Example.com".to_string(),],
            "deduped case-insensitively, first spelling kept"
        );

        // Update path: wholesale replacement of the singleton row.
        db.upsert_route_probes(vec!["c.example.com".to_string()])
            .await
            .expect("upsert update");
        assert_eq!(
            db.get_route_probes().await.expect("probes"),
            vec!["c.example.com".to_string()],
        );

        // Singleton: both upserts hit the same row.
        let mut conn = db.connection().await.expect("connection");
        let count = RouteProbes::all()
            .count()
            .exec(&mut conn)
            .await
            .expect("count");
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn route_probes_survive_reopen_via_schema_tag() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("probes.db");

        let db = Database::open(&path).await.expect("open");
        db.upsert_route_probes(vec!["probe.example.com".to_string()])
            .await
            .expect("upsert");
        drop(db);

        // Reopen must NOT wipe (schema tag skips push_schema).
        let db2 = Database::open(&path).await.expect("reopen");
        assert_eq!(
            db2.get_route_probes().await.expect("probes"),
            vec!["probe.example.com".to_string()],
        );
    }

    /// `EndpointRow.active_link` respects a manual protocol override.
    #[tokio::test]
    async fn manual_override_shapes_active_link() {
        let db = Database::in_memory().await.expect("in-memory db");
        let mut conn = db.connection().await.expect("connection");
        seed_endpoint(&mut conn, 1, 1001, "10.10.10.10", HostType::Ipv4, 53, 10).await;
        seed_link(&mut conn, 1, 1002, 20).await;

        let row = db.get_endpoint(EndpointId::new(1)).await.expect("row");
        let mut row = row.expect("row");
        assert_eq!(
            row.active_link().unwrap().protocol_id,
            ProtocolId::new(1002)
        );

        row.endpoint.manual_protocol_override = Some(ProtocolId::new(1001));
        assert_eq!(
            row.active_link().unwrap().protocol_id,
            ProtocolId::new(1001)
        );

        // Override pointing at a missing protocol falls back to selection.
        row.endpoint.manual_protocol_override = Some(ProtocolId::new(999));
        assert_eq!(
            row.active_link().unwrap().protocol_id,
            ProtocolId::new(1002)
        );
    }

    // ── Typed writes (Task 10) ───────────────────────────────────────────

    /// An address literal, for the tests' write arguments.
    fn ip(text: &str) -> std::net::IpAddr {
        text.parse().expect("test address")
    }

    /// An endpoint's stored addresses, in the table's key order.
    async fn stored_ips(conn: &mut toasty::Connection, id: i64) -> Vec<std::net::IpAddr> {
        let mut rows = crate::endpoint_ip::load(conn, &[EndpointId::new(id)])
            .await
            .expect("read addresses");
        rows.remove(&EndpointId::new(id)).unwrap_or_default()
    }

    /// A full `Endpoint` struct for the typed write methods.
    fn endpoint_struct(id: i64, host: &str, host_type: HostType, port: u16) -> Endpoint {
        Endpoint {
            id: EndpointId::new(id),
            domain: Endpoint::derive_domain(host, host_type).0,
            sub_domain: Endpoint::derive_domain(host, host_type).1,
            port,
            ports: Vec::new(),
            last_source: None,
            manual_protocol_override: None,
            resolved_at: None,
            created_at: ts(0),
            links: Deferred::default(),
            group_links: Deferred::default(),
        }
    }

    /// A full `ProfileStats` struct for the typed write methods.
    fn link_struct(protocol_id: i64, endpoint_id: i64, last_seen: i64) -> ProfileStats {
        ProfileStats {
            protocol_id: ProtocolId::new(protocol_id),
            endpoint_id: EndpointId::new(endpoint_id),
            last_used_at: None,
            last_seen_at: ts(last_seen),
            latency: Latency::default(),
            speed_bps: None,
            error: None,
            purge_reason: None,
            stab_mask: 0,
            stab_len: 0,
            traffic: zero_traffic(),
            created_at: ts(0),
            updated_at: ts(0),
            version: 1,
            protocol: Deferred::default(),
            endpoint: Deferred::default(),
        }
    }

    /// A full, loaded `Protocol` struct (deferred JSON included) for
    /// `upsert_protocol`.
    fn protocol_struct(id: i64) -> Protocol {
        Protocol {
            id: ProtocolId::new(id),
            sig: id,
            proto_kind: ProtocolKind::Vless,
            transport: tcp_transport(),
            security: no_security(),
            config: Deferred::from(Json(vless_config())),
            created_at: ts(0),
            links: Deferred::default(),
        }
    }

    #[tokio::test]
    async fn upsert_endpoint_is_idempotent() {
        let db = Database::in_memory().await.expect("in-memory db");
        db.upsert_endpoint(&endpoint_struct(1, "a.example", HostType::Dns, 443))
            .await
            .expect("upsert");
        db.upsert_endpoint(&endpoint_struct(1, "b.example", HostType::Dns, 8443))
            .await
            .expect("upsert again");

        let mut conn = db.connection().await.expect("connection");
        let count = Endpoint::all()
            .count()
            .exec(&mut conn)
            .await
            .expect("count");
        assert_eq!(count, 1, "second upsert must not duplicate the row");

        let ep = Endpoint::filter_by_id(EndpointId::new(1))
            .first()
            .exec(&mut conn)
            .await
            .expect("read")
            .expect("row");
        assert_eq!(
            ep.domain, "b.example",
            "identity fields refresh on re-upsert"
        );
        assert_eq!(ep.port, 8443);

        // Owned state (resolution cache, manual override) survives re-upserts.
        db.update_endpoint_resolution(EndpointId::new(1), vec![ip("1.1.1.1")], ts(77))
            .await
            .expect("resolve");
        db.set_manual_override(EndpointId::new(1), Some(ProtocolId::new(99)))
            .await
            .expect("override");
        db.upsert_endpoint(&endpoint_struct(1, "9.9.9.9", HostType::Ipv4, 8443))
            .await
            .expect("upsert after resolution");
        let ep = Endpoint::filter_by_id(EndpointId::new(1))
            .first()
            .exec(&mut conn)
            .await
            .expect("read")
            .expect("row");
        assert_eq!(
            stored_ips(&mut conn, 1).await,
            vec![ip("1.1.1.1")],
            "the address set survives a re-upsert of the endpoint row"
        );
        assert_eq!(ep.resolved_at, Some(ts(77)));
        assert_eq!(
            ep.manual_protocol_override,
            Some(ProtocolId::new(99)),
            "manual override preserved"
        );
    }

    #[tokio::test]
    async fn import_refresh_preserves_result_and_traffic() {
        let db = Database::in_memory().await.expect("in-memory db");
        let mut conn = db.connection().await.expect("connection");
        db.upsert_endpoint(&endpoint_struct(1, "1.2.3.4", HostType::Ipv4, 443))
            .await
            .expect("endpoint");
        db.upsert_protocol(&protocol_struct(1001))
            .await
            .expect("protocol");

        let mut probed = link_struct(1001, 1, 100);
        probed.latency = Latency::fast(42);
        probed.error = Some(crate::models_toasty::ErrorInfo {
            stage: None,
            cause: None,
            kind: crate::models_toasty::ProfileErr::Real,
            text: "timeout on tcp dial".to_string(),
        });
        probed.traffic = TrafficStats {
            today_up: 7,
            today_down: 9,
            total_up: 11,
            total_down: 13,
        };
        db.upsert_link(&probed).await.expect("probed link");

        // A subscription refresh re-persists the link from a fresh parse: its
        // snapshot carries no measurement and zeroed counters. The refresh only
        // touches `last_seen_at` among the SOURCE columns now.
        let fresh = link_struct(1001, 1, 200);
        let mut tx = conn.transaction().await.expect("tx");
        upsert_links_bulk(&mut tx, std::slice::from_ref(&fresh))
            .await
            .expect("bulk upsert");
        tx.commit().await.expect("commit");

        let stored = ProfileStats::filter_by_protocol_id_and_endpoint_id(
            ProtocolId::new(1001),
            EndpointId::new(1),
        )
        .first()
        .exec(&mut conn)
        .await
        .expect("read")
        .expect("row");
        assert_eq!(
            stored.latency,
            Latency::fast(42),
            "a measurement survives an import refresh"
        );
        assert!(
            stored.error.is_some(),
            "a failure marker survives an import refresh"
        );
        assert_eq!(
            (
                stored.traffic.today_up,
                stored.traffic.today_down,
                stored.traffic.total_up,
                stored.traffic.total_down
            ),
            (7, 9, 11, 13),
            "traffic counters survive an import refresh"
        );
        assert_eq!(stored.last_seen_at, ts(200), "source column updates");
    }

    /// Spec S1's pair must survive the SQL seam, not just `apply_test_result`
    /// (the unit test in `ops::events` asserts the struct and never reaches
    /// SQLite — 0 of 124 392 rows carried a pair on 2026-11-20 because the
    /// shared writer's column list had no `error_stage`/`error_cause`).
    #[tokio::test]
    async fn link_upsert_persists_the_failure_pair() {
        use crate::models_toasty::{ErrorInfo, FailureCause, FailureStage, ProfileErr};

        async fn read_row(conn: &mut toasty::Connection) -> ProfileStats {
            ProfileStats::filter_by_protocol_id_and_endpoint_id(
                ProtocolId::new(1001),
                EndpointId::new(1),
            )
            .first()
            .exec(conn)
            .await
            .expect("read")
            .expect("row")
        }

        let db = Database::in_memory().await.expect("in-memory db");
        let mut conn = db.connection().await.expect("connection");
        db.upsert_endpoint(&endpoint_struct(1, "1.2.3.4", HostType::Ipv4, 443))
            .await
            .expect("endpoint");
        db.upsert_protocol(&protocol_struct(1001))
            .await
            .expect("protocol");

        let mut probed = link_struct(1001, 1, 100);
        probed.error = Some(ErrorInfo {
            kind: ProfileErr::Real,
            text: "timeout on probe attempt (limit 5s)".to_string(),
            stage: Some(FailureStage::Dial),
            cause: Some(FailureCause::Timeout),
        });
        db.upsert_link(&probed).await.expect("probed link");

        let stored = read_row(&mut conn).await;
        let marker = stored.error.as_ref().expect("marker");
        assert_eq!(marker.stage, Some(FailureStage::Dial));
        assert_eq!(marker.cause, Some(FailureCause::Timeout));

        // The patch writer's RESULT group must move the pair too: a
        // bulk-upsert-only column would be overwritten back to NULL here.
        let mut patch = stored.clone();
        patch.error = Some(ErrorInfo {
            kind: ProfileErr::Real,
            text: "HTTP error: 409 Conflict".to_string(),
            stage: Some(FailureStage::Transport),
            cause: Some(FailureCause::Status),
        });
        db.apply_link_patches(&[LinkPatch {
            link: patch,
            groups: LinkGroups::RESULT,
        }])
        .await
        .expect("patch");

        let stored = read_row(&mut conn).await;
        let marker = stored.error.as_ref().expect("marker");
        assert_eq!(marker.stage, Some(FailureStage::Transport));
        assert_eq!(marker.cause, Some(FailureCause::Status));

        // A success clears both columns with the marker.
        let mut cleared = stored.clone();
        cleared.error = None;
        db.apply_link_patches(&[LinkPatch {
            link: cleared,
            groups: LinkGroups::RESULT,
        }])
        .await
        .expect("clear");

        let stored = read_row(&mut conn).await;
        assert!(stored.error.is_none(), "the success clears the marker");
        let mut conn = db.connection().await.expect("conn");
        let rows = toasty::sql::query("SELECT error_stage, error_cause FROM profile_stats")
            .exec(&mut conn)
            .await
            .expect("raw read");
        let nulls = rows.iter().all(|row| match row {
            toasty::stmt::Value::Record(record) => record
                .fields
                .iter()
                .all(|v| matches!(v, toasty::stmt::Value::Null)),
            _ => false,
        });
        assert!(nulls, "both columns are NULL after the clear");
    }

    #[tokio::test]
    async fn import_insert_writes_the_whole_snapshot() {
        let db = Database::in_memory().await.expect("in-memory db");
        let mut conn = db.connection().await.expect("connection");
        db.upsert_endpoint(&endpoint_struct(1, "1.2.3.4", HostType::Ipv4, 443))
            .await
            .expect("endpoint");
        db.upsert_protocol(&protocol_struct(1001))
            .await
            .expect("protocol");

        let mut snapshot = link_struct(1001, 1, 300);
        snapshot.traffic = TrafficStats {
            today_up: 1,
            today_down: 2,
            total_up: 3,
            total_down: 4,
        };
        let mut tx = conn.transaction().await.expect("tx");
        upsert_links_bulk(&mut tx, std::slice::from_ref(&snapshot))
            .await
            .expect("bulk upsert");
        tx.commit().await.expect("commit");

        let stored = ProfileStats::filter_by_protocol_id_and_endpoint_id(
            ProtocolId::new(1001),
            EndpointId::new(1),
        )
        .first()
        .exec(&mut conn)
        .await
        .expect("read")
        .expect("row");
        assert_eq!(
            stored.traffic.total_down, 4,
            "a first insert stores the caller's snapshot"
        );
    }

    #[tokio::test]
    async fn upsert_link_is_idempotent_and_updates_fields() {
        let db = Database::in_memory().await.expect("in-memory db");
        let mut conn = db.connection().await.expect("connection");
        db.upsert_endpoint(&endpoint_struct(1, "1.2.3.4", HostType::Ipv4, 443))
            .await
            .expect("endpoint");
        db.upsert_protocol(&protocol_struct(1001))
            .await
            .expect("protocol");

        let mut link = link_struct(1001, 1, 100);
        link.traffic = TrafficStats {
            today_up: 5,
            today_down: 6,
            total_up: 7,
            total_down: 8,
        };
        db.upsert_link(&link).await.expect("upsert link");
        db.upsert_link(&link).await.expect("upsert link again");

        let count = ProfileStats::all()
            .count()
            .exec(&mut conn)
            .await
            .expect("count");
        assert_eq!(count, 1, "composite-key upsert must not duplicate");

        // Second upsert replaces the result-state fields (e.g. latency).
        link.latency = Latency::fast(42);
        link.last_seen_at = ts(200);
        db.upsert_link(&link)
            .await
            .expect("upsert link with latency");

        let stored = ProfileStats::filter_by_protocol_id_and_endpoint_id(
            ProtocolId::new(1001),
            EndpointId::new(1),
        )
        .first()
        .exec(&mut conn)
        .await
        .expect("read")
        .expect("row");
        assert_eq!(stored.latency, Latency::fast(42));
        assert_eq!(stored.last_seen_at, ts(200));
        assert_eq!(stored.traffic, link.traffic);
    }

    #[tokio::test]
    async fn upsert_link_preserves_activity_state() {
        let db = Database::in_memory().await.expect("in-memory db");
        let mut conn = db.connection().await.expect("connection");
        db.upsert_endpoint(&endpoint_struct(1, "1.2.3.4", HostType::Ipv4, 443))
            .await
            .expect("endpoint");
        db.upsert_protocol(&protocol_struct(1001))
            .await
            .expect("protocol");

        db.upsert_link(&link_struct(1001, 1, 100))
            .await
            .expect("upsert link");
        db.update_last_used(ProtocolId::new(1001), EndpointId::new(1), ts(300))
            .await
            .expect("last used");

        // A re-upsert must not clobber the activity state.
        db.upsert_link(&link_struct(1001, 1, 150))
            .await
            .expect("re-upsert");

        let stored = ProfileStats::filter_by_protocol_id_and_endpoint_id(
            ProtocolId::new(1001),
            EndpointId::new(1),
        )
        .first()
        .exec(&mut conn)
        .await
        .expect("read")
        .expect("row");
        assert_eq!(
            stored.last_used_at,
            Some(ts(300)),
            "activity timestamp survives upsert"
        );
        assert_eq!(
            stored.last_seen_at,
            ts(150),
            "link last_seen replaces on upsert"
        );
    }

    #[tokio::test]
    async fn upsert_protocol_rejects_unloaded_config() {
        let db = Database::in_memory().await.expect("in-memory db");
        let mut conn = db.connection().await.expect("connection");
        toasty::create!(Protocol {
            created_at: 0,
            id: ProtocolId::new(1001),
            sig: 1001,
            proto_kind: ProtocolKind::Vless,
            transport: tcp_transport(),
            security: no_security(),
            config: Deferred::from(Json(vless_config())),
        })
        .exec(&mut conn)
        .await
        .expect("protocol");

        // A default read leaves the deferred JSON unloaded (the crate's own
        // read paths never include it) — upserting must fail with an error
        // instead of panicking on `.get()`.
        let loaded = Protocol::filter_by_id(ProtocolId::new(1001))
            .first()
            .exec(&mut conn)
            .await
            .expect("read")
            .expect("row");
        assert!(loaded.config.is_unloaded(), "config deferred by default");

        let err = db
            .upsert_protocol(&loaded)
            .await
            .expect_err("unloaded config must be rejected, not panic");
        assert!(
            err.to_string().contains("not loaded"),
            "error explains the unloaded state: {err}"
        );

        // A freshly-built struct with loaded config still upserts fine.
        db.upsert_protocol(&protocol_struct(1001))
            .await
            .expect("loaded protocol upserts");
    }

    /// No foreign key exists, so a link whose endpoint vanished (a staged
    /// patch landing after the delete) would otherwise live forever. The purge
    /// pass that deletes anything sweeps them in the same transaction
    /// (issue 020).
    #[tokio::test]
    async fn a_purge_pass_sweeps_orphan_links() {
        let db = Database::in_memory().await.expect("in-memory db");
        let mut conn = db.connection().await.expect("connection");
        // One stale endpoint the purge will delete…
        seed_endpoint(&mut conn, 1, 1001, "1.2.3.4", HostType::Ipv4, 443, 10).await;
        // …and a link for an endpoint that does not exist.
        toasty::sql::statement(
            "INSERT INTO profile_stats (protocol_id, endpoint_id, last_seen_at, \
             created_at, updated_at, version, stab_mask, stab_len, \
             traffic_today_up, traffic_today_down, traffic_total_up, traffic_total_down) \
             VALUES (1001, 999, 10, 0, 0, 1, 0, 0, 0, 0, 0, 0)",
        )
        .exec(&mut conn)
        .await
        .expect("orphan link");

        let deleted = db.purge_expired(100).await.expect("purge");
        assert_eq!(deleted, 1, "the stale endpoint is purged");

        let rows = toasty::sql::query("SELECT COUNT(*) FROM profile_stats WHERE endpoint_id = 999")
            .exec(&mut conn)
            .await
            .expect("count orphans");
        let count = rows.iter().find_map(|row| match row {
            toasty_core::stmt::Value::Record(r) => r.fields.first().cloned(),
            _ => None,
        });
        assert!(
            matches!(count, Some(toasty_core::stmt::Value::I64(0))),
            "the orphan link is swept: {count:?}"
        );
    }

    /// A flush whose endpoint was deleted mid-batch must not recreate the
    /// orphan: the upsert inserts what it cannot update, so the sweep runs in
    /// the same transaction (review, 2026-11-23).
    #[tokio::test]
    async fn a_patch_for_a_deleted_endpoint_does_not_leave_a_link() {
        let db = Database::in_memory().await.expect("in-memory db");
        let mut conn = db.connection().await.expect("connection");
        db.apply_link_patches(&[LinkPatch {
            link: link_struct(1001, 999, 10),
            groups: LinkGroups::RESULT,
        }])
        .await
        .expect("patch");

        let rows = toasty::sql::query("SELECT COUNT(*) FROM profile_stats WHERE endpoint_id = 999")
            .exec(&mut conn)
            .await
            .expect("count");
        let count = rows.iter().find_map(|row| match row {
            toasty_core::stmt::Value::Record(r) => r.fields.first().cloned(),
            _ => None,
        });
        assert!(
            matches!(count, Some(toasty_core::stmt::Value::I64(0))),
            "no orphan row: {count:?}"
        );
    }

    #[tokio::test]
    async fn update_last_used_sets_only_the_intent_column() {
        let db = Database::in_memory().await.expect("in-memory db");
        let mut conn = db.connection().await.expect("connection");
        seed_endpoint(&mut conn, 1, 1001, "1.2.3.4", HostType::Ipv4, 443, 10).await;

        db.update_last_used(ProtocolId::new(1001), EndpointId::new(1), ts(500))
            .await
            .expect("update");

        let link = ProfileStats::filter_by_protocol_id_and_endpoint_id(
            ProtocolId::new(1001),
            EndpointId::new(1),
        )
        .first()
        .exec(&mut conn)
        .await
        .expect("read")
        .expect("row");
        assert_eq!(link.last_used_at, Some(ts(500)));
        assert_ne!(
            link.last_seen_at,
            ts(500),
            "initiation is intent, not proof: the liveness clock must not move"
        );

        db.record_link_alive(ProtocolId::new(1001), EndpointId::new(1), ts(600))
            .await
            .expect("record proof");
        let link = ProfileStats::filter_by_protocol_id_and_endpoint_id(
            ProtocolId::new(1001),
            EndpointId::new(1),
        )
        .first()
        .exec(&mut conn)
        .await
        .expect("read")
        .expect("row");
        assert_eq!(
            link.last_seen_at,
            ts(600),
            "a built session is proof and moves the liveness clock"
        );
    }

    #[tokio::test]
    async fn update_endpoint_resolution_sets_cache() {
        let db = Database::in_memory().await.expect("in-memory db");
        let mut conn = db.connection().await.expect("connection");
        seed_endpoint(&mut conn, 1, 1001, "dns.example", HostType::Dns, 443, 10).await;

        db.update_endpoint_resolution(
            EndpointId::new(1),
            vec![ip("1.1.1.1"), ip("2.2.2.2")],
            ts(100),
        )
        .await
        .expect("resolve");

        let ep = Endpoint::filter_by_id(EndpointId::new(1))
            .first()
            .exec(&mut conn)
            .await
            .expect("read")
            .expect("row");
        assert_eq!(
            stored_ips(&mut conn, 1).await,
            vec![ip("1.1.1.1"), ip("2.2.2.2")],
            "key order == address order, not the order the resolver printed"
        );
        assert_eq!(ep.resolved_at, Some(ts(100)));
    }

    #[tokio::test]
    async fn stored_country_survives_re_resolution() {
        let db = Database::in_memory().await.expect("in-memory db");
        let mut conn = db.connection().await.expect("connection");
        seed_endpoint(&mut conn, 1, 1001, "dns.example", HostType::Dns, 443, 10).await;

        db.update_endpoint_resolution(
            EndpointId::new(1),
            vec![ip("1.1.1.1"), ip("2.2.2.2")],
            ts(100),
        )
        .await
        .expect("resolve");
        db.set_endpoint_ip_country(EndpointId::new(1), ip("1.1.1.1"), "US")
            .await
            .expect("country");

        // A re-resolution keeps the country of an address that is still
        // present — the whole point of storing it — and drops the address
        // that is gone.
        db.update_endpoint_resolution(
            EndpointId::new(1),
            vec![ip("1.1.1.1"), ip("3.3.3.3")],
            ts(200),
        )
        .await
        .expect("re-resolve");

        let resolved = db
            .endpoint_resolutions(&[EndpointId::new(1)])
            .await
            .expect("read");
        assert_eq!(
            resolved
                .get(&EndpointId::new(1))
                .cloned()
                .unwrap_or_default(),
            vec![
                (ip("1.1.1.1"), Some("US".to_string())),
                (ip("3.3.3.3"), None)
            ],
        );
    }

    #[tokio::test]
    async fn resolution_batch_writes_every_endpoint() {
        let db = Database::in_memory().await.expect("in-memory db");
        let mut conn = db.connection().await.expect("connection");
        for (id, host) in [
            (1i64, "one.example"),
            (2, "two.example"),
            (3, "three.example"),
        ] {
            seed_endpoint(&mut conn, id, 1000 + id, host, HostType::Dns, 443, 10).await;
        }

        db.update_endpoint_resolutions(&[])
            .await
            .expect("empty batch is a no-op");

        db.update_endpoint_resolutions(&[
            (
                EndpointId::new(1),
                vec![ip("2.2.2.2"), ip("1.1.1.1")],
                ts(100),
            ),
            (EndpointId::new(2), vec![ip("10.0.0.1")], ts(101)),
            (EndpointId::new(3), vec![ip("2001:db8::1")], ts(102)),
        ])
        .await
        .expect("batch");

        for (id, at, ips) in [
            (1i64, 100, vec![ip("1.1.1.1"), ip("2.2.2.2")]),
            (2, 101, vec![ip("10.0.0.1")]),
            (3, 102, vec![ip("2001:db8::1")]),
        ] {
            let ep = Endpoint::filter_by_id(EndpointId::new(id))
                .first()
                .exec(&mut conn)
                .await
                .expect("read")
                .expect("row");
            assert_eq!(
                ep.resolved_at,
                Some(ts(at)),
                "endpoint {id} keeps its own stamp"
            );
            assert_eq!(
                stored_ips(&mut conn, id).await,
                ips,
                "endpoint {id} keeps its own address set"
            );
        }
    }

    /// The address set is tier 5 of the ordering law, so the stored rank bin
    /// must move when the resolution lands: 15 is the DNS-unresolved band,
    /// 12 untested. Deleting the batch's rank refresh keeps every other
    /// resolution test green.
    #[tokio::test]
    async fn resolution_batch_moves_the_rank_out_of_the_dns_band() {
        let db = Database::in_memory().await.expect("in-memory db");
        let mut conn = db.connection().await.expect("connection");
        seed_endpoint(&mut conn, 1, 1001, "dns.example", HostType::Dns, 443, 10).await;
        // The seed writes no rank row; materialize one first so the batch is
        // the only thing that can move it.
        db.refresh_endpoint_ranks(&[EndpointId::new(1)])
            .await
            .expect("seed rank");

        let before = bin_of(&mut conn, 1).await;
        db.update_endpoint_resolutions(&[(EndpointId::new(1), vec![ip("1.1.1.1")], ts(100))])
            .await
            .expect("batch");
        let after = bin_of(&mut conn, 1).await;

        assert_eq!(before, 15, "no stored address = the DNS-unresolved band");
        assert_eq!(after, 12, "the resolved address leaves that band");
    }

    async fn bin_of(conn: &mut toasty::Connection, id: i64) -> i64 {
        EndpointRank::filter_by_endpoint_id(EndpointId::new(id))
            .first()
            .exec(conn)
            .await
            .expect("read")
            .expect("rank row")
            .bin
    }

    /// A batch past the chunk size must write its TAIL chunk too — the
    /// chunk loop is the only thing standing between a 65-endpoint flush and
    /// a silently dropped last endpoint.
    #[tokio::test]
    async fn resolution_batch_spans_the_chunk_size() {
        let db = Database::in_memory().await.expect("in-memory db");
        let mut conn = db.connection().await.expect("connection");
        let ids: Vec<i64> = (1..=65).collect();
        for id in &ids {
            seed_endpoint(
                &mut conn,
                *id,
                1000 + id,
                "dns.example",
                HostType::Dns,
                443,
                10,
            )
            .await;
        }

        let rows: Vec<_> = ids
            .iter()
            .map(|id| (EndpointId::new(*id), vec![ip("1.1.1.1")], ts(*id)))
            .collect();
        db.update_endpoint_resolutions(&rows).await.expect("batch");

        for id in &ids {
            let ep = Endpoint::filter_by_id(EndpointId::new(*id))
                .first()
                .exec(&mut conn)
                .await
                .expect("read")
                .expect("row");
            assert_eq!(ep.resolved_at, Some(ts(*id)), "endpoint {id}");
        }
        assert_eq!(
            stored_ips(&mut conn, 65).await,
            vec![ip("1.1.1.1")],
            "the tail chunk's address set lands too"
        );
    }

    /// The bulk path must go through `endpoint_ip::replace` (not a plain
    /// insert): a re-resolution keeps the country of an address that survives.
    #[tokio::test]
    async fn resolution_batch_keeps_stored_countries() {
        let db = Database::in_memory().await.expect("in-memory db");
        let mut conn = db.connection().await.expect("connection");
        seed_endpoint(&mut conn, 1, 1001, "dns.example", HostType::Dns, 443, 10).await;

        db.update_endpoint_resolutions(&[(
            EndpointId::new(1),
            vec![ip("1.1.1.1"), ip("2.2.2.2")],
            ts(100),
        )])
        .await
        .expect("resolve");
        db.set_endpoint_ip_country(EndpointId::new(1), ip("1.1.1.1"), "US")
            .await
            .expect("country");

        db.update_endpoint_resolutions(&[(
            EndpointId::new(1),
            vec![ip("1.1.1.1"), ip("3.3.3.3")],
            ts(200),
        )])
        .await
        .expect("re-resolve");

        let resolved = db
            .endpoint_resolutions(&[EndpointId::new(1)])
            .await
            .expect("read");
        assert_eq!(
            resolved
                .get(&EndpointId::new(1))
                .cloned()
                .unwrap_or_default(),
            vec![
                (ip("1.1.1.1"), Some("US".to_string())),
                (ip("3.3.3.3"), None)
            ],
        );
    }

    #[tokio::test]
    async fn country_writes_before_the_address_row_exists() {
        let db = Database::in_memory().await.expect("in-memory db");
        let mut conn = db.connection().await.expect("connection");
        seed_endpoint(&mut conn, 1, 1001, "dns.example", HostType::Dns, 443, 10).await;

        // The geo step can finish before the resolution event's write lands
        // (they are separate tasks): the country must create the row rather
        // than be dropped.
        db.set_endpoint_ip_country(EndpointId::new(1), ip("9.9.9.9"), "DE")
            .await
            .expect("country first");
        db.update_endpoint_resolution(EndpointId::new(1), vec![ip("9.9.9.9")], ts(100))
            .await
            .expect("resolve second");

        let resolved = db
            .endpoint_resolutions(&[EndpointId::new(1)])
            .await
            .expect("read");
        assert_eq!(
            resolved
                .get(&EndpointId::new(1))
                .cloned()
                .unwrap_or_default(),
            vec![(ip("9.9.9.9"), Some("DE".to_string()))],
        );
    }

    #[tokio::test]
    async fn country_batch_writes_every_row() {
        let db = Database::in_memory().await.expect("in-memory db");
        let mut conn = db.connection().await.expect("connection");
        seed_endpoint(&mut conn, 1, 1001, "dns.example", HostType::Dns, 443, 10).await;
        db.update_endpoint_resolution(
            EndpointId::new(1),
            vec![ip("1.1.1.1"), ip("2.2.2.2"), ip("3.3.3.3")],
            ts(100),
        )
        .await
        .expect("resolve");

        db.set_endpoint_ip_countries(&[
            (EndpointId::new(1), ip("1.1.1.1"), "US".to_string()),
            (EndpointId::new(1), ip("2.2.2.2"), "DE".to_string()),
            (EndpointId::new(1), ip("3.3.3.3"), "JP".to_string()),
        ])
        .await
        .expect("batch");

        let resolved = db
            .endpoint_resolutions(&[EndpointId::new(1)])
            .await
            .expect("read");
        assert_eq!(
            resolved
                .get(&EndpointId::new(1))
                .cloned()
                .unwrap_or_default(),
            vec![
                (ip("1.1.1.1"), Some("US".to_string())),
                (ip("2.2.2.2"), Some("DE".to_string())),
                (ip("3.3.3.3"), Some("JP".to_string())),
            ],
            "every row of the batch landed, and none overwrote another"
        );
    }

    #[tokio::test]
    async fn country_batch_empty_changes_nothing() {
        let db = Database::in_memory().await.expect("in-memory db");
        let mut conn = db.connection().await.expect("connection");
        seed_endpoint(&mut conn, 1, 1001, "dns.example", HostType::Dns, 443, 10).await;
        db.set_endpoint_ip_country(EndpointId::new(1), ip("1.1.1.1"), "US")
            .await
            .expect("country");

        db.set_endpoint_ip_countries(&[])
            .await
            .expect("empty batch");

        let resolved = db
            .endpoint_resolutions(&[EndpointId::new(1)])
            .await
            .expect("read");
        assert_eq!(
            resolved
                .get(&EndpointId::new(1))
                .cloned()
                .unwrap_or_default(),
            vec![(ip("1.1.1.1"), Some("US".to_string()))],
        );
    }

    /// The chunked protocol writer stores exactly what the typed single-row
    /// upsert stores — the enum text, the INTEGER flag, the config JSON — and a
    /// re-upsert updates the config while keeping `created_at`. The two paths
    /// must never drift: a wrong spelling here is a protocol that no longer
    /// decodes into its own model.
    #[tokio::test]
    async fn protocols_bulk_matches_the_typed_writer() {
        async fn row_for(conn: &mut toasty::Connection, id: i64) -> toasty_core::stmt::Value {
            let mut rows = toasty::sql::query(format!(
                "SELECT proto_kind, transport_type, security_type, security_sni, \
                 security_fp, security_insecure, config, created_at \
                 FROM protocols WHERE id = {id}"
            ))
            .exec(conn)
            .await
            .expect("read");
            rows.pop().expect("one row")
        }
        let db = Database::in_memory().await.expect("in-memory db");
        let mut conn = db.connection().await.expect("connection");

        let bulk_row = Protocol {
            created_at: 0,
            id: ProtocolId::new(1),
            sig: 11,
            proto_kind: ProtocolKind::Vless,
            transport: tcp_transport(),
            security: no_security(),
            config: Deferred::from(Json(vless_config())),
            links: Deferred::default(),
        };
        // The typed upsert this writer replaced, kept as the reference.
        Protocol::upsert_by_id(ProtocolId::new(2))
            .sig(22)
            .proto_kind(ProtocolKind::Vless)
            .transport(tcp_transport())
            .security(no_security())
            .config(vless_config())
            .on_create(|create| create.created_at(now_epoch()))
            .exec(&mut conn)
            .await
            .expect("typed upsert");

        upsert_protocols_bulk(&mut conn, std::slice::from_ref(&bulk_row))
            .await
            .expect("bulk upsert");

        let bulk = row_for(&mut conn, 1).await;
        let typed = row_for(&mut conn, 2).await;
        assert_eq!(bulk, typed, "bulk and typed rows must be identical");

        // The columns come from the MODEL fields, never from `config`: a row
        // whose Security embed disagrees with its JSON must store the embed's
        // values (the typed writer reads `security.sni`/`insecure`, not
        // `config.security`). This pins that mapping against a future refactor
        // that derives the columns from the config.
        let divergent = Protocol {
            created_at: 0,
            id: ProtocolId::new(3),
            sig: 33,
            proto_kind: ProtocolKind::Vless,
            transport: tcp_transport(),
            security: Security {
                r#type: SecurityType::Tls,
                sni: Some("divergent.example".to_string()),
                fp: Some("chrome".to_string()),
                insecure: Some(true),
            },
            // The default fixture's SecurityConfig is empty: no disagreement
            // leaks in from the JSON.
            config: Deferred::from(Json(vless_config())),
            links: Deferred::default(),
        };
        Protocol::upsert_by_id(ProtocolId::new(4))
            .sig(44)
            .proto_kind(ProtocolKind::Vless)
            .transport(tcp_transport())
            .security(divergent.security.clone())
            .config(vless_config())
            .on_create(|create| create.created_at(now_epoch()))
            .exec(&mut conn)
            .await
            .expect("typed divergent");
        upsert_protocols_bulk(&mut conn, std::slice::from_ref(&divergent))
            .await
            .expect("bulk divergent");
        assert_eq!(
            row_for(&mut conn, 3).await,
            row_for(&mut conn, 4).await,
            "the embeds' columns must match the typed writer even when config disagrees"
        );

        // A re-upsert of the SAME id carries a new config: it must land, while
        // `created_at` (the typed writer's on_create stamp) must not.
        let mut changed = vless_config();
        if let ProtocolConfig::Vless(cfg) = &mut changed {
            cfg.uuid = "11111111-1111-4111-8111-111111111111".to_string();
        }
        let mut refreshed = bulk_row.clone();
        refreshed.config = Deferred::from(Json(changed));
        upsert_protocols_bulk(&mut conn, std::slice::from_ref(&refreshed))
            .await
            .expect("re-upsert");
        let after = row_for(&mut conn, 1).await;
        let created_before = match &typed {
            toasty_core::stmt::Value::Record(r) => r.fields.last().cloned(),
            _ => None,
        };
        let created_after = match &after {
            toasty_core::stmt::Value::Record(r) => r.fields.last().cloned(),
            _ => None,
        };
        assert_eq!(
            created_before, created_after,
            "created_at is on_create only"
        );
        assert_ne!(bulk, after, "the new config must be stored");
    }

    /// Every kind and transport stores the same checked-column labels through
    /// the raw writer as through the typed writer.
    ///
    /// The single VLESS+TCP row above cannot see the label split: `vless` and
    /// `tcp` are spelled identically in the wire dialect and the embed one. 20
    /// of 27 kinds and 2 of 8 transports differ (`ss`/`shadowsocks`,
    /// `hy2`/`hysteria2`, `any-tls`/`any_tls`, `xhttp`/`x_http`, …), and the
    /// column is `CHECK`-constrained to the embed spelling — the wire spelling
    /// fails the whole import chunk (`CHECK constraint failed: proto_kind`).
    #[tokio::test]
    async fn every_protocol_kind_and_transport_bulk_matches_the_typed_writer() {
        async fn labels(conn: &mut toasty::Connection, id: i64) -> toasty_core::stmt::Value {
            let mut rows = toasty::sql::query(format!(
                "SELECT proto_kind, transport_type, security_type \
                 FROM protocols WHERE id = {id}"
            ))
            .exec(conn)
            .await
            .expect("read");
            rows.pop().expect("one row")
        }
        let db = Database::in_memory().await.expect("in-memory db");
        let mut conn = db.connection().await.expect("connection");
        let transports = [
            TransportType::Tcp,
            TransportType::Ws,
            TransportType::Grpc,
            TransportType::Http,
            TransportType::Quic,
            TransportType::Kcp,
            TransportType::HttpUpgrade,
            TransportType::XHttp,
        ];
        let mut id = 100;
        for kind in (1_i32..=27).filter_map(ProtocolKind::try_from_i32) {
            for transport in transports {
                let bulk = Protocol {
                    created_at: 0,
                    id: ProtocolId::new(id),
                    sig: id,
                    proto_kind: kind,
                    transport: Transport { r#type: transport },
                    security: no_security(),
                    config: Deferred::from(Json(vless_config())),
                    links: Deferred::default(),
                };
                Protocol::upsert_by_id(ProtocolId::new(id + 1))
                    .sig(id + 1)
                    .proto_kind(kind)
                    .transport(Transport { r#type: transport })
                    .security(no_security())
                    .config(vless_config())
                    .on_create(|create| create.created_at(0))
                    .exec(&mut conn)
                    .await
                    .expect("typed upsert");
                upsert_protocols_bulk(&mut conn, std::slice::from_ref(&bulk))
                    .await
                    .expect("bulk upsert");
                assert_eq!(
                    labels(&mut conn, id).await,
                    labels(&mut conn, id + 1).await,
                    "{kind:?} / {transport:?}"
                );
                id += 2;
            }
        }
    }

    /// The import path's bulk literal writer (db-rewamp D10): an IP literal's
    /// row is written once, and a re-import of the SAME literal must NOT erase
    /// the country the geo step stored — `ON CONFLICT DO NOTHING`, not a
    /// re-insert. A duplicated literal in one batch must not raise either.
    #[tokio::test]
    async fn import_literal_bulk_writes_once_and_keeps_the_country() {
        let db = Database::in_memory().await.expect("in-memory db");
        let mut conn = db.connection().await.expect("connection");

        crate::endpoint_ip::insert_literals_bulk(
            &mut conn,
            &[
                (EndpointId::new(1), ip("198.51.100.7")),
                (EndpointId::new(1), ip("198.51.100.7")), // duplicate in-batch
                (EndpointId::new(2), ip("2001:db8::1")),
            ],
        )
        .await
        .expect("bulk literals");
        db.set_endpoint_ip_country(EndpointId::new(1), ip("198.51.100.7"), "FR")
            .await
            .expect("country");

        // A second import of the same literal keeps the row and its country.
        crate::endpoint_ip::insert_literals_bulk(
            &mut conn,
            &[(EndpointId::new(1), ip("198.51.100.7"))],
        )
        .await
        .expect("re-import");
        assert_eq!(
            db.endpoint_resolutions(&[EndpointId::new(1)])
                .await
                .expect("read")
                .get(&EndpointId::new(1))
                .cloned()
                .unwrap_or_default(),
            vec![(ip("198.51.100.7"), Some("FR".to_string()))],
            "one row, country intact, no duplicate",
        );
    }

    #[tokio::test]
    async fn country_batch_creates_missing_address_rows() {
        let db = Database::in_memory().await.expect("in-memory db");
        let mut conn = db.connection().await.expect("connection");
        seed_endpoint(&mut conn, 1, 1001, "dns.example", HostType::Dns, 443, 10).await;

        // The geo step can finish before the resolution event's write lands
        // (they are separate tasks): a country in the batch must create its
        // row, and the later resolution write must keep it.
        db.set_endpoint_ip_countries(&[
            (EndpointId::new(1), ip("9.9.9.9"), "DE".to_string()),
            (EndpointId::new(1), ip("1.1.1.1"), "US".to_string()),
        ])
        .await
        .expect("batch first");
        db.update_endpoint_resolution(
            EndpointId::new(1),
            vec![ip("9.9.9.9"), ip("1.1.1.1")],
            ts(100),
        )
        .await
        .expect("resolve second");

        let resolved = db
            .endpoint_resolutions(&[EndpointId::new(1)])
            .await
            .expect("read");
        assert_eq!(
            resolved
                .get(&EndpointId::new(1))
                .cloned()
                .unwrap_or_default(),
            vec![
                (ip("1.1.1.1"), Some("US".to_string())),
                (ip("9.9.9.9"), Some("DE".to_string())),
            ],
        );
    }

    #[tokio::test]
    async fn set_manual_override_sets_and_clears() {
        let db = Database::in_memory().await.expect("in-memory db");
        let mut conn = db.connection().await.expect("connection");
        seed_endpoint(&mut conn, 1, 1001, "10.10.10.10", HostType::Ipv4, 53, 10).await;
        seed_link(&mut conn, 1, 1002, 20).await;

        db.set_manual_override(EndpointId::new(1), Some(ProtocolId::new(1001)))
            .await
            .expect("set");
        let ep = Endpoint::filter_by_id(EndpointId::new(1))
            .first()
            .exec(&mut conn)
            .await
            .expect("read")
            .expect("row");
        assert_eq!(ep.manual_protocol_override, Some(ProtocolId::new(1001)));

        db.set_manual_override(EndpointId::new(1), None)
            .await
            .expect("clear");
        let ep = Endpoint::filter_by_id(EndpointId::new(1))
            .first()
            .exec(&mut conn)
            .await
            .expect("read")
            .expect("row");
        assert_eq!(ep.manual_protocol_override, None);
    }

    #[tokio::test]
    async fn restore_endpoint_bumps_last_seen() {
        let db = Database::in_memory().await.expect("in-memory db");
        let mut conn = db.connection().await.expect("connection");
        seed_endpoint(&mut conn, 1, 1001, "1.2.3.4", HostType::Ipv4, 443, 10).await;
        seed_link(&mut conn, 1, 1002, 20).await;

        db.restore_endpoint(EndpointId::new(1))
            .await
            .expect("restore");

        let now = crate::models_toasty::now_epoch();
        let links: Vec<ProfileStats> =
            ProfileStats::filter(ProfileStats::fields().endpoint_id().eq(EndpointId::new(1)))
                .exec(&mut conn)
                .await
                .expect("links");
        assert_eq!(links.len(), 2);
        for link in links {
            assert!(
                link.last_seen_at >= now - 60,
                "every link of the endpoint is refreshed"
            );
        }
    }

    #[tokio::test]
    async fn upsert_group_replaces_row() {
        let db = Database::in_memory().await.expect("in-memory db");
        let mut conn = db.connection().await.expect("connection");
        let mut g = Group {
            id: "g1".to_string(),
            name: Some("A".to_string()),
            url: Some("https://example.com/sub".to_string()),
            enabled: true,
            user_agent: None,
            convert_target: None,
            sort_order: Some(0),
            last_refreshed: None,
            status: None,
            error_message: None,
            refresh_interval: Some(30),
        };
        db.upsert_group(&g).await.expect("insert");

        g.name = Some("B".to_string());
        g.enabled = false;
        db.upsert_group(&g).await.expect("update");

        let rows: Vec<Group> = Group::filter(Group::fields().id().eq("g1".to_string()))
            .exec(&mut conn)
            .await
            .expect("rows");
        assert_eq!(rows.len(), 1, "upsert replaces insert_group/update_group");
        let stored = Group::filter_by_id("g1".to_string())
            .first()
            .exec(&mut conn)
            .await
            .expect("read")
            .expect("row");
        assert_eq!(stored.name.as_deref(), Some("B"));
        assert!(!stored.enabled);
    }

    #[tokio::test]
    async fn clear_group_endpoints_and_delete_group() {
        let db = Database::in_memory().await.expect("in-memory db");
        let mut conn = db.connection().await.expect("connection");
        seed_endpoint(&mut conn, 1, 1001, "1.2.3.4", HostType::Ipv4, 443, 10).await;
        toasty::create!(EndpointGroup {
            endpoint_id: EndpointId::new(1),
            group_id: "g-a".to_string(),
            last_seen_at: ts(1),
        })
        .exec(&mut conn)
        .await
        .expect("link a");
        toasty::create!(EndpointGroup {
            endpoint_id: EndpointId::new(1),
            group_id: "g-b".to_string(),
            last_seen_at: ts(1),
        })
        .exec(&mut conn)
        .await
        .expect("link b");

        let n = db.clear_group_endpoints("g-a").await.expect("clear");
        assert_eq!(n, 1, "clear_group returns the link count");
        let remaining: Vec<EndpointGroup> =
            EndpointGroup::all().exec(&mut conn).await.expect("rows");
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].group_id, "g-b");

        // delete_group removes the remaining links + the group, keeps endpoints.
        db.upsert_group(&Group {
            id: "g-b".to_string(),
            name: None,
            url: None,
            enabled: true,
            user_agent: None,
            convert_target: None,
            sort_order: None,
            last_refreshed: None,
            status: None,
            error_message: None,
            refresh_interval: None,
        })
        .await
        .expect("group b");
        db.delete_group("g-b").await.expect("delete group");

        let count = EndpointGroup::all()
            .count()
            .exec(&mut conn)
            .await
            .expect("count");
        assert_eq!(count, 0, "group links deleted");
        assert!(
            Group::filter_by_id("g-b".to_string())
                .first()
                .exec(&mut conn)
                .await
                .expect("read")
                .is_none(),
            "group deleted"
        );
        assert!(
            Endpoint::filter_by_id(EndpointId::new(1))
                .first()
                .exec(&mut conn)
                .await
                .expect("read")
                .is_some(),
            "endpoint + links survive group deletion"
        );
    }

    /// Aggregating a group's addresses into ONE blob, and decoding it without
    /// hex parsing. Measured 2026-09-16, and **not** adopted for the page:
    /// `docs/aegis/specs/2026-09-16-db-claim-verification.md` §2 row 6c.
    ///
    /// The idea (this test): `unhex(string_agg(hex(x), ''))` concatenates every
    /// address of a group into a single BLOB, and the decoder slices it by a
    /// fixed width — no comma split, no per-token hex parse, where the shipped
    /// carrier is `group_concat(hex(ip_key), ',')` and decodes token by token.
    ///
    /// What the measurement says (200-endpoint resolved page, 277 addresses,
    /// 7,656-endpoint feed, release build):
    ///
    /// * **The SQL side is not gated** — `string_agg`, `hex`, `unhex` and
    ///   `FILTER` all work with the custom-types flag OFF (the flag this test
    ///   passes is only what makes the `STRICT` DDL below legal; see the note in
    ///   `docs/database-manual-sql.md`).
    /// * **Equal in cost, identical in output**: statement 747–836 µs shipped
    ///   against 758–776 µs as one blob (the spread is run-to-run noise), decode
    ///   4.7 µs against 4.6–7.4 µs, and the decoded address sets are EQUAL
    ///   (277 == 277). Parsing the shipped text form for a whole page costs
    ///   8–14 µs, which is ≤0.4 % of a page.
    /// * **The split variant is wrong, not just slower**: on a `(family, addr)`
    ///   table the same `chunks::<4>()` decode returned **367** addresses where
    ///   the packed key has 277 — a single concatenated blob cannot be sliced by
    ///   one width when IPv4 and IPv6 are mixed, so it silently invents
    ///   addresses. Two `FILTER`ed aggregates would be needed to fix that.
    ///
    /// So the shipped `group_concat(hex(ip_key))` stays: same result, same cost,
    /// one authoritative spelling (the packed key's byte order IS address
    /// order), and no mixed-family trap. If the blob form is ever adopted, the
    /// correct decoder is a WALK over the packed key — the same bytes, family
    /// byte then 4/16 octets — which is byte-identical to the shipped output and
    /// needs no schema change.
    #[tokio::test]
    async fn test_array_agg_result_deserialize_to_ips() {
        use toasty::stmt::Value;

        #[derive(Debug, PartialEq)]
        struct TestIPs {
            epid: i64,
            ipv4: Box<[std::net::Ipv4Addr]>,
            ipv6: Box<[std::net::Ipv6Addr]>,
        }

        fn blob_to_ipv4(full_blob: &[u8]) -> Option<Box<[std::net::Ipv4Addr]>> {
            let (ipv4_blobs, &[]) = full_blob.as_chunks::<4>() else {
                return None;
            };
            Some(
                ipv4_blobs
                    .iter()
                    .copied()
                    .map(std::net::Ipv4Addr::from_octets)
                    .collect(),
            )
        }
        fn blob_to_ipv6(full_blob: &[u8]) -> Option<Box<[std::net::Ipv6Addr]>> {
            let (ipv4_blobs, &[]) = full_blob.as_chunks::<16>() else {
                return None;
            };
            Some(
                ipv4_blobs
                    .iter()
                    .copied()
                    .map(std::net::Ipv6Addr::from_octets)
                    .collect(),
            )
        }

        let db = Database::in_memory().await.expect("should open");
        // let db = toasty::Db::builder()
        //     .build(crate::driver::Turso::in_memory().experimental_custom_types(true))
        //     .await
        //     .expect("should open");
        let mut conn = db.connection().await.expect("should connect");

        toasty::sql::statement(
            "CREATE TABLE IF NOT EXISTS test_ips (epid INTEGER, ipv4 BLOB, ipv6 BLOB);",
        )
        .exec(&mut conn)
        .await
        .expect("should create");

        toasty::sql::statement("INSERT INTO test_ips VALUES (?, ?, ?), (?, ?, ?);")
            .bind(1_i32)
            .bind((0_u8..4).collect::<Vec<_>>())
            .bind((0_u8..16).collect::<Vec<_>>())
            .bind(1_i32)
            .bind((8_u8..12).collect::<Vec<_>>())
            .bind((16_u8..32).collect::<Vec<_>>())
            .exec(&mut conn)
            .await
            .expect("should insert");

        let mut rows = toasty::sql::query(
            "select epid, unhex(string_agg(hex(ipv4), '')) as ipv4, unhex(string_agg(hex(ipv6), '')) as ipv6 from test_ips group by epid",
        )
        .exec(&mut conn)
        .await
        .expect("should select")
        .into_iter()
        .map(Value::into_record);

        let test_ips = {
            let row = rows.next().expect("at least one row");
            let [Value::I64(epid), Value::Bytes(ipv4), Value::Bytes(ipv6)] = row.as_ref() else {
                panic!("expected three columns (bigint, blob, blob), found: {row:#?}");
            };
            TestIPs {
                epid: *epid,
                ipv4: blob_to_ipv4(ipv4).expect("valid blob"),
                ipv6: blob_to_ipv6(ipv6).expect("valid blob"),
            }
        };
        assert_eq!(
            test_ips,
            TestIPs {
                epid: 1,
                ipv4: Box::from(&[
                    std::net::Ipv4Addr::from_octets([0, 1, 2, 3]),
                    std::net::Ipv4Addr::from_octets([8, 9, 10, 11])
                ] as &[_]),
                ipv6: Box::from(&[
                    std::net::Ipv6Addr::from_octets([
                        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15
                    ]),
                    std::net::Ipv6Addr::from_octets([
                        16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31
                    ])
                ] as &[_])
            }
        );
        assert!(rows.next().is_none());
    }

    /// The keyset walk must return exactly the single-statement set: an
    /// off-by-one in the page boundary would silently skip an endpoint every
    /// 10 000 rows, and the sweep is the only thing that reclaims it.
    #[tokio::test]
    async fn the_sweep_pages_to_the_same_candidate_set() {
        let db = Database::in_memory().await.expect("in-memory db");
        let mut conn = db.connection().await.expect("connection");
        for id in 1..=5 {
            db.upsert_endpoint(&endpoint_struct(id, "1.2.3.4", HostType::Ipv4, 443))
                .await
                .expect("endpoint");
        }
        db.upsert_protocol(&protocol_struct(1001))
            .await
            .expect("protocol");
        // Endpoint 3 is fresh; the other four are stale at the cutoff.
        db.upsert_link(&link_struct(1001, 3, 100))
            .await
            .expect("link");

        let cutoff = 50;
        let paged = Database::never_observed_candidates_paged(&mut conn, cutoff, 2)
            .await
            .expect("paged");
        let whole = Database::never_observed_candidates_paged(&mut conn, cutoff, 1000)
            .await
            .expect("whole");

        assert_eq!(paged, whole, "the page size must not change the set");
        assert_eq!(
            paged.iter().map(|id| id.get()).collect::<Vec<_>>(),
            vec![1, 2, 4, 5]
        );
    }
}
