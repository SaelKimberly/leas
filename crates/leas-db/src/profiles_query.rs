//! Raw-SQL owner of the Profiles page query (ADR 0001).
//!
//! Ordering, filtering, counting and paging are SQL; the page IS the filtered
//! list. The page queries decode ids and keys.
//!
//! Hydration is the exception that proves the rule: [`Database::
//! load_page_projection`] decodes whole rows (endpoint + links + the
//! protocols' display columns) from ONE statement, because binding a page's
//! ids into the typed hydration reads costs ~0.8 ms per parameter in turso.
//! Everything it decodes comes back through toasty's own [`Load`] impls (see
//! the projection section at the bottom of this file), so the models it
//! returns are the same values the typed path returns — minus the deferred
//! JSON carriers the page never reads.
//!
//! The ORDER BY reads the materialized keys in `endpoint_rank`
//! ([`crate::endpoint_rank`]), which the Rust ordering law computes. SQL never
//! re-derives that law: an index-driven scan of 200 rows replaced a
//! `ROW_NUMBER()` window that cost ~975 ms per page on the reference feed.

use std::collections::HashMap;
use std::net::IpAddr;

use crate::Database;
use crate::error::{DatabaseError, Result};
use crate::models_toasty::{
    Endpoint, EndpointId, EndpointRow, ErrorInfo, Latency, ProfileErr, ProfileStats, Protocol,
    ProtocolId, PurgatoryView, PurgeReason, Security, TrafficStats, Transport,
};
use leas_proto::proto_spec::{ProtocolKind, SecurityType, TransportType};
use toasty::Deferred;
use toasty::schema::Load;
use toasty_core::stmt::{Value, ValueRecord};

/// Default rows per page.
pub const DEFAULT_PAGE_SIZE: usize = 200;

/// Projection of every page-shaped query: the endpoint id, taken from the
/// rank table the query drives from.
const PROJ_ID: &str = "k.endpoint_id";

// ── Request / response ──────────────────────────────────────────────────

/// Sort column of the Profiles tab. `Core` is absent by design: it resolves
/// through runtime `protocol_core_overrides` and cannot be expressed in SQL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageSort {
    /// Decision-16 test priority, ordered by the representative link.
    Test,
    Port,
    /// The endpoint's lowest resolved address (`endpoint_ip.ip_key`). The
    /// addresses are the only IP fact stored per endpoint, so this is the one
    /// sort the JSON-array column could not express at all.
    Ip,
    /// The endpoint id — the batch's feed walk.
    ///
    /// Ids never change, so the order is stable under a running batch, and it
    /// is 3.2× cheaper than a host-text order (measured on the 7,486-endpoint
    /// reference feed: 3.6 ms per page against 11.6 ms, both through the app's
    /// own driver). Nothing displays this order; it exists for the lab.
    Id,
}

/// Which endpoints a batch plans — the "Fast + Real Ping" scope variants.
///
/// Every variant is a predicate over the endpoint's materialized `rank_bin`
/// (ADR 0003), so the plan is index-driven and needs no new stored column:
///
/// | tier | means |
/// | --- | --- |
/// | 0 | a live, resolved link with a real measurement and no marker |
/// | 2 | no link has a clean measurement, and ≥1 link is untested |
/// | 3/4/5 | no live link is measured or untested (real / fast / name error) |
///
/// The one boundary this cannot express exactly: an endpoint with BOTH an
/// untested link and a failed link reports tier 2, so `Failed` does not select
/// it even though its row shows a marker. It is selected by `SuccessfulAndNew`
/// instead, which is correct — it still has a link worth probing, and one
/// failed probe later it lands in `Failed`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PlanScope {
    /// Every endpoint that has a link (the default).
    #[default]
    All,
    /// Endpoints that achieved a real success.
    Successful,
    /// Endpoints with an untested link and no clean measurement — the ones a
    /// run has never answered for.
    New,
    /// `Successful` plus every endpoint with an untested link (= `Successful ∪
    /// New`).
    SuccessfulAndNew,
    /// Endpoints whose links all failed, or whose name never resolved.
    Failed,
}

impl PlanScope {
    /// The SQL predicate this scope contributes, over the `endpoint_rank` alias
    /// `k`. `None` = no predicate.
    ///
    /// The R1 partition: membership is `rank_proven` FIRST, then the bin.
    /// `New` is "not proven AND untested"; `Failed` is "not proven AND a
    /// failure marker"; `Successful` is proven at any bin. A proven endpoint
    /// whose representative is an untested sibling (bin 12) is therefore
    /// Successful, NOT New — which is the whole reason the column exists.
    ///
    /// The three arms are pairwise disjoint, so `SuccessfulAndNew` is their
    /// union and not a double-count. Replaces the retired `bins()` list: a
    /// proven endpoint can carry bin 12 or 13 (spec
    /// `2026-10-09-stab-bin-design` §5.3), so membership is no longer a bin
    /// set for any scope.
    #[must_use]
    pub const fn predicate(self) -> Option<&'static str> {
        match self {
            Self::All => None,
            Self::Successful => Some("k.rank_proven = 1"),
            Self::New => Some("(k.rank_proven = 0 AND k.rank_bin = 12)"),
            Self::SuccessfulAndNew => Some("(k.rank_proven = 1 OR k.rank_bin = 12)"),
            Self::Failed => Some("(k.rank_proven = 0 AND k.rank_bin IN (13, 14, 15))"),
        }
    }
}

/// One page request. The thresholds are view filters, not ordering inputs.
#[derive(Debug, Clone)]
pub struct PageRequest {
    pub view: PurgatoryView,
    /// The view bound, in epoch seconds (the unit the key columns store):
    /// `Active` selects `>= active`, `Purgatory` selects `< active`.
    ///
    /// There is no lower bound: with a live-only `rank_newest_seen`, an endpoint
    /// whose only live links are older than retention while a purged link was
    /// confirmed today is a state this feature creates deliberately, and a lower
    /// bound would hide it from both views. The retention sweep owns deletion.
    pub active_threshold: i64,
    pub search: Option<String>,
    pub group_id: Option<String>,
    /// The plan scope — a batch entry point's filter. The tab always asks for
    /// `All`; the scoped batch variants narrow the walk.
    pub scope: PlanScope,
    pub sort: PageSort,
    pub ascending: bool,
    pub offset: usize,
    pub limit: usize,
}

impl PageRequest {
    /// The sort this request asks for, with its direction.
    #[must_use]
    pub fn order_terms(&self) -> Vec<OrderTerm> {
        order_terms(self.sort, self.ascending)
    }
}

/// One page of endpoint ids in display order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PageMeta {
    pub ids: Vec<EndpointId>,
    /// Filtered total across all pages (the footer count).
    pub total: u64,
    /// Effective offset after clamping to `total`.
    pub offset: usize,
}

/// The aggregate counts for one scope, as the Details panel renders them.
///
/// The four **partition members** — [`proven`][Self::proven],
/// [`untested`][Self::untested], [`failed`][Self::failed],
/// [`other`][Self::other] — are pairwise disjoint and sum to
/// [`total`][Self::total]. [`alive`][Self::alive] and
/// [`reliable`][Self::reliable] are **orthogonal**: they are filters over the
/// same rows and overlap any partition member, so they must never be drawn as
/// part of the partition (spec D28).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct AggregateCounts {
    /// Every endpoint in the scope.
    pub total: u64,
    /// Seen within the TTL window — live (`rank_newest_seen`) for the global
    /// group, the swept `band` for the view group.
    pub alive: u64,
    /// `rank_proven = 1` — any live unpurged link with a real success.
    pub proven: u64,
    /// The representative link's success rate ≥ 75% (`rank_stab <= 2`).
    pub reliable: u64,
    /// Not proven AND never measured (`rank_bin = 12`).
    pub untested: u64,
    /// Not proven AND a failure marker (`rank_bin` 13/14/15).
    pub failed: u64,
    /// Not proven and in no other bucket — measured but with no real success
    /// in the ring (e.g. a fast-only-ok endpoint).
    pub other: u64,
}

impl AggregateCounts {
    fn decode(row: &Value) -> Result<Self> {
        let Value::Record(record) = row else {
            return Err(DatabaseError::Generic(format!(
                "profiles_aggregate: unexpected row: {row:?}"
            )));
        };
        // `SUM(CASE …)` over an empty set is NULL, not 0.
        let field = |i: usize| -> Result<u64> {
            match record.fields.get(i) {
                Some(Value::I64(n)) => Ok(u64::try_from(*n).unwrap_or(0)),
                _ => Ok(0),
            }
        };
        Ok(Self {
            total: field(0)?,
            alive: field(1)?,
            proven: field(2)?,
            reliable: field(3)?,
            untested: field(4)?,
            failed: field(5)?,
            other: field(6)?,
        })
    }
}

// ── SQL building ────────────────────────────────────────────────────────

/// Statement text plus its ordered binds.
struct Sql {
    text: String,
    params: Vec<Value>,
}

impl Sql {
    const fn new() -> Self {
        Self {
            text: String::new(),
            params: Vec::new(),
        }
    }

    fn push(&mut self, s: &str) {
        self.text.push_str(s);
    }

    fn bind<T: Into<Value>>(&mut self, v: T) -> String {
        self.params.push(v.into());
        format!("?{}", self.params.len())
    }

    async fn exec(&self, conn: &mut toasty::Connection) -> Result<Vec<Value>> {
        let mut query = toasty::sql::query(self.text.clone());
        for param in &self.params {
            query = query.bind(param.clone());
        }
        Ok(query.exec(conn).await?)
    }

    /// Run the statement on the LONG-LIVED direct turso connection (T13) and
    /// return the ids/count as `Value::I64` — the page's id and count queries
    /// each select one INTEGER column. `self.params` (toasty `Value`s) are
    /// converted to turso values.
    async fn exec_direct(&self, conn: &turso::Connection) -> Result<Vec<Value>> {
        let params: Vec<turso::Value> = self.params.iter().map(to_turso_value).collect();
        let mut rows = conn
            .query(self.text.clone(), turso::params_from_iter(params))
            .await
            .map_err(crate::export::turso_error)?;
        let mut out = Vec::new();
        while let Some(row) = rows.next().await.map_err(crate::export::turso_error)? {
            out.push(Value::I64(row.get::<i64>(0).unwrap_or(0)));
        }
        Ok(out)
    }

    /// Run the statement on the LONG-LIVED direct turso connection and return
    /// every row as a `Value::Record`, in the shape toasty's own raw-SQL path
    /// produces.
    ///
    /// The toasty driver routes EVERY statement through the connection's
    /// `prepare_cached`, whose statement map (`turso_sdk_kit::rsapi::
    /// TursoConnection::cached_statements`) is **unbounded** and keyed by SQL
    /// text: every distinct statement is compiled and retained for the
    /// connection's life. The projection's ids are INLINED as literals (see the
    /// perf note on [`Database::load_page_projection`]), so its text is unique
    /// per page — a fresh page compiled and cached on every load, ~116-310 KiB
    /// each, forever. `turso::Connection::query` uses the UNCACHED `prepare`,
    /// so running the projection here keeps the inlining perf and drops the
    /// retention.
    ///
    /// Values are converted by STORAGE CLASS, exactly as the driver's own
    /// `from_turso_infer` does for a raw statement (`SqlReturn::Infer`), so the
    /// shared decoder reads the same `Value`s the toasty path would hand it.
    async fn exec_raw(&self, conn: &turso::Connection) -> Result<Vec<Value>> {
        let params: Vec<turso::Value> = self.params.iter().map(to_turso_value).collect();
        let mut rows = conn
            .query(self.text.clone(), turso::params_from_iter(params))
            .await
            .map_err(crate::export::turso_error)?;
        let mut out = Vec::new();
        while let Some(row) = rows.next().await.map_err(crate::export::turso_error)? {
            let mut items = Vec::with_capacity(row.column_count());
            for index in 0..row.column_count() {
                let value = row.get_value(index).map_err(crate::export::turso_error)?;
                items.push(from_turso_infer(value));
            }
            out.push(Value::Record(ValueRecord::from_vec(items)));
        }
        Ok(out)
    }
}

/// turso `Value` → toasty `Value` by SQLite storage class — the mirror of the
/// driver's `from_turso_infer`. Kept as a re-export so the seam and this module
/// cannot drift.
use crate::driver::from_turso_infer;

/// toasty `Value` → turso `Value` (only the page's bind kinds: ints, text, blobs).
fn to_turso_value(v: &Value) -> turso::Value {
    match v {
        Value::I64(n) => turso::Value::Integer(*n),
        Value::String(s) => turso::Value::Text(s.clone()),
        Value::Bytes(b) => turso::Value::Blob(b.clone()),
        _ => turso::Value::Null,
    }
}

/// The packed-key half-open range `[lo, hi)` an IP search term selects, or
/// `None` for a name term. A full address, a CIDR, and a three-octet partial
/// (the /24 range) are all understood.
fn ip_range_bounds(term: &str) -> Option<(Vec<u8>, Vec<u8>)> {
    use std::net::IpAddr;
    if let Some((addr, bits)) = term.split_once('/') {
        let ip = addr.trim().parse::<IpAddr>().ok()?;
        return cidr_bounds(ip, bits.trim().parse().ok()?);
    }
    if let Ok(ip) = term.parse::<IpAddr>() {
        let lo = crate::endpoint_ip::key_of(ip);
        return Some((lo.clone(), next_key(lo)));
    }
    let octets: Vec<&str> = term.split('.').collect();
    if octets.len() == 3 && octets.iter().all(|o| o.parse::<u8>().is_ok()) {
        let ip: IpAddr = format!("{term}.0").parse().ok()?;
        return cidr_bounds(ip, 24);
    }
    None
}

/// The packed-key half-open range of a CIDR block.
fn cidr_bounds(ip: std::net::IpAddr, bits: u8) -> Option<(Vec<u8>, Vec<u8>)> {
    let octets = match ip {
        std::net::IpAddr::V4(_) => 4,
        std::net::IpAddr::V6(_) => 16,
    };
    if usize::from(bits) > octets * 8 {
        return None;
    }
    let mut lo = crate::endpoint_ip::key_of(ip);
    let full = usize::from(bits / 8);
    let rem = bits % 8;
    for byte in lo.iter_mut().skip(full + 1) {
        *byte = 0;
    }
    if rem != 0 {
        lo[full + 1] &= 0xff << (8 - rem);
    }
    let mut hi = lo.clone();
    for byte in hi.iter_mut().skip(full + 1) {
        *byte = 0xff;
    }
    Some((lo, next_key(hi)))
}

/// The next packed key (big-endian successor): the exclusive upper bound.
fn next_key(mut k: Vec<u8>) -> Vec<u8> {
    for b in k.iter_mut().rev() {
        if *b == 0xff {
            *b = 0;
        } else {
            *b += 1;
            return k;
        }
    }
    k
}

/// Escape LIKE metacharacters for an `ESCAPE '\'` clause.
fn escape_like(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for ch in s.chars() {
        if matches!(ch, '\\' | '%' | '_') {
            out.push('\\');
        }
        out.push(ch);
    }
    out
}

// ── Ordering ────────────────────────────────────────────────────────────

/// One ORDER BY term: the expression and its EFFECTIVE direction. A descending
/// request reverses every term (tiebreaks included), mirroring the Rust
/// oracle's `cmp.reverse()`.
#[derive(Debug, Clone)]
pub struct OrderTerm {
    pub expr: String,
    pub asc: bool,
}

/// A stored rank column, referenced bare so the ORDER BY can be served by the
/// covering index (wrapping it in `COALESCE` forces a sort of every row:
/// measured 240 ms versus 1 ms). Every endpoint that has links has a rank row
/// — the write paths and the backfill keep it that way, and the freshness test
/// pins it — so a NULL here means a write path skipped the refresh, and the
/// row lands at the window's edge instead of silently mid-list.
fn rank_col(column: &str) -> String {
    format!("k.{column}")
}

/// The ORDER BY term list for a sort column and direction.
#[must_use]
pub fn order_terms(sort: PageSort, ascending: bool) -> Vec<OrderTerm> {
    let term = |expr: String, natural_asc: bool| OrderTerm {
        expr,
        asc: natural_asc == ascending,
    };
    match sort {
        // Decision-16 law with the static weight inside the tier. The weight
        // term is DESCENDING, and that direction is the whole point: the Rust
        // oracle reads it NEGATED (`u64::MAX - packed`) inside one ascending
        // tuple, so "negated ascending" and "pack descending" are the same
        // order. Flipping this term to ASC inverts the page against the
        // comparator — the parity test fails, not the field.
        PageSort::Test => vec![
            // band FIRST: the covering index leads with it, so `ORDER BY band,
            // …` is the index order for BOTH the Active/Purgatory seek (`band =
            // ?`, constant) and the All/batch scan (mixed bands) — without it
            // the All view would filesort (turso `USE SORTER`).
            term(rank_col("band"), true),
            term(rank_col("rank_bin"), true),
            term(rank_col("rank_stab"), true),
            term(rank_col("rank_weight"), false),
            term(rank_col("rank_domain"), true),
            term(rank_col("rank_sub_domain"), true),
            term(rank_col("rank_addr"), true),
            term("k.endpoint_id".to_string(), true),
        ],
        PageSort::Port => vec![
            term("e.port".to_string(), true),
            term("k.endpoint_id".to_string(), true),
        ],
        // Correlated on the RANK table, not on `endpoints`: the page source is
        // `endpoint_rank k` and the join to `endpoints` is only added for the
        // predicates that read it (`needs_endpoints`), so this sort does not
        // pay for one. `min()` over the packed keys is memcmp — the address
        // order.
        //
        // The sentinel `x'ff'` stands for "no address" and is greater than
        // every key (each key starts with the family byte `0x04`/`0x06`), so
        // an endpoint the resolver has not answered for sorts after the
        // addressed ones ascending and before them descending — the reversal
        // the other sorts rely on. It is not a NULL on purpose: every ordering
        // term here is non-null (see `NO_SEEN`/`NO_SPEED`/`CONFIG_OTHER`),
        // and the anchor query binds a sort term's value back into the
        // comparison, which this engine refuses to type for a NULL.
        PageSort::Ip => vec![
            term(
                "COALESCE((SELECT min(ip.ip_key) FROM endpoint_ip ip \
                 WHERE ip.endpoint_id = k.endpoint_id), x'ff')"
                    .to_string(),
                true,
            ),
            term("k.endpoint_id".to_string(), true),
        ],
        // The id IS the rank table's primary key: no `endpoints` join, no
        // temp B-tree, and an order that cannot move while a batch runs (the
        // feed walk's stability requirement, met without sorting by host).
        PageSort::Id => vec![term("k.endpoint_id".to_string(), true)],
    }
}

/// Append `ORDER BY <terms>`.
fn order_by(sql: &mut Sql, order: &[OrderTerm]) {
    sql.push(" ORDER BY ");
    for (i, term) in order.iter().enumerate() {
        if i > 0 {
            sql.push(", ");
        }
        sql.push(&term.expr);
        sql.push(if term.asc { " ASC" } else { " DESC" });
    }
}

/// The page source: endpoints that have at least one link, left-joined to
/// their materialized ordering keys, plus the view / group / search
/// predicates.
///
/// Membership comes from the `EXISTS` terms — the SAME terms
/// [`Database::profiles_page`] counts — so the page and the footer cannot
/// disagree, and an endpoint whose rank row is missing (or stale) still lists;
/// only its position degrades.
fn base_from_where(sql: &mut Sql, req: &PageRequest, join_endpoints: bool) {
    sql.push(" FROM endpoint_rank k");
    if join_endpoints {
        sql.push(" JOIN endpoints e ON e.id = k.endpoint_id");
    }
    sql.push(" WHERE ");
    view_predicate(sql, req);
    if let Some(group_id) = &req.group_id {
        let gid = sql.bind(group_id.clone());
        sql.push(&format!(
            " AND EXISTS (SELECT 1 FROM endpoint_groups eg WHERE eg.endpoint_id = k.endpoint_id \
             AND eg.group_id = {gid})"
        ));
    }
    if let Some(search) = &req.search
        && !search.is_empty()
    {
        // The indexed PREFIX search (db-rewamp D6): the materialized
        // `rank_domain` / `rank_sub_domain` (lowercased) are matched by a byte
        // RANGE (`>= term AND < term||U+10FFFF`) rather than `LIKE '%term%'`,
        // so a keystroke is an index seek, not a full scan.
        //
        // CONTRACT (deliberate, per D6): the match is a PREFIX of the domain or
        // of the sub-domain — never a substring, a suffix, or the assembled
        // full host. `exa` finds `example.com`; `www` finds the `www` label;
        // but typing the whole `www.example.com`, or a mid-name `ample`, matches
        // nothing (the pre-D6 `LIKE '%…%'` did). An IP/CIDR term ranges over the
        // packed `rank_addr`; the port keeps its substring match.
        let term = search.to_lowercase();
        let escaped = escape_like(&term);
        let port_pat = sql.bind(format!("%{escaped}%"));
        let mut clauses = vec![format!("CAST(e.port AS TEXT) LIKE {port_pat} ESCAPE '\\'")];
        if let Some((lo, hi)) = ip_range_bounds(&term) {
            let l = sql.bind(Value::Bytes(lo));
            let h = sql.bind(Value::Bytes(hi));
            clauses.push(format!("(k.rank_addr >= {l} AND k.rank_addr < {h})"));
        } else {
            let l = sql.bind(term.clone());
            let h = sql.bind(format!("{term}\u{10ffff}"));
            clauses.push(format!("(k.rank_domain >= {l} AND k.rank_domain < {h})"));
            let l2 = sql.bind(term.clone());
            let h2 = sql.bind(format!("{term}\u{10ffff}"));
            clauses.push(format!(
                "(k.rank_sub_domain >= {l2} AND k.rank_sub_domain < {h2})"
            ));
        }
        sql.push(&format!(" AND ({})", clauses.join(" OR ")));
    }
    // The plan scope reads the endpoint's MATERIALIZED membership (proven-first
    // bin partition, spec `2026-10-09-stab-bin-design` §5.3). The predicate is
    // a shared const so the page, the walk and the count cannot drift. It is
    // an inline filter over the covering index: `rank_proven` is a trailing
    // covering column, so no scope needs a sorter or a second index.
    if let Some(pred) = req.scope.predicate() {
        sql.push(&format!(" AND ({pred})"));
    }
}

/// Build the aggregate statement for one scope.
///
/// `live_alive` picks the `alive` arm: `true` computes liveness live from
/// `rank_newest_seen` against the TTL (the global group — the swept `band` can
/// lag up to the reband interval); `false` uses the swept `band` (the view
/// group, which must describe the same set the table shows).
///
/// The partition arms are the crate's OWN scope predicates, verbatim
/// (`PlanScope::predicate`): `rank_proven` FIRST, then the bin. A proven
/// endpoint carrying bin 12 is `proven`, NOT `untested` — dropping the
/// `rank_proven = 0` guard would double-count it (spec D28).
fn aggregate_sql(req: &PageRequest, live_alive: bool) -> Sql {
    let mut sql = Sql::new();
    sql.push("SELECT COUNT(*)");
    if live_alive {
        let threshold = sql.bind(req.active_threshold);
        sql.push(&format!(
            ", SUM(CASE WHEN k.rank_newest_seen >= {threshold} THEN 1 ELSE 0 END)"
        ));
    } else {
        sql.push(", SUM(CASE WHEN k.band = 0 THEN 1 ELSE 0 END)");
    }
    sql.push(", SUM(CASE WHEN k.rank_proven = 1 THEN 1 ELSE 0 END)");
    sql.push(", SUM(CASE WHEN k.rank_stab <= 2 THEN 1 ELSE 0 END)");
    sql.push(", SUM(CASE WHEN k.rank_proven = 0 AND k.rank_bin = 12 THEN 1 ELSE 0 END)");
    sql.push(", SUM(CASE WHEN k.rank_proven = 0 AND k.rank_bin IN (13, 14, 15) THEN 1 ELSE 0 END)");
    sql.push(", SUM(CASE WHEN k.rank_proven = 0 AND k.rank_bin NOT IN (12, 13, 14, 15) THEN 1 ELSE 0 END)");
    base_from_where(&mut sql, req, needs_endpoints(req));
    sql
}

/// The view predicate: "has a link matching the window". `Active` and
/// `Purgatory` share the one computed bound and differ only in direction.
fn view_predicate(sql: &mut Sql, req: &PageRequest) {
    // "Some link falls in the band" is the same question as "the newest LIVE
    // link does", so the window reads the stored maximum instead of scanning
    // `profile_stats` per row. `rank_newest_seen` is live-only (decision 16),
    // which makes the two views a single range each: an endpoint whose every
    // link is purged reports `NO_SEEN` and lands in Purgatory by construction,
    // so no `OR` (which would defeat the window index) is needed.
    match req.view {
        PurgatoryView::All => sql.push("1 = 1"),
        // Membership is the materialized `band` — the SOLE Active predicate for
        // every sort, so switching sort column cannot flip the set mid-drift
        // (the reband sweep, not a per-query threshold, moves a row 0→1). A
        // not-yet-banded row (`NULL`) is treated as not-Active by `IS NOT 0`.
        PurgatoryView::Active => sql.push("k.band = 0"),
        PurgatoryView::Purgatory => sql.push("k.band IS NOT 0"),
    }
}

/// `SELECT <projection>` over the page source.
fn base_select(sql: &mut Sql, req: &PageRequest, projection: &str, join_endpoints: bool) {
    sql.push("SELECT ");
    sql.push(projection);
    base_from_where(sql, req, join_endpoints);
}

/// Whether a query needs the `endpoints` row: the search predicate reads the
/// host/port, and the Port sort orders by it.
fn needs_endpoints(req: &PageRequest) -> bool {
    req.search.as_ref().is_some_and(|s| !s.is_empty()) || matches!(req.sort, PageSort::Port)
}

// ── Value decoding ──────────────────────────────────────────────────────

fn decode_id(row: &Value) -> Result<EndpointId> {
    match row {
        Value::Record(record) => match record.fields.first() {
            Some(Value::I64(id)) => Ok(EndpointId::new(*id)),
            other => Err(DatabaseError::Generic(format!(
                "profiles_query: unexpected id column: {other:?}"
            ))),
        },
        other => Err(DatabaseError::Generic(format!(
            "profiles_query: unexpected row: {other:?}"
        ))),
    }
}

fn decode_count(row: &Value) -> Result<u64> {
    match row {
        Value::Record(record) => match record.fields.first() {
            Some(Value::I64(n)) => Ok(u64::try_from(*n).unwrap_or(0)),
            other => Err(DatabaseError::Generic(format!(
                "profiles_query: unexpected count column: {other:?}"
            ))),
        },
        other => Err(DatabaseError::Generic(format!(
            "profiles_query: unexpected row: {other:?}"
        ))),
    }
}

// ── Public queries ──────────────────────────────────────────────────────

impl Database {
    /// One page of endpoint ids in display order, plus the filtered total.
    #[tracing::instrument(target = "db_method", skip_all, fields(retries = tracing::field::Empty))]
    pub async fn profiles_page(&self, req: &PageRequest) -> Result<PageMeta> {
        let _ = self.drain_dirty_ranks().await;
        if let Some(direct) = &self.direct {
            let conn = direct.lock().await;
            return Self::page_ids_direct(&conn, req).await;
        }
        let mut conn = self.connection().await?;
        let total = self.profiles_count_with(&mut conn, req).await?;
        let offset = req.offset.min(usize::try_from(total).unwrap_or(usize::MAX));

        let mut sql = Sql::new();
        base_select(&mut sql, req, PROJ_ID, needs_endpoints(req));
        order_by(&mut sql, &req.order_terms());
        let limit = sql.bind(i64::try_from(req.limit).unwrap_or(i64::MAX));
        let offset_bind = sql.bind(i64::try_from(offset).unwrap_or(i64::MAX));
        sql.push(&format!(" LIMIT {limit} OFFSET {offset_bind}"));

        let rows = sql.exec(&mut conn).await?;
        let ids = rows.iter().map(decode_id).collect::<Result<Vec<_>>>()?;
        Ok(PageMeta { ids, total, offset })
    }

    /// The aggregate counts for one scope, as the Details panel renders them.
    ///
    /// `live_alive` picks the `alive` arm: `true` computes liveness live from
    /// `rank_newest_seen` against the TTL (the global group — the swept `band`
    /// can lag up to the reband interval); `false` uses the swept `band`
    /// (the view group, which must describe the same set the table shows).
    ///
    /// The four partition members (`proven` / `untested` / `failed` / `other`)
    /// sum to `total`; `alive` and `reliable` are orthogonal filters that
    /// overlap any subset.
    #[tracing::instrument(target = "db_method", skip_all, fields(retries = tracing::field::Empty))]
    pub async fn profiles_aggregate(&self, req: &PageRequest, live_alive: bool) -> Result<AggregateCounts> {
        let _ = self.drain_dirty_ranks().await;
        let sql = aggregate_sql(req, live_alive);
        // Same executor branch as every other read here: the direct turso
        // connection in production, the pooled toasty path otherwise.
        let rows = if let Some(direct) = &self.direct {
            let conn = direct.lock().await;
            sql.exec_raw(&conn).await?
        } else {
            let mut conn = self.connection().await?;
            sql.exec(&mut conn).await?
        };
        rows.first().map_or_else(
            || Ok(AggregateCounts::default()),
            AggregateCounts::decode,
        )
    }

    /// One page of the feed walk's ids plus (optionally) the feed-wide count.
    ///
    /// **No production caller since 2026-10-01**: the batch walk now freezes its
    /// whole id set up front (`PlanWalk::next_page`) because ordering by the
    /// decision-16 law made the walk's order result-dependent — see
    /// `docs/aegis/specs/2026-10-01-static-config-weight-design`. This stays as
    /// the STREAMING counterpart: it is what `ops/ping/flow_cost.rs` measures and
    /// what the streaming tests pin. Retire it once the lab stops needing a
    /// streaming baseline.
    ///
    /// One page of endpoint ids for a sequential walk of the whole feed, in
    /// display order.
    ///
    /// [`Self::profiles_page`] re-counts the filtered set on every call, which
    /// made a feed-wide plan walk `O(feed²/200)` (92 `COUNT(*)`s for one
    /// 18,334-endpoint batch, 2026-09-17). A walk asks for the total once
    /// (`with_total`) and then reads ids only. Same builders, same ordering,
    /// same offset paging as the page query — the parity test pins them
    /// together.
    #[tracing::instrument(target = "db_method", skip_all, fields(retries = tracing::field::Empty))]
    pub async fn profiles_walk_page(
        &self,
        req: &PageRequest,
        with_total: bool,
    ) -> Result<(Vec<EndpointId>, Option<u64>)> {
        let mut conn = self.connection().await?;
        let total = if with_total {
            Some(self.profiles_count_with(&mut conn, req).await?)
        } else {
            None
        };

        let mut sql = Sql::new();
        base_select(&mut sql, req, PROJ_ID, needs_endpoints(req));
        order_by(&mut sql, &req.order_terms());
        let limit = sql.bind(i64::try_from(req.limit).unwrap_or(i64::MAX));
        let offset_bind = sql.bind(i64::try_from(req.offset).unwrap_or(i64::MAX));
        sql.push(&format!(" LIMIT {limit} OFFSET {offset_bind}"));

        let rows = sql.exec(&mut conn).await?;
        let ids = rows.iter().map(decode_id).collect::<Result<Vec<_>>>()?;
        Ok((ids, total))
    }

    /// The page's ids + total over the long-lived direct connection (T13) —
    /// no toasty execution layer, which is the measured 80× gap.
    async fn page_ids_direct(conn: &turso::Connection, req: &PageRequest) -> Result<PageMeta> {
        let mut count_sql = Sql::new();
        count_sql.push("SELECT COUNT(*)");
        base_from_where(
            &mut count_sql,
            req,
            req.search.as_ref().is_some_and(|s| !s.is_empty()),
        );
        let total = count_sql
            .exec_direct(conn)
            .await?
            .first()
            .and_then(|v| match v {
                Value::I64(n) => u64::try_from(*n).ok(),
                _ => None,
            })
            .unwrap_or(0);
        let offset = req.offset.min(usize::try_from(total).unwrap_or(usize::MAX));

        let mut sql = Sql::new();
        base_select(&mut sql, req, PROJ_ID, needs_endpoints(req));
        order_by(&mut sql, &req.order_terms());
        let limit = sql.bind(i64::try_from(req.limit).unwrap_or(i64::MAX));
        let offset_bind = sql.bind(i64::try_from(offset).unwrap_or(i64::MAX));
        sql.push(&format!(" LIMIT {limit} OFFSET {offset_bind}"));
        let rows = sql.exec_direct(conn).await?;
        // `exec_direct` already reduced each row to its integer column.
        let ids = rows
            .iter()
            .map(|v| match v {
                Value::I64(n) => Ok(EndpointId::new(*n)),
                other => Err(DatabaseError::Generic(format!(
                    "profiles_page (direct): unexpected id {other:?}"
                ))),
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(PageMeta { ids, total, offset })
    }

    async fn profiles_count_with(
        &self,
        conn: &mut toasty::Connection,
        req: &PageRequest,
    ) -> Result<u64> {
        let mut sql = Sql::new();
        sql.push("SELECT COUNT(*)");
        // COUNT never orders, so it needs the `endpoints` join ONLY when the
        // search predicate reads host/port — not for a Port-sorted page.
        base_from_where(
            &mut sql,
            req,
            req.search.as_ref().is_some_and(|s| !s.is_empty()),
        );
        let rows = sql.exec(conn).await?;
        rows.first().map_or(Ok(0), decode_count)
    }

    /// Offset the endpoint currently occupies in the ordered view — used to
    /// re-anchor the window when a re-sort moves the selected row out of it.
    ///
    /// Counts the rows that sort strictly before the target, using the SAME
    /// term expressions and directions the page orders by, so it is exact for
    /// every sort and direction rather than only the default one.
    #[tracing::instrument(target = "db_method", skip_all, fields(retries = tracing::field::Empty))]
    pub async fn profiles_anchor(
        &self,
        req: &PageRequest,
        endpoint_id: EndpointId,
    ) -> Result<Option<usize>> {
        let mut conn = self.connection().await?;
        let terms = req.order_terms();

        // The target's own key values, read through the same expressions.
        let key_projection = terms
            .iter()
            .map(|t| t.expr.clone())
            .collect::<Vec<_>>()
            .join(", ");
        let mut key_sql = Sql::new();
        key_sql.push(&format!("SELECT {key_projection}"));
        // The Port sort reads an endpoint column, so its key query needs the
        // join the page query also takes for it.
        key_sql.push(" FROM endpoint_rank k");
        if needs_endpoints(req) {
            key_sql.push(" JOIN endpoints e ON e.id = k.endpoint_id");
        }
        key_sql.push(" WHERE k.endpoint_id = ");
        let bind = key_sql.bind(endpoint_id.get());
        key_sql.push(&bind);
        let rows = key_sql.exec(&mut conn).await?;
        let Some(Value::Record(record)) = rows.first() else {
            return Ok(None);
        };
        let target = record.fields.clone();
        if target.len() != terms.len() {
            return Err(DatabaseError::Generic(
                "profiles_query: anchor key arity mismatch".to_string(),
            ));
        }

        // Lexicographic "sorts strictly before the target": equal on every
        // earlier term, strictly before on this one. The term expressions and
        // directions are the ones `ORDER BY` uses, so this holds for every
        // sort and both directions.
        let mut sql = Sql::new();
        sql.push("SELECT COUNT(*)");
        base_from_where(&mut sql, req, needs_endpoints(req));
        sql.push(" AND (");
        for (i, term) in terms.iter().enumerate() {
            if i > 0 {
                sql.push(" OR ");
            }
            sql.push("(");
            for (j, prefix) in terms.iter().take(i).enumerate() {
                let eq = sql.bind(target[j].clone());
                sql.push(&format!("{} = {eq} AND ", prefix.expr));
            }
            let cmp = sql.bind(target[i].clone());
            let op = if term.asc { "<" } else { ">" };
            sql.push(&format!("{} {op} {cmp})", term.expr));
        }
        sql.push(")");

        let rows = sql.exec(&mut conn).await?;
        let Some(row) = rows.first() else {
            return Ok(None);
        };
        let offset = decode_count(row)?;
        Ok(Some(usize::try_from(offset).unwrap_or(0)))
    }
}

// ── Page projection: one statement per page (H1) ────────────────────────

/// The projection's columns, in decode order.
///
/// The SQL text and the positional decoder both read this list, so a column
/// can never be read at the wrong index. Every `endpoints` and
/// `profile_stats` column is present; `protocols` omits its three deferred
/// JSON carriers (`transport_data`, `security_data`, `config`) — no page
/// consumer reads them, and decoding them is what made the typed page
/// hydration cost ~0.5 s on the reference feed (7,672 endpoints).
const PAGE_PROJECTION: &[&str] = &[
    // endpoints (11)
    "e.id",
    "e.domain",
    "e.sub_domain",
    "e.port",
    "e.ports",
    "e.last_source",
    "e.manual_protocol_override",
    // The resolved address set, from the table that owns it (one row per
    // address, PK `(endpoint_id, ip_key)`). The column is the PACKED address,
    // so the aggregate carries its hex and the decoder rebuilds the
    // `IpAddr` — the engine has no `inet_ntoa`-style renderer (measured: the
    // function does not exist), and storing a text copy beside the bytes
    // would be a second, disagreeable spelling of the same fact.
    //
    // The rows come back in the PK scan order, i.e. key order — the same order
    // the IP sort and the panel show — so the list needs no ORDER BY inside
    // the aggregate (a correlated derived table with one would be materialized
    // per row: measured 389 ms for a page against 29 ms for this shape).
    "(SELECT group_concat(hex(ip_key), ',') FROM endpoint_ip ip WHERE ip.endpoint_id = e.id)",
    "e.resolved_at",
    "e.created_at",
    // profile_stats (26)
    "ps.protocol_id",
    "ps.endpoint_id",
    "ps.last_used_at",
    "ps.last_seen_at",
    "ps.latency_real_delay",
    "ps.latency_fast_delay",
    "ps.latency_ip",
    "ps.latency_auth",
    "ps.speed_bps",
    "ps.error",
    "ps.error_kind",
    "ps.error_text",
    "ps.purge_reason",
    "ps.stab_mask",
    "ps.stab_len",
    "ps.traffic_today_up",
    "ps.traffic_today_down",
    "ps.traffic_total_up",
    "ps.traffic_total_down",
    "ps.created_at",
    "ps.updated_at",
    "ps.version",
    // protocols (10; the JSON carriers are absent on purpose)
    "pr.id",
    "pr.sig",
    "pr.proto_kind",
    "pr.transport_type",
    "pr.security_type",
    "pr.security_sni",
    "pr.security_fp",
    "pr.security_insecure",
    "pr.created_at",
];

/// Positional reader over one projection row.
///
/// The driver hands back each SQLite column as a bare [`Value`]
/// (`I64`/`String`/`Null`), never as the engine's converted shapes, so the
/// JSON-array and timestamp columns are decoded here from their stored text
/// and everything else through toasty's own [`Load`] impl.
struct Projection<'a> {
    fields: &'a [Value],
    at: usize,
}

impl<'a> Projection<'a> {
    fn new(row: &'a Value) -> Result<Self> {
        match row {
            Value::Record(record) => Ok(Self {
                fields: &record.fields,
                at: 0,
            }),
            other => Err(DatabaseError::Generic(format!(
                "profiles_query: unexpected row: {other:?}"
            ))),
        }
    }

    /// The next column's raw value.
    fn take(&mut self) -> Result<Value> {
        let value = self.fields.get(self.at).cloned().ok_or_else(|| {
            DatabaseError::Generic(format!(
                "profiles_query: projection row has {} columns, column {} wanted",
                self.fields.len(),
                self.at + 1
            ))
        })?;
        self.at += 1;
        Ok(value)
    }

    /// The next column, decoded through `T`'s own `Load` impl — the same one
    /// the typed reads use, so an enum or scalar can never decode differently
    /// here than it does on the ORM path.
    fn next<T: Load<Output = T>>(&mut self) -> Result<T> {
        let column = self.at;
        let value = self.take()?;
        T::load(value).map_err(|e| {
            DatabaseError::Generic(format!(
                "profiles_query: projection column {column} ({}): {e}",
                PAGE_PROJECTION.get(column).copied().unwrap_or("?")
            ))
        })
    }

    fn next_i64(&mut self) -> Result<i64> {
        let column = self.at;
        match self.take()? {
            Value::I64(n) => Ok(n),
            other => Err(DatabaseError::Generic(format!(
                "profiles_query: projection column {column} ({}): expected an integer, got {other:?}",
                PAGE_PROJECTION.get(column).copied().unwrap_or("?")
            ))),
        }
    }

    fn next_opt_i64(&mut self) -> Result<Option<i64>> {
        let column = self.at;
        match self.take()? {
            Value::Null => Ok(None),
            Value::I64(n) => Ok(Some(n)),
            other => Err(DatabaseError::Generic(format!(
                "profiles_query: projection column {column} ({}): expected an integer or NULL, got {other:?}",
                PAGE_PROJECTION.get(column).copied().unwrap_or("?")
            ))),
        }
    }

    fn next_endpoint_id(&mut self) -> Result<EndpointId> {
        Ok(EndpointId::new(self.next_i64()?))
    }

    fn next_protocol_id(&mut self) -> Result<ProtocolId> {
        Ok(ProtocolId::new(self.next_i64()?))
    }

    fn next_opt_protocol_id(&mut self) -> Result<Option<ProtocolId>> {
        Ok(self.next_opt_i64()?.map(ProtocolId::new))
    }

    /// SQLite stores BOOLEAN as an INTEGER, which `Load` for `bool` rejects.
    fn next_opt_bool(&mut self) -> Result<Option<bool>> {
        Ok(self.next_opt_i64()?.map(|n| n != 0))
    }

    /// The next TEXT column, NULL as `None`.
    fn next_opt_string(&mut self) -> Result<Option<String>> {
        let column = self.at;
        match self.take()? {
            Value::Null => Ok(None),
            Value::String(s) => Ok(Some(s)),
            other => Err(DatabaseError::Generic(format!(
                "profiles_query: projection column {column} ({}): expected text or NULL, got {other:?}",
                PAGE_PROJECTION.get(column).copied().unwrap_or("?")
            ))),
        }
    }

    /// A JSON-array TEXT column (`ports`, `task_queue`): the stored text is
    /// what toasty itself wrote, so parsing it directly is exact.
    fn next_u16_vec(&mut self) -> Result<Vec<u16>> {
        let (column, text) = self.take_json_text()?;
        serde_json::from_str(&text).map_err(|e| {
            DatabaseError::Generic(format!(
                "profiles_query: projection column {column} ({}): invalid JSON array: {e}",
                PAGE_PROJECTION.get(column).copied().unwrap_or("?")
            ))
        })
    }

    fn take_json_text(&mut self) -> Result<(usize, String)> {
        let column = self.at;
        let text: String = self.next()?;
        Ok((column, text))
    }

    /// An epoch-seconds INTEGER timestamp column.
    fn next_ts(&mut self) -> Result<i64> {
        self.next_i64()
    }

    fn next_opt_ts(&mut self) -> Result<Option<i64>> {
        self.next_opt_i64()
    }
}

/// `endpoints` (11 columns, in [`PAGE_PROJECTION`] order).
fn decode_projected_endpoint(p: &mut Projection<'_>) -> Result<(Endpoint, Vec<IpAddr>)> {
    let id = p.next_endpoint_id()?;
    let domain: String = p.next()?;
    let sub_domain: String = p.next()?;
    let port: u16 = p.next()?;
    let ports: Vec<u16> = p.next_u16_vec()?;
    let last_source: Option<String> = p.next()?;
    let manual_protocol_override = p.next_opt_protocol_id()?;
    let resolved_ips = p.next_opt_string()?.map_or_else(Vec::new, |text| {
        let mut ips: Vec<std::net::IpAddr> = text
            .split(',')
            .filter_map(crate::endpoint_ip::key_from_hex)
            .collect();
        // Sorted by address, not by whatever order the aggregate emitted: the
        // display order must be the table's order (IPv4 then IPv6, by
        // address), and an aggregate's order is not a contract.
        ips.sort_unstable();
        ips
    });
    let resolved_at = p.next_opt_ts()?;
    let created_at = p.next_ts()?;
    Ok((
        Endpoint {
            id,
            domain,
            sub_domain,
            port,
            ports,
            last_source,
            manual_protocol_override,
            resolved_at,
            created_at,
            links: Deferred::default(),
            group_links: Deferred::default(),
        },
        resolved_ips,
    ))
}

/// `profile_stats` (25 columns, in [`PAGE_PROJECTION`] order). The three
/// multi-column embeds (`latency`, `error`, `traffic`) are flattened in the
/// table, so they are reassembled by hand — the parity test against
/// [`Database::load_page_rows`] pins every one of them.
fn decode_projected_link(p: &mut Projection<'_>) -> Result<ProfileStats> {
    let protocol_id = p.next_protocol_id()?;
    let endpoint_id = p.next_endpoint_id()?;
    let last_used_at = p.next_opt_ts()?;
    let last_seen_at = p.next_ts()?;
    let latency_real_delay: Option<i64> = p.next()?;
    let latency_fast_delay: Option<i64> = p.next()?;
    let latency_ip: Option<String> = p.next()?;
    let latency_auth: Option<i64> = p.next()?;
    let speed_bps: Option<i64> = p.next()?;
    let error_flag = p.next_opt_bool()?;
    let error_kind: Option<ProfileErr> = p.next()?;
    let error_text: Option<String> = p.next()?;
    // Only the Active view's panel hides purged links; the page decides which
    // links it asked for, so this column is always decoded.
    let purge_reason: Option<PurgeReason> = p.next()?;
    let stab_mask: i64 = p.next()?;
    let stab_len: i64 = p.next()?;
    let today_up: i64 = p.next()?;
    let today_down: i64 = p.next()?;
    let total_up: i64 = p.next()?;
    let total_down: i64 = p.next()?;
    let created_at = p.next_ts()?;
    let updated_at = p.next_ts()?;
    let version: u64 = p.next()?;

    // The two delay columns carry the provenance now (schema 19): a row can
    // hold BOTH, and the real one outranks the fast one.
    let latency = Latency {
        real_delay: latency_real_delay.map(|d| i32::try_from(d).unwrap_or(i32::MAX)),
        fast_delay: latency_fast_delay.map(|d| i32::try_from(d).unwrap_or(i32::MAX)),
        ip: latency_ip,
        auth: latency_auth,
    };
    let error = match (error_flag, error_kind) {
        // `ErrorInfo.text` is not optional: the flag only ever accompanies a
        // text on the write paths, so a missing one is a corrupt row.
        (Some(true), Some(kind)) => Some(ErrorInfo {
            kind,
            text: error_text.unwrap_or_default(),
        }),
        (Some(true), None) => {
            return Err(DatabaseError::Generic(
                "profiles_query: link carries an error flag without a kind".to_string(),
            ));
        }
        _ => None,
    };

    Ok(ProfileStats {
        protocol_id,
        endpoint_id,
        last_used_at,
        last_seen_at,
        latency,
        speed_bps,
        error,
        purge_reason,
        stab_mask,
        stab_len,
        traffic: TrafficStats {
            today_up,
            today_down,
            total_up,
            total_down,
        },
        created_at,
        updated_at,
        version,
        protocol: Deferred::default(),
        endpoint: Deferred::default(),
    })
}

/// `protocols` (10 columns, in [`PAGE_PROJECTION`] order). `None` when the
/// link's protocol row is absent: the join is LEFT and every `pr.*` column is
/// NULL together, exactly as [`Database::load_endpoint_rows`] drops it.
fn decode_projected_protocol(p: &mut Projection<'_>) -> Result<Option<Protocol>> {
    let id: Option<i64> = p.next()?;
    let sig: Option<i64> = p.next()?;
    let proto_kind: Option<ProtocolKind> = p.next()?;
    let transport_type: Option<TransportType> = p.next()?;
    let security_type: Option<SecurityType> = p.next()?;
    let sni: Option<String> = p.next()?;
    let fp: Option<String> = p.next()?;
    let insecure = p.next_opt_bool()?;
    let created_at: Option<i64> = p.next_opt_ts()?;

    let Some(id) = id else {
        debug_assert_eq!(
            [sig.is_none(), proto_kind.is_none()],
            [true; 2],
            "a LEFT JOIN nulls every protocol column together"
        );
        return Ok(None);
    };
    let (Some(sig), Some(proto_kind), Some(transport_type), Some(security_type), Some(created_at)) =
        (sig, proto_kind, transport_type, security_type, created_at)
    else {
        return Err(DatabaseError::Generic(
            "profiles_query: partial protocol row".to_string(),
        ));
    };
    Ok(Some(Protocol {
        id: ProtocolId::new(id),
        sig,
        proto_kind,
        transport: Transport {
            r#type: transport_type,
        },
        security: Security {
            r#type: security_type,
            sni,
            fp,
            insecure,
        },
        config: Deferred::default(),
        created_at,
        links: Deferred::default(),
    }))
}

impl Database {
    /// One page's rows in ONE statement: the endpoints, their links and the
    /// links' protocol display columns, joined and decoded positionally.
    ///
    /// The typed path ([`Database::load_page_rows`]) spends most of its time
    /// binding the page's ids into three `IN (...)` hydration reads — turso
    /// charges ~0.8 ms per bound parameter, and there are ~600 of them for a
    /// 200-row page (measured: 488 ms end to end, 29 ms for the same rows
    /// returned by a single inlined-id statement). The ids are therefore
    /// inlined as integer literals — the same rule
    /// [`crate::endpoint_rank::refresh`] follows — and the projection carries
    /// only display columns, so no deferred JSON is decoded.
    ///
    /// `ids` are page ids (they all have at least one link — the page source
    /// requires it), returned in the order given. The deferred `config` JSON
    /// carrier on `Protocol` comes back unloaded: reading it is a bug, not a
    /// fallback, because the connect path re-reads its protocol through
    /// [`Database::load_protocol_with_config`].
    #[tracing::instrument(target = "db_method", skip_all, fields(retries = tracing::field::Empty))]
    pub async fn load_page_projection(
        &self,
        ids: &[EndpointId],
        include_purged: bool,
    ) -> Result<Vec<EndpointRow>> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let mut sql = Sql::new();
        sql.push("SELECT ");
        sql.push(&PAGE_PROJECTION.join(", "));
        sql.push(
            " FROM endpoints e JOIN profile_stats ps ON ps.endpoint_id = e.id \
             LEFT JOIN protocols pr ON pr.id = ps.protocol_id WHERE e.id IN (",
        );
        for (i, id) in ids.iter().enumerate() {
            if i > 0 {
                sql.push(", ");
            }
            sql.push(&id.get().to_string());
        }
        sql.push(")");
        // The Active view is the effective-profiles list: a purged sibling of a
        // live link is hidden there and shown in Purgatory/All (spec §5).
        if !include_purged {
            sql.push(" AND ps.purge_reason IS NULL");
        }
        // The ids are inlined as literals, so this statement's text is unique
        // per page. toasty's driver routes every statement through the
        // connection's `prepare_cached`, whose statement map is unbounded and
        // keyed by text — so each page's fresh text would compile and retain a
        // program for the connection's life. Run it on the raw connection
        // (`query` = uncached `prepare`) when one exists; the toasty path stays
        // for an in-memory db (no second connection) and is the oracle the raw
        // path is pinned to (`page_projection_raw_matches_toasty`).
        let rows = if let Some(direct) = &self.direct {
            let conn = direct.lock().await;
            sql.exec_raw(&conn).await?
        } else {
            let mut conn = self.connection().await?;
            sql.exec(&mut conn).await?
        };

        let mut endpoints: HashMap<EndpointId, (Endpoint, Vec<IpAddr>)> = HashMap::new();
        let mut links: HashMap<EndpointId, Vec<ProfileStats>> = HashMap::new();
        let mut protocols: HashMap<ProtocolId, Protocol> = HashMap::new();
        for row in &rows {
            let mut p = Projection::new(row)?;
            let (endpoint, resolved_ips) = decode_projected_endpoint(&mut p)?;
            let link = decode_projected_link(&mut p)?;
            let protocol = decode_projected_protocol(&mut p)?;
            links.entry(endpoint.id).or_default().push(link);
            endpoints
                .entry(endpoint.id)
                .or_insert((endpoint, resolved_ips));
            if let Some(protocol) = protocol {
                protocols.entry(protocol.id).or_insert(protocol);
            }
        }

        let mut out = Vec::with_capacity(ids.len());
        for id in ids {
            let Some((endpoint, resolved_ips)) = endpoints.remove(id) else {
                continue;
            };
            let links = links.remove(id).unwrap_or_default();
            let protocols = links
                .iter()
                .filter_map(|l| protocols.get(&l.protocol_id).map(|p| (p.id, p.clone())))
                .collect();
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
            row.select_best_measured_link();
            out.push(row);
        }
        Ok(out)
    }
}
