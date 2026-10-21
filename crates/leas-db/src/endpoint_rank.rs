//! Materialized per-endpoint ordering keys.
//!
//! The Profiles page used to derive each endpoint's position from a
//! `ROW_NUMBER() OVER (PARTITION BY endpoint_id …)` window over every link
//! plus correlated subqueries for the display-link sorts. On the reference
//! feed (7,672 endpoints / 9,048 links) that cost ~975 ms per page fetch: the
//! window re-evaluates the ordering law for the whole table on every page.
//! Storing the keys and reading them through an index makes the same page
//! ~1 ms (measured; the plan is `SCAN … USING COVERING INDEX`).
//!
//! The keys are DERIVED STATE of the decision-16 law. The law is implemented
//! ONCE, here, over a minimal [`RankLink`] view — `EndpointRow::link_test_key`
//! delegates to it, so the panel order, the stored keys, and the parity golden
//! cannot drift apart. SQL only stores the numbers and reads them back; it
//! never re-derives the law.

use std::collections::HashMap;

use toasty_core::driver::operation::TransactionMode;
use toasty_core::stmt::Value;

use crate::models_toasty::{
    Endpoint, EndpointId, EndpointRank, EndpointRow, ProfileErr, ProfileStats, Protocol, ProtocolId,
};
use leas_proto::proto_spec::{
    SecurityType, TransportType,
    weight::{ConfigWeight, ZERO_WEIGHT, weight_of},
};

/// Sentinel for "no display link": sorts before any real timestamp, matching
/// the retired SQL `COALESCE(<seen>, '')` (empty text sorts first ascending).
pub const NO_SEEN: i64 = i64::MIN;
/// Process-wide Active-view TTL (seconds). `band` is materialized against
/// `now − this` at write and sweep time, so the DB layer needs the same ttl
/// the page uses. Set once at startup (and on settings save) from the config;
/// defaults to 7 days so a write before the setter runs is still sensible.
static ACTIVE_TTL_SECS: std::sync::atomic::AtomicI64 = std::sync::atomic::AtomicI64::new(7 * 86400);

/// Set the Active-view TTL used to materialize `band` (startup + settings save).
pub fn set_active_ttl_secs(secs: i64) {
    ACTIVE_TTL_SECS.store(secs, std::sync::atomic::Ordering::Relaxed);
}

/// The link facts the ordering law reads. Built from a typed `ProfileStats`
/// when one is in hand, or straight from the stored columns when the refresh
/// path would otherwise pay ~0.8 ms per bound id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RankLink {
    pub protocol_id: i64,
    /// `Some(real)` / `Some(fast)` for a measured link (the flag is "is it a
    /// real ping"), `None` when the link carries no latency.
    pub measured: Option<bool>,
    pub delay: i32,
    pub error_kind: Option<ProfileErr>,
    /// Epoch seconds of the link's `last_seen_at` (the recency tiebreak).
    pub seen_secs: i64,
    pub speed: Option<i64>,
    pub traffic: i64,
    /// The link carries a purge verdict (spec `2026-09-17-purge-reason`). It can
    /// no longer represent the endpoint while a live link exists.
    pub purged: bool,
    /// The link's stability bin, `0` (best) `..=7` (worst) — its recent
    /// real-probe success rate, coarsened (spec `2026-10-09-stab-bin-design`).
    /// Derived from the ring at construction, never stored on [`RankLink`] as a
    /// mask: nothing above the law needs the raw bits.
    pub stab: u8,
    /// The link's ring holds at least one success — the input to the endpoint
    /// `proven` OR. Not part of the key: reliability orders, it does not
    /// represent.
    pub proven: bool,
    /// Whether the link's NEWEST ring sample succeeded (`None`: never
    /// sampled). The live-first representative/display predicate (spec
    /// `2026-10-20-stab-alive-design` D3/D4), derived once at construction so
    /// the panel order, the stored keys, and the display link cannot drift.
    pub latest_ok: Option<bool>,
    /// The static config weight — the compiled "which stack is likelier to
    /// work" prior (spec `2026-10-01-static-config-weight-design`).
    ///
    /// A FIELD, not something a `ProfileStats` conversion can derive: that row
    /// carries no protocol. Every construction site resolves it and passes it
    /// to [`RankLink::new`]; there is deliberately no weight-less constructor.
    pub weight: ConfigWeight,
}

/// The weight as the packed `u64` the law compares and the DB stores.
///
/// Big-endian packing puts the dominant `security` band in the most significant
/// bytes, so this number and the memcmp order of the stored BLOB are the same
/// order by construction.
#[must_use]
pub const fn weight_u64(weight: ConfigWeight) -> u64 {
    u64::from_be_bytes(weight.to_be_bytes())
}

/// The representative-LINK key tuple: `(bin, stab, !weight, -seen, protocol_id)`.
pub type LinkKey = (u8, u8, u64, i64, i64);

/// The ONE statement of the live-first representative rule (spec
/// `2026-10-20-stab-alive-design` D3).
///
/// The rule: the min-key link among links whose NEWEST ring sample succeeded
/// and that carry no purge verdict; when no link
/// is live, the plain min-key link. Every representative choice — the stored
/// rank keys and the typed in-memory panel — reads this, so the panel order,
/// the stored keys, and the parity golden cannot drift apart.
///
/// Returns the chosen link's index and its key.
#[must_use]
pub fn representative_index(links: &[RankLink], dns_unresolved: bool) -> Option<(usize, LinkKey)> {
    let live = |(_, l): &(usize, &RankLink)| !l.purged && l.latest_ok == Some(true);
    links
        .iter()
        .enumerate()
        .filter(&live)
        .map(|(i, l)| (i, l.key(dns_unresolved)))
        .min_by_key(|&(_, key)| key)
        .or_else(|| {
            links
                .iter()
                .enumerate()
                .map(|(i, l)| (i, l.key(dns_unresolved)))
                .min_by_key(|&(_, key)| key)
        })
}

impl RankLink {
    /// Build a link view. The weight is REQUIRED, not defaulted: it comes from
    /// the link's protocol, which this row does not carry.
    #[must_use]
    pub fn new(link: &ProfileStats, weight: ConfigWeight) -> Self {
        // A row's provenance is carried by WHICH delay column is populated
        // (schema 19): a real delay outranks a fast one of any delay, so the
        // real one is read first and the fast one only when there is no real
        // measurement.
        let (measured, delay) = match (link.latency.real_delay, link.latency.fast_delay) {
            (Some(delay), _) => (Some(true), delay),
            (None, Some(delay)) => (Some(false), delay),
            (None, None) => (None, i32::MAX),
        };
        let (mask, len) = (
            link.stab_mask.cast_unsigned(),
            u8::try_from(link.stab_len.clamp(0, i64::from(STAB_WINDOW))).unwrap_or(0),
        );
        Self {
            protocol_id: link.protocol_id.get(),
            measured,
            delay,
            error_kind: link.error.as_ref().map(|e| e.kind),
            seen_secs: link.last_seen_at,
            speed: link.speed_bps,
            traffic: link
                .traffic
                .total_up
                .saturating_add(link.traffic.total_down),
            purged: link.purge_reason.is_some(),
            // A negative or oversized stored len is a corrupt row: clamp rather
            // than shift by >63 (which is UB-ish in debug) or index a bogus bin.
            stab: stab_bin(mask, len),
            proven: stab_proven(mask, len),
            latest_ok: stab_latest_ok(mask, len),
            weight,
        }
    }

    /// Ascending key `(bin, stab, !weight, -seen, protocol_id)` — the
    /// representative-LINK key (db-rewamp D11 + stab-bin spec +
    /// `2026-10-20-stab-alive-design` D2/D3). The bin buckets delay AND error
    /// class (see [`Self::bin`]); the weight is NEGATED (`u64::MAX -`) so this
    /// stays ONE plain ascending tuple consumed by a single `.min()`, exactly
    /// like the negated recency below: a `Reverse` or any non-tuple wrapper
    /// would fork the single-implementation property the panel order and the
    /// stored keys both depend on. Higher weight = better, and — deliberately,
    /// at the accepted cost of the feature — it outranks the raw delay inside
    /// a bin, so a 900 ms REALITY link sorts above a 40 ms TCP one.
    ///
    /// The purged bin (16) sits below every live band, so an endpoint's
    /// representative key is a live link whenever one exists; an endpoint
    /// whose links are all purged still gets a deterministic position for the
    /// Purgatory/All views.
    #[must_use]
    pub const fn key(&self, dns_unresolved: bool) -> (u8, u8, u64, i64, i64) {
        // The representative-LINK key (db-rewamp D11 + stab-bin spec): delay
        // BIN, then STABILITY bin, then negated weight, then recency and
        // protocol id. `latency` is gone (the bin buckets it); recency stays as
        // a LINK tiebreak so the newest link represents its endpoint — it is
        // deliberately NOT in the endpoint key (which orders by
        // `domain`/`sub_domain`/`addr`), only in this same-endpoint selection.
        //
        // Stability sits BEFORE the weight on purpose: inside one delay bin a
        // link that has proved reliable outranks a heavier stack that keeps
        // failing. The weight is the prior for the links stability has no
        // evidence about (neutral bin), not a trump card.
        (
            self.bin(dns_unresolved),
            self.stab,
            u64::MAX - weight_u64(self.weight),
            -self.seen_secs,
            self.protocol_id,
        )
    }

    /// The delay bin (db-rewamp D11 + spec `2026-10-20-stab-alive-design`
    /// D2): real<50..real≥1000 = 0-5, fast<50..fast≥1000 = 6-11, untested =
    /// 12, dns-err = 15, purged = 16. A real measurement stays above a fast
    /// one of any delay.
    ///
    /// An error no longer dominates a known-good delay: a real/name error
    /// keeps the link's STORED latency bin while the link's ring holds a real
    /// success (`proven`) — the recent failure demotes through the stab bin —
    /// and falls to 13 only when the ring has no success at all (never
    /// succeeded, or the window died). The fast-error arm is UNCHANGED: a
    /// fast failure never samples the ring, so the stab demotion cannot
    /// express it.
    #[must_use]
    pub const fn bin(&self, dns_unresolved: bool) -> u8 {
        if self.purged {
            return 16;
        }
        if dns_unresolved {
            return 15;
        }
        if let Some(kind) = &self.error_kind {
            if matches!(kind, ProfileErr::Real | ProfileErr::Name) {
                if !self.proven {
                    return 13;
                }
                return match self.measured {
                    Some(true) => delay_bin(self.delay),
                    Some(false) => 6 + delay_bin(self.delay),
                    None => 13,
                };
            }
            return 14;
        }
        match self.measured {
            Some(true) => delay_bin(self.delay),
            Some(false) => 6 + delay_bin(self.delay),
            None => 12,
        }
    }
}

/// `0..5` for a delay: `<50 <100 <250 <500 <1000 ≥1000`.
const fn delay_bin(delay: i32) -> u8 {
    if delay < 50 {
        0
    } else if delay < 100 {
        1
    } else if delay < 250 {
        2
    } else if delay < 500 {
        3
    } else if delay < 1000 {
        4
    } else {
        5
    }
}

// ── Stability ring (spec `2026-10-09-stab-bin-design`) ──────────────────
//
// A link's recent real-probe outcomes, packed as a ring of the last
// `STAB_WINDOW` samples: bit `i` is the `i`-th OLDEST live sample, `1` = the
// probe succeeded. Only real-level evidence appends (a real probe that ran, or
// — in a real-capable batch — the hard-fast failure that retired it); a fast
// success never does, and a fast-ONLY batch never does.
//
// The ring rather than two counters because a counter cannot evict ONE
// outcome: a tumbling reset throws the whole window away at once and makes
// `stab_bin` sawtooth. `bits [len, 64)` are always zero, so `count_ones()` is
// the success count at every length.

/// The stability derivation's own version.
///
/// An edit to the `stab_bin` thresholds (or to
/// `STAB_WINDOW`/`STAB_WARMUP`/`STAB_NEUTRAL`) invalidates every STORED
/// `rank_stab` exactly as a weight-cell edit invalidates every stored
/// `rank_weight`. Bump on any such change.
///
/// v2 (spec `2026-10-20-stab-alive-design`): the bin law reads the stored
/// latency through a real error (last-good-delay bin) and the representative
/// is live-first — every stored `rank_bin`/`rank_stab` pair must re-derive.
pub const STAB_VERSION: u32 = 2;

/// The version of every INPUT to the stored rank keys — the compiled weight
/// tables *and* the stability thresholds. The stamp in `rank_weight_meta` holds
/// this one number, so a mismatch rebuilds both `rank_weight` and
/// `rank_stab`/`rank_proven` in a single pass; a second meta table would be a
/// second staleness path for one fact (spec `2026-10-09-stab-bin-design` §6.4).
///
/// The folded form changes whenever either input does, and an existing
/// database's stored `WEIGHT_VERSION`-only value never equals it, so the first
/// open after this feature ships recomputes once — which is what the new
/// `rank_stab`/`rank_proven` columns need anyway.
// `as` (not `From`) because a `const` cannot call a `From` impl on this
// toolchain; both casts are lossless by construction (`u32` -> `i64`).
#[allow(clippy::cast_lossless)]
const KEY_INPUTS_VERSION: i64 =
    (crate::weight::WEIGHT_VERSION as i64) * 100 + (STAB_VERSION as i64);

/// The running code's key-input version, for tests that assert what an open
/// stamps into `rank_weight_meta`.
#[must_use]
pub const fn key_inputs_version() -> i64 {
    KEY_INPUTS_VERSION
}

/// Samples in the window.
///
/// One real sample per link per batch run, so this is ~2 weeks of daily runs:
/// long enough to survive a bad week, short enough that a dead link does not
/// squat in `Successful` for a month (hard-dead cleanup is purge's job, not
/// stability's).
pub const STAB_WINDOW: u8 = 16;

/// Samples needed before the ratio is trusted. `> 1` so the day-one seed
/// (one success) stays neutral until there is repeat evidence.
pub const STAB_WARMUP: u8 = 4;

/// The bin for "no estimate": warm-up, never-sampled.
///
/// The one value with a nameable rule — an untested link outranks a link that
/// loses more often than it wins. Used three ways and they must not drift: the
/// warm-up return, the `rank_stab` column DEFAULT, and the panel's "no data"
/// rendering.
pub const STAB_NEUTRAL: u8 = 4;

/// Append one outcome to the ring, returning the new `(mask, len)`.
///
/// Two distinct arms on purpose: below the window the new sample is the NEWEST,
/// so every existing bit keeps its own index; at the window the oldest shifts
/// out and the new one enters at the top.
#[must_use]
pub const fn append_sample(mask: u64, len: u8, ok: bool) -> (u64, u8) {
    let bit = if ok { 1u64 } else { 0u64 };
    if len < STAB_WINDOW {
        (mask | (bit << len), len + 1)
    } else {
        ((mask >> 1) | (bit << (STAB_WINDOW - 1)), len)
    }
}

/// Successes in the live window — `mask.count_ones()` is the whole answer
/// because `bits [len, 64)` are zero by construction (pinned by a test).
#[must_use]
pub const fn stab_successes(mask: u64, len: u8) -> u32 {
    // A mask with garbage above `len` would overcount; mask it off rather than
    // trusting the append invariant on a row read back from the database.
    // `u64::BITS` as a literal: a `const fn` cannot call `TryFrom`, and 64
    // always fits a `u8`.
    let live = if len >= 64 {
        u64::MAX
    } else {
        (1u64 << len) - 1
    };
    (mask & live).count_ones()
}

/// The stability bin, `0` (best) `..=7` (worst): the success rate, coarsened.
///
/// Neutral while the window is warming up or empty. Monotonic in successes at
/// every length; the ONE implementation, read by `compute_rank` and the panel —
/// SQL never re-derives it.
#[must_use]
pub const fn stab_bin(mask: u64, len: u8) -> u8 {
    if len < STAB_WARMUP {
        return STAB_NEUTRAL;
    }
    let rate = (stab_successes(mask, len) * 100) / len as u32;
    if rate >= 95 {
        0
    } else if rate >= 85 {
        1
    } else if rate >= 75 {
        2
    } else if rate >= 60 {
        3
    } else if rate >= 45 {
        4
    } else if rate >= 30 {
        5
    } else if rate >= 15 {
        6
    } else {
        7
    }
}

/// Whether the link's window holds at least one success.
///
/// The link-level `proven` fact. Derived from the ring, never a separate durable bit, so a full window
/// of failures retires a link from `Successful` on its own.
#[must_use]
pub const fn stab_proven(mask: u64, len: u8) -> bool {
    stab_successes(mask, len) > 0
}

/// Whether the NEWEST sample in the window succeeded.
///
/// The link-level "live"
/// fact (spec `2026-10-20-stab-alive-design` D3). The newest sample is always
/// the top live bit (`bit len-1`): below the window the new sample enters as
/// the newest with every existing bit keeping its index; at the window it
/// enters at the top. `None` when the ring is empty.
#[must_use]
pub const fn stab_latest_ok(mask: u64, len: u8) -> Option<bool> {
    if len == 0 {
        None
    } else {
        Some(mask >> (len - 1) & 1 == 1)
    }
}

/// The endpoint's own packed address key for the rank `addr` tiebreak (db-rewamp
/// D10): an IP host's literal lives in `endpoint_ip`; a DNS host gets an empty key.
fn endpoint_addr_key(row: &EndpointRow) -> Vec<u8> {
    if row.endpoint.is_dns() {
        Vec::new()
    } else {
        row.resolved_ips
            .first()
            .map(|ip| crate::endpoint_ip::key_of(*ip))
            .unwrap_or_default()
    }
}

/// True when the endpoint is a DNS host whose resolution has not landed —
/// the flag that collapses its links into one band (decision 16, tier 5).
///
/// The second input is "does it have any resolved address", which the
/// `endpoint_ip` table answers (`EndpointRow::resolved_ips`). A failed lookup
/// is not a different state: it stamps `resolved_at` and leaves the address
/// set empty, which is exactly the unresolved band this flag is for.
#[must_use]
pub const fn dns_unresolved_endpoint(domain: &str, has_address: bool) -> bool {
    !domain.is_empty() && !has_address
}

/// True for an [`EndpointRow`].
#[must_use]
pub const fn dns_unresolved(row: &EndpointRow) -> bool {
    row.endpoint.is_dns() && row.resolved_ips.is_empty()
}

/// A rank row plus the one key that is NOT a model field.
///
/// `rank_weight` is a RAW column (added with `ALTER TABLE ADD COLUMN` beside
/// `band`), and the toasty model has no seat for a raw column —
/// declaring it on `EndpointRank` instead would need schema tag 15, which
/// decision 4 defines as a full database wipe. So the write path carries this
/// plain row instead of the model.
#[derive(Debug, Clone)]
pub struct RankRow {
    pub rank: EndpointRank,
    /// The REPRESENTATIVE link's weight — the one the law picked, so the stored
    /// key and the stored weight always describe the same link.
    pub weight: ConfigWeight,
}

/// The weight of a protocol row.
///
/// From the discriminators it already stores in scalar columns
/// (`transport.type`, `security.type`/`sni`/`fp`). The deferred `config` JSON
/// is NOT read: nothing in the formula needs it.
#[must_use]
pub fn weight_of_protocol(protocol: &Protocol) -> ConfigWeight {
    weight_of(
        protocol.transport.r#type,
        protocol.security.r#type,
        protocol.security.sni.as_deref(),
        protocol.security.fp.as_deref(),
    )
}

/// The weight for one link read from the raw `protocols` columns.
///
/// A NULL (the LEFT JOIN missed) or an unrecognised spelling is
/// [`ZERO_WEIGHT`] — "worst", never a guess, so a schema drift surfaces as a
/// worst-case weight instead of a panic on the write path.
///
/// The transport column is read with `TransportType::from_db_label`, NOT
/// `FromStr`: toasty's embed stores `http_upgrade`/`x_http` where the wire form
/// says `httpupgrade`/`xhttp`, and `FromStr` rejects those — which would
/// silently persist a ZERO weight for every such link while every typed path
/// computes a real one, splitting the stored page order from the in-memory
/// comparator. Verified against a real feed (145 `http_upgrade` + 169 `x_http`
/// protocol rows).
#[must_use]
pub fn weight_from_discriminators(
    transport: Option<&str>,
    security: Option<&str>,
    sni: Option<&str>,
    fp: Option<&str>,
) -> ConfigWeight {
    let (Some(transport), Some(security)) = (
        transport.and_then(TransportType::from_db_label),
        security.and_then(|s| s.parse::<SecurityType>().ok()),
    ) else {
        return ZERO_WEIGHT;
    };
    weight_of(transport, security, sni, fp)
}

/// Compute the stored keys for one endpoint. `None` when it has no links: the
/// page only ever lists endpoints that have at least one.
#[must_use]
pub fn compute_rank(
    endpoint_id: EndpointId,
    domain: &str,
    sub_domain: &str,
    addr: Vec<u8>,
    dns_unresolved: bool,
    links: &[RankLink],
) -> Option<RankRow> {
    // The representative link: the live-first rule (spec
    // `2026-10-20-stab-alive-design` D3), the ONE statement in
    // `representative_index`. Its OWN stab is what the stored column reports —
    // the same link the bin/weight came from, so the stored stab and the
    // stored key cannot describe different links.
    let (bin, stab, neg_weight, _, _) = representative_index(links, dns_unresolved)?.1;
    // `proven` is ENDPOINT-level and NOT the representative's: a link that has
    // worked in its window keeps the endpoint in `Successful` even when a
    // sibling is the representative (an untested sibling outranks a failed
    // one). Purged links never contribute — a verdict retired them.
    //
    // A DNS-unresolved endpoint is NOT proven, even when a link's ring holds a
    // success: the host cannot be dialled, so it is not in the working pool.
    // The old law excluded it structurally (its links collapse to bin 15, never
    // 0..=5); under the proven-first partition that exclusion has to be stated.
    let proven = !dns_unresolved && links.iter().any(|l| !l.purged && l.proven);
    // The view windows ask whether any LIVE link falls in the band. A
    // purged-only endpoint therefore reports `NO_SEEN`, which is below every
    // window bound — that is exactly "it belongs to Purgatory" (spec §5), and it
    // is why one index range serves both populations.
    let newest_seen = links
        .iter()
        .filter(|l| !l.purged)
        .map(|l| l.seen_secs)
        .max()
        .unwrap_or(NO_SEEN);
    // The minimum key's weight term is `u64::MAX - weight`; invert it back.
    let weight = ConfigWeight::from_be_bytes((u64::MAX - neg_weight).to_be_bytes());
    Some(RankRow {
        rank: EndpointRank {
            endpoint_id,
            bin: i64::from(bin),
            domain: domain.to_string(),
            sub_domain: sub_domain.to_string(),
            addr,
            stab: i64::from(stab),
            proven: i64::from(proven),
            newest_seen,
        },
        weight,
    })
}

/// Keys for a whole row (the backfill/typed entry point).
#[must_use]
pub fn rank_of_row(row: &EndpointRow) -> Option<RankRow> {
    let links: Vec<RankLink> = row
        .links
        .iter()
        .map(|link| {
            let weight = row
                .protocols
                .get(&link.protocol_id)
                .map_or(ZERO_WEIGHT, weight_of_protocol);
            RankLink::new(link, weight)
        })
        .collect();
    compute_rank(
        row.endpoint.id,
        &row.endpoint.domain,
        &row.endpoint.sub_domain,
        endpoint_addr_key(row),
        dns_unresolved(row),
        &links,
    )
}

// ── Persistence ─────────────────────────────────────────────────────────
//
// A side table, not a `toasty` model: adding a model would need `push_schema`
// (skipped at the current tag) and therefore a tag bump, which decision 4
// defines as a full wipe. `CREATE TABLE IF NOT EXISTS` is additive and
// idempotent, so an existing database keeps its rows, and dropping the table
// restores the previous behaviour.
//
// Reads and writes inline their integer ids instead of binding them: the
// engine parses ~0.8 ms per bound parameter (200 ids = 174 ms; the same
// statement with literals = 9.7 ms), which would dominate every refresh.

/// Rows per bulk statement.
const RANK_CHUNK: usize = 400;

/// Column order the bulk insert writes (explicit so a schema reorder cannot
/// silently mis-map values).
///
/// `rank_weight` is a RAW column and IS listed here. `INSERT OR REPLACE`
/// re-inserts the row, so any column missing from this list is reset to NULL
/// on every single refresh — and a NULL there makes `profiles_anchor` fail
/// rather than merely mis-sort, because the anchor binds each term's value back
/// into a comparison.
const RANK_COLUMNS: &str = "endpoint_id, rank_bin, rank_stab, rank_proven, rank_weight, \
     rank_domain, rank_sub_domain, rank_addr, rank_newest_seen";

/// Fill the ordering keys and heal stale ones. The table's DDL (and its
/// indexes) now lives in `crate::schema::ddl`, run by the migration runner
/// before this; this is the DATA half, once per open.
///
/// One transaction, so the fill and the heal land together and no implicit
/// write lock outlives the call (leaving one behind made the next writer on the
/// pool time out with "database is locked").
pub(crate) async fn ensure(conn: &mut toasty::Connection) -> crate::Result<()> {
    let mut tx = conn
        .transaction_builder()
        .mode(TransactionMode::Immediate)
        .begin()
        .await?;
    let result = ensure_in(&mut tx).await;
    match result {
        Ok(()) => tx.commit().await?,
        Err(e) => return Err(e),
    }
    Ok(())
}

async fn ensure_in(conn: &mut impl toasty::Executor) -> crate::Result<()> {
    // The DDL that used to open this function — the two `ALTER TABLE ADD
    // COLUMN`s, the covering/band-window indexes and the meta table — now
    // lives in `crate::schema::ddl` and runs from the migration runner BEFORE
    // this call (`Database::open`). What remains is DATA: heal absent rows and
    // recompute keys whose weight tables changed.
    //
    // The compiled weight tables are opinions that live in code, so an upgrade
    // can invalidate every stored weight. This check MUST sit on the populated
    // branch below: an upgraded database takes the `> 0` path, and a NULL-based
    // fill cannot help it — `ADD COLUMN … NOT NULL DEFAULT` materializes
    // "worst" for every pre-existing row, so there are no NULLs to find.
    // Absence of the meta table reads as a mismatch too: that is exactly "this
    // database predates the weight".
    let stored_version = scalar_i64(
        conn,
        "SELECT weight_version FROM rank_weight_meta WHERE id = 0",
    )
    .await
    .unwrap_or(0);
    let weight_stale = stored_version != KEY_INPUTS_VERSION;

    if scalar_i64(conn, "SELECT COUNT(*) FROM endpoint_rank").await? > 0 {
        // A database whose keys are absent or stale (written before a refresh
        // path existed, or by a path that bypassed one) heals here rather than
        // hiding rows from the page.
        repair_missing(conn).await?;
        // One-time band backfill for rows that predate the column:
        // `repair_missing` fills only ABSENT rows, so an existing rank row
        // carries a NULL band until it is next refreshed. Fill them once here.
        backfill_bands(conn).await?;
        if weight_stale {
            let written = backfill_all(conn).await?;
            stamp_weight_version(conn).await?;
            tracing::info!(target: "leas_db",
                stored = stored_version, want = KEY_INPUTS_VERSION, written,
                "endpoint_rank: key inputs changed, keys recomputed");
        }
        return Ok(());
    }
    let written = backfill_all(conn).await?;
    stamp_weight_version(conn).await?;
    tracing::info!(target: "leas_db", "endpoint_rank: backfilled {written} rows");
    Ok(())
}

/// Record the key-input version, so the next open can tell whether the stored
/// keys were produced by the code that is running now.
async fn stamp_weight_version(conn: &mut impl toasty::Executor) -> crate::Result<()> {
    toasty::sql::query(format!(
        "INSERT INTO rank_weight_meta (id, weight_version) VALUES (0, {KEY_INPUTS_VERSION}) \
         ON CONFLICT(id) DO UPDATE SET weight_version = excluded.weight_version"
    ))
    .exec(conn)
    .await?;
    Ok(())
}

/// Fill `band` for rows that predate the column (`band IS NULL`) — the
/// non-destructive upgrade's one-time cost. Same derivation as `write`'s
/// follow-up: the ttl membership.
async fn backfill_bands(conn: &mut impl toasty::Executor) -> crate::Result<()> {
    if scalar_i64(
        conn,
        "SELECT COUNT(*) FROM endpoint_rank WHERE band IS NULL",
    )
    .await?
        == 0
    {
        return Ok(());
    }
    let threshold = crate::models_toasty::now_epoch()
        - ACTIVE_TTL_SECS.load(std::sync::atomic::Ordering::Relaxed);
    toasty::sql::query(format!(
        "UPDATE endpoint_rank SET \
         band = CASE WHEN rank_newest_seen >= {threshold} THEN 0 ELSE 1 END \
         WHERE band IS NULL"
    ))
    .exec(conn)
    .await?;
    Ok(())
}

/// One integer from a single-value query.
async fn scalar_i64(conn: &mut impl toasty::Executor, sql: &str) -> crate::Result<i64> {
    let rows = toasty::sql::query(sql).exec(conn).await?;
    Ok(rows
        .first()
        .and_then(|row| match row {
            Value::Record(record) => record.fields.first().cloned(),
            _ => None,
        })
        .and_then(|v| match v {
            Value::I64(n) => Some(n),
            _ => None,
        })
        .unwrap_or(0))
}

/// Upsert the rank rows on the caller's executor, one multi-row statement per
/// chunk.
///
/// Per-row `upsert_by_endpoint_id` costs ~1.2 ms per statement on this engine,
/// so a flush window's 400 endpoints took ~470 ms and a 7.7k-endpoint import
/// ~8 s of key writes; this form does the same rows in one statement per chunk
/// (measured ~10× cheaper). The values are inlined for the same reason the
/// reads are: they are integers the database produced, never user text, and
/// the engine charges ~0.8 ms per bound parameter.
pub(crate) async fn write(
    conn: &mut impl toasty::Executor,
    ranks: &[RankRow],
) -> crate::Result<usize> {
    let threshold = crate::models_toasty::now_epoch()
        - ACTIVE_TTL_SECS.load(std::sync::atomic::Ordering::Relaxed);
    for chunk in ranks.chunks(RANK_CHUNK) {
        let values = chunk
            .iter()
            .map(|row| {
                let r = &row.rank;
                format!(
                    "({},{},{},{},{},{},{},{},{})",
                    r.endpoint_id.get(),
                    r.bin,
                    r.stab,
                    r.proven,
                    row.weight.sql_literal(),
                    crate::database::sql_lit(&r.domain),
                    crate::database::sql_lit(&r.sub_domain),
                    blob_lit(&r.addr),
                    r.newest_seen
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        toasty::sql::statement(format!(
            "INSERT OR REPLACE INTO endpoint_rank ({RANK_COLUMNS}) VALUES {values}"
        ))
        .exec(conn)
        .await?;
        // `band` is a RAW column (not in the toasty model): INSERT OR REPLACE
        // re-inserts the row and nulls it, so re-set it for this chunk — the
        // ttl membership from the just-written rank_newest_seen.
        //
        // `rank_weight` is NOT re-set here: it is Rust-computed, so it went
        // into the INSERT's values tuple above and needs no second statement.
        let ids = chunk
            .iter()
            .map(|row| row.rank.endpoint_id.get().to_string())
            .collect::<Vec<_>>()
            .join(",");
        toasty::sql::statement(format!(
            "UPDATE endpoint_rank SET \
             band = CASE WHEN rank_newest_seen >= {threshold} THEN 0 ELSE 1 END \
             WHERE endpoint_id IN ({ids})"
        ))
        .exec(conn)
        .await?;
    }
    Ok(ranks.len())
}

/// The raw facts the rank law needs, straight from the stored columns.
struct RawEndpoint {
    domain: String,
    sub_domain: String,
    addr: Vec<u8>,
    dns_unresolved: bool,
}

impl crate::Database {
    /// Create the keys of any endpoint that has links but no rank row.
    ///
    /// The page drives from `endpoint_rank`, so a write that bypassed the
    /// refresh would hide its endpoint until this ran. It runs at `open` and
    /// is available to callers that write links outside the normal paths
    /// (fixtures, maintenance scripts).
    #[tracing::instrument(target = "db_method", skip_all, fields(retries = tracing::field::Empty))]
    pub async fn repair_endpoint_ranks(&self) -> crate::Result<usize> {
        let db = self;
        crate::retry_on_busy(
            move || async move {
                let mut conn = db.connection().await?;
                repair_missing(&mut conn).await
            },
            5,
        )
        .await
    }
    /// Recompute the stored ordering keys for `endpoint_ids`.
    ///
    /// Called by every write path that can change a link, so a stored key is
    /// never older than the write that invalidated it.
    #[tracing::instrument(target = "db_method", skip_all, fields(retries = tracing::field::Empty))]
    pub async fn refresh_endpoint_ranks(
        &self,
        endpoint_ids: &[EndpointId],
    ) -> crate::Result<usize> {
        let db = self;
        let endpoint_ids = endpoint_ids.to_vec();
        crate::retry_on_busy(
            move || {
                let endpoint_ids = endpoint_ids.clone();
                async move {
                    let mut conn = db.connection().await?;
                    refresh(&mut conn, &endpoint_ids).await
                }
            },
            5,
        )
        .await
    }

    /// Set the Active-view TTL used to materialize `band` (startup + settings
    /// save). Band is stored against `now − ttl`, so this must match the ttl
    /// the page's view means by "Active".
    pub fn set_band_ttl_secs(&self, secs: i64) {
        set_active_ttl_secs(secs);
    }

    /// Directional reband sweep: demote endpoints whose newest LIVE link has
    /// aged past the Active threshold (`band` 0 → 1). Monotonic and
    /// continuity-independent — it seeks exactly the drifted rows through the
    /// `(band, rank_newest_seen)` index, so an arbitrary downtime gap is
    /// corrected in one range scan (not a fixed window that a long gap could
    /// skip). Run at startup after the ttl is set (before the first page) and
    /// on the retention tick.
    #[tracing::instrument(target = "db_method", skip_all, fields(retries = tracing::field::Empty))]
    pub async fn reband_expired(&self) -> crate::Result<()> {
        let db = self;
        crate::retry_on_busy(
            move || async move {
                let threshold = crate::models_toasty::now_epoch()
                    - ACTIVE_TTL_SECS.load(std::sync::atomic::Ordering::Relaxed);
                let mut conn = db.connection().await?;
                toasty::sql::query(format!(
                    "UPDATE endpoint_rank SET band = 1 WHERE band = 0 AND rank_newest_seen < {threshold}"
                ))
                .exec(&mut conn)
                .await?;
                Ok(())
            },
            5,
        )
        .await
    }

    /// Full reband: recompute `band` for EVERY row against the current
    /// threshold, in BOTH directions. Used at startup, where the configured
    /// ttl may differ from the open-time default either way (a larger ttl must
    /// PROMOTE rows the default demoted), so the directional sweep alone is not
    /// enough. One indexed pass, once.
    #[tracing::instrument(target = "db_method", skip_all, fields(retries = tracing::field::Empty))]
    pub async fn reband_all(&self) -> crate::Result<()> {
        let db = self;
        crate::retry_on_busy(
            move || async move {
                let threshold = crate::models_toasty::now_epoch()
                    - ACTIVE_TTL_SECS.load(std::sync::atomic::Ordering::Relaxed);
                let mut conn = db.connection().await?;
                toasty::sql::query(format!(
                    "UPDATE endpoint_rank SET \
                     band = CASE WHEN rank_newest_seen >= {threshold} THEN 0 ELSE 1 END"
                ))
                .exec(&mut conn)
                .await?;
                Ok(())
            },
            5,
        )
        .await
    }
}

/// Delete rank rows whose endpoint no longer has any link.
///
/// The page drives from this table, so a lingering row would list a linkless
/// endpoint. Called by the deletion owners (`purge_expired`) rather than on a
/// timer: they are the only writers that remove links.
pub(crate) async fn prune(
    conn: &mut impl toasty::Executor,
    endpoint_ids: &[EndpointId],
) -> crate::Result<usize> {
    for id in endpoint_ids {
        EndpointRank::filter_by_endpoint_id(*id)
            .delete()
            .exec(conn)
            .await?;
    }
    Ok(endpoint_ids.len())
}

/// The first packed address key per endpoint (for the rank `addr` tiebreak) —
/// an IP host's literal lives in `endpoint_ip` now (db-rewamp D10).
async fn first_ip_keys(
    conn: &mut impl toasty::Executor,
) -> crate::Result<std::collections::HashMap<i64, Vec<u8>>> {
    let rows = toasty::sql::query(
        "SELECT endpoint_id, ip_key FROM endpoint_ip ORDER BY endpoint_id, ip_key",
    )
    .exec(conn)
    .await?;
    let mut out: std::collections::HashMap<i64, Vec<u8>> = std::collections::HashMap::new();
    for row in &rows {
        let Value::Record(record) = row else { continue };
        let Some(id) = record.fields.first().and_then(as_i64) else {
            continue;
        };
        if let Some(key) = record.fields.get(1).and_then(as_blob) {
            out.entry(id).or_insert(key);
        }
    }
    Ok(out)
}

/// Recompute EVERY endpoint's stored keys from its current links.
///
/// For the wholesale resets (`clear_all_stats`), for an upgraded database whose
/// stored weights came from a different version of the compiled tables, and for
/// a database that has no keys at all: every case where nothing narrower is
/// correct, because every link just lost — or never had — the columns the keys
/// are made of.
pub(crate) async fn backfill_all(conn: &mut impl toasty::Executor) -> crate::Result<usize> {
    let endpoints: Vec<Endpoint> = Endpoint::all().exec(conn).await?;
    let links: Vec<ProfileStats> = ProfileStats::all().exec(conn).await?;
    // The weight lives on the PROTOCOL row, not the link, so a third typed load
    // is what puts it in scope here. It is a scan of a small table (one row per
    // distinct config, shared by every endpoint carrying it) and the deferred
    // `config` JSON stays unloaded.
    let weights = protocol_weights(conn).await?;
    let resolved = resolved_endpoint_ids(conn).await?;
    let addr_keys = first_ip_keys(conn).await?;
    let mut by_endpoint: HashMap<EndpointId, Vec<RankLink>> = HashMap::new();
    for link in links {
        let weight = weights
            .get(&link.protocol_id)
            .copied()
            .unwrap_or(ZERO_WEIGHT);
        by_endpoint
            .entry(link.endpoint_id)
            .or_default()
            .push(RankLink::new(&link, weight));
    }
    let ranks: Vec<RankRow> = endpoints
        .into_iter()
        .filter_map(|endpoint| {
            let links = by_endpoint.remove(&endpoint.id)?;
            let addr = addr_keys
                .get(&endpoint.id.get())
                .cloned()
                .unwrap_or_default();
            compute_rank(
                endpoint.id,
                &endpoint.domain,
                &endpoint.sub_domain,
                addr,
                dns_unresolved_endpoint(&endpoint.domain, resolved.contains(&endpoint.id.get())),
                &links,
            )
        })
        .collect();
    write(conn, &ranks).await
}

/// Every protocol's weight, keyed by protocol id — the one map that lets a
/// `ProfileStats`-only row be turned into a [`RankLink`] with its weight.
pub(crate) async fn protocol_weights(
    conn: &mut impl toasty::Executor,
) -> crate::Result<HashMap<ProtocolId, ConfigWeight>> {
    let protocols: Vec<Protocol> = Protocol::all().exec(conn).await?;
    Ok(protocols
        .iter()
        .map(|p| (p.id, weight_of_protocol(p)))
        .collect())
}

/// The endpoints that have at least one resolved address, as a set.
///
/// The ordering law's DNS band is the only thing that reads it, and both
/// readers (the wholesale backfill and the per-window refresh) need the same
/// answer: "is this endpoint's address set non-empty". One grouped scan for
/// the backfill, a correlated `EXISTS` for the window refresh.
async fn resolved_endpoint_ids(
    conn: &mut impl toasty::Executor,
) -> crate::Result<std::collections::HashSet<i64>> {
    let rows = toasty::sql::query("SELECT DISTINCT endpoint_id FROM endpoint_ip")
        .exec(conn)
        .await?;
    let mut out = std::collections::HashSet::new();
    for row in &rows {
        if let Value::Record(record) = row
            && let Some(Value::I64(id)) = record.fields.first()
        {
            out.insert(*id);
        }
    }
    Ok(out)
}

/// Backfill rank rows for endpoints that have links but no row yet.
pub(crate) async fn repair_missing(conn: &mut impl toasty::Executor) -> crate::Result<usize> {
    let rows = toasty::sql::query(
        "SELECT e.id FROM endpoints e WHERE \
         EXISTS (SELECT 1 FROM profile_stats p WHERE p.endpoint_id = e.id) \
         AND NOT EXISTS (SELECT 1 FROM endpoint_rank k WHERE k.endpoint_id = e.id)",
    )
    .exec(conn)
    .await?;
    let ids: Vec<EndpointId> = rows
        .iter()
        .filter_map(|row| match row {
            Value::Record(record) => record.fields.first().cloned(),
            _ => None,
        })
        .filter_map(|v| match v {
            Value::I64(id) => Some(EndpointId::new(id)),
            _ => None,
        })
        .collect();
    if ids.is_empty() {
        return Ok(0);
    }
    refresh(conn, &ids).await
}

/// Recompute the stored keys for `endpoint_ids` from their current links.
///
/// The single refresh entry point: every write path that can change a link
/// (patch flush, bulk upsert, error sweep) calls it for the endpoints it
/// touched, so a stored key is never older than the write that invalidated it.
pub(crate) async fn refresh(
    conn: &mut impl toasty::Executor,
    endpoint_ids: &[EndpointId],
) -> crate::Result<usize> {
    let mut ids: Vec<i64> = endpoint_ids.iter().map(|id| id.get()).collect();
    ids.sort_unstable();
    ids.dedup();
    if ids.is_empty() {
        return Ok(0);
    }
    let id_list = ids
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",");

    let endpoints = load_raw_endpoints(conn, &id_list).await?;
    // The weight comes from the link's PROTOCOL row, joined into the statement
    // that already reads every link for these endpoints: five small
    // discriminator columns cost one indexed lookup per link, where a separate
    // load would re-scan the whole protocols table on every flush window. The
    // deferred `config` JSON is NOT touched — nothing in the formula reads it.
    let mut links: HashMap<i64, Vec<RankLink>> = HashMap::new();
    let rows = toasty::sql::query(format!(
        "SELECT ps.endpoint_id, ps.protocol_id, ps.error_kind, \
         ps.latency_real_delay, ps.latency_fast_delay, \
         ps.last_seen_at, ps.speed_bps, ps.traffic_total_up, ps.traffic_total_down, \
         ps.purge_reason, \
         pr.transport_type, pr.security_type, pr.security_sni, pr.security_fp, \
         ps.stab_mask, ps.stab_len \
         FROM profile_stats ps LEFT JOIN protocols pr ON pr.id = ps.protocol_id \
         WHERE ps.endpoint_id IN ({id_list})"
    ))
    .exec(conn)
    .await?;
    for row in &rows {
        let Value::Record(record) = row else { continue };
        let field = |i: usize| record.fields.get(i);
        let Some(endpoint_id) = field(0).and_then(as_i64) else {
            continue;
        };
        let protocol_id = field(1).and_then(as_i64).unwrap_or(0);
        // A negative or oversized stored len is a corrupt row: clamp rather
        // than shift by >63 (which is UB-ish in debug) or index a bogus bin.
        // The projection's column order: 0 endpoint, 1 protocol, 2 error_kind,
        // 3 real delay, 4 fast delay, 5 last_seen, 6 speed, 7 traffic up,
        // 8 traffic down, 9 purge_reason, 10..13 the protocol discriminators,
        // 14 the ring mask, 15 the ring length.
        let raw_mask = field(14).and_then(as_i64).unwrap_or(0).cast_unsigned();
        let raw_len = u8::try_from(
            field(15)
                .and_then(as_i64)
                .unwrap_or(0)
                .clamp(0, i64::from(STAB_WINDOW)),
        )
        .unwrap_or(0);
        // The two delay columns carry the provenance now: a real delay
        // outranks a fast one of any delay (schema 19).
        let real_delay = field(3)
            .and_then(as_i64)
            .and_then(|d| i32::try_from(d).ok());
        let fast_delay = field(4)
            .and_then(as_i64)
            .and_then(|d| i32::try_from(d).ok());
        let (measured, delay) = match (real_delay, fast_delay) {
            (Some(delay), _) => (Some(true), delay),
            (None, Some(delay)) => (Some(false), delay),
            (None, None) => (None, i32::MAX),
        };
        links.entry(endpoint_id).or_default().push(RankLink {
            protocol_id,
            error_kind: field(2)
                .and_then(as_text)
                .and_then(|k| parse_error_kind(&k)),
            measured,
            delay,
            seen_secs: field(5).and_then(as_i64).unwrap_or(0),
            speed: field(6).and_then(as_i64),
            traffic: field(7).and_then(as_i64).unwrap_or(0)
                + field(8).and_then(as_i64).unwrap_or(0),
            // A NULL column is a live link; any stored spelling is a verdict
            // (the value itself is the page's business, not the rank law's).
            purged: field(9).and_then(as_text).is_some(),
            // A negative or oversized stored len is a corrupt row: clamp rather
            // than shift by >63 (which is UB-ish in debug) or index a bogus bin.
            stab: stab_bin(raw_mask, raw_len),
            proven: stab_proven(raw_mask, raw_len),
            latest_ok: stab_latest_ok(raw_mask, raw_len),
            // A link whose protocol row is absent (the join is LEFT) has no
            // known stack, so it sorts as "worst" — the same value an
            // un-refreshed endpoint carries, never a silent average.
            weight: weight_from_discriminators(
                field(10).and_then(as_text).as_deref(),
                field(11).and_then(as_text).as_deref(),
                field(12).and_then(as_text).as_deref(),
                field(13).and_then(as_text).as_deref(),
            ),
        });
    }

    let ranks: Vec<RankRow> = ids
        .iter()
        .filter_map(|id| {
            let endpoint = endpoints.get(id)?;
            let empty: Vec<RankLink> = Vec::new();
            let endpoint_links = links.get(id).unwrap_or(&empty);
            compute_rank(
                EndpointId::new(*id),
                &endpoint.domain,
                &endpoint.sub_domain,
                endpoint.addr.clone(),
                endpoint.dns_unresolved,
                endpoint_links,
            )
        })
        .collect();
    write(conn, &ranks).await
}

async fn load_raw_endpoints(
    conn: &mut impl toasty::Executor,
    id_list: &str,
) -> crate::Result<HashMap<i64, RawEndpoint>> {
    // The DNS band's input is "has a resolved address", which is a question
    // for `endpoint_ip`, not for the endpoint row — one correlated EXISTS in
    // the statement that already reads the ids, so the refresh stays a single
    // round trip.
    let rows = toasty::sql::query(format!(
        "SELECT e.id, e.domain, e.sub_domain, \
         (SELECT ip.ip_key FROM endpoint_ip ip WHERE ip.endpoint_id = e.id LIMIT 1), \
         EXISTS (SELECT 1 FROM endpoint_ip ip WHERE ip.endpoint_id = e.id) \
         FROM endpoints e WHERE e.id IN ({id_list})"
    ))
    .exec(conn)
    .await?;
    let mut out = HashMap::new();
    for row in &rows {
        let Value::Record(record) = row else { continue };
        let field = |i: usize| record.fields.get(i);
        let Some(id) = field(0).and_then(as_i64) else {
            continue;
        };
        let domain = field(1).and_then(as_text).unwrap_or_default();
        let sub_domain = field(2).and_then(as_text).unwrap_or_default();
        let addr = field(3).and_then(as_blob).unwrap_or_default();
        let has_address = field(4).and_then(as_i64).unwrap_or(0) != 0;
        out.insert(
            id,
            RawEndpoint {
                dns_unresolved: !domain.is_empty() && !has_address,
                domain,
                sub_domain,
                addr,
            },
        );
    }
    Ok(out)
}

const fn as_i64(value: &Value) -> Option<i64> {
    match value {
        Value::I64(n) => Some(*n),
        _ => None,
    }
}

/// A `x'…'` BLOB literal for the packed address key.
fn blob_lit(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(3 + bytes.len() * 2);
    out.push_str("x'");
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(out, "{b:02x}");
    }
    out.push('\'');
    out
}

fn as_blob(value: &Value) -> Option<Vec<u8>> {
    match value {
        Value::Bytes(b) => Some(b.clone()),
        _ => None,
    }
}

fn as_text(value: &Value) -> Option<String> {
    match value {
        Value::String(s) => Some(s.clone()),
        _ => None,
    }
}

fn parse_error_kind(text: &str) -> Option<ProfileErr> {
    match text {
        "real" => Some(ProfileErr::Real),
        "fast" => Some(ProfileErr::Fast),
        "name" => Some(ProfileErr::Name),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    // ── stability ring (spec §5.1) ──────────────────────────────────────

    /// The quantizer table, pinned at every boundary. Written as
    /// (successes, len) → bin so a threshold edit shows up here, not as a
    /// subtle page reorder.
    #[test]
    fn stab_bin_maps_every_boundary_to_its_bin() {
        let at = |s: u32, len: u8| stab_bin((1u64 << s) - 1, len);
        // full window (len 16): each rate band's floor
        assert_eq!(at(16, 16), 0, "100%");
        assert_eq!(at(15, 16), 1, "93.75%");
        assert_eq!(at(13, 16), 2, "81.25%");
        assert_eq!(at(12, 16), 2, "75%");
        assert_eq!(at(11, 16), 3, "68.75%");
        assert_eq!(at(10, 16), 3, "62.5%");
        assert_eq!(at(9, 16), 4, "56.25%");
        assert_eq!(at(8, 16), 4, "50%");
        assert_eq!(at(7, 16), 5, "43.75%");
        assert_eq!(at(5, 16), 5, "31.25%");
        assert_eq!(at(4, 16), 6, "25%");
        assert_eq!(at(2, 16), 7, "12.5%");
        assert_eq!(at(0, 16), 7, "0%");
        // Just below each threshold
        assert_eq!(at(14, 16), 1, "87.5% -> bin 1 (>= 85)");
    }

    #[test]
    fn warm_up_and_empty_are_neutral_never_best_or_worst() {
        for len in 0..STAB_WARMUP {
            for s in 0..=len {
                assert_eq!(
                    stab_bin((1u64 << s) - 1, len),
                    STAB_NEUTRAL,
                    "{s}/{len} is warm-up"
                );
            }
        }
        assert_eq!(stab_bin(0, 0), STAB_NEUTRAL);
        assert_eq!(
            stab_bin((1u64 << STAB_WARMUP) - 1, STAB_WARMUP),
            0,
            "the first trusted sample of an all-success window is best"
        );
    }

    #[test]
    fn stab_bin_is_monotonic_in_successes_at_every_length() {
        // Lower bin = better, so more successes can only ever give a bin that
        // is <= the previous one — never worse.
        for len in STAB_WARMUP..=STAB_WINDOW {
            let mut prev = 7u8;
            for s in 0..=len {
                let b = stab_bin((1u64 << s) - 1, len);
                assert!(b <= prev, "{s}/{len}: {b} > {prev} (non-monotonic)");
                prev = b;
            }
            assert_eq!(prev, 0, "an all-success window of len {len} is best");
            assert_eq!(
                stab_bin(0, len),
                7,
                "an all-failure window of len {len} is worst"
            );
        }
    }

    #[test]
    fn append_fills_above_the_window_then_evicts_the_oldest() {
        // Filling: every bit keeps its index, the newest is the top bit.
        let (mask, len) = append_sample(0, 0, true);
        assert_eq!((mask, len), (0b1, 1), "first success is bit 0");
        let (mask, len) = append_sample(mask, len, false);
        assert_eq!((mask, len), (0b01, 2), "a failure lands at bit 1");
        let (mask, len) = append_sample(mask, len, true);
        assert_eq!((mask, len), (0b101, 3), "…and the next success at bit 2");

        // Eviction: after a full window, the oldest leaves and the new enters.
        let mut mask = 0u64;
        let mut len = 0u8;
        for _ in 0..STAB_WINDOW {
            (mask, len) = append_sample(mask, len, true);
        }
        assert_eq!(len, STAB_WINDOW);
        assert_eq!(mask, u64::MAX >> (64 - STAB_WINDOW), "full window of ones");
        let (mask, len) = append_sample(mask, len, false);
        assert_eq!(len, STAB_WINDOW, "length stays at the window");
        assert_eq!(
            stab_successes(mask, len),
            u32::from(STAB_WINDOW) - 1,
            "the oldest success left the window"
        );
    }

    #[test]
    fn bits_above_len_are_always_zero_and_successes_match() {
        // An arbitrary interleaved op sequence; the invariant checked at each
        // step, which is what makes `count_ones()` the success count.
        let ops = [
            true, true, false, true, false, false, true, true, true, false,
        ];
        let mut mask = 0u64;
        let mut len = 0u8;
        let mut track = std::collections::VecDeque::new();
        for _ in 0..3 {
            for &ok in &ops {
                (mask, len) = append_sample(mask, len, ok);
                track.push_back(ok);
                if track.len() > usize::from(STAB_WINDOW) {
                    track.pop_front();
                }
                let shifted_out: u64 = mask >> len;
                assert_eq!(shifted_out, 0, "bits [{len}, 64) must be zero");
                assert_eq!(
                    u32::try_from(track.iter().filter(|o| **o).count()).unwrap(),
                    stab_successes(mask, len),
                    "count_ones() must equal the live success count"
                );
            }
        }
    }

    #[test]
    fn proven_is_any_success_left_in_the_window() {
        assert!(!stab_proven(0, 0), "never sampled");
        assert!(!stab_proven(0, STAB_WINDOW), "a full window of failures");
        assert!(stab_proven(0b1000, 4), "one success anywhere");
        // One success ages out of a full window after 16 failures.
        let mut mask = 0u64;
        let mut len = 0u8;
        (mask, len) = append_sample(mask, len, true);
        for _ in 0..STAB_WINDOW {
            (mask, len) = append_sample(mask, len, false);
        }
        assert!(!stab_proven(mask, len), "the last success left the window");
    }

    const fn link(protocol_id: i64, measured: Option<bool>, delay: i32, seen: i64) -> RankLink {
        RankLink {
            protocol_id,
            measured,
            delay,
            error_kind: None,
            seen_secs: seen,
            speed: None,
            traffic: 0,
            purged: false,
            stab: STAB_NEUTRAL,
            proven: false,
            latest_ok: None,
            weight: ZERO_WEIGHT,
        }
    }

    /// A weight with a known packing, so a test can reason about the negated
    /// term without depending on any particular cell value.
    const fn weight(security: u16) -> ConfigWeight {
        ConfigWeight {
            security,
            mimicry: 0,
            sec_cost: 0,
            transport_cost: 0,
        }
    }

    #[test]
    fn a_higher_weight_outranks_within_a_bin() {
        // The bin is the delay bucket and comes FIRST (db-rewamp D11), so the
        // weight decides only WITHIN a bin: two links in the same bin, the
        // heavier stack leads.
        let mut heavy = link(1, Some(true), 900, 10);
        heavy.weight = weight(10);
        let mut light = link(2, Some(true), 940, 10);
        light.weight = weight(2);
        assert_eq!(
            heavy.key(false).0,
            light.key(false).0,
            "same bin (≥1000? no: both <1000)"
        );
        assert!(
            heavy.key(false) < light.key(false),
            "the heavier stack leads inside one bin"
        );
        // The bin still dominates the weight: a slow REAL (worse bin) never
        // leads a fast REAL whatever its weight.
        let fast = link(3, Some(true), 40, 10);
        let mut slow_heavy = link(4, Some(true), 900, 10);
        slow_heavy.weight = weight(10);
        assert!(
            fast.key(false) < slow_heavy.key(false),
            "40ms bin 0 leads 900ms bin 4"
        );
        // …and a measured success never leads a failed link.
        let mut failed = link(4, Some(true), 900, 10);
        failed.error_kind = Some(ProfileErr::Real);
        assert!(
            fast.key(false) < failed.key(false),
            "success leads a failed link"
        );
    }

    #[test]
    fn equal_weights_fall_through_to_latency_recency_and_id() {
        let fast = link(1, Some(false), 30, 100);
        let slow = link(2, Some(false), 300, 100);
        assert!(
            fast.key(false) < slow.key(false),
            "weight ties, latency decides"
        );
        let newer = link(3, Some(false), 30, 200);
        assert!(
            newer.key(false) < fast.key(false),
            "weight and latency tie, the newer link leads"
        );
        let lower_id = link(0, Some(false), 30, 200);
        assert!(
            lower_id.key(false) < newer.key(false),
            "protocol id is the last tiebreak"
        );
    }

    #[test]
    fn the_stored_weight_is_the_representative_links_own() {
        let mut weak = link(1, Some(true), 10, 5);
        weak.weight = weight(2);
        let mut strong = link(2, Some(true), 10, 5);
        strong.weight = weight(10);
        let row = compute_rank(
            EndpointId::new(7),
            "h.example",
            "",
            Vec::new(),
            false,
            &[weak, strong],
        )
        .expect("rank");
        assert_eq!(
            row.weight,
            weight(10),
            "the stored weight must describe the SAME link the tier came from"
        );
    }

    #[test]
    fn stability_outranks_weight_inside_a_bin() {
        // Same bin, same weight: the more stable link leads. This is the whole
        // point of the term — a reliable plain stack beats a flaky heavier one.
        let mut stable = link(1, Some(true), 300, 10);
        stable.stab = 0;
        let mut flaky = link(2, Some(true), 300, 10);
        flaky.stab = 6;
        assert!(
            stable.key(false) < flaky.key(false),
            "inside one bin, stability leads"
        );
        // …and it outranks the WEIGHT, which used to lead inside a bin.
        let mut stable_light = link(3, Some(true), 300, 10);
        stable_light.stab = 1;
        stable_light.weight = weight(2);
        let mut flaky_heavy = link(4, Some(true), 300, 10);
        flaky_heavy.stab = 5;
        flaky_heavy.weight = weight(10);
        assert!(
            stable_light.key(false) < flaky_heavy.key(false),
            "a stable light stack leads a flaky heavy one — stability > weight"
        );
        // The bin still dominates both.
        let fast_flaky = link(5, Some(true), 40, 10);
        assert!(
            fast_flaky.key(false) < stable_light.key(false),
            "a faster bin leads whatever the stability"
        );
    }

    #[test]
    fn a_proven_sibling_keeps_the_endpoint_proven_at_a_worse_bin() {
        // The representative is the untested sibling (bin 12 < 13): the failed
        // proven link does NOT represent the endpoint, yet the endpoint must
        // stay proven — that is `rank_proven`'s entire job.
        let mut proven_failed = link(1, None, 0, 100);
        proven_failed.error_kind = Some(ProfileErr::Real);
        proven_failed.proven = true;
        let untested = link(2, None, 0, 100);
        let row = compute_rank(
            EndpointId::new(9),
            "h.example",
            "",
            Vec::new(),
            false,
            &[proven_failed, untested],
        )
        .expect("rank");
        assert_eq!(
            row.rank.bin, 12,
            "the untested sibling is the representative"
        );
        assert_eq!(
            row.rank.proven, 1,
            "but a live proven sibling keeps it proven"
        );
        assert_eq!(
            row.rank.stab,
            i64::from(STAB_NEUTRAL),
            "the stored stab is the REPRESENTATIVE's"
        );
    }

    #[test]
    fn a_purged_link_never_makes_an_endpoint_proven() {
        let mut purged = link(1, None, 0, 100);
        purged.proven = true;
        purged.purged = true;
        let row = compute_rank(
            EndpointId::new(9),
            "h.example",
            "",
            Vec::new(),
            false,
            &[purged],
        )
        .expect("rank");
        assert_eq!(row.rank.proven, 0, "a verdict retired the link's evidence");
    }

    #[test]
    fn the_stored_stab_is_the_representatives_own() {
        let mut weak = link(1, Some(true), 300, 10);
        weak.stab = 5;
        let mut strong = link(2, Some(true), 300, 10);
        strong.stab = 0;
        let row = compute_rank(
            EndpointId::new(7),
            "h.example",
            "",
            Vec::new(),
            false,
            &[weak, strong],
        )
        .expect("rank");
        assert_eq!(
            row.rank.stab, 0,
            "the stored stab must describe the link the key picked"
        );
    }

    /// The link-level ring feeds the law: a full window of successes is bin 0,
    /// a full window of failures is 7, a partial window is neutral.
    #[test]
    fn the_ring_flows_into_the_link_key() {
        use crate::models_toasty::{Latency, ProfileStats, TrafficStats};
        let mk = |mask: i64, len: i64| {
            let l = ProfileStats {
                protocol_id: crate::models_toasty::ProtocolId::new(1),
                endpoint_id: crate::models_toasty::EndpointId::new(1),
                last_used_at: None,
                last_seen_at: 0,
                latency: Latency::real_with_ip(10, None),
                speed_bps: None,
                error: None,
                purge_reason: None,
                stab_mask: mask,
                stab_len: len,
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
            let k = RankLink::new(&l, ZERO_WEIGHT);
            (k.stab, k.proven, k.key(false))
        };
        let (stab, proven, _) = mk((1 << 16) - 1, 16);
        assert_eq!((stab, proven), (0, true), "a full window of successes");
        let (stab, proven, _) = mk(0, 16);
        assert_eq!((stab, proven), (7, false), "a full window of failures");
        let (stab, proven, _) = mk(1, 1);
        assert_eq!(
            (stab, proven),
            (STAB_NEUTRAL, true),
            "the seed: one success, no reliability estimate, proven"
        );
        let (stab, proven, _) = mk(0, 0);
        assert_eq!((stab, proven), (STAB_NEUTRAL, false), "never sampled");
        // A corrupt stored len must not panic or shift past 63.
        let (stab, _, _) = mk(0, 99);
        assert_eq!(stab, 7, "clamped len is a full failure window");
    }

    #[test]
    fn a_missing_protocol_yields_the_zero_weight_not_a_mid_band() {
        assert_eq!(
            weight_from_discriminators(None, None, None, None),
            ZERO_WEIGHT,
            "an unknown stack must sort as worst, not as an unexamined average"
        );
        assert_eq!(
            weight_from_discriminators(Some("tcp"), Some("not-a-security"), None, None),
            ZERO_WEIGHT,
            "an unparseable spelling is a schema drift, not a guess"
        );
    }

    /// The transports whose DATABASE label differs from their wire spelling.
    /// `toasty`'s embed derive writes `snake_case` idents, so these two rows used
    /// to parse as `Err` on the refresh path and persist a ZERO weight while
    /// every typed path computed a real one — the stored page order then
    /// disagreed with the panel. Pinned here so the label set cannot drift.
    #[test]
    fn toasty_storage_labels_for_multiword_transports_parse() {
        for (label, wire) in [("http_upgrade", "httpupgrade"), ("x_http", "xhttp")] {
            assert_eq!(
                TransportType::from_db_label(label).map(TransportType::as_str),
                Some(wire),
                "{label} is what toasty writes"
            );
            assert_eq!(
                label.parse::<TransportType>().ok(),
                None,
                "FromStr is the WIRE parser and must keep rejecting the storage label"
            );
        }
    }

    /// The invariant the page actually depends on: the RAW-column read and the
    /// TYPED read must produce the SAME weight for every transport.
    ///
    /// This is the revert-proof. A test that merely checks "the `x_http` weight
    /// differs from the `tcp` weight" passes under the bug too, because a ZERO
    /// weight also differs — it proves nothing. Comparing against the typed
    /// path's own answer is the only form that goes red when the raw reader
    /// stops understanding a label.
    #[test]
    fn the_raw_column_read_agrees_with_the_typed_read_for_every_transport() {
        for (label, wire) in [
            ("tcp", TransportType::Tcp),
            ("ws", TransportType::Ws),
            ("grpc", TransportType::Grpc),
            ("http", TransportType::Http),
            ("quic", TransportType::Quic),
            ("kcp", TransportType::Kcp),
            ("http_upgrade", TransportType::HttpUpgrade),
            ("x_http", TransportType::XHttp),
        ] {
            for security in ["none", "tls", "reality"] {
                let typed = weight_of(wire, security.parse::<SecurityType>().unwrap(), None, None);
                let raw = weight_from_discriminators(Some(label), Some(security), None, None);
                assert_eq!(
                    raw, typed,
                    "{label}+{security}: the stored label must read as the same weight \
                     the typed protocol does, or the SQL page order and the panel \
                     disagree"
                );
                assert_ne!(
                    raw, ZERO_WEIGHT,
                    "{label}+{security} must not collapse to the zero pack"
                );
            }
        }
    }

    #[test]
    fn purged_links_sink_below_every_live_tier_including_dns() {
        let mut purged = link(1, Some(true), 5, 100);
        purged.purged = true;
        assert_eq!(purged.key(false).0, 16, "purged is its own band");
        assert_eq!(purged.key(true).0, 16, "and it outranks the DNS collapse");
        // Below a fast/real error band: a purged real-ok link must not lead.
        let fast_err = RankLink {
            error_kind: Some(ProfileErr::Fast),
            ..link(2, None, 0, 1)
        };
        assert!(fast_err.key(false) < purged.key(false));
    }

    #[test]
    fn newest_seen_is_the_live_only_maximum() {
        let mut purged = link(1, Some(false), 10, 9_000);
        purged.purged = true;
        let links = [link(2, None, 0, 100), purged];
        let rank = compute_rank(
            EndpointId::new(1),
            "h.example",
            "",
            Vec::new(),
            false,
            &links,
        )
        .expect("rank");
        assert_eq!(
            rank.rank.newest_seen, 100,
            "a purged link's recency does not keep the endpoint in the Active window"
        );
        assert_eq!(
            rank.rank.bin, 12,
            "the live untested link is the representative"
        );

        let all_purged = [purged];
        let rank = compute_rank(
            EndpointId::new(1),
            "h.example",
            "",
            Vec::new(),
            false,
            &all_purged,
        )
        .expect("rank");
        assert_eq!(
            rank.rank.newest_seen, NO_SEEN,
            "no live link -> below every window bound (Purgatory)"
        );
        assert_eq!(rank.rank.bin, 16);
    }

    // ── last-good-delay bin law (spec `2026-10-20-stab-alive-design` D2) ──

    /// Every D2 row: (measured, delay, error kind, per-link proven) → bin.
    /// The failed real probe keeps the link's stored delay; the err band only
    /// claims links with no real success in their ring.
    #[rstest]
    #[case::no_error_real_is_its_delay_bin(Some(true), 40, None, false, 0)]
    #[case::no_error_fast_is_its_delay_bin(Some(false), 300, None, false, 6 + 3)]
    #[case::no_error_untested_is_twelve(None, i32::MAX, None, false, 12)]
    #[case::real_err_never_succeeded_is_thirteen(None, i32::MAX, Some(ProfileErr::Real), false, 13)]
    #[case::real_err_short_failure_ring_is_thirteen(
        Some(false),
        300,
        Some(ProfileErr::Real),
        false,
        13
    )]
    #[case::real_err_full_dead_window_is_thirteen(
        Some(true),
        40,
        Some(ProfileErr::Real),
        false,
        13
    )]
    #[case::real_err_proven_no_latency_is_thirteen(
        None,
        i32::MAX,
        Some(ProfileErr::Real),
        true,
        13
    )]
    #[case::real_err_proven_keeps_its_real_delay(Some(true), 40, Some(ProfileErr::Real), true, 0)]
    #[case::real_err_proven_fast_latency_uses_stored_latency(Some(false), 300, Some(ProfileErr::Real), true, 6 + 3)]
    #[case::name_err_without_success_is_thirteen(None, i32::MAX, Some(ProfileErr::Name), false, 13)]
    #[case::fast_err_with_latency_unchanged(Some(true), 40, Some(ProfileErr::Fast), false, 14)]
    #[case::fast_err_without_latency_unchanged(None, i32::MAX, Some(ProfileErr::Fast), false, 14)]
    #[case::purged_is_sixteen(Some(true), 40, None, true, 16)]
    #[case::dns_unresolved_is_fifteen(Some(true), 40, None, true, 15)]
    fn the_bin_law_keeps_a_known_good_delay_alive(
        #[case] measured: Option<bool>,
        #[case] delay: i32,
        #[case] error_kind: Option<ProfileErr>,
        #[case] proven: bool,
        #[case] expected: u8,
    ) {
        let mut l = link(1, measured, delay, 10);
        l.error_kind = error_kind;
        l.proven = proven;
        l.purged = expected == 16;
        let dns_unresolved = expected == 15;
        assert_eq!(l.bin(dns_unresolved), expected);
    }

    #[rstest]
    #[case::empty_ring(0, 0, None)]
    #[case::newest_success_below_window(0b011, 2, Some(true))]
    #[case::newest_failure_below_window(0b001, 2, Some(false))]
    #[case::newest_success_at_window(u64::MAX, STAB_WINDOW, Some(true))]
    #[case::newest_failure_at_window(u64::MAX ^ (1 << 15), STAB_WINDOW, Some(false))]
    fn stab_latest_ok_reads_the_top_live_bit(
        #[case] mask: u64,
        #[case] len: u8,
        #[case] expected: Option<bool>,
    ) {
        assert_eq!(stab_latest_ok(mask, len), expected);
    }

    #[test]
    fn a_live_sibling_represents_over_a_ghost() {
        // The ghost: once the fastest link (40 ms), now failing — its key
        // (bin 0, stab 7) would beat the live sibling's (bin 2, stab 0) under
        // a pure min-key, and the endpoint row would show the dead link.
        let mut ghost = link(1, Some(true), 40, 10);
        ghost.error_kind = Some(ProfileErr::Real);
        ghost.stab = 7;
        ghost.proven = true;
        ghost.latest_ok = Some(false);
        let mut live = link(2, Some(true), 300, 10);
        live.stab = 0;
        live.proven = true;
        live.latest_ok = Some(true);
        let row = compute_rank(
            EndpointId::new(7),
            "h.example",
            "",
            Vec::new(),
            false,
            &[ghost, live],
        )
        .expect("rank");
        assert_eq!(
            row.rank.bin, 3,
            "the live sibling's bin is the endpoint's bin"
        );
        assert_eq!(
            row.rank.stab, 0,
            "the stored stab describes the live sibling"
        );
    }

    #[test]
    fn a_purged_link_never_enters_the_live_representative_subset() {
        // The purged link's ring froze at purge time; its newest bit is still
        // a success. It must not represent over the failing live-band sibling.
        let mut purged = link(1, Some(true), 40, 10);
        purged.purged = true;
        purged.proven = true;
        purged.latest_ok = Some(true);
        let mut failing = link(2, Some(true), 300, 10);
        failing.error_kind = Some(ProfileErr::Real);
        failing.proven = false;
        failing.latest_ok = Some(false);
        let row = compute_rank(
            EndpointId::new(7),
            "h.example",
            "",
            Vec::new(),
            false,
            &[purged, failing],
        )
        .expect("rank");
        assert_eq!(
            row.rank.bin, 13,
            "the failing sibling represents, not the purged link"
        );
    }

    #[tokio::test]
    #[allow(
        clippy::items_after_statements,
        reason = "fixture items are scoped next to the discriminating case that needs them"
    )]
    async fn test_dirty_rank_set_tracks_and_drains() {
        let db = crate::Database::in_memory().await.expect("db");
        let eid1 = EndpointId::new(101);
        let eid2 = EndpointId::new(102);

        assert_eq!(db.dirty_rank_count(), 0);
        db.mark_endpoint_ranks_dirty(&[eid1, eid2]);
        assert_eq!(db.dirty_rank_count(), 2);

        let drained = db.drain_dirty_ranks().await.expect("drain");
        assert_eq!(drained, 0); // No links exist in empty in-memory DB
        assert_eq!(db.dirty_rank_count(), 0);

        // Discriminating case: a REAL link whose stored key would be stale
        // without the drain. Seed endpoint+link, then mark dirty WITHOUT a
        // refresh and drain — the drain must create the endpoint_rank row.
        use crate::models_toasty::{
            Endpoint, HostType, Latency, ProfileStats, Protocol, Security, TrafficStats, Transport,
        };
        use leas_proto::proto_spec::{ProtocolKind, SecurityType, TransportType};
        {
            let mut conn = db.connection().await.expect("conn");
            toasty::create!(Endpoint {
                created_at: 0,
                id: EndpointId::new(201),
                domain: Endpoint::derive_domain("dirty.example", HostType::Dns).0,
                sub_domain: Endpoint::derive_domain("dirty.example", HostType::Dns).1,
                port: 443,
                ports: Vec::<u16>::new(),
            })
            .exec(&mut conn)
            .await
            .expect("endpoint");
            toasty::create!(Protocol {
                created_at: 0,
                id: ProtocolId::new(201),
                sig: 201,
                proto_kind: ProtocolKind::Vless,
                transport: Transport {
                    r#type: TransportType::Tcp,
                },
                security: Security {
                    r#type: SecurityType::None,
                    sni: None,
                    fp: None,
                    insecure: None,
                },
                config: toasty::Deferred::from(toasty::Json(
                    leas_proto::proto_spec::ProtocolConfig::Vless(
                        leas_proto::proto_spec::VlessConfig {
                            uuid: "00000000-0000-0000-0000-000000000000".to_string(),
                            uuid_origin: None,
                            security: leas_proto::proto_spec::common::SecurityConfig::default(),
                            transport: leas_proto::proto_spec::common::TransportConfig::Tcp,
                            encryption: None,
                            flow: None,
                            path: None,
                            splice: None,
                            remarks: None,
                            mux: None,
                        },
                    ),
                )),
            })
            .exec(&mut conn)
            .await
            .expect("protocol");
            toasty::create!(ProfileStats {
                created_at: 0,
                updated_at: 0,
                protocol_id: ProtocolId::new(201),
                endpoint_id: EndpointId::new(201),
                last_seen_at: 1,
                stab_mask: 0,
                stab_len: 0,
                traffic: TrafficStats {
                    today_up: 0,
                    today_down: 0,
                    total_up: 0,
                    total_down: 0,
                },
                latency: Latency::default(),
            })
            .exec(&mut conn)
            .await
            .expect("link");
        }
        // No rank row exists yet — the write path that seeded the link did
        // NOT refresh (this is the MVCC deferred-refresh shape).
        let rows = toasty::sql::query("SELECT COUNT(*) FROM endpoint_rank WHERE endpoint_id = 201")
            .exec(&mut db.connection().await.expect("conn"))
            .await
            .expect("count");
        assert_eq!(
            rows.first().and_then(|v| match v {
                toasty::stmt::Value::Record(f) => f.first().cloned(),
                other => Some(other.clone()),
            }),
            Some(toasty::stmt::Value::I64(0)),
            "no rank row before the drain"
        );

        db.mark_endpoint_ranks_dirty(&[EndpointId::new(201)]);
        let drained = db.drain_dirty_ranks().await.expect("drain");
        assert_eq!(drained, 1, "the dirty endpoint was refreshed");
        let rows = toasty::sql::query("SELECT COUNT(*) FROM endpoint_rank WHERE endpoint_id = 201")
            .exec(&mut db.connection().await.expect("conn"))
            .await
            .expect("count");
        assert_eq!(
            rows.first().and_then(|v| match v {
                toasty::stmt::Value::Record(f) => f.first().cloned(),
                other => Some(other.clone()),
            }),
            Some(toasty::stmt::Value::I64(1)),
            "the drain created the rank row"
        );
        // A second drain is a no-op — the set is empty.
        let drained = db.drain_dirty_ranks().await.expect("second drain");
        assert_eq!(drained, 0, "second drain has nothing to do");
    }
}
