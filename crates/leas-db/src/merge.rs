//! Endpoint merge — the Smart Endpoints Compact write path.
//!
//! Collapses two endpoints that are PROVABLY the same server into one row.
//! The pair criterion (the caller decides it) is: same port, a shared
//! [`ProtocolId`], AND an `endpoint_ip` overlap. `protocol_id` alone can
//! never identify a server — it is deliberately host-independent
//! (`leas_proto::proto_spec::identity`: one UUID across a whole provider
//! fleet dedups to one uid) — so the address overlap is the discriminator,
//! and config equality only narrows. Endpoints without resolved addresses
//! carry no evidence and are never merged.
//!
//! Merge law (approved design, `docs/aegis/plans/2026-10-19-maintenance-commands.md`):
//!
//! - **Survivor**: DNS host over an IP-literal host (DNS re-resolves; an IP
//!   is a frozen snapshot); DNS↔DNS or IP↔IP keeps the lower endpoint id.
//! - **Link collision** (same `protocol_id` on both sides): better evidence
//!   wins — a measured latency beats an untested link, then the lower
//!   [`RankLink::key`] bin. The absorbed side's `purge_reason` NEVER
//!   propagates: a verdict is a statement about the probed (endpoint,
//!   protocol) pair, and the absorbed endpoint was a different address. The
//!   survivor's own verdict survives any overwrite.
//! - **Fan-out**: absorbed addresses move to the survivor (set-deduped,
//!   countries carried), `endpoint_groups` membership moves (collision keeps
//!   the survivor's `sort_order`, `last_seen_at` = max), `ports` union.
//!   Absorbed `last_source` / `manual_protocol_override` are dropped with
//!   their row. Rank keys are refreshed for the survivor AFTER the link
//!   re-keying, inside the same transaction — the page never reads a stale
//!   representative link.
//!
//! Everything lands in ONE transaction with the absorbed row's cascade
//! delete, so a crash mid-merge either shows both endpoints (rerun heals it)
//! or one merged endpoint — never a half-move that loses protocol rows.
//!
//! Note the schema has NO foreign keys (ADR 0011): `PRAGMA foreign_keys=ON`
//! is inert, so a `profile_stats`/`endpoint_ip` write staged for the absorbed
//! endpoint and flushed after the delete would silently RE-CREATE an orphan
//! row, not error. That is why the caller flushes first and then discards
//! every staged patch (`LinkSpec` AND `CountrySpec`) keyed by the absorbed
//! ids — the guard is against resurrection, not against an FK failure.

use crate::database::sql_lit;
use crate::endpoint_rank::RankLink;
use crate::models_toasty::{
    Endpoint, EndpointGroup, EndpointId, EndpointIp, Latency, ProfileStats, ProtocolId,
};
use crate::weight::ConfigWeight;
use crate::{Database, DatabaseError, Result, retry_on_busy};
use std::collections::{HashMap, HashSet};

/// What one merge did, for the actions-log audit entry (the only record —
/// the command applies directly and there is no undo).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MergeReport {
    pub survivor: EndpointId,
    pub absorbed: EndpointId,
    /// Absorbed-only links re-keyed to the survivor (latency, stability and
    /// traffic ride the create).
    pub links_moved: usize,
    /// Same-protocol collisions resolved by the evidence rule.
    pub links_collided: usize,
    /// Of those, how many the absorbed side's evidence won (its measured
    /// fields moved onto the survivor's row).
    pub collisions_won_by_absorbed: usize,
    /// Addresses added to the survivor's `endpoint_ip` set.
    pub addresses_moved: usize,
    /// `endpoint_groups` memberships re-keyed to the survivor.
    pub groups_moved: usize,
    /// Memberships both sides had: `last_seen_at` = max, survivor's
    /// `sort_order` kept.
    pub groups_collided: usize,
}

/// The merge direction: which of a candidate pair survives, per the law.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Survivor {
    /// First endpoint of the pair survives.
    Left,
    /// Second endpoint of the pair survives.
    Right,
}

/// Pick the survivor of a candidate pair: DNS host over IP-literal, else the
/// lower endpoint id (the older row). `dns_a`/`dns_b` are `Endpoint::is_dns`.
#[must_use]
pub fn pick_survivor(id_a: EndpointId, dns_a: bool, id_b: EndpointId, dns_b: bool) -> Survivor {
    if dns_a != dns_b {
        if dns_a {
            Survivor::Left
        } else {
            Survivor::Right
        }
    } else if id_a <= id_b {
        Survivor::Left
    } else {
        Survivor::Right
    }
}

/// The link evidence key the collision rule compares: lower wins. Both
/// colliding links share the protocol row (same weight) and the comparison
/// holds the DNS flag constant, so those terms cannot flip it.
fn link_evidence_key(link: &ProfileStats, weight: ConfigWeight) -> (u8, u8, u64, i64, i64) {
    RankLink::new(link, weight).key(false)
}

impl Database {
    /// Merge `absorbed` into `survivor` in one transaction.
    ///
    /// # Errors
    ///
    /// [`DatabaseError`] when any step fails: the transaction rolls back and
    /// both endpoints remain untouched.
    #[tracing::instrument(target = "db_method", skip_all, fields(retries = tracing::field::Empty))]
    pub async fn merge_endpoints(
        &self,
        survivor: EndpointId,
        absorbed: EndpointId,
    ) -> Result<MergeReport> {
        if survivor == absorbed {
            return Err(DatabaseError::Generic(
                "merge_endpoints: survivor and absorbed are the same endpoint".into(),
            ));
        }
        let db = self;
        retry_on_busy(
            move || async move {
                let mut conn = db.connection().await?;
                let mut tx = conn.transaction().await?;
                let report = merge_in(&mut tx, survivor, absorbed).await?;
                tx.commit().await?;
                Ok(report)
            },
            5,
        )
        .await
    }
}

/// The whole merge on the caller's executor.
pub(crate) async fn merge_in(
    tx: &mut impl toasty::Executor,
    survivor: EndpointId,
    absorbed: EndpointId,
) -> Result<MergeReport> {
    // ── Read both sides ─────────────────────────────────────────────────
    let ids = vec![survivor, absorbed];
    let endpoints: Vec<Endpoint> =
        Endpoint::filter(toasty::stmt::in_list(Endpoint::fields().id(), ids.clone()))
            .exec(&mut *tx)
            .await?;
    if endpoints.len() != 2 {
        return Err(DatabaseError::Generic(format!(
            "merge_endpoints: expected both endpoints {survivor:?}/{absorbed:?} to exist"
        )));
    }

    let links: Vec<ProfileStats> = ProfileStats::filter(toasty::stmt::in_list(
        ProfileStats::fields().endpoint_id(),
        ids.clone(),
    ))
    .exec(&mut *tx)
    .await?;
    let addresses = crate::endpoint_ip::load_resolved(&mut *tx, &ids).await?;
    let memberships: Vec<EndpointGroup> = EndpointGroup::filter(toasty::stmt::in_list(
        EndpointGroup::fields().endpoint_id(),
        ids.clone(),
    ))
    .exec(&mut *tx)
    .await?;
    // Weights per protocol id: the collision comparison needs the CONFIG
    // weight, and both colliding links share the same protocol row.
    let weights = crate::endpoint_rank::protocol_weights(&mut *tx).await?;
    let weight_of = |pid: i64| -> ConfigWeight {
        weights
            .get(&ProtocolId::new(pid))
            .copied()
            .unwrap_or(crate::weight::ZERO_WEIGHT)
    };

    let report = merge_links(tx, survivor, absorbed, &links, &weight_of).await?;
    merge_addresses(tx, survivor, absorbed, &addresses).await?;
    merge_memberships(tx, survivor, absorbed, &memberships).await?;
    merge_ports(tx, survivor, &endpoints).await?;
    delete_absorbed(tx, absorbed).await?;
    // Ordering law: the survivor's keys follow its links, after the re-keying
    // and once the absorbed row is gone.
    crate::endpoint_rank::refresh(&mut *tx, &[survivor]).await?;
    Ok(report)
}

/// Resolve link collisions and move absorbed-only links.
async fn merge_links(
    tx: &mut impl toasty::Executor,
    survivor: EndpointId,
    absorbed: EndpointId,
    links: &[ProfileStats],
    weight_of: &(dyn Fn(i64) -> ConfigWeight + Send + Sync),
) -> Result<MergeReport> {
    let now = crate::models_toasty::now_epoch();
    let mut survivor_links: HashMap<i64, &ProfileStats> = HashMap::new();
    let mut absorbed_links: Vec<&ProfileStats> = Vec::new();
    for link in links {
        if link.endpoint_id == survivor {
            survivor_links.insert(link.protocol_id.get(), link);
        } else if link.endpoint_id == absorbed {
            absorbed_links.push(link);
        }
    }

    let mut report = MergeReport {
        survivor,
        absorbed,
        links_moved: 0,
        links_collided: 0,
        collisions_won_by_absorbed: 0,
        addresses_moved: 0,
        groups_moved: 0,
        groups_collided: 0,
    };

    let mut moved: Vec<ProfileStats> = Vec::new();
    for link in absorbed_links {
        let pid = link.protocol_id.get();
        if let Some(kept) = survivor_links.get(&pid).copied() {
            report.links_collided += 1;
            // Better evidence wins; a purged survivor row keeps its
            // verdict (the overwrite below never touches purge_reason).
            let absorbed_key = link_evidence_key(link, weight_of(pid));
            let survivor_key = link_evidence_key(kept, weight_of(pid));
            if absorbed_key < survivor_key {
                report.collisions_won_by_absorbed += 1;
                overwrite_link_fields(&mut *tx, survivor, link, now).await?;
            }
        } else {
            report.links_moved += 1;
            let mut rekeyed = link.clone();
            rekeyed.endpoint_id = survivor;
            moved.push(rekeyed);
        }
    }
    // Full-snapshot create: latency/stability/traffic ride the VALUES tuple;
    // the (protocol_id, endpoint_id) pairs moved here cannot conflict by
    // construction (absorbed-only protocols).
    if !moved.is_empty() {
        crate::upsert_links_bulk(&mut *tx, &moved).await?;
        // The bulk upsert's VALUES tuple writes `last_used_at` as literal NULL
        // and its SOURCE conflict action never restores it — its owner is
        // `update_last_used`, which cannot run inside this transaction. So the
        // merge re-stamps the moved row's own timestamp here.
        for m in moved.iter().filter(|m| m.last_used_at.is_some()) {
            let used = m.last_used_at.unwrap_or(0);
            toasty::sql::statement(format!(
                "UPDATE profile_stats SET last_used_at = {used} \
                 WHERE protocol_id = {} AND endpoint_id = {}",
                m.protocol_id.get(),
                m.endpoint_id.get()
            ))
            .exec(&mut *tx)
            .await?;
        }
    }
    Ok(report)
}

/// Write the absorbed link's measured fields onto the survivor's same-protocol
/// row. `purge_reason` and the traffic counters are deliberately NOT in the
/// SET list: the survivor's verdict and counters are its own.
async fn overwrite_link_fields(
    tx: &mut impl toasty::Executor,
    survivor: EndpointId,
    absorbed: &ProfileStats,
    now: i64,
) -> Result<()> {
    use std::fmt::Write as _;
    let (latency, latency_delay, latency_ip) = match &absorbed.latency {
        Some(Latency::Real { delay, ip }) => (
            "'real'".to_owned(),
            delay.to_string(),
            ip.as_deref().map_or_else(|| "NULL".to_owned(), sql_lit),
        ),
        Some(Latency::Fast { delay }) => {
            ("'fast'".to_owned(), delay.to_string(), "NULL".to_owned())
        }
        None => ("NULL".to_owned(), "NULL".to_owned(), "NULL".to_owned()),
    };
    // `speed_bps` is independent of the error embed (the upsert writer emits
    // it unconditionally), so it always copies; the error embed only when the
    // absorbed side carries one.
    let speed = absorbed
        .speed_bps
        .map_or_else(|| "NULL".to_owned(), |s| s.to_string());
    let (error, error_kind, error_text) = absorbed.error.as_ref().map_or_else(
        || ("NULL".to_owned(), "NULL".to_owned(), "NULL".to_owned()),
        |e| {
            (
                "1".to_owned(),
                sql_lit(crate::database::error_kind_str(e.kind)),
                sql_lit(&e.text),
            )
        },
    );
    let mut sql = String::with_capacity(512);
    let _ = write!(
        sql,
        "UPDATE profile_stats SET latency = {latency}, latency_delay = {latency_delay}, \
         latency_ip = {latency_ip}, speed_bps = {speed}, error = {error}, \
         error_kind = {error_kind}, error_text = {error_text}, \
         stab_mask = {}, stab_len = {}, \
         last_seen_at = MAX(last_seen_at, {}), \
         last_used_at = MAX(COALESCE(last_used_at, 0), COALESCE({}, 0)), \
         updated_at = {now}, version = version + 1 \
         WHERE protocol_id = {} AND endpoint_id = {}",
        absorbed.stab_mask,
        absorbed.stab_len,
        absorbed.last_seen_at,
        absorbed
            .last_used_at
            .map_or_else(|| "NULL".to_owned(), |u| u.to_string()),
        absorbed.protocol_id.get(),
        survivor.get(),
    );
    toasty::sql::statement(sql).exec(tx).await?;
    Ok(())
}

/// Move the absorbed endpoint's addresses onto the survivor's set, deduped by
/// the PK and carrying each address's stored country.
async fn merge_addresses(
    tx: &mut impl toasty::Executor,
    survivor: EndpointId,
    absorbed: EndpointId,
    addresses: &HashMap<EndpointId, Vec<(std::net::IpAddr, Option<String>)>>,
) -> Result<()> {
    let have: HashSet<Vec<u8>> = addresses
        .get(&survivor)
        .map(|ips| {
            ips.iter()
                .map(|(ip, _)| crate::endpoint_ip::key_of(*ip))
                .collect()
        })
        .unwrap_or_default();
    for (ip, country) in addresses.get(&absorbed).map_or(&[][..], Vec::as_slice) {
        let key = crate::endpoint_ip::key_of(*ip);
        if have.contains(&key) {
            continue;
        }
        toasty::create!(EndpointIp {
            endpoint_id: survivor,
            ip_key: key,
            country: country.clone().filter(|c| !c.is_empty()),
        })
        .exec(&mut *tx)
        .await?;
    }
    Ok(())
}

/// Move the absorbed endpoint's group memberships onto the survivor.
async fn merge_memberships(
    tx: &mut impl toasty::Executor,
    survivor: EndpointId,
    absorbed: EndpointId,
    memberships: &[EndpointGroup],
) -> Result<()> {
    let mut rekeyed: Vec<EndpointGroup> = Vec::new();
    for m in memberships {
        if m.endpoint_id != absorbed {
            continue;
        }
        if let Some(s) = memberships
            .iter()
            .find(|s| s.endpoint_id == survivor && s.group_id == m.group_id)
        {
            // Both sides in the group: the fresher confirmation wins, the
            // survivor's display order stays.
            let seen = m.last_seen_at.max(s.last_seen_at);
            if seen != s.last_seen_at {
                toasty::sql::statement(format!(
                    "UPDATE endpoint_groups SET last_seen_at = {seen} \
                     WHERE endpoint_id = {} AND group_id = {}",
                    survivor.get(),
                    crate::database::sql_lit(&m.group_id)
                ))
                .exec(&mut *tx)
                .await?;
            }
        } else {
            let mut moved = m.clone();
            moved.endpoint_id = survivor;
            rekeyed.push(moved);
        }
    }
    if !rekeyed.is_empty() {
        crate::upsert_endpoint_group_links_bulk(&mut *tx, &rekeyed).await?;
    }
    Ok(())
}

/// Union the absorbed endpoint's `ports` into the survivor's.
///
/// `ports` is the FULL hop list INCLUDING the primary port (`vless.rs` asserts
/// `[443, 8443, …]`); empty means single-port. The union therefore folds in
/// BOTH primaries plus both lists, and normalizes to `vec![]` only when the
/// result is exactly `{survivor.port}` — a shortcut that drops the primary
/// would corrupt a multi-port spec.
async fn merge_ports(
    tx: &mut impl toasty::Executor,
    survivor: EndpointId,
    endpoints: &[Endpoint],
) -> Result<()> {
    let (Some(s), Some(a)) = (
        endpoints.iter().find(|e| e.id == survivor),
        endpoints.iter().find(|e| e.id != survivor),
    ) else {
        return Ok(());
    };
    let set: std::collections::BTreeSet<u16> = s
        .ports
        .iter()
        .chain(a.ports.iter())
        .chain(std::iter::once(&s.port))
        .chain(std::iter::once(&a.port))
        .copied()
        .collect();
    let single = set.len() == 1 && set.contains(&s.port);
    let ports = if single {
        Vec::new()
    } else {
        set.into_iter().collect::<Vec<_>>()
    };
    if ports != s.ports {
        Endpoint::filter_by_id(survivor)
            .update()
            .ports(ports)
            .exec(&mut *tx)
            .await?;
    }
    Ok(())
}

/// The absorbed row's cascade delete — the same steps
/// [`Database::delete_endpoints`] runs, on the merge's transaction.
async fn delete_absorbed(tx: &mut impl toasty::Executor, absorbed: EndpointId) -> Result<()> {
    let ids = vec![absorbed];
    EndpointGroup::filter(toasty::stmt::in_list(
        EndpointGroup::fields().endpoint_id(),
        ids.clone(),
    ))
    .delete()
    .exec(&mut *tx)
    .await?;
    ProfileStats::filter(toasty::stmt::in_list(
        ProfileStats::fields().endpoint_id(),
        ids.clone(),
    ))
    .delete()
    .exec(&mut *tx)
    .await?;
    Database::purge_orphan_protocols(tx).await?;
    crate::endpoint_ip::delete_for(&mut *tx, &ids).await?;
    Endpoint::filter_by_id(absorbed)
        .delete()
        .exec(&mut *tx)
        .await?;
    crate::endpoint_rank::prune(&mut *tx, &ids).await?;
    Ok(())
}
