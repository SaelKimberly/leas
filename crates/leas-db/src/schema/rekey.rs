//! Marker-guarded identity re-key (`IDENTITY_VERSION` 4).
//!
//! The core choice left the protocol identity, so every stored uid changes.
//! This is a DATA step, not a schema step: `SCHEMA_VERSION` and the migration
//! cursor stay put, and `app_meta.identity_version` gates the work.
//!
//! The rebuild is required, not a convenience: a new uid can equal another
//! row's OLD uid (a permutation), so an in-place primary-key update would
//! collide. `protocols` and `profile_stats` are rebuilt into fresh tables and
//! atomically renamed; only provably duplicate identities (same recomputed
//! uid) merge, using the same link-collision evidence law as `merge.rs`.

use toasty::stmt::Value;
use toasty_core::driver::operation::TransactionMode;

use crate::Result;
use crate::error::DatabaseError;
use crate::models_toasty::{AppMeta, ProtocolId};
use leas_proto::proto_spec::IDENTITY_VERSION;

const MARKER: &str = "identity_version";

/// Re-key once, stamped in the same transaction. A no-op when the marker
/// already equals [`IDENTITY_VERSION`].
pub(super) async fn rekey_once(conn: &mut toasty::Connection) -> Result<()> {
    if marker(conn).await? >= i64::from(IDENTITY_VERSION) {
        return Ok(());
    }
    let mut tx = conn
        .transaction_builder()
        .mode(TransactionMode::Immediate)
        .begin()
        .await?;
    let result = rekey_in(&mut tx).await;
    match result {
        Ok(()) => {
            tx.commit().await?;
            tracing::info!(target: "leas_db",
                "protocols: re-keyed the identity (IDENTITY_VERSION {IDENTITY_VERSION})");
            Ok(())
        }
        Err(e) => Err(e),
    }
}

/// Stamp a fresh database (no protocols to re-key).
pub(super) async fn stamp(conn: &mut toasty::Connection) -> Result<()> {
    if marker(conn).await? >= i64::from(IDENTITY_VERSION) {
        return Ok(());
    }
    toasty::sql::query(format!(
        "INSERT INTO app_meta (key, value) VALUES ('{MARKER}', '{IDENTITY_VERSION}') \
         ON CONFLICT(key) DO UPDATE SET value = excluded.value"
    ))
    .exec(conn)
    .await?;
    Ok(())
}

async fn marker(conn: &mut impl toasty::Executor) -> Result<i64> {
    let Some(row) = AppMeta::filter_by_key(MARKER.to_owned())
        .first()
        .exec(conn)
        .await?
    else {
        return Ok(0);
    };
    Ok(row.value.parse().unwrap_or(0))
}

async fn rekey_in(tx: &mut impl toasty::Executor) -> Result<()> {
    // (old id, new id, new sig)
    let mut rekeyed: Vec<(i64, i64, i64)> = Vec::new();
    for (old, kind, config) in read_protocols(tx).await? {
        let parsed = leas_proto::proto_spec::ParsedProto {
            endpoints: Vec::new(),
            protocol: leas_proto::proto_spec::ProtocolEssentials {
                proto_kind: kind,
                config,
            },
        };
        rekeyed.push((old, parsed.uid(), parsed.sig()));
    }

    // Collision groups: identical recomputed identity, different old rows.
    let mut groups: std::collections::BTreeMap<i64, Vec<i64>> = std::collections::BTreeMap::new();
    for &(old, new, _) in &rekeyed {
        groups.entry(new).or_default().push(old);
    }
    let mut losers: Vec<(i64, i64)> = Vec::new(); // (loser old, survivor old)
    for olds in groups.values().filter(|v| v.len() > 1) {
        let survivor = *olds.iter().min().expect("non-empty group");
        for &old in olds {
            if old != survivor {
                losers.push((old, survivor));
            }
        }
    }
    if !losers.is_empty() {
        merge_collisions(tx, &losers).await?;
    }

    let losers_set: std::collections::BTreeSet<i64> = losers.iter().map(|(l, _)| *l).collect();
    rekeyed.retain(|(old, _, _)| !losers_set.contains(old));

    rebuild_protocols(tx, &rekeyed).await?;
    rebuild_profile_stats(tx, &rekeyed).await?;

    // `endpoints.manual_protocol_override` points at a protocol id; re-point
    // losers before their rows disappear, then move winners to their new ids.
    for (loser, survivor) in &losers {
        toasty::sql::statement(format!(
            "UPDATE endpoints SET manual_protocol_override = {survivor} \
             WHERE manual_protocol_override = {loser}"
        ))
        .exec(&mut *tx)
        .await?;
    }
    for &(old, new, _) in &rekeyed {
        toasty::sql::statement(format!(
            "UPDATE endpoints SET manual_protocol_override = {new} \
             WHERE manual_protocol_override = {old}"
        ))
        .exec(&mut *tx)
        .await?;
    }

    // Rank rows cache the protocol id and ordering keys; drop the cache so
    // `endpoint_rank::ensure` rebuilds it from the re-keyed links.
    for sql in ["DELETE FROM endpoint_rank", "DELETE FROM rank_weight_meta"] {
        let _ = toasty::sql::query(sql).exec(&mut *tx).await;
    }

    toasty::sql::query(format!(
        "INSERT INTO app_meta (key, value) VALUES ('{MARKER}', '{IDENTITY_VERSION}') \
         ON CONFLICT(key) DO UPDATE SET value = excluded.value"
    ))
    .exec(&mut *tx)
    .await?;
    Ok(())
}

/// Read `(id, kind, config)` from every protocol row.
async fn read_protocols(
    tx: &mut impl toasty::Executor,
) -> Result<
    Vec<(
        i64,
        leas_proto::proto_spec::ProtocolKind,
        leas_proto::proto_spec::ProtocolConfig,
    )>,
> {
    let rows = toasty::sql::query("SELECT id, proto_kind, config FROM protocols")
        .exec(tx)
        .await?;
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let (Some(id), Some(kind), Some(config)) =
            (i64_at(&row, 0), text_at(&row, 1), text_at(&row, 2))
        else {
            return Err(DatabaseError::Generic(
                "rekey: a protocols row has a NULL id/kind/config".into(),
            ));
        };
        let kind = serde_json::from_value(serde_json::Value::String(kind.clone()))
            .or_else(|_| serde_json::from_str(&kind))
            .map_err(|e| DatabaseError::Generic(format!("rekey: bad proto_kind: {e}")))?;
        let config: leas_proto::proto_spec::ProtocolConfig = serde_json::from_str(&config)
            .map_err(|e| DatabaseError::Generic(format!("rekey: bad protocol config: {e}")))?;
        out.push((id, kind, config));
    }
    Ok(out)
}

/// Merge a loser identity's stats into its survivor's, using the merge law:
/// measured beats untested, then the lower `RankLink::key`. The survivor keeps
/// its traffic counters and `purge_reason`.
async fn merge_collisions(tx: &mut impl toasty::Executor, losers: &[(i64, i64)]) -> Result<()> {
    let weights = crate::endpoint_rank::protocol_weights(&mut *tx).await?;
    for &(loser, survivor) in losers {
        let loser_links: Vec<crate::models_toasty::ProfileStats> =
            crate::models_toasty::ProfileStats::filter(toasty::stmt::in_list(
                crate::models_toasty::ProfileStats::fields().protocol_id(),
                vec![ProtocolId::new(loser)],
            ))
            .exec(&mut *tx)
            .await?;
        for link in loser_links {
            let survivor_link: Option<crate::models_toasty::ProfileStats> =
                crate::models_toasty::ProfileStats::filter_by_protocol_id_and_endpoint_id(
                    ProtocolId::new(survivor),
                    link.endpoint_id,
                )
                .first()
                .exec(&mut *tx)
                .await?;
            if let Some(kept) = survivor_link {
                let weight = weights
                    .get(&ProtocolId::new(survivor))
                    .copied()
                    .unwrap_or(crate::weight::ZERO_WEIGHT);
                let loser_key = crate::endpoint_rank::RankLink::new(&link, weight).key(false);
                let kept_key = crate::endpoint_rank::RankLink::new(&kept, weight).key(false);
                if loser_key < kept_key {
                    overwrite_measured_fields(&mut *tx, survivor, link.endpoint_id.get(), &link)
                        .await?;
                }
            } else {
                crate::upsert_links_bulk(&mut *tx, std::slice::from_ref(&link)).await?;
                toasty::sql::statement(format!(
                    "UPDATE profile_stats SET protocol_id = {survivor} \
                     WHERE protocol_id = {loser} AND endpoint_id = {}",
                    link.endpoint_id.get()
                ))
                .exec(&mut *tx)
                .await?;
            }
        }
        toasty::sql::statement(format!(
            "DELETE FROM profile_stats WHERE protocol_id = {loser}"
        ))
        .exec(&mut *tx)
        .await?;
        toasty::sql::statement(format!("DELETE FROM protocols WHERE id = {loser}"))
            .exec(&mut *tx)
            .await?;
    }
    Ok(())
}

/// Copy the loser's measured columns onto the survivor's row; traffic and
/// `purge_reason` are deliberately untouched (merge law).
async fn overwrite_measured_fields(
    tx: &mut impl toasty::Executor,
    survivor: i64,
    endpoint: i64,
    loser: &crate::models_toasty::ProfileStats,
) -> Result<()> {
    let latency_real = loser
        .latency
        .real_delay
        .map_or_else(|| "NULL".to_owned(), |v| v.to_string());
    let latency_fast = loser
        .latency
        .fast_delay
        .map_or_else(|| "NULL".to_owned(), |v| v.to_string());
    let speed = loser
        .speed_bps
        .map_or_else(|| "NULL".to_owned(), |v| v.to_string());
    let (error, kind, text) = loser.error.as_ref().map_or_else(
        || ("NULL".to_owned(), "NULL".to_owned(), "NULL".to_owned()),
        |e| {
            (
                "1".to_owned(),
                crate::database::sql_lit(crate::database::error_kind_str(e.kind)),
                crate::database::sql_lit(&e.text),
            )
        },
    );
    toasty::sql::statement(format!(
        "UPDATE profile_stats SET latency_real_delay = {latency_real}, \
         latency_fast_delay = {latency_fast}, speed_bps = {speed}, \
         error = {error}, error_kind = {kind}, error_text = {text}, \
         stab_mask = {}, stab_len = {}, last_seen_at = MAX(last_seen_at, {}) \
         WHERE protocol_id = {survivor} AND endpoint_id = {endpoint}",
        loser.stab_mask, loser.stab_len, loser.last_seen_at,
    ))
    .exec(tx)
    .await?;
    Ok(())
}

/// Rebuild `protocols` into a fresh table with the recomputed ids/sigs.
async fn rebuild_protocols(
    tx: &mut impl toasty::Executor,
    rekeyed: &[(i64, i64, i64)],
) -> Result<()> {
    let ddl = table_ddl(tx, "protocols", "protocols_identity_new").await?;
    let indexes = index_ddl(tx, "protocols").await?;
    toasty::sql::query("DROP TABLE IF EXISTS protocols_identity_new")
        .exec(&mut *tx)
        .await?;
    toasty::sql::query(ddl).exec(&mut *tx).await?;
    let columns = columns(tx, "protocols").await?;
    let column_list = columns
        .iter()
        .map(|c| format!("\"{c}\""))
        .collect::<Vec<_>>()
        .join(", ");
    for &(old, new, sig) in rekeyed {
        // Insert with the FINAL id/sig in the SELECT: a permutation (new id =
        // another row's old id) would collide if the old id were copied first.
        let select = columns
            .iter()
            .map(|c| match c.as_str() {
                "id" => new.to_string(),
                "sig" => sig.to_string(),
                _ => format!("\"{c}\""),
            })
            .collect::<Vec<_>>()
            .join(", ");
        toasty::sql::statement(format!(
            "INSERT INTO protocols_identity_new ({column_list}) \
             SELECT {select} FROM protocols WHERE id = {old}"
        ))
        .exec(&mut *tx)
        .await?;
    }
    toasty::sql::query("DROP TABLE protocols")
        .exec(&mut *tx)
        .await?;
    toasty::sql::query("ALTER TABLE protocols_identity_new RENAME TO protocols")
        .exec(&mut *tx)
        .await?;
    for sql in indexes {
        toasty::sql::query(sql).exec(&mut *tx).await?;
    }
    Ok(())
}

/// Rebuild `profile_stats` into a fresh table with the recomputed protocol ids.
async fn rebuild_profile_stats(
    tx: &mut impl toasty::Executor,
    rekeyed: &[(i64, i64, i64)],
) -> Result<()> {
    let ddl = table_ddl(tx, "profile_stats", "profile_stats_identity_new").await?;
    let indexes = index_ddl(tx, "profile_stats").await?;
    toasty::sql::query("DROP TABLE IF EXISTS profile_stats_identity_new")
        .exec(&mut *tx)
        .await?;
    toasty::sql::query(ddl).exec(&mut *tx).await?;
    let columns = columns(tx, "profile_stats").await?;
    let column_list = columns
        .iter()
        .map(|c| format!("\"{c}\""))
        .collect::<Vec<_>>()
        .join(", ");
    for &(old, new, _) in rekeyed {
        let select = columns
            .iter()
            .map(|c| {
                if c == "protocol_id" {
                    new.to_string()
                } else {
                    format!("\"{c}\"")
                }
            })
            .collect::<Vec<_>>()
            .join(", ");
        toasty::sql::statement(format!(
            "INSERT INTO profile_stats_identity_new ({column_list}) \
             SELECT {select} FROM profile_stats WHERE protocol_id = {old}"
        ))
        .exec(&mut *tx)
        .await?;
    }
    toasty::sql::query("DROP TABLE profile_stats")
        .exec(&mut *tx)
        .await?;
    toasty::sql::query("ALTER TABLE profile_stats_identity_new RENAME TO profile_stats")
        .exec(&mut *tx)
        .await?;
    for sql in indexes {
        toasty::sql::query(sql).exec(&mut *tx).await?;
    }
    Ok(())
}

async fn table_ddl(tx: &mut impl toasty::Executor, table: &str, new_table: &str) -> Result<String> {
    let rows = toasty::sql::query(format!(
        "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = '{table}'"
    ))
    .exec(tx)
    .await?;
    let Some(sql) = rows.first().and_then(|r| text_at(r, 0)) else {
        return Err(DatabaseError::Generic(format!(
            "rekey: missing table {table}"
        )));
    };
    Ok(sql.replacen(table, new_table, 1))
}

async fn index_ddl(tx: &mut impl toasty::Executor, table: &str) -> Result<Vec<String>> {
    let rows = toasty::sql::query(format!(
        "SELECT sql FROM sqlite_master WHERE type = 'index' AND tbl_name = '{table}' \
         AND sql IS NOT NULL"
    ))
    .exec(tx)
    .await?;
    Ok(rows.iter().filter_map(|r| text_at(r, 0)).collect())
}

fn text_at(row: &Value, idx: usize) -> Option<String> {
    match row {
        Value::Record(record) => match record.fields.get(idx) {
            Some(Value::String(s)) => Some(s.clone()),
            _ => None,
        },
        _ => None,
    }
}

fn i64_at(row: &Value, idx: usize) -> Option<i64> {
    match row {
        Value::Record(record) => match record.fields.get(idx) {
            Some(Value::I64(n)) => Some(*n),
            _ => None,
        },
        _ => None,
    }
}

async fn columns(tx: &mut impl toasty::Executor, table: &str) -> Result<Vec<String>> {
    let rows = toasty::sql::query(format!("PRAGMA table_info({table})"))
        .exec(tx)
        .await?;
    Ok(rows.iter().filter_map(|r| text_at(r, 1)).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Database;
    use crate::models_toasty::{
        Endpoint, EndpointId, HostType, Latency, ProfileStats, Protocol, ProtocolId, Security,
        TrafficStats, Transport,
    };
    use leas_proto::proto_spec::{
        ParsedProto, PlaceholderConfig, ProtocolConfig, ProtocolEssentials, ProtocolKind,
        SecurityType, TransportType,
    };
    use toasty::{Deferred, Json};

    fn new_id(config: ProtocolConfig) -> (i64, i64) {
        let parsed = ParsedProto {
            endpoints: Vec::new(),
            protocol: ProtocolEssentials {
                proto_kind: ProtocolKind::Redirect,
                config,
            },
        };
        (parsed.uid(), parsed.sig())
    }

    fn protocol(id: i64, sig: i64, body: &[u8]) -> Protocol {
        Protocol {
            id: ProtocolId::new(id),
            sig,
            proto_kind: ProtocolKind::Redirect,
            transport: Transport {
                r#type: TransportType::Tcp,
            },
            security: Security {
                r#type: SecurityType::None,
                sni: None,
                fp: None,
                insecure: None,
            },
            config: Deferred::from(Json(ProtocolConfig::Redirect(PlaceholderConfig::new(
                "redirect".to_string(),
                body.to_vec(),
            )))),
            created_at: 0,
            links: Deferred::default(),
        }
    }

    fn link(pid: i64, eid: i64, latency: Latency, up: i64) -> ProfileStats {
        ProfileStats {
            protocol_id: ProtocolId::new(pid),
            endpoint_id: EndpointId::new(eid),
            last_used_at: None,
            last_seen_at: 1,
            latency,
            speed_bps: None,
            error: None,
            purge_reason: None,
            stab_mask: 0,
            stab_len: 0,
            traffic: TrafficStats {
                today_up: up,
                today_down: 0,
                total_up: up,
                total_down: 0,
            },
            created_at: 0,
            updated_at: 0,
            version: 1,
            protocol: Deferred::default(),
            endpoint: Deferred::default(),
        }
    }

    #[tokio::test]
    async fn identity_rekey_merges_duplicates_and_handles_a_permutation() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("rekey.db");

        // Two DISTINCT configs, used to build a permutation: each row is
        // stored under the OTHER's new id.
        let cfg_a =
            ProtocolConfig::Redirect(PlaceholderConfig::new("redirect".into(), b"a".to_vec()));
        let cfg_b =
            ProtocolConfig::Redirect(PlaceholderConfig::new("redirect".into(), b"b".to_vec()));
        let cfg_c =
            ProtocolConfig::Redirect(PlaceholderConfig::new("redirect".into(), b"c".to_vec()));
        let (new_a, sig_a) = new_id(cfg_a.clone());
        let (new_b, sig_b) = new_id(cfg_b.clone());
        let (new_c, sig_c) = new_id(cfg_c.clone());

        {
            let db = Database::open(&path).await.expect("open");
            let mut conn = db.connection().await.expect("connection");
            toasty::create!(Endpoint {
                created_at: 0,
                id: EndpointId::new(1),
                domain: Endpoint::derive_domain("1.1.1.1", HostType::Ipv4).0,
                sub_domain: Endpoint::derive_domain("1.1.1.1", HostType::Ipv4).1,
                port: 443,
                ports: Vec::<u16>::new(),
                manual_protocol_override: Some(ProtocolId::new(5002)),
                resolved_at: None,
            })
            .exec(&mut conn)
            .await
            .expect("endpoint");

            // Permutation pair: A stored as new_b, B stored as new_a.
            crate::upsert_protocols_bulk(
                &mut conn,
                &[
                    protocol(new_b, sig_b, b"a"),
                    protocol(new_a, sig_a, b"b"),
                    // Duplicate identity group: the same config twice.
                    protocol(5001, sig_c, b"c"),
                    protocol(5002, sig_c, b"c"),
                ],
            )
            .await
            .expect("protocols");

            // Duplicate group stats: survivor (5001) untested traffic 1;
            // loser (5002) measured 42 ms traffic 9.
            crate::upsert_links_bulk(
                &mut conn,
                &[
                    link(5001, 1, Latency::fast(200), 1),
                    link(5002, 1, Latency::real(42), 9),
                ],
            )
            .await
            .expect("links");

            toasty::sql::query("DELETE FROM app_meta WHERE key = 'identity_version'")
                .exec(&mut conn)
                .await
                .expect("clear marker");
        }

        let db = Database::open(&path).await.expect("reopen");
        let mut conn = db.connection().await.expect("connection");
        let rows = toasty::sql::query("SELECT id FROM protocols ORDER BY id")
            .exec(&mut conn)
            .await
            .expect("ids");
        let mut ids: Vec<i64> = rows.iter().filter_map(|r| i64_at(r, 0)).collect();
        ids.sort_unstable();
        let mut want = vec![new_a, new_b, new_c];
        want.sort_unstable();
        assert_eq!(ids, want, "permutation swap + duplicate collapse");

        let merged = ProfileStats::filter_by_protocol_id_and_endpoint_id(
            ProtocolId::new(new_c),
            EndpointId::new(1),
        )
        .first()
        .exec(&mut conn)
        .await
        .expect("merged link")
        .expect("survivor row");
        assert_eq!(
            merged.latency.real_delay,
            Some(42),
            "measured evidence wins"
        );
        assert_eq!(merged.traffic.total_up, 1, "survivor keeps its counters");

        let endpoint = Endpoint::filter_by_id(EndpointId::new(1))
            .first()
            .exec(&mut conn)
            .await
            .expect("endpoint read")
            .expect("endpoint");
        assert_eq!(
            endpoint.manual_protocol_override,
            Some(ProtocolId::new(new_c)),
            "override re-pointed to the survivor's new id"
        );
        drop(conn);
        drop(db);

        // Re-opening is a marker no-op: the ids do not move again.
        let db = Database::open(&path).await.expect("second reopen");
        let mut conn = db.connection().await.expect("connection");
        let rows = toasty::sql::query("SELECT id FROM protocols ORDER BY id")
            .exec(&mut conn)
            .await
            .expect("ids");
        let again: Vec<i64> = rows.iter().filter_map(|r| i64_at(r, 0)).collect();
        assert_eq!(again, ids);
    }
}
