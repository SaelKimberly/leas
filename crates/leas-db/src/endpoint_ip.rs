//! `endpoint_ip` support: the sortable address key and the table's accessors.
//!
//! The table ([`crate::models_toasty::EndpointIp`]) is the single owner of a
//! DNS endpoint's resolved addresses — the JSON-array `endpoints.resolved_as`
//! column it replaces could not be indexed, joined, or ordered, and stored an
//! address list as opaque text.
//!
//! # Why not the engine's `inet` type
//!
//! Turso ships `inet` as a built-in custom type,
//! `CREATE TYPE inet(value text) BASE text ENCODE validate_ipaddr(value)
//! DECODE value` (`turso_core` `schema.rs`). It validates, and does
//! nothing else: with no `OPERATOR '<'` the engine refuses to order or index a
//! column of that type (`cannot ORDER BY column 'ip' of type 'inet': type does
//! not declare OPERATOR '<'`), and it is inert outside a STRICT table, which
//! `toasty` cannot emit. So the ordering lives in the *stored key* instead —
//! [`key_of`] / [`ip_of`], byte order == numeric order.
//!
//! # The key
//!
//! `[family, address-bytes…]`: `4` + 4 bytes for IPv4, `6` + 16 bytes for
//! IPv6. The family byte leads so IPv4 (`0x04…`) sorts before every IPv6
//! (`0x06…`), and within a family the big-endian bytes compare as the
//! addresses do. B-tree comparison of blobs is `memcmp`, so `ORDER BY ip_key`
//! (and an index on it) is exactly the address order.
//!
//! [`key_of`] is total over `IpAddr` and the column stores nothing else, so
//! the address and its order cannot disagree; the text form exists only for a
//! display, rendered from the bytes on read.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::error::Result;
use crate::models_toasty::{EndpointId, EndpointIp};
use toasty_core::stmt::Value;

/// Family byte of an IPv4 key: every IPv4 address sorts before every IPv6.
const FAMILY_V4: u8 = 4;
/// Family byte of an IPv6 key.
const FAMILY_V6: u8 = 6;
/// Longest key: the family byte plus 16 address octets.
const MAX_KEY_LEN: usize = 17;

/// The sortable key of an address. Byte order is address order, IPv4 first.
#[must_use]
pub fn key_of(ip: IpAddr) -> Vec<u8> {
    let mut out = Vec::with_capacity(MAX_KEY_LEN);
    match ip {
        IpAddr::V4(v4) => {
            out.push(FAMILY_V4);
            out.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            out.push(FAMILY_V6);
            out.extend_from_slice(&v6.octets());
        }
    }
    out
}

/// The sortable key of a textual address, `None` when the text is not one.
///
/// The stored column is the binary key, so no write path parses text any
/// more; this stays for callers that start from a string (fixtures, a URL's
/// host field) and as the codec's textual entry point.
#[must_use]
pub fn key_of_str(text: &str) -> Option<Vec<u8>> {
    text.parse::<IpAddr>().ok().map(key_of)
}

/// The address a key encodes, in its canonical text form.
#[must_use]
pub fn ip_of(key: &[u8]) -> Option<IpAddr> {
    match key {
        [FAMILY_V4, a, b, c, d] => Some(IpAddr::V4(Ipv4Addr::new(*a, *b, *c, *d))),
        [FAMILY_V6, rest @ ..] if rest.len() == 16 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(rest);
            Some(IpAddr::V6(Ipv6Addr::from(octets)))
        }
        _ => None,
    }
}

/// The key behind a hex string — the form a SQL aggregate can carry.
///
/// `hex()` on a BLOB is the only way the engine can hand a stored key back
/// through `group_concat` (it has no address renderer, and a raw-blob
/// `group_concat` coerces the bytes through TEXT), so the page's decoder walks
/// hex → key → [`IpAddr`]. The key is built in a stack buffer: the only
/// allocation on this path is the driver's own `Vec<u8>` for the hex string.
/// A malformed string yields `None` rather than a guess.
#[must_use]
pub fn key_from_hex(hex: &str) -> Option<IpAddr> {
    let bytes = hex.as_bytes();
    if !bytes.len().is_multiple_of(2) || bytes.len() > 2 * MAX_KEY_LEN {
        return None;
    }
    let mut key = [0u8; MAX_KEY_LEN];
    for (slot, pair) in key.iter_mut().zip(bytes.as_chunks::<2>().0) {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        *slot = u8::try_from(hi * 16 + lo).ok()?;
    }
    ip_of(&key[..bytes.len() / 2])
}

/// Replace the resolved address set of `endpoint_id` with `ips`.
///
/// One transaction's worth of work — the caller owns the transaction — and a
/// full replacement, because the set is what the resolver just returned:
/// prune-what-is-gone would need the old set, and a re-resolution is rare
/// enough (TTL-gated) that rewriting one to three rows is the cheap path.
pub async fn replace(
    conn: &mut impl toasty::Executor,
    endpoint_id: EndpointId,
    ips: &[IpAddr],
) -> Result<()> {
    // Carry the countries of the addresses that are still present: a
    // re-resolution must not throw away a lookup that already happened (the
    // whole point of storing them), and the set is small enough that one
    // per-endpoint read is cheaper than re-walking the mmdb.
    let known = countries_of(conn, &[endpoint_id]).await?;
    let known = known.get(&endpoint_id);
    EndpointIp::filter_by_endpoint_id(endpoint_id)
        .delete()
        .exec(conn)
        .await?;
    // Dedup by key: the PK is (endpoint_id, ip_key), and a duplicated address
    // in one DNS answer must not be a constraint violation.
    let mut keys: Vec<Vec<u8>> = ips.iter().map(|ip| key_of(*ip)).collect();
    keys.sort_unstable();
    keys.dedup();
    for key in keys {
        // The set was just emptied, so this is a plain insert — there is no
        // value to update on conflict (`upsert` refuses a key-only model).
        let country = known
            .and_then(|map| map.get(&key).cloned())
            .filter(|iso| !iso.is_empty());
        toasty::create!(EndpointIp {
            endpoint_id,
            ip_key: key,
            country,
        })
        .exec(conn)
        .await?;
    }
    Ok(())
}

/// Bulk-insert IP-literal address rows — the IMPORT hot path (db-rewamp D10).
///
/// An IP literal's address set is immutable and its row is written once, at
/// import, so this is a single multi-row `INSERT … ON CONFLICT DO NOTHING` per
/// 400 rows — NO per-endpoint read or delete. `replace` (delete-then-insert
/// plus a `countries_of` read) is the RESOLUTION path, where the set is what
/// the resolver just returned; reusing it here cost 3 statements × ~56k
/// IP-literal endpoints, reintroducing the per-row import shape ADR 0008
/// measured at 360 ms/2k links vs 44.3 ms bulk.
///
/// `DO NOTHING` is semantically exact: the row already exists only when the
/// same literal was imported before, and then its `country` (written by the
/// geo step) MUST survive — an insert that overwrote it would erase a lookup.
pub async fn insert_literals_bulk(
    conn: &mut impl toasty::Executor,
    rows: &[(EndpointId, IpAddr)],
) -> Result<()> {
    use std::fmt::Write as _;
    if rows.is_empty() {
        return Ok(());
    }
    // Dedup by (endpoint, key): the PK is the pair, and a duplicated literal
    // must not be a constraint violation.
    let mut seen: std::collections::HashSet<(i64, Vec<u8>)> =
        std::collections::HashSet::with_capacity(rows.len());
    let mut pairs: Vec<(i64, Vec<u8>)> = Vec::with_capacity(rows.len());
    for (id, ip) in rows {
        let key = key_of(*ip);
        if seen.insert((id.get(), key.clone())) {
            pairs.push((id.get(), key));
        }
    }
    for chunk in pairs.chunks(LITERAL_BULK_ROWS) {
        let mut sql = String::with_capacity(chunk.len() * 48 + 96);
        sql.push_str("INSERT INTO \"endpoint_ip\" (\"endpoint_id\", \"ip_key\") VALUES ");
        for (i, (id, key)) in chunk.iter().enumerate() {
            if i > 0 {
                sql.push(',');
            }
            let _ = write!(sql, "({id}, x'{}')", hex_lit(key));
        }
        sql.push_str(" ON CONFLICT(\"endpoint_id\", \"ip_key\") DO NOTHING");
        toasty::sql::statement(sql).exec(conn).await?;
    }
    Ok(())
}

/// Rows per bulk statement — the same 400 the other import bulk writers use
/// (`database::IMPORT_STATEMENT_ROWS`); kept local because that constant is
/// private to its module.
const LITERAL_BULK_ROWS: usize = 400;

/// Lowercase hex of a key, for a `x'…'` blob literal.
fn hex_lit(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// The persisted countries of `ids`, keyed by endpoint and address key.
///
/// One statement for the whole set, ids inlined for the same reason [`load`]
/// inlines them (the engine charges per bound parameter).
async fn countries_of(
    conn: &mut impl toasty::Executor,
    ids: &[EndpointId],
) -> Result<HashMap<EndpointId, HashMap<Vec<u8>, String>>> {
    let mut out: HashMap<EndpointId, HashMap<Vec<u8>, String>> = HashMap::new();
    if ids.is_empty() {
        return Ok(out);
    }
    let id_list = id_list(ids);
    let rows = toasty::sql::query(format!(
        "SELECT endpoint_id, ip_key, country FROM endpoint_ip \
         WHERE endpoint_id IN ({id_list}) AND country IS NOT NULL"
    ))
    .exec(conn)
    .await?;
    for row in &rows {
        let Value::Record(record) = row else {
            continue;
        };
        let id = record.fields.first().and_then(|v| match v {
            Value::I64(n) => Some(*n),
            _ => None,
        });
        let key = record.fields.get(1).and_then(|v| match v {
            Value::Bytes(bytes) => Some(bytes.clone()),
            _ => None,
        });
        let country = record.fields.get(2).and_then(|v| match v {
            Value::String(text) if !text.is_empty() => Some(text.clone()),
            _ => None,
        });
        if let (Some(id), Some(key), Some(country)) = (id, key, country) {
            out.entry(EndpointId::new(id))
                .or_default()
                .insert(key, country);
        }
    }
    Ok(out)
}

/// Record the countries of a whole geo window — ONE multi-row upsert per 400
/// rows.
///
/// The write the geo lookup makes once per address; `replace` keeps it
/// afterwards. Rows are created when missing: the lookup and the address write
/// race by design (the geo step runs after the resolution event was already
/// queued), and a country that arrives first must not be dropped — hence
/// `DO UPDATE SET country = excluded.country` rather than `DO NOTHING`.
///
/// Two properties are load-bearing, both learned the hard way:
///
/// * **`ON CONFLICT … DO UPDATE`, not SELECT-then-write.** The per-row shape was
///   a TOCTOU: two writers could both miss and both INSERT the same composite
///   PK. Under WAL that cannot happen (the transaction holds the write lock),
///   but under MVCC it can, and the resulting `Constraint` is NOT a busy error —
///   [`crate::is_busy_error`] is false for it — so `retry_on_busy` never retried
///   it, at ANY budget. One statement removes the race.
/// * **Multi-row, chunked.** A geo window is hundreds of addresses, and each row
///   carries a distinct `endpoint_id`/`ip_key`, so per-row statements are that
///   many distinct SQL texts (each an uncached compile on the `RawSql` route).
///   `insert_literals_bulk` above set this precedent for the address half
///   (204,592 statements → ~511) and the country half is the same data at the
///   same rate.
pub(crate) async fn set_countries_bulk(
    conn: &mut impl toasty::Executor,
    rows: &[(EndpointId, IpAddr, String)],
) -> Result<()> {
    use std::collections::hash_map::Entry;
    use std::fmt::Write as _;
    if rows.is_empty() {
        return Ok(());
    }
    // Dedup by (endpoint, key), LAST occurrence winning: the PK is the pair, and
    // two rows for one address in one statement are a write collision, not two
    // writes. Last-wins is the semantics of the per-row loop this replaced (a
    // later `set_country` overwrote an earlier one) and of
    // `write_behind::CountrySpec::coalesce`, which already keeps one row per
    // endpoint — so this branch is not reachable FROM the geo drain today, and it
    // exists to keep the ordering contract explicit rather than to be exercised.
    // First-seen order is preserved so the statement's row order is stable.
    let mut slot: std::collections::HashMap<(i64, Vec<u8>), usize> =
        std::collections::HashMap::with_capacity(rows.len());
    let mut pairs: Vec<(i64, Vec<u8>, &str)> = Vec::with_capacity(rows.len());
    for (id, ip, iso) in rows {
        let key = key_of(*ip);
        match slot.entry((id.get(), key.clone())) {
            Entry::Occupied(e) => pairs[*e.get()].2 = iso.as_str(),
            Entry::Vacant(e) => {
                e.insert(pairs.len());
                pairs.push((id.get(), key, iso.as_str()));
            }
        }
    }
    for chunk in pairs.chunks(LITERAL_BULK_ROWS) {
        let mut sql = String::with_capacity(chunk.len() * 64 + 160);
        sql.push_str(
            "INSERT INTO \"endpoint_ip\" (\"endpoint_id\", \"ip_key\", \"country\") VALUES ",
        );
        for (i, (id, key, iso)) in chunk.iter().enumerate() {
            if i > 0 {
                sql.push(',');
            }
            let _ = write!(
                sql,
                "({id}, x'{}', {})",
                hex_lit(key),
                crate::database::sql_lit(iso)
            );
        }
        sql.push_str(
            " ON CONFLICT(\"endpoint_id\", \"ip_key\") DO UPDATE SET \"country\" = excluded.\"country\"",
        );
        toasty::sql::statement(sql).exec(conn).await?;
    }
    Ok(())
}

/// The id list form every raw statement here inlines.
fn id_list(ids: &[EndpointId]) -> String {
    ids.iter()
        .map(|id| id.get().to_string())
        .collect::<Vec<_>>()
        .join(",")
}

/// The resolved addresses of `ids`, key-ordered (the display order).
///
/// Inlined ids and one statement for the whole set: the page's typed oracle
/// and the enrich seed both read a page at a time, and the engine charges
/// ~0.8 ms per *bound* parameter — the same reason the page's hydration
/// inlines its ids (`profiles_query`).
pub(crate) async fn load(
    conn: &mut impl toasty::Executor,
    ids: &[EndpointId],
) -> Result<HashMap<EndpointId, Vec<IpAddr>>> {
    let resolved = load_resolved(conn, ids).await?;
    Ok(resolved
        .into_iter()
        .map(|(id, addrs)| (id, addrs.into_iter().map(|(ip, _)| ip).collect()))
        .collect())
}

/// The resolved addresses of `ids` with the country each one carries.
///
/// The enrichment seed reads this one: an address whose country is already
/// stored needs no mmdb walk (and a launch whose addresses are all stored
/// needs no mmdb at all), while `None` is exactly the set worth looking up.
pub(crate) async fn load_resolved(
    conn: &mut impl toasty::Executor,
    ids: &[EndpointId],
) -> Result<HashMap<EndpointId, Vec<(IpAddr, Option<String>)>>> {
    let mut out: HashMap<EndpointId, Vec<(IpAddr, Option<String>)>> = HashMap::new();
    if ids.is_empty() {
        return Ok(out);
    }
    let id_list = id_list(ids);
    let rows = toasty::sql::query(format!(
        "SELECT endpoint_id, ip_key, country FROM endpoint_ip WHERE endpoint_id IN ({id_list}) \
         ORDER BY endpoint_id, ip_key"
    ))
    .exec(conn)
    .await?;
    for row in &rows {
        let Value::Record(record) = row else {
            continue;
        };
        let id = record.fields.first().and_then(|v| match v {
            Value::I64(n) => Some(*n),
            _ => None,
        });
        let ip = record
            .fields
            .get(1)
            .and_then(|v| match v {
                Value::Bytes(bytes) => Some(bytes.as_slice()),
                _ => None,
            })
            .and_then(ip_of);
        let country = record.fields.get(2).and_then(|v| match v {
            Value::String(text) if !text.is_empty() => Some(text.clone()),
            _ => None,
        });
        if let (Some(id), Some(ip)) = (id, ip) {
            out.entry(EndpointId::new(id))
                .or_default()
                .push((ip, country));
        }
    }
    Ok(out)
}

/// Delete the addresses of `endpoint_ids`. The deletion owners call this in
/// the same transaction that removes the endpoint rows.
pub(crate) async fn delete_for(
    conn: &mut impl toasty::Executor,
    endpoint_ids: &[EndpointId],
) -> Result<()> {
    if endpoint_ids.is_empty() {
        return Ok(());
    }
    let list = endpoint_ids
        .iter()
        .map(|id| id.get().to_string())
        .collect::<Vec<_>>()
        .join(",");
    toasty::sql::query(format!(
        "DELETE FROM endpoint_ip WHERE endpoint_id IN ({list})"
    ))
    .exec(conn)
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The canonical text of a stored key — what the display column holds.
    fn text_of(key: &[u8]) -> String {
        ip_of(key)
            .expect("a key this module wrote decodes")
            .to_string()
    }

    /// `set_countries_bulk` MUST be an atomic upsert, not a read-then-write.
    ///
    /// The old shape was a TOCTOU: two writers could both SELECT-miss and both
    /// INSERT the same `(endpoint_id, ip_key)` PK. Under WAL the transaction
    /// holds the write lock so it cannot happen; under MVCC it can, and the
    /// resulting `Constraint` is not a busy error — `retry_on_busy` would never
    /// retry it, at ANY budget. This pins the single-statement form: the write
    /// count for a fresh row is 1 (an upsert), and the second call UPDATES
    /// rather than failing on the existing PK.
    /// An in-batch duplicate `(endpoint_id, ip_key)` takes the LAST value.
    ///
    /// Not reachable from the geo drain (`CountrySpec::coalesce` keeps one row
    /// per endpoint), so this pins the ORDERING CONTRACT rather than a live path:
    /// it is the semantics of the per-row loop the bulk writer replaced, and a
    /// comment (or a later refactor) that flipped it to first-wins would change
    /// which country a racing window lands on without any test objecting.
    #[tokio::test]
    async fn set_countries_bulk_keeps_the_last_value_for_a_duplicate_row() {
        let db = crate::Database::in_memory().await.expect("db");
        let mut conn = db.connection().await.expect("conn");
        let ip: std::net::IpAddr = "203.0.113.9".parse().expect("ip");
        let id = EndpointId::new(11);

        set_countries_bulk(
            &mut conn,
            &[
                (id, ip, "DE".to_string()),
                (id, ip, "FR".to_string()), // same pair: this one wins
            ],
        )
        .await
        .expect("bulk write");

        let stored = load_resolved(&mut conn, &[id]).await.expect("load");
        let rows = stored.get(&id).expect("one endpoint");
        assert_eq!(rows.len(), 1, "the duplicate must collapse to one PK row");
        assert_eq!(rows[0].1.as_deref(), Some("FR"), "LAST value wins");
    }

    #[tokio::test]
    async fn set_countries_bulk_is_an_atomic_upsert() {
        let db = crate::Database::in_memory().await.expect("db");
        let mut conn = db.connection().await.expect("conn");
        // No endpoint row is needed: `set_country` writes `endpoint_ip` alone
        // (there is no FK — see ADR 0012's T12 rejection).
        let ip: std::net::IpAddr = "198.51.100.77".parse().expect("ip");

        // First write: creates the row.
        set_countries_bulk(&mut conn, &[(EndpointId::new(7), ip, "DE".to_string())])
            .await
            .expect("first write");

        // Second write on the SAME row: the upsert's DO UPDATE branch. A
        // read-then-create would have raced here; without the upsert it is at
        // best an update, at worst a constraint violation.
        set_countries_bulk(&mut conn, &[(EndpointId::new(7), ip, "FR".to_string())])
            .await
            .expect("second write must update, not conflict");

        let stored = load_resolved(&mut conn, &[EndpointId::new(7)])
            .await
            .expect("load");
        let rows = stored.get(&EndpointId::new(7)).expect("one endpoint");
        assert_eq!(rows.len(), 1, "the upsert must not duplicate the PK");
        assert_eq!(rows[0].1.as_deref(), Some("FR"), "the later country wins");
    }

    #[test]
    fn key_round_trips_every_family() {
        for text in [
            "0.0.0.0",
            "10.0.0.1",
            "255.255.255.255",
            "::",
            "::1",
            "2001:db8::1",
            "fe80::1",
            "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
        ] {
            let key = key_of_str(text).expect("parses");
            assert_eq!(text_of(&key), text);
        }
    }

    #[test]
    fn byte_order_is_numeric_order() {
        // The property the whole design rests on: sorting keys as bytes gives
        // the address order, with IPv4 ahead of IPv6.
        let mut ips = vec![
            "9.9.9.9",
            "10.0.0.1",
            "10.0.0.2",
            "100.0.0.1",
            "2001:db8::1",
            "::1",
            "1.2.3.4",
        ];
        ips.sort_by_key(|t| key_of_str(t).expect("parses"));
        assert_eq!(
            ips,
            vec![
                "1.2.3.4",
                "9.9.9.9",
                "10.0.0.1",
                "10.0.0.2",
                "100.0.0.1",
                "::1",
                "2001:db8::1",
            ],
            "10.0.0.1 must precede 9.9.9.9 (numeric, not lexicographic), and IPv4 must precede IPv6"
        );
    }

    #[test]
    fn bad_input_has_no_key() {
        assert!(key_of_str("").is_none());
        assert!(key_of_str("not-an-ip").is_none());
        assert!(key_of_str("10.0.0.256").is_none());
        assert!(key_of_str("10.0.0.1/24").is_none());
        assert_eq!(ip_of(&[4, 1, 2]), None);
        assert_eq!(ip_of(&[]), None);
        assert_eq!(ip_of(&[7, 1, 2, 3, 4]), None);
        assert_eq!(
            ip_of(&[6, 1, 2]),
            None,
            "a short IPv6 key is not an address"
        );
    }

    #[test]
    fn hex_round_trips_and_rejects_junk() {
        // The page's decoder reads the key back out of a `group_concat(hex())`
        // column, so this is the contract the projection depends on.
        for text in ["10.0.0.1", "2001:db8::1", "::1"] {
            let key = key_of_str(text).expect("parses");
            let mut hex = String::new();
            for byte in &key {
                use std::fmt::Write as _;
                let _ = write!(hex, "{byte:02x}");
            }
            assert_eq!(key_from_hex(&hex), Some(text.parse().expect("addr")));
            assert_eq!(
                key_from_hex(&hex.to_uppercase()),
                Some(text.parse().expect("addr")),
                "the engine's hex() is uppercase"
            );
        }
        assert_eq!(key_from_hex(""), None);
        assert_eq!(key_from_hex("abc"), None, "odd length");
        assert_eq!(key_from_hex("zz"), None, "not hex");
        // `0400000001` is NOT junk: it is the v4 key of 0.0.0.1.
        assert_eq!(
            key_from_hex("0400000001"),
            Some("0.0.0.1".parse().expect("addr"))
        );
        assert_eq!(key_from_hex("04000000"), None, "a short v4 payload");
        assert_eq!(key_from_hex("040000000000"), None, "a long v4 payload");
        assert_eq!(
            key_from_hex("0400000000000000000000000000000000000001"),
            None,
            "beyond the longest key"
        );
    }

    #[test]
    fn keys_of_the_same_address_are_identical() {
        assert_eq!(key_of_str("10.0.0.1"), key_of_str("10.0.0.1"));
        assert_eq!(
            key_of_str("2001:DB8::1"),
            key_of_str("2001:db8:0:0:0:0:0:1"),
            "text spelling must not reach the key"
        );
    }
}
