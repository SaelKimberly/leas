//! Direct Turso reader lifecycle and row projection for whole-feed export.

use std::path::Path;

use leas_proto::proto_spec::{EndpointEssentials, HostKind, ProtocolConfig, ProtocolKind};
use turso::Value;

use crate::error::{DatabaseError, Result};
use crate::models_toasty::{
    EndpointId, ErrorInfo, Latency, ProfileErr, ProfileStats, ProtocolId, PurgeReason, TrafficStats,
};
use crate::{Database, endpoint_ip};

/// Stored-link selection for export.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportScope {
    Alive,
    Resolved,
    Active,
    Full,
}

impl ExportScope {
    /// Header title suffix.
    #[must_use]
    pub const fn title(self) -> &'static str {
        match self {
            Self::Alive => "Alive",
            Self::Resolved => "Resolved",
            Self::Active => "Active",
            Self::Full => "Full",
        }
    }

    const fn predicate(self) -> &'static str {
        match self {
            Self::Alive => {
                "ps.purge_reason IS NULL AND ps.error_kind IS NULL \
                 AND (ps.latency_real_delay IS NOT NULL OR ps.latency_fast_delay IS NOT NULL) \
                 AND (e.domain = '' OR EXISTS (SELECT 1 FROM endpoint_ip dial WHERE dial.endpoint_id = e.id))"
            }
            Self::Resolved => {
                // "has a dialable address" — the address row IS the condition.
                // `e.domain = ''` would also admit an exotic/Undefined host
                // (empty domain, NO address row), which must not be emitted.
                "EXISTS (SELECT 1 FROM endpoint_ip dial WHERE dial.endpoint_id = e.id)"
            }
            Self::Active => "er.band = 0 AND ps.purge_reason IS NULL",
            Self::Full => "ps.purge_reason IS NULL",
        }
    }
}

/// One decoded export row. Resolved rows carry one stored address each.
#[derive(Debug, Clone)]
pub struct ExportRow {
    pub endpoint: EndpointEssentials,
    pub protocol: ProtocolConfig,
    pub proto_kind: ProtocolKind,
    pub transport_type: String,
    pub security_type: String,
    pub link: ProfileStats,
    pub resolved_ip: Option<std::net::IpAddr>,
    pub ip_key: Vec<u8>,
}

/// A direct read transaction over one dedicated Turso connection.
pub struct ExportReader {
    _guard: tokio::sync::OwnedMutexGuard<()>,
    conn: turso::Connection,
    rows: Option<turso::Rows>,
    candidate_count: u64,
    scope: ExportScope,
    finished: bool,
}

impl ExportReader {
    /// Number of matching stored links before Resolved expansion or serializer
    /// failures.
    #[must_use]
    pub const fn candidate_count(&self) -> u64 {
        self.candidate_count
    }

    /// Fetch and decode the next physical row.
    pub async fn next_row(&mut self) -> Result<Option<ExportRow>> {
        let Some(rows) = self.rows.as_mut() else {
            return Ok(None);
        };
        let Some(row) = rows.next().await.map_err(turso_error)? else {
            self.rows = None;
            return Ok(None);
        };
        decode_row(&row, self.scope).map(Some)
    }

    /// Drain the cursor, commit, and release the export lock.
    pub async fn finish(mut self) -> Result<()> {
        self.finish_inner("COMMIT").await
    }

    /// Drain the cursor, roll back, and release the export lock.
    pub async fn rollback(mut self) -> Result<()> {
        self.finish_inner("ROLLBACK").await
    }

    async fn finish_inner(&mut self, statement: &str) -> Result<()> {
        if self.finished {
            return Ok(());
        }
        self.finished = true;
        if let Some(mut rows) = self.rows.take() {
            while rows.next().await.map_err(turso_error)?.is_some() {}
        }
        self.conn
            .execute(statement, ())
            .await
            .map_err(turso_error)?;
        Ok(())
    }
}

impl Drop for ExportReader {
    fn drop(&mut self) {
        // Explicit finish/rollback is normal. Drop owns only the dedicated
        // connection and cannot strand a Toasty pool slot.
    }
}

impl Database {
    /// Start a whole-feed export read in one direct read transaction.
    pub async fn open_export_reader(&self, scope: ExportScope) -> Result<ExportReader> {
        let Some(path) = self.export_path() else {
            return Err(DatabaseError::Generic(
                "streaming export requires a file-backed database".into(),
            ));
        };
        let guard = self.export_guard().await;
        let turso_db = turso::Builder::new_local(path_str(path)?)
            .build()
            .await
            .map_err(turso_error)?;
        let conn = turso_db.connect().map_err(turso_error)?;
        let journal = if self.uses_concurrent_writes() {
            "mvcc"
        } else {
            "wal"
        };
        conn.pragma_update("journal_mode", format!("'{journal}'"))
            .await
            .map_err(turso_error)?;
        conn.execute(
            if self.uses_concurrent_writes() {
                "BEGIN CONCURRENT"
            } else {
                "BEGIN DEFERRED"
            },
            (),
        )
        .await
        .map_err(turso_error)?;

        let count_sql = format!(
            "SELECT COUNT(*) FROM profile_stats ps \
             JOIN endpoints e ON e.id = ps.endpoint_id \
             LEFT JOIN endpoint_rank er ON er.endpoint_id = e.id \
             WHERE {}",
            scope.predicate()
        );
        let candidate_count = query_count(&conn, &count_sql).await?;
        let rows = conn
            .query(projection_sql(scope), ())
            .await
            .map_err(turso_error)?;
        Ok(ExportReader {
            _guard: guard,
            conn,
            rows: Some(rows),
            candidate_count,
            scope,
            finished: false,
        })
    }
}

async fn query_count(conn: &turso::Connection, sql: &str) -> Result<u64> {
    let mut rows = conn.query(sql, ()).await.map_err(turso_error)?;
    let Some(row) = rows.next().await.map_err(turso_error)? else {
        return Err(DatabaseError::Generic(
            "export count returned no row".into(),
        ));
    };
    let count = row.get::<i64>(0).map_err(turso_error)?;
    while rows.next().await.map_err(turso_error)?.is_some() {}
    u64::try_from(count).map_err(|_| DatabaseError::Generic("export count was negative".into()))
}

fn projection_sql(scope: ExportScope) -> String {
    let (address_join, address_key) = if scope == ExportScope::Resolved {
        (
            "LEFT JOIN endpoint_ip ip ON ip.endpoint_id = e.id",
            "ip.ip_key",
        )
    } else {
        (
            "",
            "(SELECT min(dial.ip_key) FROM endpoint_ip dial WHERE dial.endpoint_id = e.id)",
        )
    };
    format!(
        "SELECT e.domain, e.sub_domain, e.port, e.ports, \
         pr.proto_kind, pr.transport_type, pr.security_type, pr.config, \
         ps.protocol_id, ps.endpoint_id, \
         ps.last_used_at, ps.last_seen_at, ps.latency_real_delay, ps.latency_fast_delay, \
         ps.latency_ip, ps.latency_auth, \
         ps.speed_bps, ps.error, ps.error_kind, ps.error_text, ps.purge_reason, \
         ps.traffic_today_up, ps.traffic_today_down, ps.traffic_total_up, ps.traffic_total_down, \
         ps.created_at, ps.updated_at, ps.version, {address_key} AS ip_key, \
         CASE WHEN e.domain = '' AND EXISTS (SELECT 1 FROM endpoint_ip dial WHERE dial.endpoint_id = e.id) THEN 1 \
              WHEN EXISTS (SELECT 1 FROM endpoint_ip dial WHERE dial.endpoint_id = e.id) THEN 0 \
              ELSE 2 END AS address_rank, \
         ps.stab_mask, ps.stab_len \
         FROM profile_stats ps \
         JOIN endpoints e ON e.id = ps.endpoint_id \
         JOIN protocols pr ON pr.id = ps.protocol_id \
         LEFT JOIN endpoint_rank er ON er.endpoint_id = e.id \
         {address_join} WHERE {} \
         ORDER BY pr.proto_kind, pr.transport_type, pr.security_type, address_rank, \
                  ip_key, e.domain, e.sub_domain, e.port, ps.protocol_id, ps.endpoint_id",
        scope.predicate()
    )
}

fn decode_row(row: &turso::Row, _scope: ExportScope) -> Result<ExportRow> {
    let domain = text(row, 0)?;
    let sub_domain = text(row, 1)?;
    let port = u16::try_from(integer(row, 2)?)
        .map_err(|_| DatabaseError::Generic("export endpoint port out of range".into()))?;
    let ports = serde_json::from_str::<Vec<u16>>(&text(row, 3)?)
        .map_err(|e| DatabaseError::Generic(format!("export endpoint ports: {e}")))?;
    let proto_kind = text(row, 4)?
        .parse::<ProtocolKind>()
        .map_err(|e| DatabaseError::Generic(format!("export protocol kind: {e:?}")))?;
    let transport_type = text(row, 5)?;
    let security_type = text(row, 6)?;
    let protocol: ProtocolConfig = serde_json::from_str(&text(row, 7)?)
        .map_err(|e| DatabaseError::Generic(format!("export protocol config: {e}")))?;
    let protocol_id = ProtocolId::new(integer(row, 8)?);
    let endpoint_id = EndpointId::new(integer(row, 9)?);
    // The two delay columns carry the provenance now (schema 19): a row can
    // hold BOTH, and the real one outranks the fast one.
    let latency = Latency {
        real_delay: optional_integer(row, 12)?.and_then(|v| i32::try_from(v).ok()),
        fast_delay: optional_integer(row, 13)?.and_then(|v| i32::try_from(v).ok()),
        ip: optional_text(row, 14)?,
        auth: optional_integer(row, 15)?,
    };
    let error = match (optional_bool(row, 17)?, optional_text(row, 18)?) {
        (Some(true), Some(kind)) => Some(ErrorInfo {
            kind: profile_err(&kind)?,
            text: optional_text(row, 19)?.unwrap_or_default(),
        }),
        (Some(true), None) => {
            return Err(DatabaseError::Generic(
                "export link has error flag without kind".into(),
            ));
        }
        _ => None,
    };
    let purge_reason = optional_text(row, 20)?
        .map(|value| purge_reason(&value))
        .transpose()?;
    let link = ProfileStats {
        protocol_id,
        endpoint_id,
        last_used_at: optional_integer(row, 10)?,
        last_seen_at: integer(row, 11)?,
        latency,
        speed_bps: optional_integer(row, 16)?,
        error,
        purge_reason,
        stab_mask: optional_integer(row, 30)?.unwrap_or(0),
        stab_len: optional_integer(row, 31)?.unwrap_or(0),
        traffic: TrafficStats {
            today_up: integer(row, 21)?,
            today_down: integer(row, 22)?,
            total_up: integer(row, 23)?,
            total_down: integer(row, 24)?,
        },
        created_at: integer(row, 25)?,
        updated_at: integer(row, 26)?,
        version: u64::try_from(integer(row, 27)?).unwrap_or_default(),
        protocol: toasty::Deferred::default(),
        endpoint: toasty::Deferred::default(),
    };
    let ip_key = optional_blob(row, 28)?.unwrap_or_default();
    let resolved_ip = endpoint_ip::ip_of(&ip_key);
    // db-rewamp D2/D10: `domain` empty ⇒ an IP/exotic host whose literal lives
    // in `endpoint_ip`; otherwise the DNS name is `sub_domain.domain`.
    let (host, host_type) = if domain.is_empty() {
        let literal = resolved_ip.map_or_else(String::new, |ip| ip.to_string());
        let kind = match resolved_ip {
            Some(std::net::IpAddr::V4(_)) => HostKind::Ipv4,
            Some(std::net::IpAddr::V6(_)) => HostKind::Ipv6,
            None => HostKind::Undefined,
        };
        (literal, kind)
    } else {
        let name = if sub_domain.is_empty() {
            domain
        } else {
            format!("{sub_domain}.{domain}")
        };
        (name, HostKind::Dns)
    };
    let endpoint = EndpointEssentials {
        host,
        host_type,
        port,
        ports,
    };
    Ok(ExportRow {
        endpoint,
        protocol,
        proto_kind,
        transport_type,
        security_type,
        link,
        resolved_ip,
        ip_key,
    })
}

fn value(row: &turso::Row, index: usize) -> Result<Value> {
    row.get_value(index).map_err(turso_error)
}
fn text(row: &turso::Row, index: usize) -> Result<String> {
    match value(row, index)? {
        Value::Text(value) => Ok(value),
        other => Err(DatabaseError::Generic(format!(
            "export expected text, got {other:?}"
        ))),
    }
}
fn optional_text(row: &turso::Row, index: usize) -> Result<Option<String>> {
    match value(row, index)? {
        Value::Null => Ok(None),
        Value::Text(value) => Ok(Some(value)),
        other => Err(DatabaseError::Generic(format!(
            "export expected text, got {other:?}"
        ))),
    }
}
fn integer(row: &turso::Row, index: usize) -> Result<i64> {
    match value(row, index)? {
        Value::Integer(value) => Ok(value),
        other => Err(DatabaseError::Generic(format!(
            "export expected integer, got {other:?}"
        ))),
    }
}
fn optional_integer(row: &turso::Row, index: usize) -> Result<Option<i64>> {
    match value(row, index)? {
        Value::Null => Ok(None),
        Value::Integer(value) => Ok(Some(value)),
        other => Err(DatabaseError::Generic(format!(
            "export expected integer, got {other:?}"
        ))),
    }
}
fn optional_bool(row: &turso::Row, index: usize) -> Result<Option<bool>> {
    Ok(optional_integer(row, index)?.map(|value| value != 0))
}
fn optional_blob(row: &turso::Row, index: usize) -> Result<Option<Vec<u8>>> {
    match value(row, index)? {
        Value::Null => Ok(None),
        Value::Blob(value) => Ok(Some(value)),
        other => Err(DatabaseError::Generic(format!(
            "export expected blob, got {other:?}"
        ))),
    }
}
fn profile_err(value: &str) -> Result<ProfileErr> {
    match value {
        "real" => Ok(ProfileErr::Real),
        "fast" => Ok(ProfileErr::Fast),
        "name" => Ok(ProfileErr::Name),
        other => Err(DatabaseError::Generic(format!(
            "unknown profile error {other}"
        ))),
    }
}
fn purge_reason(value: &str) -> Result<PurgeReason> {
    match value {
        "reality_fallback" => Ok(PurgeReason::RealityFallback),
        "certificate_mismatch" => Ok(PurgeReason::CertificateMismatch),
        "certificate_expired" => Ok(PurgeReason::CertificateExpired),
        "not_tls" => Ok(PurgeReason::NotTls),
        "config_invalid" => Ok(PurgeReason::ConfigInvalid),
        "transport_rejected" => Ok(PurgeReason::TransportRejected),
        "origin_unreachable" => Ok(PurgeReason::OriginUnreachable),
        other => Err(DatabaseError::Generic(format!(
            "unknown purge reason {other}"
        ))),
    }
}
fn path_str(path: &Path) -> Result<&str> {
    path.to_str()
        .ok_or_else(|| DatabaseError::Generic("database path is not valid UTF-8".into()))
}
#[allow(clippy::needless_pass_by_value)]
pub(crate) fn turso_error(error: turso::Error) -> DatabaseError {
    DatabaseError::Generic(format!("turso export: {error}"))
}

#[cfg(test)]
#[allow(clippy::significant_drop_tightening)]
mod tests {
    use super::*;
    use crate::models_toasty::{Endpoint, EndpointId, HostType, Protocol, Security, Transport};
    use leas_proto::proto_spec::common::TransportConfig;
    use leas_proto::proto_spec::{
        ProtocolConfig, ProtocolKind, SecurityConfig, SsConfig, VlessConfig,
    };
    use tempfile::tempdir;
    use toasty::{Deferred, Json};

    fn endpoint(id: i64, host: &str, host_type: HostType) -> Endpoint {
        Endpoint {
            id: EndpointId::new(id),
            domain: Endpoint::derive_domain(host, host_type).0,
            sub_domain: Endpoint::derive_domain(host, host_type).1,
            port: 443,
            ports: Vec::new(),
            last_source: None,
            manual_protocol_override: None,
            resolved_at: None,
            created_at: 0,
            links: Deferred::default(),
            group_links: Deferred::default(),
        }
    }

    fn protocol(id: i64) -> Protocol {
        Protocol {
            id: ProtocolId::new(id),
            sig: id,
            proto_kind: ProtocolKind::Vless,
            transport: Transport {
                r#type: leas_proto::proto_spec::TransportType::Tcp,
            },
            security: Security {
                r#type: leas_proto::proto_spec::SecurityType::None,
                sni: None,
                fp: None,
                insecure: None,
            },
            config: Deferred::from(Json(ProtocolConfig::Vless(VlessConfig {
                uuid: "00000000-0000-0000-0000-000000000001".into(),
                uuid_origin: None,
                security: SecurityConfig::default(),
                transport: TransportConfig::Tcp,
                encryption: None,
                flow: None,
                path: None,
                splice: None,
                remarks: None,
                mux: None,
            }))),
            created_at: 0,
            links: Deferred::default(),
        }
    }

    fn link(
        protocol_id: i64,
        endpoint_id: i64,
        latency: Latency,
        error: Option<ErrorInfo>,
    ) -> ProfileStats {
        ProfileStats {
            protocol_id: ProtocolId::new(protocol_id),
            endpoint_id: EndpointId::new(endpoint_id),
            last_used_at: None,
            last_seen_at: 1,
            latency,
            speed_bps: None,
            error,
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
            protocol: Deferred::default(),
            endpoint: Deferred::default(),
        }
    }

    async fn seed(
        db: &Database,
        id: i64,
        host: &str,
        host_type: HostType,
        ips: &[std::net::IpAddr],
        latency: Latency,
        error: Option<ErrorInfo>,
    ) {
        db.upsert_endpoint(&endpoint(id, host, host_type))
            .await
            .expect("endpoint");
        db.upsert_protocol(&protocol(1000 + id))
            .await
            .expect("protocol");
        db.upsert_link(&link(1000 + id, id, latency, error))
            .await
            .expect("link");
        // db-rewamp D10: an IP-literal endpoint's address lives in
        // `endpoint_ip` (the DIAL target), not on the row; a DNS endpoint's
        // addresses come from the explicit `ips`.
        let addrs: Vec<std::net::IpAddr> = if ips.is_empty() {
            host.parse::<std::net::IpAddr>().ok().into_iter().collect()
        } else {
            ips.to_vec()
        };
        if !addrs.is_empty() {
            db.update_endpoint_resolution(EndpointId::new(id), addrs, 1)
                .await
                .expect("resolution");
        }
    }

    #[tokio::test]
    async fn alive_uses_canonical_link_tier_and_dns_resolution() {
        let dir = tempdir().expect("tempdir");
        let db = Database::open(dir.path().join("export.db"))
            .await
            .expect("database");
        seed(
            &db,
            1,
            "one.example",
            HostType::Dns,
            &["1.1.1.1".parse().unwrap()],
            Latency::fast(10),
            None,
        )
        .await;
        seed(
            &db,
            2,
            "two.example",
            HostType::Dns,
            &[],
            Latency::real_with_ip(10, None),
            None,
        )
        .await;
        seed(
            &db,
            3,
            "three.example",
            HostType::Dns,
            &["3.3.3.3".parse().unwrap()],
            Latency::real_with_ip(10, None),
            Some(ErrorInfo {
                kind: crate::models_toasty::ProfileErr::Fast,
                text: "later failure".into(),
            }),
        )
        .await;

        let mut reader = db
            .open_export_reader(ExportScope::Alive)
            .await
            .expect("reader");
        assert_eq!(reader.candidate_count(), 1);
        let row = reader.next_row().await.expect("row").expect("one row");
        assert_eq!(row.link.endpoint_id.get(), 1);
        reader.finish().await.expect("finish");
    }

    #[tokio::test]
    async fn resolved_emits_each_dns_address_and_one_ip_literal() {
        let dir = tempdir().expect("tempdir");
        let db = Database::open(dir.path().join("export.db"))
            .await
            .expect("database");
        seed(
            &db,
            1,
            "many.example",
            HostType::Dns,
            &["1.1.1.1".parse().unwrap(), "2.2.2.2".parse().unwrap()],
            Latency::default(),
            None,
        )
        .await;
        seed(
            &db,
            2,
            "8.8.8.8",
            HostType::Ipv4,
            &[],
            Latency::default(),
            None,
        )
        .await;

        let mut reader = db
            .open_export_reader(ExportScope::Resolved)
            .await
            .expect("reader");
        assert_eq!(reader.candidate_count(), 2);
        let first = reader.next_row().await.expect("row").expect("first");
        let second = reader.next_row().await.expect("row").expect("second");
        assert_eq!(first.resolved_ip, Some("1.1.1.1".parse().unwrap()));
        assert_eq!(second.resolved_ip, Some("2.2.2.2".parse().unwrap()));
        let literal = reader.next_row().await.expect("row").expect("literal");
        assert_eq!(literal.endpoint.host, "8.8.8.8");
        assert!(reader.next_row().await.expect("end").is_none());
        reader.finish().await.expect("finish");
    }

    #[tokio::test]
    async fn export_decodes_shadowsocks2022_and_reconstructs() {
        let dir = tempdir().expect("tempdir");
        let db = Database::open(dir.path().join("export.db"))
            .await
            .expect("database");
        let config = ProtocolConfig::Ss(SsConfig {
            method: "2022-blake3-aes-128-gcm".into(),
            password: "AAAAAAAAAAAAAAAAAAAAAA==".into(),
            security: SecurityConfig::default(),
            remarks: None,
            plugin: None,
        });
        let protocol = Protocol {
            id: ProtocolId::new(2022),
            sig: 2022,
            proto_kind: ProtocolKind::Shadowsocks2022,
            transport: Transport {
                r#type: leas_proto::proto_spec::TransportType::Tcp,
            },
            security: Security {
                r#type: leas_proto::proto_spec::SecurityType::None,
                sni: None,
                fp: None,
                insecure: None,
            },
            config: Deferred::from(Json(config)),
            created_at: 0,
            links: Deferred::default(),
        };
        db.upsert_endpoint(&endpoint(22, "ss2022.example", HostType::Dns))
            .await
            .expect("endpoint");
        db.upsert_protocol(&protocol).await.expect("protocol");
        db.upsert_link(&link(2022, 22, Latency::default(), None))
            .await
            .expect("link");

        let mut reader = db
            .open_export_reader(ExportScope::Full)
            .await
            .expect("reader");
        let row = reader.next_row().await.expect("row").expect("row");
        assert_eq!(row.proto_kind, ProtocolKind::Shadowsocks2022);
        let url = row.protocol.reconstruct_proto(&row.endpoint).expect("url");
        assert!(url.starts_with("ss://"));
        reader.finish().await.expect("finish");
    }
}
