//! Export orchestration: DB stream → reconstructed URLs → bounded sink.

use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use leas_db::Database;
use leas_db::export::{ExportRow, ExportScope};
use leas_proto::proto_spec::HostKind;
use tokio::io::AsyncWriteExt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportDestination {
    Clipboard,
    File,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportReport {
    pub scope: ExportScope,
    pub destination: ExportDestination,
    pub candidate_count: u64,
    pub emitted_count: u64,
    pub skipped_count: u64,
}

#[derive(Debug)]
pub enum ExportError {
    Database(leas_db::DatabaseError),
    Io(std::io::Error),
    Clipboard(String),
    Serialize(String),
}

impl std::fmt::Display for ExportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Database(error) => write!(f, "export database: {error}"),
            Self::Io(error) => write!(f, "export file: {error}"),
            Self::Clipboard(error) => write!(f, "export clipboard: {error}"),
            Self::Serialize(error) => write!(f, "export serializer: {error}"),
        }
    }
}

impl std::error::Error for ExportError {}

impl From<leas_db::DatabaseError> for ExportError {
    fn from(error: leas_db::DatabaseError) -> Self {
        Self::Database(error)
    }
}

impl From<std::io::Error> for ExportError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

// `significant_drop_tightening` is silenced here rather than obeyed: it reports
// the export reader as "dropped at the end of its contained scope", but
// `reader.finish()` takes it BY VALUE — the snapshot is released on that line,
// and an explicit `drop(reader)` after it is a use-after-move (the compiler
// says so). The suggestion is not applicable to a value that is consumed.
#[allow(clippy::significant_drop_tightening)]
pub async fn run_export(
    db: Arc<Database>,
    scope: ExportScope,
    destination: ExportDestination,
    path: Option<&Path>,
) -> Result<ExportReport, ExportError> {
    let mut reader = db.open_export_reader(scope).await?;
    let candidate_count = reader.candidate_count();
    let started = std::time::Instant::now();
    let mut sink = match Sink::new(destination, path, scope, candidate_count).await {
        Ok(sink) => sink,
        Err(error) => {
            let _ = reader.rollback().await;
            return Err(error);
        }
    };

    let mut emitted_count = 0_u64;
    let mut skipped_count = 0_u64;
    loop {
        let row = match reader.next_row().await {
            Ok(Some(row)) => row,
            Ok(None) => break,
            Err(error) => {
                let _ = reader.rollback().await;
                return Err(ExportError::Database(error));
            }
        };
        match urls_for_row(&row, scope) {
            Some(url) => {
                if let Err(error) = sink.write_line(&url).await {
                    let _ = reader.rollback().await;
                    return Err(ExportError::Io(error));
                }
                emitted_count += 1;
            }
            None => skipped_count += 1,
        }
    }
    reader.finish().await?;
    sink.finish(scope, started, emitted_count).await?;
    Ok(ExportReport {
        scope,
        destination,
        candidate_count,
        emitted_count,
        skipped_count,
    })
}

fn header(scope: ExportScope, candidate_count: u64) -> String {
    let offset = chrono::FixedOffset::east_opt(3 * 60 * 60).expect("Moscow offset");
    let now = chrono::Utc::now().with_timezone(&offset);
    format!(
        "# profile-title: leas export • {}\n# profile-update-interval: 1\n# Date/Time: {} (Moscow)\n# Количество: {}\n\n",
        scope.title(),
        now.format("%Y-%m-%d / %H:%M"),
        candidate_count
    )
}

fn urls_for_row(row: &ExportRow, scope: ExportScope) -> Option<String> {
    let Some(ip) = row.resolved_ip else {
        return row.protocol.reconstruct_proto(&row.endpoint).ok();
    };
    if scope != ExportScope::Resolved || row.endpoint.host.parse::<std::net::IpAddr>().is_ok() {
        return row.protocol.reconstruct_proto(&row.endpoint).ok();
    }
    let mut endpoint = row.endpoint.clone();
    endpoint.host = ip.to_string();
    endpoint.host_type = match ip {
        std::net::IpAddr::V4(_) => HostKind::Ipv4,
        std::net::IpAddr::V6(_) => HostKind::Ipv6,
    };
    let mut protocol = row.protocol.clone();
    protocol.set_export_defaults(&row.endpoint.host);
    protocol.reconstruct_proto(&endpoint).ok()
}

enum Sink {
    Clipboard(ClipboardBuffer),
    File(tokio::fs::File),
}

impl Sink {
    async fn new(
        destination: ExportDestination,
        path: Option<&Path>,
        scope: ExportScope,
        candidate_count: u64,
    ) -> Result<Self, ExportError> {
        let header = header(scope, candidate_count);
        match destination {
            ExportDestination::Clipboard => Ok(Self::Clipboard(ClipboardBuffer::new(header))),
            ExportDestination::File => {
                let path = path.ok_or_else(|| {
                    ExportError::Io(std::io::Error::new(
                        ErrorKind::InvalidInput,
                        "file export requires a path",
                    ))
                })?;
                let mut file = tokio::fs::File::create(path).await?;
                file.write_all(header.as_bytes()).await?;
                Ok(Self::File(file))
            }
        }
    }

    async fn write_line(&mut self, url: &str) -> std::io::Result<()> {
        match self {
            Self::Clipboard(buffer) => {
                buffer.push(url);
                Ok(())
            }
            Self::File(file) => {
                file.write_all(url.as_bytes()).await?;
                file.write_all(b"\n").await
            }
        }
    }

    async fn finish(
        &mut self,
        scope: ExportScope,
        started: std::time::Instant,
        emitted_count: u64,
    ) -> Result<(), ExportError> {
        match self {
            Self::Clipboard(buffer) => buffer.finish(scope, started, emitted_count),
            Self::File(file) => {
                file.flush().await?;
                Ok(())
            }
        }
    }
}

struct ClipboardBuffer {
    text: String,
}

impl ClipboardBuffer {
    // Not a `const fn`: the parameter is an owned `String`, and a const fn may
    // not move or drop one. The lint's suggestion is not applicable here.
    #[allow(clippy::missing_const_for_fn)]
    fn new(header: String) -> Self {
        Self { text: header }
    }

    fn push(&mut self, url: &str) {
        self.text.push_str(url);
        self.text.push('\n');
    }

    fn finish(
        &mut self,
        scope: ExportScope,
        started: std::time::Instant,
        _emitted_count: u64,
    ) -> Result<(), ExportError> {
        let text = std::mem::take(&mut self.text);
        let bytes = text.len();
        // The shared handle owns the X11 selection; a local create-set-drop
        // would lose the payload the moment it drops (see ops::clipboard).
        crate::ops::clipboard::set_text(text).map_err(ExportError::Clipboard)?;
        tracing::debug!(target: "tui::ops::export", scope = scope.title(), bytes, elapsed_ms = started.elapsed().as_millis(), "clipboard export complete");
        Ok(())
    }
}

#[must_use]
pub fn default_export_path(scope: ExportScope) -> PathBuf {
    PathBuf::from(format!(
        "./leas-export-{}-{}",
        scope.title().to_ascii_lowercase(),
        chrono::Local::now().format("%Y%m%d-%H%M")
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use leas_db::models::{EndpointId, ProfileStats, ProtocolId};
    use leas_proto::proto_spec::{
        EndpointEssentials, PlaceholderConfig, ProtocolConfig, ProtocolKind,
    };
    use tempfile::tempdir;

    #[test]
    fn header_has_required_fields() {
        let text = header(ExportScope::Full, 7);
        assert!(text.contains("# profile-title: leas export • Full"));
        assert!(text.contains("# profile-update-interval: 1"));
        assert!(text.contains(" (Moscow)"));
        assert!(text.contains("# Количество: 7\n\n"));
    }

    #[test]
    fn failed_serializer_is_skipped() {
        let row = ExportRow {
            endpoint: EndpointEssentials::new("example.test", 443),
            protocol: ProtocolConfig::Redirect(PlaceholderConfig::new(
                "redirect".into(),
                Vec::new(),
            )),
            proto_kind: ProtocolKind::Redirect,
            transport_type: "tcp".into(),
            security_type: "none".into(),
            link: ProfileStats {
                protocol_id: ProtocolId::new(1),
                endpoint_id: EndpointId::new(1),
                last_used_at: None,
                last_seen_at: 0,
                latency: None,
                speed_bps: None,
                error: None,
                purge_reason: None,
                stab_mask: 0,
                stab_len: 0,
                traffic: leas_db::models::TrafficStats {
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
            },
            resolved_ip: None,
            ip_key: Vec::new(),
        };
        assert!(urls_for_row(&row, ExportScope::Full).is_none());
    }

    #[tokio::test]
    async fn file_export_writes_header_and_final_newline() {
        let dir = tempdir().expect("tempdir");
        let db = Arc::new(
            Database::open(dir.path().join("export.db"))
                .await
                .expect("db"),
        );
        let path = dir.path().join("out.txt");
        let report = run_export(db, ExportScope::Full, ExportDestination::File, Some(&path))
            .await
            .expect("export");
        assert_eq!(report.emitted_count, 0);
        let text = tokio::fs::read_to_string(path).await.expect("read");
        assert!(text.contains("# profile-title: leas export • Full"));
        assert!(text.ends_with("\n\n"));
    }
}
