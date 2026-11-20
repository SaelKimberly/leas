//! DNS sources, the live resolver pool, and the latency test job.
//!
//! Spec `2026-11-20-dns-resolvers`: the DB is the only persisted truth (D2); a
//! resolver is unique by stamp and a source refresh never writes a measurement
//! (D4); the pool is the fastest enabled-and-ok rows (D5); the test is a manual
//! job through the queue (D6/D10); the resolver is swapped live (D11).

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use leas_db::models::{DnsSetting, DnsSource, GroupStatus, now_epoch};
use leas_db::{Database, DnsCandidateRow};
use tokio::sync::mpsc::Sender;

use crate::AppState;
use crate::types::{BatchMeters, CoreEvent};

/// The built-in publicly published list, seeded when no source exists.
pub const BUILTIN_ID: &str = "builtin:public-resolvers";
pub const BUILTIN_URL: &str =
    "https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v3/public-resolvers.md";
/// Re-fetch a source older than this on boot (the old file-cache rule).
const SOURCE_MAX_AGE_SECS: i64 = 7 * 24 * 60 * 60;
/// Per-candidate test budget.
pub const TEST_TIMEOUT: Duration = Duration::from_secs(2);
/// In-flight probes inside one chunk.
pub const TEST_CONCURRENCY: usize = 32;
pub const DEFAULT_POOL_SIZE: usize = 10;
pub const DEFAULT_TEST_DOMAIN: &str = "www.google.com";

#[must_use]
fn builtin_source() -> DnsSource {
    DnsSource {
        id: BUILTIN_ID.to_string(),
        name: Some("DNSCrypt public resolvers".to_string()),
        url: BUILTIN_URL.to_string(),
        enabled: true,
        user_agent: None,
        sort_order: Some(0),
        last_refreshed: None,
        status: Some(GroupStatus::Never),
        error_message: None,
        refresh_interval: Some(24 * 60),
    }
}

fn source_is_stale(source: &DnsSource) -> bool {
    source
        .last_refreshed
        .is_none_or(|at| now_epoch().saturating_sub(at) > SOURCE_MAX_AGE_SECS)
}

/// Boot: seed the built-in source when the table is empty, load the rows,
/// install the pool, and refresh stale sources in the background.
pub async fn boot(state: &mut AppState) {
    if let Err(e) = state.db.seed_dns_source_if_empty(&builtin_source()).await {
        state.log_trace(
            "warn",
            "tui::ops::dns",
            &format!("failed to seed the built-in DNS source: {e}"),
        );
    }
    reload(state).await;
    spawn_refresh(state);
}

/// Re-reads the sources and resolvers and reinstalls the pool.
pub async fn reload(state: &mut AppState) {
    match state.db.list_dns_sources().await {
        Ok(sources) => state.dns_sources = sources,
        Err(e) => state.log_trace(
            "error",
            "tui::ops::dns",
            &format!("failed to load DNS sources: {e}"),
        ),
    }
    match state.db.list_dns_resolvers().await {
        Ok(rows) => state.dns_resolvers = rows,
        Err(e) => state.log_trace(
            "error",
            "tui::ops::dns",
            &format!("failed to load DNS resolvers: {e}"),
        ),
    }
    rebuild(state).await;
}

/// Installs the pool: the fastest measured rows, or — before the first test —
/// every enabled row (the pre-test behaviour).
///
/// No rows at all leaves the resolver unconfigured, which falls back to the OS
/// configuration.
pub async fn rebuild(state: &mut AppState) {
    let Some(resolver) = state.dns_resolver.clone() else {
        return;
    };
    let mut rows = match state.db.dns_pool(state.dns_pool_size).await {
        Ok(rows) => rows,
        Err(e) => {
            state.log_trace(
                "error",
                "tui::ops::dns",
                &format!("failed to read the DNS pool: {e}"),
            );
            return;
        }
    };
    if rows.is_empty() {
        rows = state
            .dns_resolvers
            .iter()
            .filter(|row| row.enabled)
            .cloned()
            .collect();
    }
    let candidates: Vec<leas_dns::Candidate> = rows
        .iter()
        .filter_map(|row| leas_dns::candidate_from_stamp(&row.stamp))
        .collect();
    if let Err(e) = resolver.set_candidates(&candidates) {
        state.log_trace(
            "error",
            "tui::ops::dns",
            &format!("failed to build the DNS pool: {e}"),
        );
    }
}

/// Refreshes every enabled source that is empty or older than a week, without
/// blocking boot. The completion event reloads the rows and rebuilds the pool.
pub fn spawn_refresh(state: &mut AppState) {
    let Some(tx) = state.core_event_tx.clone() else {
        return;
    };
    let due: Vec<DnsSource> = state
        .dns_sources
        .iter()
        .filter(|source| source.enabled && source_is_stale(source))
        .cloned()
        .collect();
    if due.is_empty() {
        return;
    }
    let db = state.db.clone();
    let shutdown = state.shutdown_token.clone();
    tokio::spawn(async move {
        // Same 10 s grace as the subscription updater: the first frame and the
        // settings load come first, and a test runtime never reaches the fetch.
        tokio::select! {
            () = tokio::time::sleep(Duration::from_secs(10)) => {},
            () = async {
                while !shutdown.load(Ordering::Relaxed) {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            } => return,
        }
        // Any attempt writes a status row (ok or error), so the UI reloads
        // even when the fetch failed.
        let mut touched = false;
        for source in due {
            if shutdown.load(Ordering::Relaxed) {
                return;
            }
            let _ = refresh_and_record(&db, &source).await;
            touched = true;
        }
        if touched {
            let _ = tx.send(CoreEvent::DnsChanged).await;
        }
    });
}

/// Refreshes one source on demand (the Sources tab's update), then reloads.
pub async fn refresh_source(state: &mut AppState, source_id: &str) {
    let Some(source) = state
        .dns_sources
        .iter()
        .find(|source| source.id == source_id)
        .cloned()
    else {
        state.log_trace("warn", "tui::ops::dns", "DNS source not found");
        return;
    };
    match refresh_and_record(&state.db, &source).await {
        Ok((count, skipped)) => state.log_trace(
            "info",
            "tui::ops::dns",
            &format!(
                "DNS source '{}' refreshed: {count} resolver(s), {skipped} skipped",
                source.name.as_deref().unwrap_or(&source.id)
            ),
        ),
        Err(e) => state.log_trace(
            "error",
            "tui::ops::dns",
            &format!(
                "DNS source '{}' refresh failed: {e}",
                source.name.as_deref().unwrap_or(&source.id)
            ),
        ),
    }
    reload(state).await;
}

/// Fetches one source, applies its resolvers, and records the outcome. A
/// failed fetch marks the source `error` and keeps its rows.
///
/// The status write is update-only: a source deleted while the fetch ran must
/// not be resurrected by it.
async fn refresh_and_record(db: &Database, source: &DnsSource) -> anyhow::Result<(usize, usize)> {
    let result = refresh_one(db, source).await;
    let (status, error) = match &result {
        Ok(_) => (GroupStatus::Ok, None),
        Err(e) => (GroupStatus::Error, Some(e.to_string())),
    };
    if let Err(e) = db
        .update_dns_source_status(&source.id, now_epoch(), status, error)
        .await
    {
        tracing::warn!(error = %e, "failed to record the DNS source status");
    }
    result
}

/// Returns `(accepted, skipped)`, where skipped counts `sdns://` lines the
/// policy refused (plain DNS, local address, missing `NO_LOGS|NO_FILTER`, or a
/// duplicate). A body with no usable stamp is a FAILURE: a 200 HTML page
/// (captive portal, rate limit) must not wipe the source's rows.
async fn refresh_one(db: &Database, source: &DnsSource) -> anyhow::Result<(usize, usize)> {
    let text = leas_dns::fetch_source(&source.url).await?;
    let declared = text
        .lines()
        .filter(|line| line.trim().starts_with("sdns://"))
        .count();
    let candidates = leas_dns::parse_stamps(&text);
    if candidates.is_empty() {
        anyhow::bail!("source listed no usable sdns:// stamps; keeping the existing rows");
    }
    let skipped = declared.saturating_sub(candidates.len());
    let rows: Vec<DnsCandidateRow> = candidates
        .iter()
        .map(|candidate| DnsCandidateRow {
            stamp: candidate.stamp.clone(),
            protocol: candidate.protocol.as_str().to_string(),
            host: candidate.host.clone(),
            port: candidate.port,
        })
        .collect();
    db.refresh_source_links(&source.id, &rows).await?;
    Ok((rows.len(), skipped))
}

/// Starts the test as one queued job: every enabled resolver, measured against
/// the configured domain. The meters drive the Tasks bar; the terminal event
/// clears the running task.
pub fn start_test(state: &mut AppState) {
    let Some(tx) = state.core_event_tx.clone() else {
        return;
    };
    let stamps: Vec<String> = state
        .dns_resolvers
        .iter()
        .filter(|row| row.enabled)
        .map(|row| row.stamp.clone())
        .collect();
    if stamps.is_empty() {
        state.log_trace(
            "warn",
            "tui::ops::dns",
            "no DNS resolvers to test — refresh a source first",
        );
        return;
    }
    let db = state.db.clone();
    let domain = state.dns_test_domain.clone();
    let stop = state.speed_test_stop.clone();
    let meters = Arc::new(BatchMeters::default());
    state.batch_progress = Some(Arc::clone(&meters));
    tokio::spawn(async move {
        run_test(db, stamps, domain, stop, tx, meters).await;
    });
}

async fn run_test(
    db: Arc<Database>,
    stamps: Vec<String>,
    domain: String,
    stop: Arc<AtomicBool>,
    tx: Sender<CoreEvent>,
    meters: Arc<BatchMeters>,
) {
    let started = Instant::now();
    // A stamp that no longer parses contributes nothing to measure; it still
    // counts toward the total so the bar reaches 100%.
    let candidates: Vec<leas_dns::Candidate> = stamps
        .iter()
        .filter_map(|stamp| leas_dns::candidate_from_stamp(stamp))
        .collect();
    let unparsed = stamps.len().saturating_sub(candidates.len());
    let total = u32::try_from(stamps.len()).unwrap_or(u32::MAX);
    meters.main.total.store(total, Ordering::Relaxed);

    let mut done = u32::try_from(unparsed).unwrap_or(0);
    meters.main.done.store(done, Ordering::Relaxed);
    for chunk in candidates.chunks(TEST_CONCURRENCY * 2) {
        if stop.load(Ordering::Relaxed) {
            break;
        }
        let outcomes = leas_dns::measure(chunk, &domain, TEST_TIMEOUT, TEST_CONCURRENCY).await;
        let batch: Vec<(String, Option<u32>, Option<String>)> = outcomes
            .iter()
            .map(|outcome| {
                (
                    outcome.stamp.clone(),
                    outcome.latency_ms,
                    outcome.error.clone(),
                )
            })
            .collect();
        if let Err(e) = db.apply_dns_test_results(&batch).await {
            tracing::warn!(error = %e, "failed to persist DNS test results");
        }
        done = done.saturating_add(u32::try_from(outcomes.len()).unwrap_or(u32::MAX));
        meters.main.done.store(done.min(total), Ordering::Relaxed);
        let elapsed = started.elapsed().as_secs_f64();
        if elapsed > 0.0 {
            let rate_milli = (f64::from(done) / elapsed * 1000.0) as u32;
            meters.main.rate_milli.store(rate_milli, Ordering::Relaxed);
        }
    }
    let _ = tx.send(CoreEvent::DnsTestDone).await;
}

/// Applies the two pool knobs from a settings save and reinstalls the pool.
pub async fn apply_settings(state: &mut AppState, settings: Option<&DnsSetting>) {
    state.dns_pool_size = settings
        .and_then(|d| d.resolver_pool_size)
        .and_then(|n| usize::try_from(n).ok())
        .unwrap_or(DEFAULT_POOL_SIZE);
    state.dns_test_domain = settings
        .and_then(|d| d.resolver_test_domain.clone())
        .filter(|domain| !domain.is_empty())
        .unwrap_or_else(|| DEFAULT_TEST_DOMAIN.to_string());
    rebuild(state).await;
}

// ── Sources tab: add / edit / delete / refresh-all ─────────────────────

/// The Sources tab's `A`: the DNS form, sharing the group form's renderer.
pub fn start_add_source(state: &mut AppState) {
    state.mode = crate::AppMode::GroupForm {
        group_id: None,
        kind: crate::types::SourceFormKind::Dns,
        fields: vec![
            ("name".into(), String::new()),
            ("subscription_url".into(), String::new()),
            ("user_agent".into(), String::new()),
            ("update_interval".into(), "24h".into()),
        ],
        focus_index: 0,
        form_errors: std::collections::HashMap::new(),
    };
}

pub fn start_edit_source(state: &mut AppState, source_id: &str) {
    let Some(source) = state
        .dns_sources
        .iter()
        .find(|source| source.id == source_id)
        .cloned()
    else {
        return;
    };
    let interval = source.refresh_interval.map_or_else(
        || "24h".to_string(),
        |minutes| {
            humantime::format_duration(std::time::Duration::from_secs(
                u64::try_from(minutes).unwrap_or(0) * 60,
            ))
            .to_string()
        },
    );
    state.mode = crate::AppMode::GroupForm {
        group_id: Some(source.id.clone()),
        kind: crate::types::SourceFormKind::Dns,
        fields: vec![
            ("name".into(), source.name.unwrap_or_default()),
            ("subscription_url".into(), source.url),
            ("user_agent".into(), source.user_agent.unwrap_or_default()),
            ("update_interval".into(), interval),
        ],
        focus_index: 0,
        form_errors: std::collections::HashMap::new(),
    };
}

/// The URL a DNS source stores: parsed and canonicalised, http(s) only.
/// Returns the user-facing error on refusal.
fn canonical_url(raw: &str) -> Result<String, String> {
    let parsed = url::Url::parse(raw.trim()).map_err(|e| format!("invalid URL: {e}"))?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err("URL must be http(s)".to_string());
    }
    Ok(parsed.to_string())
}

fn interval_minutes(fields: &[(String, String)]) -> i64 {
    crate::get_field(fields, "update_interval")
        .and_then(|value| humantime::parse_duration(&value).ok())
        .map_or(24 * 60, |duration| (duration.as_secs() / 60) as i64)
}

pub async fn confirm_add_source(state: &mut AppState) {
    let fields = match &state.mode {
        crate::AppMode::GroupForm { fields, .. } => fields.clone(),
        _ => return,
    };
    let Some(raw) = crate::get_field(&fields, "subscription_url") else {
        state.log_trace("error", "tui::ops::dns", "DNS source URL is required");
        return;
    };
    let url = match canonical_url(&raw) {
        Ok(url) => url,
        Err(e) => {
            state.log_trace("error", "tui::ops::dns", &e);
            return;
        }
    };
    if let Some(existing) = state.dns_sources.iter().find(|source| source.url == url) {
        state.log_trace(
            "error",
            "tui::ops::dns",
            &format!(
                "that URL is already a source: {}",
                existing.name.as_deref().unwrap_or(&existing.id)
            ),
        );
        return;
    }
    let source = DnsSource {
        id: uuid::Uuid::new_v4().to_string(),
        name: crate::get_field(&fields, "name"),
        url,
        enabled: true,
        user_agent: crate::get_field(&fields, "user_agent"),
        sort_order: Some(i32::try_from(state.dns_sources.len()).unwrap_or(i32::MAX) + 1),
        last_refreshed: None,
        status: Some(GroupStatus::Never),
        error_message: None,
        refresh_interval: Some(interval_minutes(&fields)),
    };
    if let Err(e) = state.db.upsert_dns_source(&source).await {
        state.log_trace(
            "error",
            "tui::ops::dns",
            &format!("failed to add DNS source: {e}"),
        );
        return;
    }
    state.mode = crate::AppMode::List;
    state.log_trace(
        "info",
        "tui::ops::dns",
        &format!(
            "DNS source '{}' added",
            source.name.as_deref().unwrap_or(&source.id)
        ),
    );
    reload(state).await;
}

pub async fn confirm_edit_source(state: &mut AppState) {
    let (source_id, fields) = match &state.mode {
        crate::AppMode::GroupForm {
            group_id, fields, ..
        } => (group_id.clone(), fields.clone()),
        _ => return,
    };
    let Some(source_id) = source_id else {
        return;
    };
    let Some(mut source) = state
        .dns_sources
        .iter()
        .find(|source| source.id == source_id)
        .cloned()
    else {
        return;
    };
    let Some(raw) = crate::get_field(&fields, "subscription_url") else {
        state.log_trace("error", "tui::ops::dns", "DNS source URL is required");
        return;
    };
    let url = match canonical_url(&raw) {
        Ok(url) => url,
        Err(e) => {
            state.log_trace("error", "tui::ops::dns", &e);
            return;
        }
    };
    if state
        .dns_sources
        .iter()
        .any(|other| other.url == url && other.id != source.id)
    {
        state.log_trace("error", "tui::ops::dns", "that URL is already a source");
        return;
    }
    source.name = crate::get_field(&fields, "name");
    source.url = url;
    source.user_agent = crate::get_field(&fields, "user_agent");
    source.refresh_interval = Some(interval_minutes(&fields));
    if let Err(e) = state.db.upsert_dns_source(&source).await {
        state.log_trace(
            "error",
            "tui::ops::dns",
            &format!("failed to save DNS source: {e}"),
        );
        return;
    }
    state.mode = crate::AppMode::List;
    reload(state).await;
}

pub async fn delete_source(state: &mut AppState, source_id: &str) {
    if let Err(e) = state.db.delete_dns_source(source_id).await {
        state.log_trace(
            "error",
            "tui::ops::dns",
            &format!("failed to delete DNS source: {e}"),
        );
        return;
    }
    state.log_trace("info", "tui::ops::dns", "DNS source deleted");
    reload(state).await;
}

/// The DNS tab's `Space`: flip one resolver's `enabled` and reinstall.
pub async fn toggle_resolver(state: &mut AppState, stamp: &str) {
    let Some(row) = state.dns_resolvers.iter().find(|row| row.stamp == stamp) else {
        return;
    };
    let enabled = !row.enabled;
    if let Err(e) = state.db.set_dns_resolver_enabled(stamp, enabled).await {
        state.log_trace(
            "error",
            "tui::ops::dns",
            &format!("failed to toggle resolver: {e}"),
        );
        return;
    }
    reload(state).await;
}

/// The Sources tab's `u`: refresh every enabled DNS source, in the background.
pub fn refresh_all(state: &mut AppState) {
    let Some(tx) = state.core_event_tx.clone() else {
        return;
    };
    let sources: Vec<DnsSource> = state
        .dns_sources
        .iter()
        .filter(|source| source.enabled)
        .cloned()
        .collect();
    if sources.is_empty() {
        return;
    }
    let db = state.db.clone();
    let shutdown = state.shutdown_token.clone();
    tokio::spawn(async move {
        for source in sources {
            if shutdown.load(Ordering::Relaxed) {
                return;
            }
            let _ = refresh_and_record(&db, &source).await;
        }
        let _ = tx.send(CoreEvent::DnsChanged).await;
    });
}
