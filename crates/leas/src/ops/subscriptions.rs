use std::collections::HashMap;
use std::sync::Arc;
use std::sync::LazyLock;
use std::sync::atomic::Ordering;
use std::time::Duration;

use dashmap::DashSet;
use leas_config::import_export::{ValidationSettings, ValidationSummary};
use leas_db::Database;
use leas_db::models::{Group, GroupStatus};

use crate::AppState;
use crate::ops::stream_import::ImportOutcome;

use crate::types::{CoreEvent, SplitRightPane};
use crate::{get_field, try_send_or_warn};

pub fn start_add_group(state: &mut AppState) {
    let fields = vec![
        ("name".into(), String::new()),
        ("subscription_url".into(), String::new()),
        ("user_agent".into(), String::new()),
        ("update_interval".into(), "1h".into()),
    ];
    if let crate::AppMode::Settings {
        mode: crate::SettingsMode::Split { right, .. },
    } = &mut state.mode
    {
        *right = SplitRightPane::GroupForm {
            group_id: None,
            fields,
            focus_index: 0,
            form_errors: HashMap::new(),
        };
    }
}

pub fn start_edit_group(state: &mut AppState, group_id: &str) {
    let group = if let Some(g) = state.groups.iter().find(|g| g.id == group_id) {
        g.clone()
    } else {
        state.log_trace("error", "tui::ops::subscriptions", "Group not found");
        return;
    };
    let update_interval_value = group.refresh_interval.map_or_else(
        || "1h".into(),
        |mins| {
            humantime::format_duration(std::time::Duration::from_secs(mins as u64 * 60)).to_string()
        },
    );
    let fields = vec![
        ("name".into(), group.name.clone().unwrap_or_default()),
        (
            "subscription_url".into(),
            group.url.clone().unwrap_or_default(),
        ),
        ("user_agent".into(), group.user_agent.unwrap_or_default()),
        ("update_interval".into(), update_interval_value),
    ];
    if let crate::AppMode::Settings {
        mode: crate::SettingsMode::Split { right, .. },
    } = &mut state.mode
    {
        *right = SplitRightPane::GroupForm {
            group_id: Some(group_id.into()),
            fields,
            focus_index: 0,
            form_errors: HashMap::new(),
        };
    }
}

pub async fn confirm_add_group(state: &mut AppState) {
    let fields = match &state.mode {
        crate::AppMode::Settings {
            mode:
                crate::SettingsMode::Split {
                    right: SplitRightPane::GroupForm { fields, .. },
                    ..
                },
        } => fields.clone(),
        _ => return,
    };
    let interval: i64 = get_field(&fields, "update_interval")
        .and_then(|v| humantime::parse_duration(&v).ok())
        .map_or(60, |d| (d.as_secs() / 60) as i64);
    let group = Group {
        id: uuid::Uuid::new_v4().to_string(),
        name: get_field(&fields, "name"),
        url: get_field(&fields, "subscription_url"),
        enabled: true,
        user_agent: get_field(&fields, "user_agent"),
        convert_target: None,
        sort_order: Some((state.groups.len() + 1) as i32),
        refresh_interval: Some(interval),
        last_refreshed: None,
        status: None,
        error_message: None,
    };
    if let Err(e) = state.db.upsert_group(&group).await {
        state.log_trace(
            "error",
            "tui::ops::subscriptions",
            &format!("Failed to add group: {e}"),
        );
        return;
    }
    state.log_trace(
        "info",
        "tui::ops::subscriptions",
        &format!(
            "Group '{}' added",
            group.name.as_deref().unwrap_or("unnamed")
        ),
    );
    state.reload_groups().await;
    if let crate::AppMode::Settings {
        mode: crate::SettingsMode::Split { right, .. },
    } = &mut state.mode
    {
        *right = SplitRightPane::GroupList {
            selected: 0,
            selected_mask: vec![false; state.groups.len()],
        };
    }
}
pub async fn confirm_edit_group(state: &mut AppState) {
    let (group_id_opt, fields) = match &state.mode {
        crate::AppMode::Settings {
            mode:
                crate::SettingsMode::Split {
                    right:
                        SplitRightPane::GroupForm {
                            group_id, fields, ..
                        },
                    ..
                },
        } => (group_id.clone(), fields.clone()),
        _ => return,
    };
    let Some(group_id) = group_id_opt else {
        return;
    };
    let Some(mut group) = state.groups.iter().find(|g| g.id == group_id).cloned() else {
        state.log_trace("error", "tui::ops::subscriptions", "Group not found");
        return;
    };
    group.name = get_field(&fields, "name");
    group.url = get_field(&fields, "subscription_url");
    group.user_agent = get_field(&fields, "user_agent");
    let interval: i64 = get_field(&fields, "update_interval")
        .and_then(|v| humantime::parse_duration(&v).ok())
        .map_or(60, |d| (d.as_secs() / 60) as i64);
    group.refresh_interval = Some(interval);
    if let Err(e) = state.db.upsert_group(&group).await {
        state.log_trace(
            "error",
            "tui::ops::subscriptions",
            &format!("Failed to update group: {e}"),
        );
        return;
    }
    state.log_trace("info", "tui::ops::subscriptions", "Group updated");
    state.reload_groups().await;
    if let crate::AppMode::Settings {
        mode: crate::SettingsMode::Split { right, .. },
    } = &mut state.mode
    {
        *right = SplitRightPane::GroupList {
            selected: 0,
            selected_mask: vec![false; state.groups.len()],
        };
    }
}

pub async fn delete_group(state: &mut AppState, group_id: &str) {
    if let Err(e) = state.db.delete_group(group_id).await {
        state.log_trace(
            "error",
            "tui::ops::subscriptions",
            &format!("Failed to delete group: {e}"),
        );
        return;
    }
    state.log_trace("info", "tui::ops::subscriptions", "Group deleted");
    state.confirmation = None;
    state.reload_groups().await;
    state.reload_profiles().await;
}

pub async fn clear_group(state: &mut AppState, group_id: &str) {
    match state.db.clear_group_endpoints(group_id).await {
        Ok(count) => {
            state.log_trace(
                "info",
                "tui::ops::subscriptions",
                &format!("Cleared {count} profiles from group"),
            );
        }
        Err(e) => {
            state.log_trace(
                "error",
                "tui::ops::subscriptions",
                &format!("Failed to clear group: {e}"),
            );
        }
    }
    state.confirmation = None;
    state.reload_profiles().await;
}

/// The ONE exclusion authority for group fetches.
///
/// `AppState::updating_groups` stays the UI's display projection — it drives
/// the group-row spinner and is cleared by the `SubscriptionsUpdated` handler
/// — and is deliberately NOT the exclusion gate: the auto-update loop never
/// consulted it, so an auto fetch and a manual refresh of the same group ran
/// concurrently against one row set. Every fetch path claims a slot here.
///
/// A slot lives exactly as long as its [`InFlightGuard`]: the guard removes
/// the id on drop, so an early return or a panic inside a fetch cannot wedge
/// a group out of future updates.
static IN_FLIGHT_IMPORTS: LazyLock<DashSet<String>> = LazyLock::new(DashSet::new);

/// RAII claim on one group's fetch slot; dropping it releases the slot.
struct InFlightGuard {
    group_id: String,
}

impl InFlightGuard {
    /// Claim `group_id` for this fetch; `None` when a fetch already holds it.
    fn acquire(group_id: &str) -> Option<Self> {
        IN_FLIGHT_IMPORTS.insert(group_id.to_owned()).then(|| Self {
            group_id: group_id.to_owned(),
        })
    }
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        IN_FLIGHT_IMPORTS.remove(&self.group_id);
    }
}

/// Whether a fetch for `group_id` is in flight right now (the skip predicate
/// of the batch updater and the auto-update loop).
fn import_in_flight(group_id: &str) -> bool {
    IN_FLIGHT_IMPORTS.contains(group_id)
}

pub fn update_group_subscriptions(state: &mut AppState, group_id: &str) {
    if state.updating_groups.contains(group_id) {
        return;
    }
    let group = if let Some(g) = state.groups.iter().find(|g| g.id == group_id) {
        g.clone()
    } else {
        state.log_trace("error", "tui::ops::subscriptions", "Group not found");
        return;
    };
    let url = match &group.url {
        Some(u) if !u.is_empty() => u.clone(),
        _ => {
            state.log_trace(
                "warn",
                "tui::ops::subscriptions",
                "Group has no subscription URL",
            );
            return;
        }
    };

    state.updating_groups.insert(group_id.to_string());
    let gid = group_id.to_string();
    let tx = state.core_event_tx.clone();
    let user_agent = group.user_agent.unwrap_or_else(|| "leas/0.1".into());
    let db = state.db.clone();
    let validation: ValidationSettings = state.config.parsing.clone().into();
    // The feed ceilings are configuration, not constants baked into the import
    // path (`specs/2026-10-02-import-budget-design.md`).
    let budget = state.config.import;
    tokio::spawn(async move {
        update_one_group(url, user_agent, gid, db, validation, budget, tx).await;
    });
}

/// One group's update cycle: fetch + parse + persist under an overall
/// timeout, then deliver `SubscriptionsUpdated` (timeout or not). The
/// `updating_groups` spinner entry is removed by the event handler; the
/// 30-minute cap exists so a 100k-URL import is never aborted mid-parse
/// (the HTTP client itself times out after 30s).
async fn update_one_group(
    url: String,
    user_agent: String,
    gid: String,
    db: Arc<Database>,
    validation: ValidationSettings,
    // The feed ceilings are configuration, not constants baked into the import
    // path (`specs/2026-10-02-import-budget-design.md`).
    import_budget: leas_config::app_config::ImportConfig,
    tx: Option<tokio::sync::mpsc::Sender<CoreEvent>>,
) {
    let Some(flight) = InFlightGuard::acquire(&gid) else {
        // Another path (the auto-update loop) already fetches this group. It
        // delivers its own `SubscriptionsUpdated`, which clears this group's
        // `updating_groups` spinner entry, so returning here is not a wedge —
        // but a user-requested refresh that was skipped must be visible.
        tracing::info!(
            target: "tui::ops::subscriptions",
            "Fetch already in flight for group {gid}; skipping duplicate fetch"
        );
        return;
    };
    let result = tokio::time::timeout(
        std::time::Duration::from_mins(30),
        do_update_subscription(
            url,
            user_agent,
            gid.clone(),
            db,
            validation,
            import_budget,
            &flight,
        ),
    )
    .await;
    if let Ok(inner) = result {
        if let Some(tx) = &tx {
            try_send_or_warn(
                tx,
                CoreEvent::SubscriptionsUpdated {
                    group_id: inner.0,
                    count: inner.1,
                    summary: inner.2,
                    error: inner.3,
                },
                "subs_updated",
            );
        }
    } else {
        tracing::error!(target: "tui::ops::subscriptions", "Subscription update timed out after 30m");
        if let Some(tx) = &tx {
            try_send_or_warn(
                tx,
                CoreEvent::SubscriptionsUpdated {
                    group_id: gid.clone(),
                    count: 0,
                    summary: ValidationSummary::default(),
                    error: Some("Subscription update timed out after 30m".into()),
                },
                "subs_timeout",
            );
        }
    }
}

/// One group's fetch. The caller holds the [`InFlightGuard`] — the exclusion
/// claim is a parameter, not a lookup, so no path can fetch without one.
async fn do_update_subscription(
    url: String,
    user_agent: String,
    group_id: String,
    db: Arc<Database>,
    validation: ValidationSettings,
    budget: leas_config::app_config::ImportConfig,
    _flight: &InFlightGuard,
) -> (String, usize, ValidationSummary, Option<String>) {
    // Warn on HTTP (non-HTTPS) subscription URLs
    if url.starts_with("http://") {
        tracing::warn!(
            target: "tui::ops::subscriptions",
            "Subscription URL uses HTTP, traffic is not encrypted"
        );
    }
    let outcome = crate::ops::stream_import::import_http_subscription(
        &url,
        &user_agent,
        &db,
        Some(&group_id),
        &validation,
        budget,
    )
    .await;
    // `links` counts only what was STORED. A run that dropped a batch, or hit a
    // budget, stored less than it parsed — so "succeeded" is only true for a
    // clean run, and the reason travels in the same line rather than only in the
    // group row the user may never open.
    if let Some(reason) = outcome.ended_early.as_deref() {
        tracing::warn!(
            target: "tui::ops::subscriptions",
            "DB upsert INCOMPLETE: {} links stored, {} errors, {} insecure-profile warnings — {reason}",
            outcome.links,
            outcome.summary.total_errors,
            outcome.summary.security_warning_count,
        );
    } else {
        tracing::info!(
            target: "tui::ops::subscriptions",
            "DB upsert succeeded: {} links, {} errors, {} insecure-profile warnings",
            outcome.links,
            outcome.summary.total_errors,
            outcome.summary.security_warning_count,
        );
    }

    record_import_result(&db, &group_id, &outcome).await;

    let error = partial_import_message(&outcome);
    (group_id, outcome.links, outcome.summary, error)
}

/// The user-facing statement of a truncated import: that it was cut short and
/// how many links survived. One owner, so the group row's `error_message` and
/// the `SubscriptionsUpdated` log line cannot drift apart.
/// Test seam: the same owner the group row and the log line read. `cfg(test)`
/// because only the import tests call it, and it would otherwise be dead code
/// in a lib build.
#[cfg(test)]
pub(crate) fn partial_import_message_for_test(outcome: &ImportOutcome) -> String {
    partial_import_message(outcome).unwrap_or_default()
}

#[must_use]
pub(crate) fn partial_import_message(outcome: &ImportOutcome) -> Option<String> {
    outcome.ended_early.as_ref().map(|reason| {
        format!(
            "subscription import ended early after {} link(s) stored — the feed is incomplete, stored rows were kept: {reason}",
            outcome.links
        )
    })
}

/// Record one finished import on the group row. `last_refreshed` always moves
/// (a partial import still refreshed what it stored), but a truncated run is
/// written as [`GroupStatus::Error`] with the partial message — it used to be
/// recorded as a clean `Ok`, which made half a feed look like a full one.
async fn record_import_result(db: &Arc<Database>, group_id: &str, outcome: &ImportOutcome) {
    if let Ok(groups) = db.get_all_groups().await
        && let Some(mut grp) = groups.into_iter().find(|g| g.id == group_id)
    {
        grp.last_refreshed = Some(leas_db::models::now_epoch());
        if let Some(message) = partial_import_message(outcome) {
            grp.status = Some(GroupStatus::Error);
            grp.error_message = Some(message);
        } else {
            grp.status = Some(GroupStatus::Ok);
            grp.error_message = None;
        }
        let _ = db.upsert_group(&grp).await;
    }
}

/// URLs per parse+stage batch. The batch is staged on the write-behind driver,
/// which commits several of them per transaction
/// ([`crate::ops::stream_import::IMPORT_FLUSH_BATCHES`]).
pub const PERSIST_CHUNK: usize = 500;

/// Parse URLs in bounded batches and persist each batch's rows with the
/// db-crate bulk upserts.
///
/// One write-behind WINDOW per transaction instead of one autocommit per row —
/// a 7000-URL feed previously issued ~28k implicit commits, pegging the `NVMe`
/// and starving the UI. Rows are deduped across the WHOLE import via
/// deterministic ids before the bulk calls, so repeated protocol configs and
/// duplicate (host, port) lines upsert once per run.
///
/// The writes are DEFERRED: each chunk is staged on
/// [`leas_db::WriteBehind`] and drained by a live flush task DURING the run,
/// then the run ends with a coordinated flush. So the returned count is what
/// was STORED (see [`ImportOutcome`]'s `links`) and a crash mid-run loses at
/// most the driver's staleness window, not the whole feed.
/// Returns `(links stored, whole-run summary)`.
pub async fn persist_parsed_urls(
    db: &Arc<Database>,
    urls: &[String],
    group_id: Option<&str>,
    validation: &ValidationSettings,
) -> (usize, ValidationSummary) {
    const PROGRESS_EVERY: usize = 5000;
    let total = urls.len();

    let mut summary = ValidationSummary::default();
    // Parsed-link total, reconciled against the final flush's `stored`.
    let mut staged_count = 0usize;
    // Monotonic per-chunk staging ids: two chunks pending at once must be two
    // pending-map entries.
    let mut next_seq = 0u64;
    let driver = crate::ops::stream_import::ImportRun::new(db);
    // Deterministic-id dedup sets: a protocol row is shared across endpoints
    // (identity excludes host/port), so subscription feeds that repeat one
    // protocol config over hundreds of server URLs collapse to one upsert.
    let mut seen_protocols = std::collections::HashSet::new();
    let mut seen_endpoints = std::collections::HashSet::new();
    let mut seen_links = std::collections::HashSet::new();

    for chunk in urls.chunks(PERSIST_CHUNK) {
        let (profiles, batch_summary) =
            leas_config::subscription::parse_url_batch(chunk, validation);
        summary.merge(&batch_summary);

        let mut endpoints: Vec<leas_db::models::Endpoint> = Vec::new();
        let mut protocols: Vec<leas_db::models::Protocol> = Vec::new();
        let mut links: Vec<leas_db::models::ProfileStats> = Vec::new();
        let mut group_links: Vec<leas_db::models::EndpointGroup> = Vec::new();
        let mut ip_literals: Vec<(leas_db::models::EndpointId, std::net::IpAddr)> = Vec::new();

        for profile in &profiles {
            let parsed = &profile.parsed;
            if parsed.endpoints.is_empty() {
                continue;
            }
            let protocol = crate::state::protocol_from_parsed(parsed);
            if seen_protocols.insert(protocol.id.get()) {
                protocols.push(protocol.clone());
            }
            for ep in &parsed.endpoints {
                let endpoint = crate::state::endpoint_from_essentials(ep);
                let link = crate::state::link_from_parsed_with_id(protocol.id, endpoint.id);
                if seen_links.insert((link.protocol_id.get(), link.endpoint_id.get())) {
                    if seen_endpoints.insert(endpoint.id.get()) {
                        if let Ok(ip) = ep.host.parse::<std::net::IpAddr>() {
                            ip_literals.push((endpoint.id, ip));
                        }
                        endpoints.push(endpoint.clone());
                    }
                    links.push(link.clone());
                    if let Some(gid) = group_id {
                        group_links.push(leas_db::models::EndpointGroup {
                            endpoint_id: endpoint.id,
                            group_id: gid.to_owned(),
                            last_seen_at: link.last_seen_at,
                            sort_order: None,
                            endpoint: toasty::Deferred::default(),
                            group: toasty::Deferred::default(),
                        });
                    }
                }
            }
        }

        let chunk_links = links.len();
        staged_count += chunk_links;
        driver.push(leas_db::SourceBatch {
            seq: next_seq,
            endpoints,
            protocols,
            links,
            group_links,
            ip_literals,
        });
        next_seq += 1;

        if staged_count / PROGRESS_EVERY != (staged_count - chunk_links) / PROGRESS_EVERY {
            tracing::info!(target: "tui::ops::subscriptions", "Imported {staged_count}/{total} links from subscription");
        }
        tokio::task::yield_now().await;
    }

    // Coordinated end-of-run flush: the staged rows are written now, so the
    // returned count is what was STORED. Run-wide, baseline included — see
    // `ImportRun`.
    let flushed = driver.finish().await;
    let flush_dropped = staged_count.saturating_sub(flushed.stored);
    if flush_dropped > 0 {
        tracing::error!(
            target: "tui::ops::subscriptions",
            "{flush_dropped} parsed link(s) from this subscription were NOT stored: \
             every flush attempt failed ({} batch(es) still staged)",
            flushed.staged_left,
        );
    }

    (flushed.stored, summary)
}

pub fn update_all_subscriptions(state: &mut AppState) {
    // One shared pipeline: a group with a URL runs sequentially. Parallel
    // group herds multiplied write contention (each group previously spawned
    // its own upsert task burst); the in-flight registry is the exclusion
    // authority for a group already being fetched by another path, and the
    // per-group `updating_groups` guard still prevents double-updates of the
    // same group from this path.
    let groups: Vec<(String, String, Option<String>)> = state
        .groups
        .iter()
        .filter(|g| g.url.as_deref().is_some_and(|u| !u.is_empty()))
        .filter(|g| !state.updating_groups.contains(&g.id))
        .filter(|g| !import_in_flight(&g.id))
        .map(|g| {
            (
                g.id.clone(),
                g.url.clone().unwrap_or_default(),
                g.user_agent.clone(),
            )
        })
        .collect();
    if groups.is_empty() {
        return;
    }

    let tx = state.core_event_tx.clone();
    let db = state.db.clone();
    let validation: ValidationSettings = state.config.parsing.clone().into();
    let budget = state.config.import;
    for (gid, _url, _ua) in &groups {
        state.updating_groups.insert(gid.clone());
    }
    tokio::spawn(async move {
        for (gid, url, ua) in groups {
            let user_agent = ua.unwrap_or_else(|| "leas/0.1".into());
            update_one_group(
                url,
                user_agent,
                gid,
                db.clone(),
                validation.clone(),
                budget,
                tx.clone(),
            )
            .await;
        }
    });
}

/// Start a background task to check and update subscriptions.
pub fn spawn_auto_update(state: &mut AppState) {
    let Some(tx) = state.core_event_tx.clone() else {
        return;
    };
    let db = state.db.clone();
    let validation: ValidationSettings = state.config.parsing.clone().into();
    let shutdown = state.shutdown_token.clone();
    tokio::spawn(async move {
        // Check shutdown before first sleep
        tokio::select! {
            () = tokio::time::sleep(Duration::from_secs(10)) => {},
            () = async { while !shutdown.load(Ordering::Relaxed) { tokio::time::sleep(Duration::from_millis(100)).await; } } => return,
        }
        loop {
            if shutdown.load(Ordering::Relaxed) {
                return;
            }
            let Ok(due_groups) = db.get_groups_due_update().await else {
                tokio::select! {
                    () = tokio::time::sleep(Duration::from_mins(1)) => {},
                    () = async { while !shutdown.load(Ordering::Relaxed) { tokio::time::sleep(Duration::from_millis(100)).await; } } => return,
                }
                continue;
            };
            for group in &due_groups {
                if shutdown.load(Ordering::Relaxed) {
                    return;
                }
                let url = match &group.url {
                    Some(u) => u.clone(),
                    None => continue,
                };
                let ua = group
                    .user_agent
                    .clone()
                    .unwrap_or_else(|| "leas/0.1".into());
                let gid = group.id.clone();
                let Some(flight) = InFlightGuard::acquire(&gid) else {
                    // A manual refresh or a batch update owns this group and
                    // will report its own outcome — a second concurrent fetch
                    // of the same URL is exactly the defect this registry
                    // exists to prevent.
                    tracing::debug!(
                        target: "tui::ops::subscriptions",
                        "Skipping auto-update of group {gid}: fetch already in flight"
                    );
                    continue;
                };
                let result = do_update_subscription(
                    url,
                    ua,
                    gid.clone(),
                    db.clone(),
                    validation.clone(),
                    leas_config::app_config::ImportConfig::default(),
                    &flight,
                )
                .await;
                drop(flight);
                try_send_or_warn(
                    &tx,
                    CoreEvent::SubscriptionsUpdated {
                        group_id: result.0,
                        count: result.1,
                        summary: result.2,
                        error: result.3,
                    },
                    "auto_subs_updated",
                );
            }
            tokio::select! {
                () = tokio::time::sleep(Duration::from_mins(1)) => {},
                () = async { while !shutdown.load(Ordering::Relaxed) { tokio::time::sleep(Duration::from_millis(100)).await; } } => return,
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_vmess_url(host: &str) -> String {
        let qr = serde_json::json!({
            "v": "2", "ps": "test", "add": host, "port": "443",
            "id": "550e8400-e29b-41d4-a716-446655440000", "aid": "0", "scy": "auto",
            "net": "tcp", "type": "none", "host": "", "path": "", "tls": "",
            "sni": "", "alpn": "", "fp": "", "insecure": "0",
        });
        let b64 = base64_simd::STANDARD.encode_to_string(serde_json::to_string(&qr).unwrap());
        format!("vmess://{b64}")
    }

    #[test]
    fn in_flight_guard_refuses_second_fetch_and_releases_on_drop() {
        let gid = "guard-drop-test";
        let first = InFlightGuard::acquire(gid).expect("first claim wins");
        assert!(import_in_flight(gid), "a claimed group is visible");
        assert!(
            InFlightGuard::acquire(gid).is_none(),
            "a second fetch of the same group is refused"
        );
        drop(first);
        assert!(!import_in_flight(gid), "drop releases the slot");
        let second = InFlightGuard::acquire(gid).expect("released group is claimable again");
        drop(second);
    }

    #[tokio::test]
    async fn in_flight_guard_releases_on_early_return() {
        // The real shape: a fetch path claims the slot, then leaves through an
        // early return (no URL / already in flight elsewhere). Only the
        // guard's Drop can free the group, so a bail-out must not wedge it.
        fn fetch_that_bails(group_id: &str) -> bool {
            let Some(_guard) = InFlightGuard::acquire(group_id) else {
                return false;
            };
            false
        }

        let gid = "guard-early-return-test";
        assert!(!fetch_that_bails(gid));
        assert!(
            !import_in_flight(gid),
            "an early return must not leave the group wedged"
        );
        assert!(
            InFlightGuard::acquire(gid).is_some(),
            "the group is fetchable again after the bail-out"
        );
    }

    #[tokio::test]
    async fn partial_import_records_error_status_and_keeps_last_refreshed() {
        let db = Arc::new(Database::in_memory().await.expect("in-memory db"));
        db.upsert_group(&Group {
            id: "g-partial".to_string(),
            name: Some("partial".to_string()),
            url: Some("https://example.invalid/sub".to_string()),
            enabled: true,
            user_agent: None,
            convert_target: None,
            sort_order: None,
            refresh_interval: Some(60),
            last_refreshed: None,
            status: Some(GroupStatus::Ok),
            error_message: None,
        })
        .await
        .expect("seed group");

        // A source that died mid-stream after 3381 links: the group must NOT
        // be recorded as a clean refresh.
        let truncated = ImportOutcome {
            links: 3381,
            summary: ValidationSummary::default(),
            ended_early: Some("error decoding response body".to_string()),
        };
        record_import_result(&db, "g-partial", &truncated).await;

        let group = db
            .get_all_groups()
            .await
            .expect("groups")
            .into_iter()
            .find(|g| g.id == "g-partial")
            .expect("group row");
        assert_eq!(group.status, Some(GroupStatus::Error));
        let message = group.error_message.expect("partial import message");
        assert!(
            message.contains("3381") && message.contains("incomplete"),
            "message states the feed was cut short and how much stored: {message}"
        );
        assert!(
            group.last_refreshed.is_some(),
            "a partial import still refreshed what it stored"
        );

        // A clean run still lands on Ok with no message.
        record_import_result(
            &db,
            "g-partial",
            &ImportOutcome {
                links: 9,
                summary: ValidationSummary::default(),
                ended_early: None,
            },
        )
        .await;
        let group = db
            .get_all_groups()
            .await
            .expect("groups")
            .into_iter()
            .find(|g| g.id == "g-partial")
            .expect("group row");
        assert_eq!(group.status, Some(GroupStatus::Ok));
        assert_eq!(group.error_message, None);
    }

    /// A page request filtered to one group (the retired
    /// `get_active_endpoints_by_group` coverage, now on the query).
    fn group_page_request(group: &str) -> leas_db::profiles_query::PageRequest {
        leas_db::profiles_query::PageRequest {
            view: leas_db::models::PurgatoryView::All,
            active_threshold: 0,
            scope: leas_db::profiles_query::PlanScope::All,
            search: None,
            group_id: Some(group.to_string()),
            sort: leas_db::profiles_query::PageSort::Test,
            ascending: true,
            offset: 0,
            limit: 10_000,
        }
    }

    #[tokio::test]
    async fn persist_parsed_urls_dedups_and_persists_group_links() {
        use leas_db::models::EndpointId;
        let db = Arc::new(Database::in_memory().await.expect("in-memory db"));
        let validation = ValidationSettings::default();

        // Two identical URLs (same host+protocol), one distinct host, one
        // garbage URL. The two identical URLs dedup to ONE link (same
        // endpoint id + protocol id), the distinct host is a second link;
        // both share ONE protocol row (identity excludes host/port).
        let urls = vec![
            valid_vmess_url("1.2.3.4"),
            valid_vmess_url("1.2.3.4"),
            valid_vmess_url("5.6.7.8"),
            "vmess://!!!not-base64!!!".to_string(),
        ];

        let (count, summary) = persist_parsed_urls(&db, &urls, Some("g1"), &validation).await;
        assert_eq!(count, 2, "duplicate (host, protocol) collapses");
        assert_eq!(summary.other_count, 1, "garbage URL counted");
        assert_eq!(summary.total_errors, 1);

        // One endpoint per unique host, both linked to the group.
        let req = group_page_request("g1");
        let meta = db.profiles_page(&req).await.expect("group read");
        let rows = db
            .load_page_rows(&meta.ids, true)
            .await
            .expect("group rows");
        assert_eq!(rows.len(), 2, "one row per unique endpoint");
        assert_eq!(rows[0].links.len(), 1);
        assert_eq!(rows[1].links.len(), 1);

        // Rerun the same list: counts identical, no duplicate rows.
        let (count2, _) = persist_parsed_urls(&db, &urls, Some("g1"), &validation).await;
        assert_eq!(count2, 2, "idempotent rerun");
        let rows2 = db
            .load_page_rows(&meta.ids, true)
            .await
            .expect("group rows 2");
        assert_eq!(rows2.len(), 2, "no row duplication on rerun");
        assert_eq!(rows2[0].links.len(), 1, "no link duplication on rerun");

        // No group id: links persist without group membership rows.
        let db2 = Arc::new(Database::in_memory().await.expect("in-memory db"));
        let (count3, _) = persist_parsed_urls(&db2, &urls, None, &validation).await;
        assert_eq!(count3, 2);
        assert!(
            db2.profiles_page(&group_page_request("g1"))
                .await
                .expect("no group rows")
                .ids
                .is_empty(),
            "group_id=None must not create group links"
        );
        let _ = EndpointId::new(1); // import reference for the models path
    }
}
