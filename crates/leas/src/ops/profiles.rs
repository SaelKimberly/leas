use std::collections::HashMap;

use jiff::Timestamp;
use leas_config::forms::build_typed_config;
use leas_config::import_export::{ParsedProfile, ValidationSettings, parse_share_url};
use leas_core::{CoreType, resolve_core};

use crate::AppState;
use crate::state::{
    endpoint_from_essentials, load_protocol_with_config, persist_parsed, protocol_from_parsed,
};
use crate::types::{AppMode, BatchImportItem};
use crate::{common_field_defaults, get_field, profile_to_fields};
use leas_db::Database;
use leas_db::DatabaseError;
use leas_db::models::{EndpointRow, ProfileStats, PurgatoryView};
use leas_db::profiles_query::{PageMeta, PageRequest, PageSort, PlanScope};
use leas_proto::proto_spec::{CoreType as ProtoCoreType, ParsedProto, ProtocolKind};

/// Unix-seconds now, as a `Timestamp` (the typed staleness clock).
fn now_ts() -> Timestamp {
    Timestamp::now()
}

/// Sweep stale persisted failure markers: clear `error` on every
/// `profile_stats` row whose `error` is set AND whose `updated_at` predates
/// `now - ttl_hours`.
///
/// This is the "Clear error after" setting (design §6.4, anchor =
/// `updated_at`): one typed query-based UPDATE (no read-modify-write).
/// `None` (the default) never clears: errors survive until the next test
/// overwrites them. Best-effort housekeeping — DB errors are logged and
/// swallowed, never surfaced to the user.
pub async fn clear_expired_errors(db: &Database, ttl_hours: Option<i64>) {
    let Some(ttl_hours) = ttl_hours.filter(|&h| h > 0) else {
        return;
    };
    let mut conn = match db.connection().await {
        Ok(conn) => conn,
        Err(e) => {
            tracing::warn!(target: "tui::ops::profiles", "clear_expired_errors: open connection: {e}");
            return;
        }
    };
    // The stored `updated_at` is epoch seconds, so the cutoff is too — no
    // timestamp formatting on the hot sweep path.
    let cutoff = leas_db::models::to_epoch(now_ts()) - ttl_hours * 3600;
    // The swept endpoints' ordering keys are derived state: collect them
    // before the update and refresh after, so a cleared marker cannot leave a
    // stale position behind (the page reads the keys, not the links).
    let cleared: Vec<i64> = ProfileStats::filter(ProfileStats::fields().error().is_some())
        .filter(ProfileStats::fields().updated_at().lt(cutoff))
        .exec(&mut conn)
        .await
        .map(|rows: Vec<ProfileStats>| rows.into_iter().map(|l| l.endpoint_id.get()).collect())
        .unwrap_or_default();
    if let Err(e) = ProfileStats::filter(ProfileStats::fields().error().is_some())
        .filter(ProfileStats::fields().updated_at().lt(cutoff))
        .update()
        .error(None)
        .exec(&mut conn)
        .await
    {
        tracing::warn!(target: "tui::ops::profiles", "clear_expired_errors: {e}");
        return;
    }
    drop(conn);
    if !cleared.is_empty() {
        let ids: Vec<leas_db::models::EndpointId> = cleared
            .into_iter()
            .map(leas_db::models::EndpointId::new)
            .collect();
        if let Err(e) = db.refresh_endpoint_ranks(&ids).await {
            tracing::warn!(target: "tui::ops::profiles", "clear_expired_errors: ranks: {e}");
        }
    }
}

/// Snapshot of the parameters a profile load needs — the spawn boundary
/// cannot carry `&AppState`.
#[derive(Clone)]
pub(crate) struct ProfilesLoad {
    pub view: PurgatoryView,
    pub purgatory_ttl_secs: i64,
    pub error_ttl_hours: Option<i64>,
    pub search: Option<String>,
    pub sort: PageSort,
    pub ascending: bool,
    pub offset: usize,
    pub limit: usize,
    /// Group filter; the Profiles tab has no group selector today (the
    /// subscription views use `group_id` through the query directly).
    pub group_id: Option<String>,
}

impl From<&AppState> for ProfilesLoad {
    fn from(s: &AppState) -> Self {
        Self {
            view: s.purgatory_view,
            purgatory_ttl_secs: s.purgatory_ttl_secs,
            error_ttl_hours: s.config.speed_test.error_ttl_hours,
            search: (!s.search_query.is_empty()).then(|| s.search_query.clone()),
            sort: PageSort::Test,
            ascending: true,
            offset: s.page_offset,
            limit: PROFILES_PAGE_SIZE,
            group_id: None,
        }
    }
}

/// Whether the current view's panel shows purged links.
///
/// The Active view is the effective-profiles list; Purgatory and All show every
/// link, which is what makes a real test on a purged row possible at all.
#[must_use]
const fn includes_purged(view: PurgatoryView) -> bool {
    matches!(view, PurgatoryView::Purgatory | PurgatoryView::All)
}

/// The DB half of a profile reload: error-TTL sweep + the current view's rows.
///
/// Safe to run OFF the UI task — whole-table reads at 10k+ endpoints take
/// seconds and must not block input/render (the subscription-update freeze).
pub(crate) async fn load_profiles_rows(
    db: &Database,
    load: &ProfilesLoad,
) -> Result<(Vec<EndpointRow>, PageMeta), DatabaseError> {
    // Error-TTL sweep (design §6.4): clear failure markers older than the
    // configured TTL before rows are (re)loaded, so a swept error never
    // renders. `None` (default) = no-op.
    clear_expired_errors(db, load.error_ttl_hours).await;
    let req = page_request(load);
    let meta = db.profiles_page(&req).await?;
    // One statement for the whole page: the typed hydration binds ~600
    // parameters per page (turso: ~0.8 ms each), the projection inlines the
    // ids and decodes the display columns only.
    let rows = db
        .load_page_projection(&meta.ids, includes_purged(load.view))
        .await?;
    Ok((rows, meta))
}

/// Fetch ONE page for an already-swept reload — the re-anchor path needs the
/// rows again but must not repeat the sweep's writes.
async fn load_profiles_page_only(
    db: &Database,
    load: &ProfilesLoad,
) -> Result<(Vec<EndpointRow>, PageMeta), DatabaseError> {
    let req = page_request(load);
    let meta = db.profiles_page(&req).await?;
    let rows = db
        .load_page_projection(&meta.ids, includes_purged(load.view))
        .await?;
    Ok((rows, meta))
}

/// Build the query request a [`ProfilesLoad`] describes.
fn page_request(load: &ProfilesLoad) -> PageRequest {
    let now = leas_db::models::to_epoch(now_ts());
    // One bound, two directions: Active is `rank_newest_seen >= active`,
    // Purgatory is `< active`. The stored maximum is live-only (decision 16), so
    // an endpoint whose links are all purged sits below both bounds by
    // construction and needs no second predicate. Passing `now` would make the
    // window `>= now`, i.e. an empty tab (a sync only ever stamps the past).
    let active_threshold = match load.view {
        PurgatoryView::Active | PurgatoryView::Purgatory => {
            now.saturating_sub(load.purgatory_ttl_secs)
        }
        // `All`: no predicate is emitted, so the bound is unused.
        PurgatoryView::All => 0,
    };
    PageRequest {
        view: load.view,
        active_threshold,
        // The tab never narrows by plan scope: its filters are the view, the
        // search box and the group. A scope belongs to a batch entry point.
        scope: PlanScope::All,
        search: load.search.clone(),
        group_id: load.group_id.clone(),
        sort: load.sort,
        ascending: load.ascending,
        offset: load.offset,
        limit: load.limit,
    }
}

/// The UI half of a profile reload: swap in fresh rows, invalidate filters,
/// re-clamp the selection, and seed background enrichment for rows that lack
/// cached `endpoint_info`.
pub(crate) fn apply_profiles_rows(state: &mut AppState, rows: Vec<EndpointRow>, meta: &PageMeta) {
    state.endpoints = rows;
    state.page_total = meta.total;
    state.page_offset = meta.offset;
    // A new page is a structural change: the display-row cache key compares the
    // loaded row COUNT and per-row expanded flags, so two same-length pages
    // (the common case) would otherwise re-serve the previous page's rows —
    // numbers included — for a frame that nothing else dirtied.
    state.endpoints_gen = state.endpoints_gen.wrapping_add(1);
    // The page was just read: nothing pending.
    state.filter_cache_valid.set(true);
    clamp_selection(state);
    // Enrich new endpoints in the background (IP hosts + persisted DNS cache;
    // no network for fresh entries).
    crate::ops::enrich::spawn_enrich_ip_hosts(state);
    // mmdb countries for persisted outbound (exit) IPs — survives reruns.
    crate::ops::enrich::spawn_outbound_countries(state);
}

pub async fn reload_profiles(state: &mut AppState) {
    // A synchronous reload supersedes any background load still in flight.
    state.reload_gen = state.reload_gen.wrapping_add(1);
    // Make staged writes durable BEFORE the load: the load starts with the
    // error-TTL sweep, which writes the same error columns a staged result
    // patch carries — flushing afterwards would resurrect the markers the
    // sweep just cleared.
    if let Err(e) = state.link_stage.flush().await {
        tracing::warn!(target: "tui::ops::profiles", "flush before reload: {e}");
    }
    let load = ProfilesLoad::from(&*state);
    match load_profiles_rows(&state.db, &load).await {
        Ok((rows, meta)) => apply_profiles_rows(state, rows, &meta),
        Err(e) => {
            state.log_trace(
                "error",
                "tui::ops::profiles",
                &format!("Failed to load profiles: {e}"),
            );
            state.endpoints.clear();
            state.filter_cache_valid.set(true);
            clamp_selection(state);
        }
    }
}

/// Reload the page for an EXTERNAL invalidation (a ping result moved a row, a
/// search/sort/view change landed), keeping the user where they were.
///
/// The selection is an endpoint id, not an index: after a reorder the row may
/// sit on another page, so the window is re-anchored on the row's new offset
/// when it left the loaded page. Deliberate navigation uses [`reload_profiles`]
/// instead — it sets the offset on purpose and must not be pulled back.
pub async fn reload_profiles_preserving_selection(state: &mut AppState) {
    let selected = state
        .selected_profile_id()
        .map(leas_db::models::EndpointId::new);
    let load = ProfilesLoad::from(&*state);
    match load_profiles_rows(&state.db, &load).await {
        Ok((rows, meta)) => {
            let moved_away =
                selected.is_some_and(|id| !rows.iter().any(|row| row.endpoint.id == id));
            apply_profiles_rows(state, rows, &meta);
            if let Some(id) = selected
                && let Some(index) = state.endpoints.iter().position(|row| row.endpoint.id == id)
            {
                state.selected_index = index;
            } else if moved_away
                && let Some(id) = selected
                && let Ok(Some(offset)) = state.db.profiles_anchor(&page_request(&load), id).await
            {
                // Re-anchor once on the row's new position, then follow it.
                // Page + rows only: the sweep already ran for this reload, and
                // repeating its writes would resurrect nothing but cost a
                // second pass over the error TTL.
                state.page_offset = offset;
                let load = ProfilesLoad::from(&*state);
                if let Ok((rows, meta)) = load_profiles_page_only(&state.db, &load).await {
                    apply_profiles_rows(state, rows, &meta);
                    if let Some(index) =
                        state.endpoints.iter().position(|row| row.endpoint.id == id)
                    {
                        state.selected_index = index;
                    }
                }
            }
        }
        Err(e) => {
            state.log_trace(
                "error",
                "tui::ops::profiles",
                &format!("Failed to load profiles: {e}"),
            );
        }
    }
}

/// Clamp a selection index into `[0, len)`, returning 0 for an empty list.
pub(crate) const fn clamp_index(selected: usize, len: usize) -> usize {
    if len == 0 {
        0
    } else if selected >= len {
        len - 1
    } else {
        selected
    }
}

/// Move the selection by `delta` rows, crossing page boundaries.
///
/// Down past the last row of the window loads the next page and lands on its
/// first row; Up before the first row loads the previous page and lands on its
/// last row. At the very start/end of the feed the index clamps and nothing is
/// fetched.
pub async fn move_selection(state: &mut AppState, delta: isize) {
    let len = filtered_len(state);
    if len == 0 {
        return;
    }
    let total = state.page_total;
    let target = state.selected_index as isize + delta;

    if target < 0 {
        if state.page_offset == 0 {
            state.selected_index = 0;
            return;
        }
        state.page_offset = state.page_offset.saturating_sub(PROFILES_PAGE_SIZE);
        reload_profiles(state).await;
        state.selected_index = filtered_len(state).saturating_sub(1);
        return;
    }

    if target as usize >= len {
        let next_offset = state.page_offset + len;
        if next_offset as u64 >= total {
            state.selected_index = len.saturating_sub(1);
            return;
        }
        let overshoot = target as usize - len;
        state.page_offset = next_offset;
        reload_profiles(state).await;
        state.selected_index = overshoot.min(filtered_len(state).saturating_sub(1));
        return;
    }

    state.selected_index = target as usize;
}

/// Jump to the first row of the feed.
pub async fn goto_first(state: &mut AppState) {
    state.selected_sub = None;
    if state.page_offset == 0 {
        state.selected_index = 0;
        return;
    }
    state.page_offset = 0;
    reload_profiles(state).await;
    state.selected_index = 0;
}

/// Jump to the last row of the feed, loading the page that holds it.
pub async fn goto_last(state: &mut AppState) {
    state.selected_sub = None;
    let total = state.page_total;
    if total == 0 {
        state.selected_index = 0;
        return;
    }
    let last_offset = (((total - 1) as usize) / PROFILES_PAGE_SIZE) * PROFILES_PAGE_SIZE;
    if state.page_offset != last_offset {
        state.page_offset = last_offset;
        reload_profiles(state).await;
    }
    state.selected_index = filtered_len(state).saturating_sub(1);
}

/// Re-clamp the selection into the loaded page.
///
/// The `DataTable` clamps its own selection visually to row 0, but `AppState`
/// keeps the stale index — which makes `selected_profile_id()` return `None`
/// and Enter/e/d/x/Space silent no-ops. Drop a `selected_sub` that no longer
/// points at a real row.
pub const fn clamp_selection(state: &mut AppState) {
    let len = filtered_len(state);
    state.selected_index = clamp_index(state.selected_index, len);
    if state.selected_index >= len || len == 0 {
        state.selected_sub = None;
    }
}

pub async fn reload_groups(state: &mut AppState) {
    match state.db.get_all_groups().await {
        Ok(groups) => state.groups = groups,
        Err(e) => {
            state.log_trace(
                "error",
                "tui::ops::profiles",
                &format!("Failed to load groups: {e}"),
            );
            state.groups.clear();
        }
    }
}

pub async fn reload_routing_rules(state: &mut AppState) {
    state.routing_rules = state.db.get_all_routing_rules().await.unwrap_or_default();
}

/// The loaded page, in display order. The page IS the filtered list: the query
/// applied the view, search, group, and sort, and `selected_index` indexes this
/// window.
pub fn filtered_profiles(state: &AppState) -> impl Iterator<Item = &EndpointRow> {
    state.endpoints.iter()
}

/// Length of the indexed space (the page), used by selection clamping and
/// navigation. The feed-wide count is [`AppState::profiles_total`].
pub const fn filtered_len(state: &AppState) -> usize {
    state.endpoints.len()
}

/// The page size.
pub(crate) const PROFILES_PAGE_SIZE: usize = 200;

/// Whether the endpoint's DNS host is currently unresolved (no known IPs).
///
/// The db crate's ordering law, applied to the loaded row — the same function
/// the stored rank keys are computed with, so the comparator, the page SQL and
/// the keys cannot disagree. `state.endpoint_info` is a display cache and is
/// deliberately not consulted: it can lag the row.
pub(crate) const fn endpoint_dns_unresolved(_state: &AppState, row: &EndpointRow) -> bool {
    leas_db::endpoint_rank::dns_unresolved(row)
}

/// Resolve which core a profile row should use, considering (in order):
///   1. Per-protocol config override (`config.core.protocol_core_overrides`)
///   2. Hardcoded auto-detection (`core_for_protocol` via `resolve_core`)
///
/// The per-pair `link.core_type` override is gone (db-rewamp D3); the core is
/// derived from the kind, the config override and the Shadowsocks method.
///
/// LIMITATION: this reads a page `EndpointRow` whose `protocol.config` is
/// UNLOADED, so `shadowsocks_method` returns `None` — a legacy-cipher SS row
/// shows the xray default here. The connect path resolves the core from the
/// LOADED protocol instead (`ops::connect`), which is authoritative; this
/// label is cosmetic. Same for the UI's core column.
pub fn resolved_core(state: &AppState, row: &EndpointRow) -> CoreType {
    let Some((_link, protocol)) = row.active_protocol() else {
        return CoreType::Auto;
    };
    let config_override = state
        .config
        .core
        .protocol_core_overrides
        .get(&protocol.proto_kind.to_string())
        .and_then(|s| s.parse::<CoreType>().ok());
    let override_ = match config_override {
        Some(CoreType::Auto) | None => None,
        Some(CoreType::Native) => return CoreType::Native,
        Some(CoreType::Xray) => Some(ProtoCoreType::Xray),
        Some(CoreType::SingBox) => Some(ProtoCoreType::SingBox),
    };
    match resolve_core(
        protocol.proto_kind,
        override_,
        leas_core::shadowsocks_method(protocol).as_deref(),
    ) {
        ProtoCoreType::Xray => CoreType::Xray,
        ProtoCoreType::SingBox => CoreType::SingBox,
    }
}

pub fn start_add_server(state: &mut AppState) {
    let fields = common_field_defaults();
    state.mode = AppMode::AddServer {
        protocol: None,
        fields,
        focus_index: 0,
        form_errors: HashMap::new(),
    };
}

/// Resolve an endpoint row for editing: check the currently loaded view
/// first, then fall back to a direct DB lookup by endpoint id (covers
/// never-seen rows that the Active view excludes).
async fn find_editable_endpoint(
    state: &AppState,
    endpoint_id: i64,
) -> Result<Option<EndpointRow>, DatabaseError> {
    if let Some(r) = state
        .endpoints
        .iter()
        .find(|r| r.endpoint.id.get() == endpoint_id)
    {
        return Ok(Some(r.clone()));
    }
    state
        .db
        .get_endpoint(endpoint_id_from_raw(endpoint_id))
        .await
}

/// The typed `EndpointId` for a raw i64 (used by edit/delete flows).
pub(crate) const fn endpoint_id_from_raw(raw: i64) -> leas_db::models::EndpointId {
    leas_db::models::EndpointId::new(raw)
}

pub async fn start_edit_profile(state: &mut AppState, id: &str) {
    let endpoint_id: i64 = id.parse().unwrap_or(0);
    let row = match find_editable_endpoint(state, endpoint_id).await {
        Ok(Some(row)) => row,
        Ok(None) => {
            state.log_trace(
                "error",
                "tui::ops::profiles",
                &format!("Profile {id} not found"),
            );
            return;
        }
        Err(e) => {
            state.log_trace(
                "error",
                "tui::ops::profiles",
                &format!("Error loading profile {id}: {e}"),
            );
            return;
        }
    };
    // The edit form is populated from the ACTIVE protocol's typed config
    // (loaded with `config` included — `profile_to_fields` and the config
    // builders require it).
    let Some((_link, protocol)) = row.active_protocol() else {
        state.log_trace(
            "error",
            "tui::ops::profiles",
            &format!("Profile {id} has no protocols"),
        );
        return;
    };
    let protocol = match load_protocol_with_config(&state.db, protocol.id).await {
        Ok(Some(p)) => p,
        Ok(None) => {
            state.log_trace(
                "error",
                "tui::ops::profiles",
                &format!("Protocol for profile {id} not found"),
            );
            return;
        }
        Err(e) => {
            state.log_trace(
                "error",
                "tui::ops::profiles",
                &format!("Error loading protocol for profile {id}: {e}"),
            );
            return;
        }
    };
    let fields = profile_to_fields(&protocol, &row.endpoint, &row.resolved_ips);
    state.mode = AppMode::EditServer {
        protocol_id: endpoint_id,
        proto_kind: protocol.proto_kind,
        fields,
        focus_index: 0,
        form_errors: HashMap::new(),
    };
}

pub fn selected_profile_id(state: &AppState) -> Option<i64> {
    filtered_profiles(state)
        .nth(state.selected_index)
        .map(|r| r.endpoint.id.get())
}

pub fn toggle_expand(state: &mut AppState) {
    let ep_id = filtered_profiles(state)
        .nth(state.selected_index)
        .map(|r| r.endpoint.id.get());
    if let Some(ep_id) = ep_id
        && let Some(ep_row) = state
            .endpoints
            .iter_mut()
            .find(|r| r.endpoint.id.get() == ep_id)
    {
        ep_row.expanded = !ep_row.expanded;
        if ep_row.expanded {
            // Enter the sub-table on its first row (user decision: expand
            // lands on the first internal protocol).
            state.selected_sub = Some(0);
        } else {
            state.selected_sub = None;
        }
    }
}
pub fn collapse_expand(state: &mut AppState) {
    let ep_id = filtered_profiles(state)
        .nth(state.selected_index)
        .map(|r| r.endpoint.id.get());
    if let Some(ep_id) = ep_id
        && let Some(ep_row) = state
            .endpoints
            .iter_mut()
            .find(|r| r.endpoint.id.get() == ep_id)
    {
        ep_row.expanded = false;
    }
    state.selected_sub = None;
}

/// Build a typed [`ParsedProto`] from the add/edit form fields — the
/// producer-side replacement for the deleted `fields_to_profile` +
/// `encode_profile_spec`.
///
/// The settings JSON is assembled with the same key routing the legacy
/// producer used (so `build_typed_config` accepts it), with the F6 fix from
/// T12: the tuic `password` field routes into `protocol_settings.password`
/// instead of clobbering the top-level `user_id` (uuid). The vmess/vless
/// form's transport `network` select routes into
/// `protocol_settings.network` (I1) — the T12 mapper builds the typed
/// transport from it. The form's `core_type` selection is returned
/// separately — it flows into the per-pair `link.core_type` (the config
/// builder takes the core from the link), never into the typed config.
///
/// # Errors
///
/// If the address/port are missing or `build_typed_config` rejects the
/// settings (unknown keys, missing credentials).
pub fn fields_to_parsed(
    kind: ProtocolKind,
    fields: &[(String, String)],
    validation: &ValidationSettings,
) -> Result<ParsedProto, String> {
    let address = get_field(fields, "address").unwrap_or_default();
    let port = get_field(fields, "port")
        .and_then(|p| p.parse::<u16>().ok())
        .ok_or_else(|| "Port must be 1-65535".to_string())?;
    if address.is_empty() {
        return Err("Address is required".to_string());
    }

    let mut proto_map = serde_json::Map::new();
    let mut stream_map = serde_json::Map::new();
    let mut user_id: Option<String> = None;

    for (key, value) in fields {
        if value.is_empty() {
            continue;
        }
        let json_val = if value == "true" {
            serde_json::Value::Bool(true)
        } else if value == "false" {
            serde_json::Value::Bool(false)
        } else if let Ok(n) = value.parse::<i64>() {
            serde_json::Value::Number(n.into())
        } else {
            serde_json::Value::String(value.clone())
        };
        match key.as_str() {
            // The vmess/vless form's transport `network` select is a real
            // setting: routed into `protocol_settings.network` so the T12
            // mapper builds the typed transport from it (network=kcp → Kcp).
            // network=tcp with non-empty ws.*/grpc.* keys is rejected by
            // build_typed_config validation (the add-flow P2 regression: the
            // form defaults the select to "tcp" while rendering the ws/grpc
            // fields unconditionally). Other kinds' `network` fields are
            // Profile columns — dropped (edit forms seed network from
            // `transport_type()`, e.g. trojan "tcp", hy/hy2/tuic "quic", and
            // those mappers do not accept the key).
            "network" if matches!(kind, ProtocolKind::Vless | ProtocolKind::Vmess) => {
                proto_map.insert(key.clone(), json_val);
            }
            // Profile-column / edit-form plumbing fields — never in the
            // settings JSON (vmess encryption defaults to auto).
            "address" | "port" | "security" | "network" | "config_type" | "core_type" => {}
            // F6: tuic's `password` is a protocol_setting credential (its
            // `uuid` owns the top-level `user_id` slot); every other
            // protocol's `user_id`/`password`/`uuid` key routes to the
            // top-level credential, as the T12 mappers expect.
            "password" if kind == ProtocolKind::Tuic => {
                proto_map.insert(key.clone(), json_val);
            }
            "user_id" | "password" | "uuid" => user_id = Some(value.clone()),
            _ if key.starts_with("tls.")
                || key.starts_with("ws.")
                || key.starts_with("grpc.")
                || key.starts_with("reality.")
                || key.starts_with("tcp.")
                || *key == "sni"
                || *key == "alpn"
                || *key == "fingerprint"
                || *key == "allow_insecure" =>
            {
                stream_map.insert(key.clone(), json_val);
            }
            _ => {
                proto_map.insert(key.clone(), json_val);
            }
        }
    }

    let mut settings = serde_json::Map::new();
    if let Some(u) = user_id {
        settings.insert("user_id".into(), serde_json::Value::String(u));
    }
    if !proto_map.is_empty() {
        settings.insert(
            "protocol_settings".into(),
            serde_json::Value::Object(proto_map),
        );
    }
    if !stream_map.is_empty() {
        settings.insert(
            "stream_settings".into(),
            serde_json::Value::Object(stream_map),
        );
    }

    let parsed = build_typed_config(kind, &address, port, &serde_json::Value::Object(settings))?;
    // The SAME host policy the URL path applies (db-rewamp T5: one rule for
    // every import path) — a form-built host with no registrable domain is
    // rejected here exactly as an imported one is. `allow_private_ips` is off
    // for the form: a single-label/private host cannot key an endpoint.
    leas_config::import_export::validate_host(&parsed, validation).map_err(|e| e.to_string())?;
    Ok(parsed)
}

/// Validation shared by add/edit: address/port presence and required
/// credentials for the credential-bearing protocols.
fn validate_form_fields(
    protocol: ProtocolKind,
    fields: &[(String, String)],
    errors: &mut HashMap<String, String>,
) {
    let address = get_field(fields, "address").unwrap_or_default();
    if address.is_empty() {
        errors.insert("address".into(), "Address is required".into());
    }
    let port = get_field(fields, "port").unwrap_or_default();
    if port.is_empty() || port.parse::<u16>().map_or(true, |p| p == 0) {
        errors.insert("port".into(), "Port must be 1-65535".into());
    }
    let user_id = get_field(fields, "user_id").unwrap_or_default();
    match protocol {
        ProtocolKind::Vmess
        | ProtocolKind::Vless
        | ProtocolKind::Trojan
        | ProtocolKind::Shadowsocks
        | ProtocolKind::Shadowsocks2022
        | ProtocolKind::ShadowsocksR
            if user_id.is_empty() =>
        {
            errors.insert("user_id".into(), "ID/Password required".into());
        }
        ProtocolKind::Tuic => {
            // uuid is the tuic credential; password is optional.
            let uuid = get_field(fields, "uuid").unwrap_or_default();
            if uuid.is_empty() {
                errors.insert("uuid".into(), "UUID required".into());
            }
        }
        _ => {}
    }
}

pub async fn confirm_add_server(state: &mut AppState) {
    let (protocol, fields) = if let AppMode::AddServer {
        protocol: Some(p),
        fields,
        ..
    } = &state.mode
    {
        (*p, fields.clone())
    } else {
        state.log_trace(
            "error",
            "tui::ops::profiles",
            "Cannot confirm: no protocol selected",
        );
        return;
    };

    let mut errors: HashMap<String, String> = HashMap::new();
    validate_form_fields(protocol, &fields, &mut errors);
    if !errors.is_empty() {
        if let AppMode::AddServer {
            ref mut form_errors,
            ..
        } = state.mode
        {
            *form_errors = errors;
        }
        return;
    }

    let fields = match &mut state.mode {
        AppMode::AddServer { fields, .. } => std::mem::take(fields),
        _ => unreachable!(),
    };

    let settings = ValidationSettings::from(state.config.parsing.clone());
    let parsed = match fields_to_parsed(protocol, &fields, &settings) {
        Ok(p) => p,
        Err(e) => {
            state.log_trace(
                "error",
                "tui::ops::profiles",
                &format!("Failed to build profile: {e}"),
            );
            if let AppMode::AddServer {
                fields: ref mut f, ..
            } = state.mode
            {
                *f = fields;
            }
            return;
        }
    };
    let group_id = state.first_group_id();
    let group = if group_id.is_empty() {
        None
    } else {
        Some(group_id.as_str())
    };
    match persist_parsed(&state.db, &parsed, group).await {
        Ok(_) => {
            let addr = parsed
                .first_endpoint()
                .map_or_else(|| "?".into(), |e| format!("{}:{}", e.host, e.port));
            state.log_trace(
                "info",
                "tui::ops::profiles",
                &format!("Added server: {addr}"),
            );
            state.mode = AppMode::List;
            state.endpoints_gen = state.endpoints_gen.wrapping_add(1);
            reload_profiles(state).await;
        }
        Err(e) => {
            state.log_trace(
                "error",
                "tui::ops::profiles",
                &format!("Failed to add server: {e}"),
            );
            if let AppMode::AddServer {
                fields: ref mut f, ..
            } = state.mode
            {
                *f = fields;
            }
        }
    }
}

pub async fn confirm_edit_server(state: &mut AppState) {
    let (endpoint_id, fields) = match &state.mode {
        AppMode::EditServer {
            protocol_id,
            fields,
            ..
        } => (*protocol_id, fields.clone()),
        _ => return,
    };

    let Ok(Some(row)) = state
        .db
        .get_endpoint(endpoint_id_from_raw(endpoint_id))
        .await
    else {
        state.log_trace("error", "tui::ops::profiles", "Profile not found for edit");
        return;
    };
    let Some((_, protocol)) = row.active_protocol() else {
        state.log_trace(
            "error",
            "tui::ops::profiles",
            "Profile has no protocol to edit",
        );
        return;
    };
    let protocol = protocol.proto_kind;

    let mut errors: HashMap<String, String> = HashMap::new();
    validate_form_fields(protocol, &fields, &mut errors);
    if !errors.is_empty() {
        if let AppMode::EditServer {
            ref mut form_errors,
            ..
        } = state.mode
        {
            *form_errors = errors;
        }
        return;
    }

    let fields = match &mut state.mode {
        AppMode::EditServer { fields, .. } => std::mem::take(fields),
        _ => unreachable!(),
    };

    let settings = ValidationSettings::from(state.config.parsing.clone());
    let parsed = match fields_to_parsed(protocol, &fields, &settings) {
        Ok(p) => p,
        Err(e) => {
            state.log_trace(
                "error",
                "tui::ops::profiles",
                &format!("Failed to build profile: {e}"),
            );
            if let AppMode::EditServer {
                fields: ref mut f, ..
            } = state.mode
            {
                *f = fields;
            }
            return;
        }
    };
    // Editing replaces the endpoint's protocol identity: upsert the new
    // endpoint/protocol/link rows (idempotent on the same uid) and reload.
    let group_id = state.first_group_id();
    let group = if group_id.is_empty() {
        None
    } else {
        Some(group_id.as_str())
    };
    match persist_parsed(&state.db, &parsed, group).await {
        Ok(_) => {
            let addr = parsed
                .first_endpoint()
                .map_or_else(|| "?".into(), |e| format!("{}:{}", e.host, e.port));
            state.log_trace(
                "info",
                "tui::ops::profiles",
                &format!("Updated server: {addr}"),
            );
            state.mode = AppMode::List;
            state.endpoints_gen = state.endpoints_gen.wrapping_add(1);
            reload_profiles(state).await;
        }
        Err(e) => {
            state.log_trace(
                "error",
                "tui::ops::profiles",
                &format!("Failed to update server: {e}"),
            );
            if let AppMode::EditServer {
                fields: ref mut f, ..
            } = state.mode
            {
                *f = fields;
            }
        }
    }
}

pub async fn delete_profile(state: &mut AppState, id: i64) {
    if let Err(e) = state.db.delete_endpoint(endpoint_id_from_raw(id)).await {
        state.log_trace(
            "error",
            "tui::ops::profiles",
            &format!("Failed to delete profile: {e}"),
        );
        return;
    }
    state.log_trace("info", "tui::ops::profiles", "Profile deleted");
    state.confirmation = None;
    state.multi_select.remove(&id);
    state.endpoints_gen = state.endpoints_gen.wrapping_add(1);
    state.filter_cache_valid.set(false);
}

pub fn clone_profile(state: &mut AppState, id: i64) {
    let found = state.endpoints.iter().find(|r| r.endpoint.id.get() == id);
    if found.is_none() {
        state.log_trace(
            "error",
            "tui::ops::profiles",
            &format!("Profile {id} not found for cloning"),
        );
        return;
    }
    state.log_trace("info", "tui::ops::profiles", "Profile cloned");
    state.endpoints_gen = state.endpoints_gen.wrapping_add(1);
    state.filter_cache_valid.set(false);
}

pub fn toggle_multi_select(state: &mut AppState, id: i64) {
    if !state.multi_select.insert(id) {
        state.multi_select.remove(&id);
    }
}

/// Populate the `AddServer` form from a parsed share URL: the first endpoint's
/// address/port plus the typed config's form fields.
fn form_from_parsed(state: &mut AppState, parsed: &ParsedProfile) {
    let Some(first) = parsed.parsed.first_endpoint().cloned() else {
        state.log_trace(
            "error",
            "tui::ops::profiles",
            "Imported profile has no endpoint address",
        );
        return;
    };
    let endpoint = endpoint_from_essentials(&first);
    let protocol = protocol_from_parsed(&parsed.parsed);
    // An IP-literal share URL's address is not in `dns_name()`; hand the form
    // the parse-boundary literal so the `address` field is populated.
    let literal: Vec<std::net::IpAddr> = first
        .host
        .parse::<std::net::IpAddr>()
        .ok()
        .into_iter()
        .collect();
    let fields = profile_to_fields(&protocol, &endpoint, &literal);
    let core_protocol = parsed.parsed.protocol.proto_kind;
    state.mode = AppMode::AddServer {
        protocol: Some(core_protocol),
        fields,
        focus_index: 0,
        form_errors: HashMap::new(),
    };
    state.log_trace("info", "tui::ops::profiles", "URL imported successfully");
}

pub fn import_url(state: &mut AppState, url: &str) {
    let settings = ValidationSettings::from(state.config.parsing.clone());
    match parse_share_url(url, &settings) {
        Ok(parsed) => form_from_parsed(state, &parsed),
        Err(e) => {
            state.mode = AppMode::ImportUrl {
                input: url.to_string(),
                error: Some(e.to_string()),
            };
        }
    }
}

pub fn start_batch_import(state: &mut AppState, urls: &[String]) {
    let settings = ValidationSettings::from(state.config.parsing.clone());
    let results: Vec<BatchImportItem> = urls
        .iter()
        .map(|url| match parse_share_url(url, &settings) {
            Ok(parsed) => BatchImportItem {
                url: url.clone(),
                profile: Some(parsed),
                error: None,
                imported: false,
            },
            Err(e) => BatchImportItem {
                url: url.clone(),
                profile: None,
                error: Some(e.to_string()),
                imported: false,
            },
        })
        .collect();
    state.mode = AppMode::BatchImport { results, scroll: 0 };
}

pub async fn confirm_batch_import(state: &mut AppState) {
    let items = match &mut state.mode {
        AppMode::BatchImport { results, .. } => std::mem::take(results),
        _ => return,
    };
    let mut imported = 0usize;
    let mut errors = 0usize;
    let group_id = state.first_group_id();
    let group = if group_id.is_empty() {
        None
    } else {
        Some(group_id.as_str())
    };
    for item in items {
        if let Some(parsed) = item.profile {
            match persist_parsed(&state.db, &parsed.parsed, group).await {
                Ok(_) => imported += 1,
                Err(_) => errors += 1,
            }
        } else {
            errors += 1;
        }
    }
    state.log_trace(
        "info",
        "tui::ops::profiles",
        &format!("Batch import: {imported} imported, {errors} errors"),
    );
    state.mode = AppMode::List;
    reload_profiles(state).await;
}

pub fn move_profile_up(state: &mut AppState) {
    let Some(id) = selected_profile_id(state) else {
        return;
    };
    let filtered: Vec<&EndpointRow> = filtered_profiles(state).collect();
    let Some(idx) = filtered.iter().position(|r| r.endpoint.id.get() == id) else {
        return;
    };
    if idx == 0 {
        return;
    }
    drop(filtered);
    state.log_trace("info", "tui::ops::profiles", "Profile moved up");
    state.endpoints_gen = state.endpoints_gen.wrapping_add(1);
    state.filter_cache_valid.set(false);
}

pub fn move_profile_down(state: &mut AppState) {
    let Some(id) = selected_profile_id(state) else {
        return;
    };
    let filtered: Vec<&EndpointRow> = filtered_profiles(state).collect();
    let Some(idx) = filtered.iter().position(|r| r.endpoint.id.get() == id) else {
        return;
    };
    if idx >= filtered.len() - 1 {
        return;
    }
    drop(filtered);
    state.log_trace("info", "tui::ops::profiles", "Profile moved down");
    state.endpoints_gen = state.endpoints_gen.wrapping_add(1);
    state.filter_cache_valid.set(false);
}

pub async fn set_active(state: &mut AppState, id: &str) {
    let endpoint_id: i64 = id.parse().unwrap_or(0);
    if let Err(e) = state
        .db
        .set_manual_override(endpoint_id_from_raw(endpoint_id), None)
        .await
    {
        state.log_trace(
            "error",
            "tui::ops::profiles",
            &format!("Failed to clear override: {e}"),
        );
        return;
    }
    // The DB write alone never reaches the UI: `state.endpoints` is only
    // rebuilt by `reload_profiles` (subscription events). Clear the override
    // in-memory so `active_protocol()` falls back immediately without a
    // reload (which would also collapse the panel).
    if let Some(row) = state
        .endpoints
        .iter_mut()
        .find(|r| r.endpoint.id.get() == endpoint_id)
    {
        row.endpoint.manual_protocol_override = None;
    }
    state.endpoints_gen = state.endpoints_gen.wrapping_add(1);
    state.filter_cache_valid.set(false);
}

/// Pin a specific protocol as the endpoint's default (manual override).
/// Writes the override to DB and updates the in-memory row so the UI
/// switches immediately — same rationale as `set_active`: no reload.
pub async fn set_protocol_default(state: &mut AppState, endpoint_id: i64, protocol_id: i64) {
    let pid = leas_db::models::ProtocolId::new(protocol_id);
    if let Err(e) = state
        .db
        .set_manual_override(endpoint_id_from_raw(endpoint_id), Some(pid))
        .await
    {
        state.log_trace(
            "error",
            "tui::ops::profiles",
            &format!("Failed to set protocol override: {e}"),
        );
        return;
    }
    if let Some(row) = state
        .endpoints
        .iter_mut()
        .find(|r| r.endpoint.id.get() == endpoint_id)
    {
        row.endpoint.manual_protocol_override = Some(pid);
    }
    state.endpoints_gen = state.endpoints_gen.wrapping_add(1);
    state.filter_cache_valid.set(false);
}

/// Cycle purgatory view: Active → Stale → All → Active
pub const fn cycle_purgatory_view(state: &mut AppState) {
    state.purgatory_view = match state.purgatory_view {
        PurgatoryView::Active => PurgatoryView::Purgatory,
        PurgatoryView::Purgatory => PurgatoryView::All,
        PurgatoryView::All => PurgatoryView::Active,
    };
}

/// Navigate protocol sub-rows when on an expanded endpoint.
/// Returns true if sub-row navigation was handled (caller should stop).
pub fn nav_protocol_down(state: &mut AppState) -> bool {
    // Extract data before any mutable access.
    let expanded_count = filtered_profiles(state)
        .nth(state.selected_index)
        .and_then(|r| {
            if r.expanded {
                Some(r.links.len())
            } else {
                None
            }
        });
    let Some(proto_count) = expanded_count else {
        // Not on an expandable endpoint: fall through to endpoint nav and
        // drop any stale sub-row selection.
        state.selected_sub = None;
        return false;
    };
    if proto_count <= 1 {
        state.selected_sub = None;
        return false;
    }
    match state.selected_sub {
        None => {
            // Full row of an expanded endpoint (reached via up-overflow):
            // re-enter the sub-table on its first row.
            state.selected_sub = Some(0);
            true
        }
        Some(n) if n + 1 < proto_count => {
            state.selected_sub = Some(n + 1);
            true
        }
        Some(_) => {
            // Last sub-row: down overflows to the next profile (full row).
            state.selected_sub = None;
            false
        }
    }
}

/// Navigate protocol sub-rows when on an expanded endpoint.
/// Returns true if sub-row navigation was handled (caller should stop).
pub fn nav_protocol_up(state: &mut AppState) -> bool {
    // Sub-rows live inside the expanded endpoint's panel — navigation never
    // crosses endpoint boundaries. Up at the first sub-row returns to the
    // endpoint row; Up on the endpoint row falls through to endpoint nav.
    let current_expanded = filtered_profiles(state)
        .nth(state.selected_index)
        .is_some_and(|r| r.expanded && r.links.len() > 1);
    if !current_expanded {
        // Fall through to endpoint nav; drop any stale sub-row selection.
        state.selected_sub = None;
        return false;
    }
    match state.selected_sub {
        Some(n) if n > 0 => {
            state.selected_sub = Some(n - 1);
            true
        }
        Some(0) => {
            // Up at the first sub-row returns to the endpoint row.
            state.selected_sub = None;
            true
        }
        None | Some(_) => false,
    }
}

/// Check whether the current selection is on a protocol sub-row.
pub const fn is_on_sub_row(state: &AppState) -> bool {
    state.selected_sub.is_some()
}

/// Get the protocol ID for the currently selected sub-row, if any.
pub fn selected_sub_protocol_id(state: &AppState) -> Option<i64> {
    let n = state.selected_sub?;
    let row = filtered_profiles(state).nth(state.selected_index)?;
    row.links.get(n).map(|l| l.protocol_id.get())
}

#[cfg(test)]
pub(crate) mod test_support {

    use crate::AppState;
    use leas_config::AppConfig;
    use leas_db::models::{
        Endpoint, EndpointId, EndpointRow, HostType, ProfileStats, ProtocolId, TrafficStats,
    };
    use std::sync::Arc;
    use toasty::Deferred;

    /// Epoch seconds — the storage unit of every timestamp column.
    pub fn ts(secs: i64) -> i64 {
        secs
    }

    /// Minimal typed `EndpointRow` with `n` links (protocol ids
    /// `id*100 .. id*100+n`).
    pub fn fake_row(id: i64, host: &str, n_protos: usize) -> EndpointRow {
        let host_type = match host.parse::<std::net::IpAddr>() {
            Ok(std::net::IpAddr::V4(_)) => HostType::Ipv4,
            Ok(std::net::IpAddr::V6(_)) => HostType::Ipv6,
            Err(_) => HostType::Dns,
        };
        let (domain, sub_domain) = Endpoint::derive_domain(host, host_type);
        // db-rewamp D10: an endpoint's addresses live in `endpoint_ip`, so a
        // named fixture host is a RESOLVED DNS endpoint (a synthetic address)
        // and an IP-literal fixture carries its own literal — the exact shape
        // the import writes. Without either, the fixture would be a row whose
        // dial target and address columns are empty.
        let resolved_ips = host
            .parse::<std::net::IpAddr>()
            .map_or_else(|_| vec!["10.0.0.1".parse().expect("addr")], |ip| vec![ip]);
        let endpoint = Endpoint {
            id: EndpointId::new(id),
            domain,
            sub_domain,
            port: 443,
            ports: Vec::new(),
            last_source: None,
            manual_protocol_override: None,
            resolved_at: None,
            created_at: ts(0),
            links: Deferred::default(),
            group_links: Deferred::default(),
        };
        let links: Vec<ProfileStats> = (0..n_protos)
            .map(|i| ProfileStats {
                protocol_id: ProtocolId::new(id * 100 + i as i64),
                endpoint_id: EndpointId::new(id),
                last_used_at: None,
                last_seen_at: ts(0),
                latency: None,
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
                created_at: ts(0),
                updated_at: ts(0),
                version: 1,
                protocol: Deferred::default(),
                endpoint: Deferred::default(),
            })
            .collect();
        let protocols = links
            .iter()
            .map(|l| {
                (
                    l.protocol_id,
                    super::leas_db_helper::vless_protocol(l.protocol_id.get()),
                )
            })
            .collect();
        EndpointRow {
            endpoint,
            links,
            protocols,
            resolved_ips,
            selected_protocol: 0,
            expanded: false,
        }
    }

    pub async fn test_state(rows: Vec<EndpointRow>) -> AppState {
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(
            leas_db::Database::open(dir.path().join("t.db"))
                .await
                .unwrap(),
        );
        let mut state = AppState::new(db, AppConfig::default()).await;
        state.endpoints = rows;
        state.filter_cache_valid.set(false);
        state.selected_index = 0;
        state.selected_sub = None;
        state
    }
}

/// A vless `Protocol` row for tests (config loaded).
#[cfg(test)]
pub(crate) mod leas_db_helper {
    pub fn vless_protocol(id: i64) -> leas_db::models::Protocol {
        use super::test_support::ts;
        use leas_db::models::{Protocol, ProtocolId, Security, Transport};
        use leas_proto::proto_spec::ProtocolKind;
        use leas_proto::proto_spec::common::TransportConfig;
        use leas_proto::proto_spec::{
            ProtocolConfig, SecurityConfig, SecurityType, TransportType, VlessConfig,
        };
        use toasty::{Deferred, Json};
        Protocol {
            id: ProtocolId::new(id),
            sig: id,
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
            config: Deferred::from(Json(ProtocolConfig::Vless(VlessConfig {
                uuid: format!("00000000-0000-0000-0000-{id:012}"),
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
            created_at: ts(0),
            links: Deferred::default(),
        }
    }
}

#[cfg(test)]
mod uid_fixed_point_tests {
    use super::test_support::test_state;
    use leas_db::models::{Protocol, ProtocolId, Security, Transport};
    use leas_proto::proto_spec::{
        EndpointEssentials, ProtocolConfig, ProtocolKind, SecurityType, TransportType,
    };
    use toasty::{Deferred, Json};

    /// Row 20 at the level it actually claims: `uid(parse(export(row))) ==
    /// uid(row)` **for a stored row**. The proto-crate test proves re-parse
    /// equivalence, which cannot fail if the DATABASE hands back a different uid
    /// than the config computes — and the database is the thing rows are keyed
    /// by. So this persists a plugin row, reads the uid back OUT of the table,
    /// and requires the export→re-import cycle to land on that same number.
    #[tokio::test]
    async fn a_stored_plugin_row_keeps_its_db_uid_through_export() {
        for (label, opts) in [
            ("host-stating, tls", "mode=websocket;host=cdn.example;tls"),
            ("host-less", "mode=websocket;tls"),
            ("mux on", "mode=websocket;host=cdn.example;mux=1"),
        ] {
            // The stored config comes from the PARSE below, not from a
            // hand-built twin: the point is the uid the importer would compute,
            // so a fixture assembled here would test the fixture.
            let parsed = ProtocolConfig::try_parse_proto(&leas_proto::urlx::RawUrlX::from(
                format!(
                    "ss://YWVzLTI1Ni1nY206cHc@1.2.3.4:8388?plugin={}",
                    opts.replace(';', "%3B")
                )
                .as_str(),
            ))
            .expect("the fixture URL parses");
            let expected_uid = parsed.identity_once().2;
            // Use the parsed config (not the hand-built one) so the number is the
            // one the importer would store.
            let stored_config = parsed.protocol.config.clone();

            let state = test_state(Vec::new()).await;
            let protocol = Protocol {
                id: ProtocolId::new(expected_uid),
                sig: parsed.identity_once().0,
                proto_kind: ProtocolKind::Shadowsocks,
                transport: Transport {
                    r#type: TransportType::Tcp,
                },
                security: Security {
                    r#type: SecurityType::None,
                    sni: None,
                    fp: None,
                    insecure: None,
                },
                config: Deferred::from(Json(stored_config.clone())),
                created_at: 0,
                links: Deferred::default(),
            };
            state.db.upsert_protocol(&protocol).await.expect("persist");

            // Read the row back OUT of the table, through the loader the app
            // itself uses (the plain filter does not hydrate the deferred
            // config, and reading it that way would test nothing).
            let stored =
                crate::state::load_protocol_with_config(&state.db, ProtocolId::new(expected_uid))
                    .await
                    .expect("read")
                    .expect("the row is there");
            assert_eq!(
                stored.id.get(),
                expected_uid,
                "{label}: the table kept the uid"
            );

            // …and require the export→re-import cycle to land on that number.
            let ProtocolConfig::Ss(ss) = stored.config.get().0.clone() else {
                panic!("expected ss");
            };
            let ss = &ss;
            let exported = ss
                .reconstruct_proto(&EndpointEssentials::new("1.2.3.4", 8388))
                .expect("export");
            let round = ProtocolConfig::try_parse_proto(&leas_proto::urlx::RawUrlX::from(
                exported.as_str(),
            ))
            .expect("re-import");
            assert_eq!(
                round.identity_once().2,
                stored.id.get(),
                "{label}: the exported row re-imports as the SAME stored row ({exported})"
            );
        }
    }
}

#[cfg(test)]
mod nav_tests {
    use super::test_support::{fake_row, test_state};
    use super::*;

    #[tokio::test]
    async fn expand_lands_on_first_sub_row() {
        let mut state = test_state(vec![fake_row(1, "a.com", 3)]).await;
        toggle_expand(&mut state);
        assert!(state.endpoints[0].expanded);
        assert_eq!(state.selected_sub, Some(0));
    }

    #[tokio::test]
    async fn pin_protocol_switches_active_in_memory() {
        let mut state = test_state(vec![fake_row(1, "a.com", 3)]).await;
        state.selected_sub = Some(1);
        let pid = selected_sub_protocol_id(&state).unwrap();
        assert_eq!(pid, 101); // fake_row protocol ids: 100, 101, 102
        assert_ne!(
            state.endpoints[0]
                .active_protocol()
                .unwrap()
                .0
                .protocol_id
                .get(),
            pid,
            "default active must be the first (unsorted) protocol before pinning"
        );

        set_protocol_default(&mut state, 1, pid).await;

        assert_eq!(
            state.endpoints[0].endpoint.manual_protocol_override,
            Some(leas_db::models::ProtocolId::new(pid))
        );
        assert_eq!(
            state.endpoints[0]
                .active_protocol()
                .unwrap()
                .0
                .protocol_id
                .get(),
            pid,
            "active protocol must switch to the pinned variant immediately"
        );
    }

    #[tokio::test]
    async fn set_active_clears_pin_and_falls_back() {
        let mut state = test_state(vec![fake_row(1, "a.com", 3)]).await;
        set_protocol_default(&mut state, 1, 101).await;
        assert_eq!(
            state.endpoints[0]
                .active_protocol()
                .unwrap()
                .0
                .protocol_id
                .get(),
            101,
            "pinned variant is active before clearing"
        );

        set_active(&mut state, "1").await;

        assert_eq!(state.endpoints[0].endpoint.manual_protocol_override, None);
        assert_eq!(
            state.endpoints[0]
                .active_protocol()
                .unwrap()
                .0
                .protocol_id
                .get(),
            100,
            "active must fall back to the first protocol after clearing"
        );
    }

    #[tokio::test]
    async fn down_walks_subs_then_overflows_to_next_profile() {
        let mut state = test_state(vec![fake_row(1, "a.com", 3), fake_row(2, "b.com", 1)]).await;
        toggle_expand(&mut state); // sub 0
        assert!(nav_protocol_down(&mut state));
        assert_eq!(state.selected_sub, Some(1));
        assert!(nav_protocol_down(&mut state));
        assert_eq!(state.selected_sub, Some(2));
        // Overflow: last sub-row down → full row, caller moves to next profile.
        assert!(!nav_protocol_down(&mut state));
        assert_eq!(state.selected_sub, None);
        assert_eq!(state.selected_index, 0);
    }

    #[tokio::test]
    async fn up_at_first_sub_returns_to_full_row() {
        let mut state = test_state(vec![fake_row(1, "a.com", 3)]).await;
        toggle_expand(&mut state);
        assert!(nav_protocol_up(&mut state));
        assert_eq!(state.selected_sub, None);
        // Up on the full row falls through to endpoint nav (caller moves up).
        assert!(!nav_protocol_up(&mut state));
        assert_eq!(state.selected_sub, None);
    }

    #[tokio::test]
    async fn down_from_full_row_reenters_sub_table() {
        let mut state = test_state(vec![fake_row(1, "a.com", 3)]).await;
        toggle_expand(&mut state);
        nav_protocol_up(&mut state); // back to full row
        assert_eq!(state.selected_sub, None);
        assert!(nav_protocol_down(&mut state));
        assert_eq!(state.selected_sub, Some(0));
    }

    #[tokio::test]
    async fn collapsed_endpoint_down_moves_directly_and_clears_stale_sub() {
        let mut state = test_state(vec![fake_row(1, "a.com", 2), fake_row(2, "b.com", 1)]).await;
        state.selected_sub = Some(1); // stale sub selection
        assert!(!nav_protocol_down(&mut state));
        assert_eq!(state.selected_sub, None);
        assert_eq!(state.selected_index, 0);
        // Up on collapsed: same, stale cleared.
        state.selected_sub = Some(0);
        assert!(!nav_protocol_up(&mut state));
        assert_eq!(state.selected_sub, None);
    }
}

#[cfg(test)]
mod edit_tests {
    use super::test_support::{fake_row, test_state};
    use super::*;
    use crate::AppState;
    use leas_config::AppConfig;
    use std::sync::Arc;

    fn matches_edit_mode(state: &AppState, endpoint_id: i64) -> bool {
        matches!(state.mode, AppMode::EditServer { protocol_id: id, .. } if id == endpoint_id)
    }

    fn assert_not_edit_mode(state: &AppState) {
        assert!(
            !matches!(state.mode, AppMode::EditServer { .. }),
            "expected no EditServer mode, got {:?}",
            state.mode
        );
    }

    #[tokio::test]
    async fn edit_resolves_against_current_view() {
        // The profile is on screen (state.endpoints) but absent from the DB —
        // a visible, manually-added profile that was never re-imported. The
        // current view must win. The edit form needs the protocol row WITH
        // config, so the state row (loaded without deferred data) cannot
        // serve it; the flow falls back to the DB and reports the profile
        // missing there. Test the guarded path: a row in state + a DB row
        // lets the form open.
        let mut state = test_state(vec![fake_row(7, "visible.example", 1)]).await;
        // Seed the DB with the same endpoint + a protocol row.
        let row = state.endpoints[0].clone();
        state.db.upsert_endpoint(&row.endpoint).await.unwrap();
        let proto = super::leas_db_helper::vless_protocol(700);
        state.db.upsert_protocol(&proto).await.unwrap();
        state.db.upsert_link(&row.links[0]).await.unwrap();
        start_edit_profile(&mut state, "7").await;
        assert!(matches_edit_mode(&state, 7));
        // The form is populated from the typed config.
        if let AppMode::EditServer { fields, .. } = &state.mode {
            assert!(
                fields
                    .iter()
                    .any(|(k, v)| k == "address" && v == "visible.example"),
                "edit form must carry the endpoint address"
            );
        } else {
            panic!("expected EditServer");
        }
    }

    /// An IP-literal endpoint's `dns_name()` is empty and its address lives in
    /// `endpoint_ip`, so the edit form must read the DIAL host (`display_host`)
    /// — a bare `dns_name()` opened the form blank and its re-submit would fail
    /// validation for ~75% of a real feed. The DNS case above is the control.
    #[tokio::test]
    async fn edit_form_shows_an_ip_literal_address() {
        let mut state = test_state(vec![fake_row(7, "203.0.113.7", 1)]).await;
        let row = state.endpoints[0].clone();
        state.db.upsert_endpoint(&row.endpoint).await.unwrap();
        let proto = super::leas_db_helper::vless_protocol(700);
        state.db.upsert_protocol(&proto).await.unwrap();
        state.db.upsert_link(&row.links[0]).await.unwrap();
        start_edit_profile(&mut state, "7").await;
        assert!(matches_edit_mode(&state, 7));
        if let AppMode::EditServer { fields, .. } = &state.mode {
            assert!(
                fields
                    .iter()
                    .any(|(k, v)| k == "address" && v == "203.0.113.7"),
                "the edit form must carry an IP-literal endpoint's address, got {fields:?}"
            );
        } else {
            panic!("expected EditServer");
        }
    }

    #[tokio::test]
    async fn edit_falls_back_to_never_seen_profile() {
        // Profile not loaded in the current view, but present in the DB with
        // last_seen_at = 0 ("never seen"). get_active_endpoints compares an
        // ABSOLUTE epoch threshold, so a fixed 86400 lookup would reject this
        // row even though it is visible in the All view; the fallback uses
        // scope 0 (everything), not 86400.
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(
            leas_db::Database::open(dir.path().join("t.db"))
                .await
                .unwrap(),
        );
        let group_id = db.get_all_groups().await.unwrap()[0].id.clone();
        let endpoint = super::test_support::fake_row(42, "never-seen.example", 1).endpoint;
        let protocol = super::leas_db_helper::vless_protocol(4200);
        let link = {
            use leas_db::models::{ProfileStats, TrafficStats};
            ProfileStats {
                protocol_id: protocol.id,
                endpoint_id: endpoint.id,
                last_used_at: None,
                last_seen_at: super::test_support::ts(0),
                latency: None,
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
                created_at: super::test_support::ts(0),
                updated_at: super::test_support::ts(0),
                version: 1,
                protocol: toasty::Deferred::default(),
                endpoint: toasty::Deferred::default(),
            }
        };
        db.upsert_endpoint(&endpoint).await.unwrap();
        db.upsert_protocol(&protocol).await.unwrap();
        db.upsert_link(&link).await.unwrap();
        db.upsert_endpoint_group_link(&leas_db::models::EndpointGroup {
            endpoint_id: endpoint.id,
            group_id,
            last_seen_at: super::test_support::ts(0),
            sort_order: None,
            endpoint: toasty::Deferred::default(),
            group: toasty::Deferred::default(),
        })
        .await
        .unwrap();
        let mut state = AppState::new(db, AppConfig::default()).await;
        state.endpoints = Vec::new(); // profile not loaded in the current view
        start_edit_profile(&mut state, "42").await;
        assert!(matches_edit_mode(&state, 42));
    }

    #[tokio::test]
    async fn edit_rejects_unknown_profile() {
        let mut state = test_state(vec![fake_row(1, "a.com", 1)]).await;
        start_edit_profile(&mut state, "999").await;
        assert_not_edit_mode(&state);
    }
}

#[cfg(test)]
mod clamp_tests {
    use super::test_support::{fake_row, test_state};
    use super::*;
    use leas_config::AppConfig;
    use std::sync::Arc;

    #[test]
    fn clamp_index_stays_in_bounds() {
        assert_eq!(clamp_index(5, 3), 2);
        assert_eq!(clamp_index(2, 3), 2);
        assert_eq!(clamp_index(0, 0), 0);
    }

    #[tokio::test]
    async fn clamp_selection_fixes_stale_index() {
        let mut state = test_state(vec![fake_row(1, "a.com", 1), fake_row(2, "b.com", 1)]).await;
        state.selected_index = 5; // stale: beyond the filtered list
        clamp_selection(&mut state);
        assert_eq!(state.selected_index, 1); // len - 1
        assert_eq!(state.selected_profile_id(), Some(2));
    }

    #[tokio::test]
    async fn clamp_selection_resets_empty_list() {
        let mut state = test_state(vec![]).await;
        state.selected_index = 3;
        state.selected_sub = Some(0);
        clamp_selection(&mut state);
        assert_eq!(state.selected_index, 0);
        assert_eq!(state.selected_sub, None);
    }

    #[tokio::test]
    async fn reload_profiles_clamps_stale_selection() {
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(
            leas_db::Database::open(dir.path().join("t.db"))
                .await
                .unwrap(),
        );
        let group_id = db.get_all_groups().await.unwrap()[0].id.clone();
        let row = super::test_support::fake_row(9, "clamp.example", 1);
        let endpoint = row.endpoint.clone();
        let protocol = super::leas_db_helper::vless_protocol(900);
        let mut link = row.links[0].clone();
        link.last_seen_at = super::test_support::ts(0);
        db.upsert_endpoint(&endpoint).await.unwrap();
        db.upsert_protocol(&protocol).await.unwrap();
        db.upsert_link(&link).await.unwrap();
        db.upsert_endpoint_group_link(&leas_db::models::EndpointGroup {
            endpoint_id: endpoint.id,
            group_id,
            last_seen_at: super::test_support::ts(0),
            sort_order: None,
            endpoint: toasty::Deferred::default(),
            group: toasty::Deferred::default(),
        })
        .await
        .unwrap();
        let mut state = AppState::new(db, AppConfig::default()).await;
        state.purgatory_view = PurgatoryView::All; // includes never-seen rows
        state.selected_index = 5; // stale: list reloads to a single row
        reload_profiles(&mut state).await;
        assert_eq!(state.selected_index, 0);
        assert_eq!(state.selected_profile_id(), Some(9));
    }
}

#[cfg(test)]
mod page_nav_tests {
    use std::sync::Arc;

    use super::test_support::{fake_row, test_state};
    use super::*;
    use crate::ops::profiles::ttl_tests::persist_rows;

    /// One more row than a page, so both boundary directions are real.
    async fn state_with_two_pages() -> AppState {
        let db = Arc::new(leas_db::Database::in_memory().await.unwrap());
        let rows: Vec<EndpointRow> = (1..=(PROFILES_PAGE_SIZE as i64 + 2))
            .map(|i| fake_row(i, &format!("h{i:05}.example"), 1))
            .collect();
        persist_rows(&db, &rows).await;
        let mut state = test_state(Vec::new()).await;
        state.db = db;
        state.purgatory_view = PurgatoryView::All;
        reload_profiles(&mut state).await;
        state
    }

    #[tokio::test]
    async fn down_past_the_last_row_loads_the_next_page() {
        let mut state = state_with_two_pages().await;
        assert_eq!(filtered_len(&state), PROFILES_PAGE_SIZE);
        assert_eq!(state.page_total, PROFILES_PAGE_SIZE as u64 + 2);

        state.selected_index = PROFILES_PAGE_SIZE - 1;
        let last_of_page = state.selected_profile_id().expect("selection");
        move_selection(&mut state, 1).await;

        assert_eq!(state.page_offset, PROFILES_PAGE_SIZE, "next page");
        assert_eq!(state.selected_index, 0, "lands on its first row");
        assert_ne!(state.selected_profile_id(), Some(last_of_page));
        assert_eq!(state.profiles_total(), PROFILES_PAGE_SIZE as u64 + 2);
    }

    #[tokio::test]
    async fn up_before_the_first_row_loads_the_previous_page() {
        let mut state = state_with_two_pages().await;
        state.page_offset = PROFILES_PAGE_SIZE;
        reload_profiles(&mut state).await;
        assert_eq!(state.selected_index, 0);

        move_selection(&mut state, -1).await;
        assert_eq!(state.page_offset, 0, "previous page");
        assert_eq!(state.selected_index, PROFILES_PAGE_SIZE - 1, "its last row");

        // One more Up is an ordinary row move inside the page...
        move_selection(&mut state, -1).await;
        assert_eq!(state.page_offset, 0);
        assert_eq!(state.selected_index, PROFILES_PAGE_SIZE - 2);

        // ...and only at the feed's first row does it clamp.
        state.selected_index = 0;
        move_selection(&mut state, -1).await;
        assert_eq!(state.page_offset, 0);
        assert_eq!(state.selected_index, 0);
    }

    #[tokio::test]
    async fn home_and_end_reach_the_feeds_edges() {
        let mut state = state_with_two_pages().await;

        goto_last(&mut state).await;
        assert_eq!(state.selected_index, filtered_len(&state) - 1);
        assert_eq!(state.page_offset, PROFILES_PAGE_SIZE, "last page");
        assert_eq!(filtered_len(&state), 2, "the tail page holds the remainder");
        let last_id = state.selected_profile_id().expect("selection");

        // Down at the feed's end clamps instead of wrapping.
        move_selection(&mut state, 1).await;
        assert_eq!(state.selected_profile_id(), Some(last_id));

        goto_first(&mut state).await;
        assert_eq!(state.page_offset, 0);
        assert_eq!(state.selected_index, 0);
    }
}

#[cfg(test)]
mod view_window_tests {
    use std::sync::Arc;

    use super::test_support::{fake_row, test_state};
    use super::*;
    use crate::ops::profiles::ttl_tests::persist_rows;
    use leas_db::models::PurgeReason;

    const DAY: i64 = 86_400;

    /// Five endpoints covering both Purgatory populations (spec §5): ages 1,
    /// 10 and 40 days against the 7d TTL, a partially purged endpoint whose
    /// live link is fresh, and a purged-only endpoint whose link was confirmed
    /// TODAY. Ages are stamped relative to *now* because the request computes
    /// its bound from now.
    async fn state_with_ages() -> AppState {
        let db = Arc::new(leas_db::Database::in_memory().await.unwrap());
        let now = now_ts();
        let aged = |id: i64, days: i64| {
            let mut row = fake_row(id, &format!("h{id}.example"), 1);
            row.links[0].last_seen_at = leas_db::models::to_epoch(now) - days * DAY;
            row
        };
        // 4: one purged link and one live link — stays Active, minus the link.
        let mut mixed = fake_row(4, "h4.example", 2);
        for link in &mut mixed.links {
            link.last_seen_at = leas_db::models::to_epoch(now);
        }
        mixed.links[0].purge_reason = Some(PurgeReason::NotTls);
        // 5: the only link is purged, and fresh — staleness cannot move it.
        let mut purged_only = fake_row(5, "h5.example", 1);
        purged_only.links[0].last_seen_at = leas_db::models::to_epoch(now);
        purged_only.links[0].purge_reason = Some(PurgeReason::RealityFallback);

        persist_rows(
            &db,
            &[aged(1, 1), aged(2, 10), aged(3, 40), mixed, purged_only],
        )
        .await;

        let mut state = test_state(Vec::new()).await;
        state.db = db;
        state.purgatory_ttl_secs = 7 * DAY;
        state.purgatory_retention_secs = 30 * DAY;
        state
    }

    /// Endpoint ids the tab shows for `view`, through the real load path
    /// (`load_profiles_rows` → the request `page_request` derives from the
    /// state), not through hand-built thresholds.
    async fn ids_for(view: PurgatoryView) -> Vec<i64> {
        let mut state = state_with_ages().await;
        state.purgatory_view = view;
        reload_profiles(&mut state).await;
        let mut ids: Vec<i64> = state
            .endpoints
            .iter()
            .map(|r| r.endpoint.id.get())
            .collect();
        ids.sort_unstable();
        ids
    }

    #[tokio::test]
    async fn active_shows_the_recently_seen_window_without_purged_links() {
        // 5 is fresh but purged-only: not an effective profile, so not Active.
        assert_eq!(ids_for(PurgatoryView::Active).await, vec![1, 4]);
        let mut state = state_with_ages().await;
        state.purgatory_view = PurgatoryView::Active;
        reload_profiles(&mut state).await;
        let mixed = state
            .endpoints
            .iter()
            .find(|r| r.endpoint.id.get() == 4)
            .expect("the partially purged endpoint stays");
        assert_eq!(
            mixed.links.len(),
            1,
            "and its purged sibling is not in the Active panel"
        );
        assert!(mixed.links[0].purge_reason.is_none());
    }

    #[tokio::test]
    async fn purgatory_shows_both_populations() {
        // Aged past the TTL (2, 3) and purged-only (5) — one view, one range.
        assert_eq!(ids_for(PurgatoryView::Purgatory).await, vec![2, 3, 5]);
        // The purged link itself IS loaded here — that is what makes the row
        // testable back to life, and what the Active view hides.
        let mut state = state_with_ages().await;
        state.purgatory_view = PurgatoryView::Purgatory;
        reload_profiles(&mut state).await;
        let only = state
            .endpoints
            .iter()
            .find(|r| r.endpoint.id.get() == 5)
            .expect("the purged-only endpoint is listed");
        assert_eq!(only.links.len(), 1);
        assert_eq!(
            only.links[0].purge_reason,
            Some(PurgeReason::RealityFallback),
            "with its verdict available for the Test column"
        );
    }

    #[tokio::test]
    async fn all_shows_every_age_and_every_link() {
        assert_eq!(ids_for(PurgatoryView::All).await, vec![1, 2, 3, 4, 5]);
        let mut state = state_with_ages().await;
        state.purgatory_view = PurgatoryView::All;
        reload_profiles(&mut state).await;
        let mixed = state
            .endpoints
            .iter()
            .find(|r| r.endpoint.id.get() == 4)
            .expect("mixed endpoint");
        assert_eq!(mixed.links.len(), 2, "All keeps every link");
    }
}

#[cfg(test)]
#[cfg(test)]
mod ttl_tests {
    use super::test_support::fake_row;
    use super::*;
    use leas_config::AppConfig;
    use leas_db::models::{EndpointId, ErrorInfo, ProfileErr, ProfileStats, ProtocolId};
    use std::sync::Arc;

    /// Stamp `error` on the row's link so it persists as a failure marker.
    fn set_error(row: &mut EndpointRow, proto_id: i64, kind: ProfileErr) {
        let link = row
            .links
            .iter_mut()
            .find(|l| l.protocol_id.get() == proto_id)
            .expect("link exists");
        link.error = Some(ErrorInfo {
            kind,
            text: "boom".to_string(),
        });
    }

    /// Persist the rows (endpoint + links + protocols) via the typed writes.
    pub(super) async fn persist_rows(db: &Database, rows: &[EndpointRow]) {
        for row in rows {
            db.upsert_endpoint(&row.endpoint).await.unwrap();
            for link in &row.links {
                db.upsert_link(link).await.unwrap();
                if let Some(proto) = row.protocols.get(&link.protocol_id) {
                    db.upsert_protocol(proto).await.unwrap();
                }
            }
        }
    }

    /// Backdate a link's `updated_at` (the error-TTL anchor) to `secs`.
    async fn backdate(db: &Database, proto_id: i64, endpoint_id: i64, secs: i64) {
        let mut conn = db.connection().await.unwrap();
        ProfileStats::filter_by_protocol_id_and_endpoint_id(
            ProtocolId::new(proto_id),
            EndpointId::new(endpoint_id),
        )
        .update()
        .updated_at(secs)
        .exec(&mut conn)
        .await
        .unwrap();
    }

    /// The persisted error kind of a link, if any.
    async fn link_latency_delay(db: &Database, proto_id: i64, endpoint_id: i64) -> Option<i32> {
        let mut conn = db.connection().await.unwrap();
        ProfileStats::filter_by_protocol_id_and_endpoint_id(
            ProtocolId::new(proto_id),
            EndpointId::new(endpoint_id),
        )
        .first()
        .exec(&mut conn)
        .await
        .unwrap()
        .expect("link persisted")
        .latency
        .map(|l| match l {
            leas_db::models::Latency::Real { delay, .. }
            | leas_db::models::Latency::Fast { delay } => delay,
        })
    }

    async fn link_error_kind(db: &Database, proto_id: i64, endpoint_id: i64) -> Option<ProfileErr> {
        let mut conn = db.connection().await.unwrap();
        ProfileStats::filter_by_protocol_id_and_endpoint_id(
            ProtocolId::new(proto_id),
            EndpointId::new(endpoint_id),
        )
        .first()
        .exec(&mut conn)
        .await
        .unwrap()
        .expect("link persisted")
        .error
        .map(|e| e.kind)
    }

    /// The reload flushes staged writes BEFORE the sweep, so nothing is
    /// written after the sweep can undo it:
    /// - the staged row's value is persisted (proving the flush ran first),
    /// - an expired marker on a row with no pending write is swept,
    /// - nothing is left staged, so a later flush cannot resurrect it.
    #[tokio::test]
    async fn reload_flushes_before_the_sweep_and_never_resurrects_a_marker() {
        use leas_db::LinkGroups;
        let mut row = fake_row(1, "10.0.0.1", 2);
        set_error(&mut row, 100, ProfileErr::Fast);
        set_error(&mut row, 101, ProfileErr::Real);
        let db = Arc::new(leas_db::Database::in_memory().await.unwrap());
        persist_rows(&db, std::slice::from_ref(&row)).await;
        let now = jiff::Timestamp::now().as_second();
        backdate(&db, 100, 1, now - 48 * 3600).await;
        backdate(&db, 101, 1, now - 48 * 3600).await;

        let mut state = AppState::new(db.clone(), AppConfig::default()).await;
        state.purgatory_view = PurgatoryView::All;
        state.config.speed_test.error_ttl_hours = Some(24);

        // p100 was re-tested successfully (staged, not yet written); p101 keeps
        // its expired marker with nothing pending.
        let mut retested = row.links[0].clone();
        retested.error = None;
        retested.latency = Some(leas_db::models::Latency::Fast { delay: 7 });
        state.link_stage.stage(&retested, LinkGroups::RESULT);

        reload_profiles(&mut state).await;

        assert_eq!(
            link_latency_delay(&db, 100, 1).await,
            Some(7),
            "the staged re-test was written before the sweep"
        );
        assert_eq!(
            link_error_kind(&db, 101, 1).await,
            None,
            "the expired marker of a row with nothing pending is swept"
        );
        assert_eq!(state.link_stage.staged_len(), 0, "nothing left to write");

        // A later flush cannot bring the swept marker back.
        state.link_stage.flush().await.expect("flush");
        assert_eq!(
            link_error_kind(&db, 101, 1).await,
            None,
            "no resurrection after a later flush"
        );
    }

    #[tokio::test]
    async fn reload_profiles_sweeps_expired_errors_and_keeps_fresh() {
        // Endpoint 1 with two failing links: p100 (error 48h old), p101
        // (error 10 min old).
        let mut row = fake_row(1, "10.0.0.1", 2);
        set_error(&mut row, 100, ProfileErr::Fast);
        set_error(&mut row, 101, ProfileErr::Real);
        let db = Arc::new(leas_db::Database::in_memory().await.unwrap());
        persist_rows(&db, std::slice::from_ref(&row)).await;
        let now = jiff::Timestamp::now().as_second();
        backdate(&db, 100, 1, now - 48 * 3600).await;
        backdate(&db, 101, 1, now - 600).await;

        let mut state = AppState::new(db.clone(), AppConfig::default()).await;
        state.purgatory_view = PurgatoryView::All;

        // Default config (ttl None): reload must NOT clear anything.
        reload_profiles(&mut state).await;
        assert_eq!(
            link_error_kind(&db, 100, 1).await,
            Some(ProfileErr::Fast),
            "ttl None: stale error untouched"
        );
        assert_eq!(
            link_error_kind(&db, 101, 1).await,
            Some(ProfileErr::Real),
            "ttl None: fresh error untouched"
        );

        // Configured ttl (24h): the 48h-old error is swept, the fresh one
        // survives, and the reloaded in-memory rows match the DB.
        state.config.speed_test.error_ttl_hours = Some(24);
        reload_profiles(&mut state).await;
        assert_eq!(link_error_kind(&db, 100, 1).await, None, "stale cleared");
        assert_eq!(
            link_error_kind(&db, 101, 1).await,
            Some(ProfileErr::Real),
            "fresh kept"
        );
        let row1 = state
            .endpoints
            .iter()
            .find(|r| r.endpoint.id.get() == 1)
            .expect("endpoint reloaded");
        let p100 = row1
            .links
            .iter()
            .find(|l| l.protocol_id.get() == 100)
            .expect("p100 link");
        assert!(p100.error.is_none(), "in-memory row reflects the sweep");
        let p101 = row1
            .links
            .iter()
            .find(|l| l.protocol_id.get() == 101)
            .expect("p101 link");
        assert!(p101.error.is_some(), "fresh marker still renders");
    }

    #[tokio::test]
    async fn clear_expired_errors_none_and_nonpositive_ttl_are_noops() {
        let mut row = fake_row(1, "10.0.0.1", 1);
        set_error(&mut row, 100, ProfileErr::Fast);
        let db = Arc::new(leas_db::Database::in_memory().await.unwrap());
        persist_rows(&db, std::slice::from_ref(&row)).await;
        let now = jiff::Timestamp::now().as_second();
        backdate(&db, 100, 1, now - 48 * 3600).await;

        // None (default) and non-positive values both mean "never clear".
        clear_expired_errors(&db, None).await;
        assert_eq!(
            link_error_kind(&db, 100, 1).await,
            Some(ProfileErr::Fast),
            "ttl None: no-op"
        );
        clear_expired_errors(&db, Some(0)).await;
        assert_eq!(
            link_error_kind(&db, 100, 1).await,
            Some(ProfileErr::Fast),
            "ttl 0: no-op"
        );

        // A positive ttl clears the stale marker.
        clear_expired_errors(&db, Some(24)).await;
        assert_eq!(link_error_kind(&db, 100, 1).await, None);
    }
}
