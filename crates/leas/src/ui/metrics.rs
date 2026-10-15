//! Pane-2 Metrics tab (spec §6/D4).
//!
//! One frameless scrollable view merging the former Statistics and Native
//! Activity screens: session traffic, native-core connection counters and
//! ring, and core system stats.
//!
//! The pane frame supplies the border; this module draws flat labelled rows
//! (no nested boxes). Scrolling reuses the native-activity window convention
//! (`native_activity::handle_key`): the module owns the scroll offset, and the
//! visible/total counter is exposed for the pane title.

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;

use crate::AppState;
use crate::ui::theme::ThemeStyles;
use leas_core::{API_ENDPOINT, CoreType, format_bytes, format_uptime};

pub use crate::ui::native_activity::{handle_key, reset_scroll};

/// Render the merged metrics view into `area` (pane-2 inner rect).
pub fn render(frame: &mut Frame, area: Rect, state: &AppState) {
    let theme = state.theme();
    let mut lines: Vec<Line> = Vec::new();

    // ── Session ───────────────────────────────────────────────────────────
    lines.push(section("session", theme));
    // The CONNECTED profile's session — the link the user is actually
    // running. `connected_protocol_id` holds the connected ENDPOINT id; when
    // nothing is connected (transient mid-connect), fall back to the filtered
    // selection: `selected_index` indexes the FILTERED list, so resolve
    // through `filtered_profiles()` — a search filter active on pane 1 would
    // otherwise show a different profile's stats here (ported from the former
    // Statistics screen, same law, same tests).
    let profile = state
        .connected_protocol_id
        .and_then(|eid| state.endpoints.iter().find(|r| r.endpoint.id.get() == eid))
        .or_else(|| state.filtered_profiles().nth(state.selected_index));
    match profile {
        Some(profile) => {
            let core = state.connected_core.map_or("", |c| c.as_str());
            lines.push(Line::from(format!(
                "  {}:{} [{}]",
                profile.endpoint.display_host(&profile.resolved_ips),
                profile.endpoint.port,
                core
            )));
            if let Some(link) = profile.active_link() {
                lines.push(Line::from(format!(
                    "  today ↑{} ↓{} · total ↑{} ↓{}",
                    format_bytes(link.traffic.today_up),
                    format_bytes(link.traffic.today_down),
                    format_bytes(link.traffic.total_up),
                    format_bytes(link.traffic.total_down)
                )));
            } else {
                lines.push(hint("  no traffic data yet"));
            }
        }
        None => lines.push(hint(
            "  not connected — select a profile and press Ctrl+Enter",
        )),
    }

    // ── Native core ───────────────────────────────────────────────────────
    lines.push(section("native", theme));
    if state.connected_core == Some(CoreType::Native) {
        let log = &state.native_activity;
        lines.push(Line::from(format!(
            "  {} open · {} closed · {} failed",
            log.open_count,
            log.entries.len(),
            log.fail_count
        )));
        // Window-then-format: only the visible slice of the 2000-row ring
        // becomes `Line`s (same law as the old tab).
        let ring_budget = area.height.saturating_sub(lines.len() as u16 + 6) as usize;
        let total = log.entries.len();
        let start = total.saturating_sub(ring_budget + native_offset(total));
        for entry in log.entries.range(start..).take(ring_budget) {
            lines.push(crate::ui::native_activity::entry_line(entry, theme));
        }
        if total > ring_budget {
            lines.push(hint(&format!(
                "  ↑↓ scroll — rows {}-{} of {}",
                start + 1,
                total.min(start + ring_budget),
                total
            )));
        }
    } else {
        lines.push(hint("  no native session"));
    }

    // ── Core system ───────────────────────────────────────────────────────
    lines.push(section("core", theme));
    if let Some(sys) = &state.system_stats {
        lines.push(Line::from(format!(
            "  mem {} / {} · routines {} · uptime {}",
            format_bytes(sys.alloc as i64),
            format_bytes(sys.sys as i64),
            sys.num_goroutine,
            format_uptime(sys.uptime)
        )));
    } else {
        lines.push(hint("  no system data yet"));
    }
    let api = match state.connected_core {
        Some(CoreType::Native) => "  api in-process (event feed)".to_string(),
        _ => format!("  api {API_ENDPOINT}"),
    };
    lines.push(Line::from(api));

    frame.render_widget(Paragraph::new(lines), area);
}

fn section(name: &str, theme: &opaline::Theme) -> Line<'static> {
    Line::from(Span::styled(
        name.to_string(),
        ThemeStyles::container_title(theme),
    ))
}

fn hint(text: &str) -> Line<'static> {
    Line::from(text.to_string())
}

fn native_offset(total: usize) -> usize {
    crate::ui::native_activity::scroll_offset(total)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::CoreEvent;
    use leas_config::AppConfig;
    use leas_db::models::EndpointRow;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;
    use std::sync::Arc;

    fn endpoint_row(id: i64, host: &str, port: i32) -> EndpointRow {
        let mut row = crate::ops::profiles::test_support::fake_row(id, host, 1);
        row.endpoint.port = port as u16;
        row
    }

    async fn filtered_state(search: &str) -> AppState {
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(
            leas_db::Database::open(dir.path().join("t.db"))
                .await
                .unwrap(),
        );
        for row in [
            endpoint_row(1, "alpha.example", 443),
            endpoint_row(2, "beta.example", 8443),
            endpoint_row(3, "gamma.example", 443),
        ] {
            db.upsert_endpoint(&row.endpoint).await.unwrap();
            for link in &row.links {
                db.upsert_link(link).await.unwrap();
                if let Some(proto) = row.protocols.get(&link.protocol_id) {
                    db.upsert_protocol(proto).await.unwrap();
                }
            }
        }
        let mut state = AppState::new(db, AppConfig::default()).await;
        state.search_query = search.to_string();
        state.purgatory_view = leas_db::models::PurgatoryView::All;
        state.connected_core = Some(CoreType::Xray);
        crate::ops::profiles::reload_profiles(&mut state).await;
        state
    }

    fn render_to_string(state: &AppState) -> String {
        let mut terminal = Terminal::new(TestBackend::new(120, 24)).unwrap();
        terminal
            .draw(|frame| render(frame, frame.area(), state))
            .unwrap();
        let buffer = terminal.backend().buffer();
        let mut out = String::new();
        for y in 0..buffer.area.height {
            for x in 0..buffer.area.width {
                out.push_str(buffer[(x, y)].symbol());
            }
            out.push('\n');
        }
        out
    }

    #[tokio::test]
    async fn shows_filtered_profile_not_endpoints_index() {
        // The page holds only the match, so index 0 is beta — an index-into-
        // endpoints render would show alpha (ported statistics test).
        let state = filtered_state("beta").await;
        let rendered = render_to_string(&state);
        assert!(rendered.contains("beta.example:8443"), "got: {rendered}");
        assert!(!rendered.contains("alpha.example"), "got: {rendered}");
        assert!(!rendered.contains("gamma.example"), "got: {rendered}");
    }

    #[tokio::test]
    async fn shows_connected_profiles_accumulated_traffic() {
        // Connected to endpoint 1 (alpha); the selection sits on endpoint 3
        // (gamma). Metrics must render the CONNECTED session's accumulated
        // traffic, not the browsing selection's zeros.
        let mut state = filtered_state("").await;
        let link = &mut state.endpoints[0].links[0];
        link.traffic = leas_db::models::TrafficStats {
            today_up: 1_024,
            today_down: 2_048,
            total_up: 10_000,
            total_down: 20_000,
        };
        link.updated_at = leas_db::models::now_epoch();
        state.connected_protocol_id = Some(1);
        state.selected_index = 2; // gamma selected
        let tx = state.core_event_tx.clone().unwrap();
        tx.send(CoreEvent::StatsUpdate {
            protocol_id: 100, // alpha's link protocol id (fake_row: id*100)
            today_up: 5,
            today_down: 10,
            total_up: 5,
            total_down: 10,
        })
        .await
        .unwrap();
        assert!(state.poll_core_events().await);

        let rendered = render_to_string(&state);
        assert!(
            rendered.contains("alpha.example:443"),
            "connected profile rendered, got: {rendered}"
        );
        assert!(
            !rendered.contains("gamma.example:443"),
            "selection must not win over the connected profile, got: {rendered}"
        );
        assert!(
            rendered.contains(&leas_core::format_bytes(1_024 + 5)),
            "today_up accumulated, got: {rendered}"
        );
        assert!(
            rendered.contains(&leas_core::format_bytes(2_048 + 10)),
            "today_down accumulated, got: {rendered}"
        );
        assert!(
            rendered.contains(&leas_core::format_bytes(10_000 + 5)),
            "total_up accumulated, got: {rendered}"
        );
        assert!(
            rendered.contains(&leas_core::format_bytes(20_000 + 10)),
            "total_down accumulated, got: {rendered}"
        );
    }

    #[tokio::test]
    async fn placeholder_when_filter_matches_nothing() {
        // The search matches nothing, so the page is empty even though the
        // database holds three endpoints.
        let state = filtered_state("nomatch").await;
        let rendered = render_to_string(&state);
        assert!(
            rendered.contains("not connected — select a profile"),
            "expected placeholder, got: {rendered}"
        );
        assert!(!rendered.contains("alpha.example"), "got: {rendered}");
    }
}
