use crate::AppState;
use crate::ui::theme::ThemeStyles;
use leas_core::{API_ENDPOINT, CoreType, format_bytes, format_uptime};
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui_cheese::fieldset::{Fieldset, FieldsetStyles};

pub fn render(frame: &mut Frame, area: Rect, state: &AppState) {
    let theme = state.theme();
    let connected = state.connected_core.is_some();
    if !connected {
        render_placeholder(frame, area, theme);
        return;
    }
    // The screen shows the CONNECTED profile's stats — the session the user
    // is actually running (the connected link's ProfileStats, accumulated by
    // the T21 handler). `connected_protocol_id` holds the connected ENDPOINT
    // id. When no endpoint is connected (transient mid-connect state), fall
    // back to the filtered selection: `selected_index` indexes the FILTERED
    // list, so resolve through the same `filtered_profiles()` path as the
    // profiles footer — a search filter active on the Profiles tab (it
    // persists across tab switches) would otherwise show a different
    // profile's stats here.
    let profile = state
        .connected_protocol_id
        .and_then(|eid| state.endpoints.iter().find(|r| r.endpoint.id.get() == eid))
        .or_else(|| state.filtered_profiles().nth(state.selected_index));
    let Some(profile) = profile else {
        render_placeholder(frame, area, theme);
        return;
    };
    let profile_name = format!(
        "{}:{}",
        profile.endpoint.display_host(&profile.resolved_ips),
        profile.endpoint.port
    );
    let core_type = state.connected_core.map_or("", |c| c.as_str());

    // Split area into 3 sections
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(6),
            Constraint::Length(5),
            Constraint::Min(3),
        ])
        .split(area);

    let traffic_title = format!(" Traffic — {profile_name} [{core_type}] ");
    let traffic_fieldset = Fieldset::new()
        .title(&traffic_title)
        .styles(FieldsetStyles {
            title: ThemeStyles::container_title(theme),
            rule: ThemeStyles::container_border(theme),
        });
    let traffic_inner = traffic_fieldset.inner(chunks[0]);
    frame.render_widget(traffic_fieldset, chunks[0]);

    let mut traffic_lines: Vec<Line> = Vec::new();
    if let Some(link) = profile.active_link() {
        let today_up = link.traffic.today_up;
        let today_down = link.traffic.today_down;
        let total_up = link.traffic.total_up;
        let total_down = link.traffic.total_down;

        traffic_lines.push(Line::from(vec![
            Span::raw("  Today:  "),
            Span::styled("↑", ThemeStyles::success(theme)),
            Span::raw(format!(" {}  ", format_bytes(today_up))),
            Span::styled("↓", ThemeStyles::error(theme)),
            Span::raw(format!(" {}", format_bytes(today_down))),
        ]));
        traffic_lines.push(Line::from(vec![
            Span::raw("  Total:  "),
            Span::styled("↑", ThemeStyles::success(theme)),
            Span::raw(format!(" {}  ", format_bytes(total_up))),
            Span::styled("↓", ThemeStyles::error(theme)),
            Span::raw(format!(" {}", format_bytes(total_down))),
        ]));
    } else {
        traffic_lines.push(Line::from("  No traffic data yet"));
    }
    frame.render_widget(Paragraph::new(traffic_lines), traffic_inner);

    // ── System section ─────────────────────────────────────────────
    let sys_fieldset = Fieldset::new().title(" System ").styles(FieldsetStyles {
        title: ThemeStyles::container_title(theme),
        rule: ThemeStyles::container_border(theme),
    });
    let sys_inner = sys_fieldset.inner(chunks[1]);
    frame.render_widget(sys_fieldset, chunks[1]);

    let mut sys_lines: Vec<Line> = Vec::new();
    if let Some(ref sys) = state.system_stats {
        sys_lines.push(Line::from(format!(
            "  Memory:    {} / {}",
            format_bytes(sys.alloc as i64),
            format_bytes(sys.sys as i64),
        )));
        sys_lines.push(Line::from(format!("  Routines:  {}", sys.num_goroutine)));
        sys_lines.push(Line::from(format!(
            "  Uptime:    {}",
            format_uptime(sys.uptime)
        )));
    } else {
        sys_lines.push(Line::from("  No system data yet"));
    }
    frame.render_widget(Paragraph::new(sys_lines), sys_inner);

    // ── Connection section ─────────────────────────────────────────
    let status_style = if connected {
        ThemeStyles::success(theme)
    } else {
        ThemeStyles::error(theme)
    };
    let api_line = match state.connected_core {
        Some(CoreType::Native) => "  API endpoint:  in-process (event feed)".to_string(),
        _ => format!("  API endpoint:  {API_ENDPOINT}"),
    };
    let conn_lines = vec![
        Line::from(api_line),
        Line::from(vec![
            Span::raw("  Status:       "),
            Span::styled("Connected", status_style),
        ]),
    ];
    let conn_fieldset = Fieldset::new()
        .title(" Connection ")
        .styles(FieldsetStyles {
            title: ThemeStyles::container_title(theme),
            rule: ThemeStyles::container_border(theme),
        });
    let conn_inner = conn_fieldset.inner(chunks[2]);
    frame.render_widget(conn_fieldset, chunks[2]);
    frame.render_widget(Paragraph::new(conn_lines), conn_inner);
}

fn render_placeholder(frame: &mut Frame, area: Rect, theme: &opaline::Theme) {
    let fieldset = Fieldset::new()
        .title(" Statistics ")
        .styles(FieldsetStyles {
            title: ThemeStyles::container_title(theme),
            rule: ThemeStyles::container_border(theme),
        });
    let inner = fieldset.inner(area);
    frame.render_widget(fieldset, area);
    let paragraph =
        Paragraph::new(" Not connected — select a profile and press Ctrl+Enter to connect ")
            .style(ThemeStyles::hint(theme))
            .alignment(ratatui::layout::Alignment::Center);
    frame.render_widget(paragraph, inner);
}

#[cfg(test)]
mod tests {
    use super::*;
    use leas_config::AppConfig;
    use leas_core::CoreType;
    use leas_db::models::EndpointRow;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;
    use std::sync::Arc;

    use crate::types::CoreEvent;

    /// Minimal typed `EndpointRow` with one link (statistics render calls
    /// `active_link()`); host + port drive the search filter.
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
        // The search filter is SQL now, and the tab holds one page of what the
        // query returned: seed the rows, set the search, and load the page
        // through the real path. Assigning `state.endpoints` by hand would
        // build a page the query never produced (a stale, unfiltered one).
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
        state.purgatory_view = leas_db::models::PurgatoryView::All; // rows carry ts(0)
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
    async fn render_shows_filtered_profile_not_endpoints_index() {
        // The page holds only the match, so index 0 is beta — the old code
        // rendered alpha.example:443 (the unfiltered first row).
        let state = filtered_state("beta").await;
        let rendered = render_to_string(&state);
        assert!(rendered.contains("beta.example:8443"), "got: {rendered}");
        assert!(!rendered.contains("alpha.example"), "got: {rendered}");
        assert!(!rendered.contains("gamma.example"), "got: {rendered}");
    }

    #[tokio::test]
    async fn render_shows_connected_profiles_accumulated_traffic() {
        // Connected to endpoint 1 (alpha); the selection sits on endpoint 3
        // (gamma). The statistics tab must render the CONNECTED session's
        // accumulated traffic, not the selected (browsing) profile's zeros.
        let mut state = filtered_state("").await;
        // Known persisted values on alpha's link. The row's `updated_at` is
        // today so the T21 day-reset does not zero `today_*` before the
        // session delta lands (that reset is covered by the events test).
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
        // Session delta via the T21 handler: the same path the pollers use.
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
        // Today/Total reflect the T21 accumulation (base + session delta).
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
    async fn render_placeholders_when_filter_matches_nothing() {
        // The search matches nothing, so the page is empty even though the
        // database holds three endpoints; the old code rendered alpha's stats.
        let state = filtered_state("nomatch").await;
        let rendered = render_to_string(&state);
        assert!(
            rendered.contains("Not connected — select a profile"),
            "expected placeholder, got: {rendered}"
        );
        assert!(!rendered.contains("alpha.example"), "got: {rendered}");
    }
}
