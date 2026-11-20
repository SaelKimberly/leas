//! DNS tab (pane 1): the listed resolvers, their last measurement, and the
//! test / apply / toggle actions.
//!
//! Spec `2026-11-20-dns-resolvers` D12–D13. The table is manual rather than a
//! `DataTable`: five fixed columns and no horizontal shedding are enough here,
//! and a row is one `Line` — no per-frame `Vec<Row>` rebuild.

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;

use crate::AppState;
use crate::ui::theme::ThemeStyles;

/// Rows a `PageUp`/`PageDown` moves (the sniffer's convention).
const PAGE_ROWS: usize = 10;

fn protocol_label(protocol: &str) -> &'static str {
    match protocol {
        "dnscrypt" => "DNSCrypt",
        "doh" => "DoH",
        "dot" => "DoT",
        "doq" => "DoQ",
        _ => "?",
    }
}

fn latency_label(latency: Option<i64>) -> String {
    latency.map_or_else(|| "—".to_string(), |ms| format!("{ms} ms"))
}

fn age_label(checked_at: Option<i64>) -> String {
    checked_at.map_or_else(
        || "never".to_string(),
        |at| {
            let secs = leas_db::models::now_epoch().saturating_sub(at);
            if secs < 60 {
                "just now".to_string()
            } else if secs < 3600 {
                format!("{}m ago", secs / 60)
            } else if secs < 86_400 {
                format!("{}h ago", secs / 3600)
            } else {
                format!("{}d ago", secs / 86_400)
            }
        },
    )
}

pub fn render(frame: &mut Frame, area: Rect, state: &AppState) {
    let theme = state.theme();
    if area.height == 0 {
        return;
    }
    if state.dns_resolvers.is_empty() {
        let hint = if state.dns_sources.is_empty() {
            " No DNS sources — press `A` in Sources to add one "
        } else {
            " No resolvers listed — press `u` in Sources to refresh "
        };
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(hint, ThemeStyles::hint(theme)))),
            area,
        );
        return;
    }
    let mut lines = Vec::with_capacity(area.height as usize);
    let header_style = ThemeStyles::hint(theme);
    lines.push(Line::from(Span::styled(
        format!(
            "  {:<9} {:<28} {:>8}  {:<9}  {}",
            "PROTOCOL", "ENDPOINT", "LATENCY", "STATUS", "CHECKED"
        ),
        header_style,
    )));
    let visible = area.height.saturating_sub(1) as usize;
    let selected = state
        .dns_selected
        .min(state.dns_resolvers.len().saturating_sub(1));
    // Keep the selection visible: scroll so the last row is the selected one
    // when it would fall below the viewport.
    let start = if selected >= visible {
        selected + 1 - visible
    } else {
        0
    };
    for (i, row) in state
        .dns_resolvers
        .iter()
        .enumerate()
        .skip(start)
        .take(visible)
    {
        let selected_style = if i == selected {
            ThemeStyles::table_row_selected(theme)
        } else {
            ThemeStyles::table_row_normal(theme)
        };
        let status = match row.status {
            leas_db::models::ResolverStatus::Ok => "ok",
            leas_db::models::ResolverStatus::Error => "error",
            leas_db::models::ResolverStatus::Unchecked => "untested",
        };
        let text = format!(
            "{:<9} {:<28} {:>8}  {:<9}  {}",
            protocol_label(&row.protocol),
            crate::ui::textfit::truncate(&format!("{}:{}", row.host, row.port), 28),
            latency_label(row.latency_ms),
            status,
            age_label(row.checked_at),
        );
        let in_pool = state.dns_pool_stamps.contains(&row.stamp);
        let marker_style = if in_pool {
            ThemeStyles::success(theme)
        } else {
            selected_style
        };
        lines.push(Line::from(vec![
            Span::styled(if in_pool { "● " } else { "  " }, marker_style),
            Span::styled(text, selected_style),
        ]));
    }
    frame.render_widget(Paragraph::new(lines), area);
}

pub fn handle_key(state: &mut AppState, key: &KeyEvent) {
    let max = state.dns_resolvers.len().saturating_sub(1);
    state.dns_selected = match key.code {
        KeyCode::Up => state.dns_selected.saturating_sub(1),
        KeyCode::Down => state.dns_selected.saturating_add(1).min(max),
        KeyCode::PageUp => state.dns_selected.saturating_sub(PAGE_ROWS),
        KeyCode::PageDown => state.dns_selected.saturating_add(PAGE_ROWS).min(max),
        KeyCode::Home => 0,
        KeyCode::End => max,
        _ => return,
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::KeyModifiers;
    use leas_db::models::{DnsResolver, ResolverStatus};
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    fn row(stamp: &str, host: &str, status: ResolverStatus, latency: Option<i64>) -> DnsResolver {
        DnsResolver {
            stamp: stamp.to_string(),
            protocol: "dnscrypt".to_string(),
            host: host.to_string(),
            port: 5443,
            latency_ms: latency,
            status,
            error: None,
            checked_at: None,
            enabled: true,
        }
    }

    fn screen(terminal: &Terminal<TestBackend>) -> Vec<String> {
        let buffer = terminal.backend().buffer();
        let width = usize::from(buffer.area.width);
        buffer
            .content
            .chunks(width)
            .map(|cells| cells.iter().map(ratatui::buffer::Cell::symbol).collect())
            .collect()
    }

    /// The empty state must name the action that fills the table; a blank pane
    /// is the failure this test discriminates (it was the pre-DNS-tab state).
    #[tokio::test]
    async fn the_empty_state_names_the_next_action() {
        let mut state = crate::ops::profiles::test_support::test_state(Vec::new()).await;
        // Boot seeds the built-in source and may list resolvers; the empty
        // state under test is "no source and no resolver row".
        state.dns_sources.clear();
        state.dns_resolvers.clear();
        let mut terminal = Terminal::new(TestBackend::new(80, 6)).expect("terminal");
        terminal
            .draw(|frame| render(frame, frame.area(), &state))
            .expect("draw");
        let text: String = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(ratatui::buffer::Cell::symbol)
            .collect();
        assert!(text.contains("No DNS sources"), "got: {text}");
    }

    /// A pool member carries the marker on ITS row; a non-member does not.
    #[tokio::test]
    async fn the_pool_members_are_marked() {
        let mut state = crate::ops::profiles::test_support::test_state(Vec::new()).await;
        state.dns_resolvers = vec![
            row("fast", "fast.example", ResolverStatus::Ok, Some(5)),
            row(
                "untested",
                "untested.example",
                ResolverStatus::Unchecked,
                None,
            ),
        ];
        state.dns_pool_stamps = std::iter::once("fast".to_string()).collect();
        let mut terminal = Terminal::new(TestBackend::new(90, 5)).expect("terminal");
        terminal
            .draw(|frame| render(frame, frame.area(), &state))
            .expect("draw");
        let lines = screen(&terminal);
        let marked = lines
            .iter()
            .find(|line| line.contains('●'))
            .expect("a pool marker");
        assert!(marked.contains("fast.example"), "got: {marked}");
        assert!(
            !lines
                .iter()
                .any(|line| line.contains("untested.example") && line.contains('●')),
            "an unselected resolver must not be marked"
        );
    }

    /// PageDown/PageUp move ten rows; Home/End jump to the edges.
    #[tokio::test]
    async fn paging_keys_move_the_cursor() {
        let mut state = crate::ops::profiles::test_support::test_state(Vec::new()).await;
        state.dns_resolvers = (0..25)
            .map(|i| {
                row(
                    &format!("s{i}"),
                    "h.example",
                    ResolverStatus::Unchecked,
                    None,
                )
            })
            .collect();
        let none = KeyModifiers::NONE;
        handle_key(&mut state, &KeyEvent::new(KeyCode::PageDown, none));
        assert_eq!(state.dns_selected, 10);
        handle_key(&mut state, &KeyEvent::new(KeyCode::PageDown, none));
        assert_eq!(state.dns_selected, 20);
        handle_key(&mut state, &KeyEvent::new(KeyCode::PageDown, none));
        assert_eq!(state.dns_selected, 24, "clamped to the last row");
        handle_key(&mut state, &KeyEvent::new(KeyCode::PageUp, none));
        assert_eq!(state.dns_selected, 14);
        handle_key(&mut state, &KeyEvent::new(KeyCode::Home, none));
        assert_eq!(state.dns_selected, 0);
        handle_key(&mut state, &KeyEvent::new(KeyCode::End, none));
        assert_eq!(state.dns_selected, 24);
    }
}
