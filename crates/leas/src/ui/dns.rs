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
            "{:<9} {:<28} {:>8}  {:<9}  {}",
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
        let line = format!(
            "{:<9} {:<28} {:>8}  {:<9}  {}",
            protocol_label(&row.protocol),
            crate::ui::textfit::truncate(&format!("{}:{}", row.host, row.port), 28),
            latency_label(row.latency_ms),
            status,
            age_label(row.checked_at),
        );
        lines.push(Line::from(Span::styled(line, selected_style)));
    }
    frame.render_widget(Paragraph::new(lines), area);
}

pub fn handle_key(state: &mut AppState, key: &KeyEvent) {
    let max = state.dns_resolvers.len().saturating_sub(1);
    match key.code {
        KeyCode::Up => state.dns_selected = state.dns_selected.saturating_sub(1),
        KeyCode::Down => state.dns_selected = state.dns_selected.saturating_add(1).min(max),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

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
}
