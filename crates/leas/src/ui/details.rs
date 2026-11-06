//! Pane-2 `Details` tab (spec §6).
//!
//! Three sections — the selected server's static facts (left), the selected
//! link (middle), and the database's own status (right) — that stack below
//! ~100 cols. The server and DB sections are short and pinned; the link section
//! scrolls with its own offset. The middle section carries the facts a link
//! alone can explain: its protocol config, exit, and last error.
//!
//! The panel reads `state.endpoint_info` for country/whitelist/exit — a
//! DISPLAY cache that lags (spec D24) — and renders `—` when the entry is
//! absent. It never triggers a background fill.

use leas_core::format_bytes;
use leas_db::models::PurgatoryView;
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::text::{Line, Span};

use crate::types::EndpointInfo;
use leas_db::models::ProfileStats;
use ratatui::widgets::Paragraph;

use crate::AppState;
use crate::ui::theme::ThemeStyles;

/// Below this width the three columns stack (facts first, aggregates after).
const THREE_COLUMN_MIN_WIDTH: u16 = 100;
/// The label column, xrat's shape (`xrat tui/theme.rs:13-16`).
const LABEL_WIDTH: usize = 13;
/// The empty-value glyph — one rule for the whole panel.
const EMPTY: &str = "—";

pub fn render(frame: &mut Frame, area: Rect, state: &AppState) {
    if area.height < 2 || area.width < 10 {
        return;
    }
    let theme = state.theme();
    if area.width >= THREE_COLUMN_MIN_WIDTH {
        // 3:6:3 — the link section gets the room an error message needs.
        let cols = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Percentage(25),
                Constraint::Length(1),
                Constraint::Percentage(50),
                Constraint::Length(1),
                Constraint::Percentage(25),
            ])
            .split(area);
        render_server(frame, cols[0], state, theme);
        draw_separator(frame, cols[1], theme);
        render_link(frame, cols[2], state, theme);
        draw_separator(frame, cols[3], theme);
        render_aggregates(frame, cols[4], state, theme);
    } else {
        // Stacked: facts take what is left after the aggregate block.
        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(3), Constraint::Length(9)])
            .split(area);
        render_facts_stacked(frame, rows[0], state, theme);
        render_aggregates(frame, rows[1], state, theme);
    }
}

/// One label/value line: a muted label column, then the value.
fn field<'a>(label: &str, value: &str, theme: &opaline::Theme) -> Line<'a> {
    let padded = format!("{label:<LABEL_WIDTH$}");
    let value_style = if value == EMPTY {
        ThemeStyles::hint(theme)
    } else {
        ThemeStyles::footer_value(theme)
    };
    Line::from(vec![
        Span::styled(padded, ThemeStyles::hint(theme)),
        Span::styled(value.to_string(), value_style),
    ])
}

fn group_header<'a>(name: &str, theme: &opaline::Theme) -> Line<'a> {
    Line::from(Span::styled(
        name.to_string(),
        ThemeStyles::container_title(theme),
    ))
}

/// A single vertical rule between two sections.
fn draw_separator(frame: &mut Frame, area: Rect, theme: &opaline::Theme) {
    let style = ThemeStyles::container_border(theme);
    for y in area.top()..area.bottom() {
        if let Some(cell) = frame.buffer_mut().cell_mut((area.x, y)) {
            cell.set_symbol("│").set_style(style);
        }
    }
}

/// Compact mode: one line of the GLOBAL bucket counts (spec D16).
///
/// No view total (the footer's `rows a-b of N` owns it) and no server identity
/// (the footer's `Server:` line owns it) — compact must not duplicate the
/// Profiles pane's bottom line.
pub fn render_compact(frame: &mut Frame, area: Rect, state: &AppState) {
    let theme = state.theme();
    let line = state.aggregates.as_ref().map_or_else(
        || Line::from(Span::styled("  computing…", ThemeStyles::hint(theme))),
        |cache| {
            let c = &cache.counts;
            Line::from(Span::styled(
                format!(
                    "{} total · {} alive · {} active · {} proven · {} untested · {} failed",
                    c.total, c.alive, c.active, c.proven, c.untested, c.failed
                ),
                ThemeStyles::footer_value(theme),
            ))
        },
    );
    frame.render_widget(Paragraph::new(line), area);
}

/// The stacked narrow layout: server and link facts above the aggregate block.
fn render_facts_stacked(frame: &mut Frame, area: Rect, state: &AppState, theme: &opaline::Theme) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(6), Constraint::Min(3)])
        .split(area);
    render_server(frame, rows[0], state, theme);
    render_link(frame, rows[1], state, theme);
}

/// The left column: the `Server` group.
fn render_server(frame: &mut Frame, area: Rect, state: &AppState, theme: &opaline::Theme) {
    let row = state.filtered_profiles().nth(state.selected_index);
    let mut lines: Vec<Line> = Vec::new();

    lines.push(group_header("Server", theme));
    match row {
        None => {
            lines.push(Line::from(Span::styled(
                "  no server selected",
                ThemeStyles::hint(theme),
            )));
        }
        Some(row) => {
            let endpoint = &row.endpoint;
            let info = state.endpoint_info.get(&endpoint.id.get());

            // The loaded row's persisted addresses are the resolution source
            // (the grid's own law — `profiles.rs:1155`); `endpoint_info` is a
            // display cache and must not replace them.
            let host = endpoint.display_host(&row.resolved_ips);
            lines.push(field(
                "Address",
                &format!("{host}:{}", endpoint.port),
                theme,
            ));
            lines.push(field(
                "Country",
                info.and_then(|i| i.country.as_deref()).unwrap_or(EMPTY),
                theme,
            ));
            lines.push(field(
                "Resolved IPs",
                &if row.resolved_ips.is_empty() {
                    EMPTY.to_string()
                } else {
                    row.resolved_ips
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(", ")
                },
                theme,
            ));
            lines.push(field("Whitelist", &white_tokens(info), theme));
        }
    }
    finish_lines(frame, area, lines, 0);
}

/// The middle column: the `Link` group — protocol config, measurements, exit,
/// and the last error when one is stored.
fn render_link(frame: &mut Frame, area: Rect, state: &AppState, theme: &opaline::Theme) {
    let row = state.filtered_profiles().nth(state.selected_index);
    let mut lines: Vec<Line> = Vec::new();

    lines.push(group_header("Link", theme));
    let Some(row) = row else {
        lines.push(Line::from(Span::styled(
            "  no link",
            ThemeStyles::hint(theme),
        )));
        return finish_lines(frame, area, lines, state.details_scroll);
    };

    // The representative link — one link, one rule, no drift from the grid's
    // Test/Stab cells.
    let dns_unresolved = crate::ops::profiles::endpoint_dns_unresolved(state, row);
    let link = row
        .representative_link_index(dns_unresolved)
        .and_then(|idx| row.links.get(idx));
    let Some(link) = link else {
        lines.push(Line::from(Span::styled(
            "  no link",
            ThemeStyles::hint(theme),
        )));
        return finish_lines(frame, area, lines, state.details_scroll);
    };

    lines.push(field(
        "Leas URL",
        &format!(
            "leas://{:x}/{:x}",
            row.endpoint.id.get(),
            link.protocol_id.get()
        ),
        theme,
    ));
    // The protocol config: names only — no credentials, paths, or keys.
    if let Some(proto) = row.protocols.get(&link.protocol_id) {
        lines.push(field("Protocol", &proto.proto_kind.to_string(), theme));
        lines.push(field("Transport", proto.transport.r#type.as_str(), theme));
        lines.push(field("Security", proto.security.r#type.as_str(), theme));
        if let Some(sni) = &proto.security.sni {
            lines.push(field("SNI", sni, theme));
        }
        if let Some(fp) = &proto.security.fp {
            lines.push(field("Fingerprint", fp, theme));
        }
    }

    lines.push(field("Last Seen", &format_epoch(link.last_seen_at), theme));
    lines.push(field(
        "Last Used",
        &link
            .last_used_at
            .map_or_else(|| EMPTY.to_string(), format_epoch),
        theme,
    ));
    lines.push(field(
        "Real Delay",
        &link
            .latency
            .real_delay
            .map_or_else(|| EMPTY.to_string(), |d| format!("{d}ms")),
        theme,
    ));
    lines.push(field(
        "Fast Delay",
        &link
            .latency
            .fast_delay
            .map_or_else(|| EMPTY.to_string(), |d| format!("{d}ms")),
        theme,
    ));
    lines.push(field("Auth", auth_label(link.latency.auth), theme));
    lines.push(field(
        "Speed",
        &link.speed_bps.map_or_else(
            || EMPTY.to_string(),
            |s| format!("{:.1}MiB/s", s as f64 / 8.0 / 1_048_576.0),
        ),
        theme,
    ));
    lines.push(field("Stability", &stability(link), theme));
    lines.push(field(
        "Traffic",
        &format!(
            "↑{} ↓{}",
            format_bytes(link.traffic.today_up),
            format_bytes(link.traffic.today_down),
        ),
        theme,
    ));

    // The ACTIVE link's persisted real-ping IP wins; the display cache is the
    // fallback — the grid's exact precedence (`profiles.rs:1183`).
    let info = state.endpoint_info.get(&row.endpoint.id.get());
    let active_ip = row
        .active_link()
        .and_then(|l| l.latency.ip.clone())
        .or_else(|| info.and_then(|i| i.outbound_ip.map(|ip| ip.to_string())));
    lines.push(field(
        "Exit IP",
        active_ip.as_deref().unwrap_or(EMPTY),
        theme,
    ));
    lines.push(field(
        "Exit Country",
        row.active_link()
            .and_then(|l| l.latency.ip.clone())
            .as_deref()
            .and_then(|ip| state.outbound_country_for(ip))
            .as_deref()
            .or_else(|| info.and_then(|i| i.outbound_country.as_deref()))
            .unwrap_or(EMPTY),
        theme,
    ));

    if let Some(error) = &link.error {
        lines.push(field("Last Error", error_label(error.kind), theme));
        lines.push(field("Error Text", &error.text, theme));
    }

    finish_lines(frame, area, lines, state.details_scroll);
}

/// Render the accumulated lines with a scroll offset.
fn finish_lines(frame: &mut Frame, area: Rect, lines: Vec<Line>, offset: usize) {
    let offset = offset.min(lines.len().saturating_sub(1));
    let visible: Vec<Line> = lines
        .into_iter()
        .skip(offset)
        .take(area.height as usize)
        .collect();
    frame.render_widget(Paragraph::new(visible), area);
}

fn white_tokens(info: Option<&EndpointInfo>) -> String {
    let Some(info) = info else {
        return EMPTY.to_string();
    };
    let sni = info.sni_whitelisted.unwrap_or(false)
        || info.host_features.sni_whitelisted
        || info.host_features.ip_whitelisted
        || info.host_features.cidr_whitelisted;
    let cidr = info.host_features.ip_whitelisted || info.host_features.cidr_whitelisted;
    match (sni, cidr) {
        (true, true) => "SNI+CIDR".to_string(),
        (true, false) => "SNI".to_string(),
        (false, true) => "CIDR".to_string(),
        (false, false) => EMPTY.to_string(),
    }
}

/// The link's auth flag, via the crate's `AuthState` (the grid's own law —
/// `profiles.rs::auth_glyph`), so the panel and the grid cannot disagree.
fn auth_label(auth: Option<i64>) -> &'static str {
    use leas_db::models::AuthState;
    match auth.and_then(AuthState::from_i64) {
        Some(AuthState::Ok) => "ok",
        Some(AuthState::Failed) => "failed",
        Some(AuthState::NotApplicable) => "n/a",
        Some(AuthState::Unknown) => "unknown",
        None => EMPTY,
    }
}

/// The persisted error class, in the same lowercase words the grid's label
/// shows (`[real]`/`[fast]`/`[name]`).
const fn error_label(kind: leas_db::models::ProfileErr) -> &'static str {
    use leas_db::models::ProfileErr;
    match kind {
        ProfileErr::Real => "real",
        ProfileErr::Fast => "fast",
        ProfileErr::Name => "name",
    }
}

fn stability(link: &ProfileStats) -> String {
    if link.stab_len == 0 {
        return EMPTY.to_string();
    }
    let successes = link.stab_mask.count_ones();
    format!("{successes}/{}", link.stab_len)
}

/// The stored epoch seconds as `YYYY-MM-DD HH:MM:SS` (the crate's single
/// timestamp law), or `—` when the value is absent.
fn format_epoch(secs: i64) -> String {
    if secs <= 0 {
        return EMPTY.to_string();
    }
    crate::format_ts(secs)
}

/// The right column: the database's own status.
///
/// A **partition block** (`proven`/`untested`/`failed`/`other`, which sums to
/// the total) and an **orthogonal block** (`alive`/`reliable`, which overlaps
/// any subset) are drawn as two blocks, so the reader cannot add the second
/// into the first (spec D28).
fn render_aggregates(frame: &mut Frame, area: Rect, state: &AppState, theme: &opaline::Theme) {
    let mut lines: Vec<Line> = Vec::new();

    let Some(cache) = &state.aggregates else {
        lines.push(Line::from(Span::styled(
            "  computing…",
            ThemeStyles::hint(theme),
        )));
        frame.render_widget(Paragraph::new(lines), area);
        return;
    };
    let c = &cache.counts;

    lines.push(Line::from(vec![
        Span::styled("DB ", ThemeStyles::container_title(theme)),
        Span::styled(format!("{}", c.total), ThemeStyles::footer_value(theme)),
    ]));
    // The partition block.
    for (label, value) in [
        ("proven", c.proven),
        ("untested", c.untested),
        ("failed", c.failed),
        ("other", c.other),
    ] {
        lines.push(field(label, &value.to_string(), theme));
    }
    lines.push(Line::raw(""));
    // The orthogonal block — separated so it cannot be summed into the above.
    // Alive and Active are distinct bands, not one "recent" bucket.
    lines.push(field("alive", &c.alive.to_string(), theme));
    lines.push(field("active", &c.active.to_string(), theme));
    lines.push(field("reliable", &c.reliable.to_string(), theme));

    lines.push(Line::raw(""));
    lines.push(Line::from(Span::styled(
        format!("View: {}", view_label(state)),
        ThemeStyles::container_title(theme),
    )));
    for (label, value) in [
        ("proven", c.proven),
        ("untested", c.untested),
        ("failed", c.failed),
        ("other", c.other),
    ] {
        lines.push(field(label, &value.to_string(), theme));
    }

    // Pinned at the top, clipped from the bottom: the global numbers are the
    // ones the user asked for first, so a short pane must not eat them.
    let visible: Vec<Line> = lines.into_iter().take(area.height as usize).collect();
    frame.render_widget(Paragraph::new(visible), area);
}

fn view_label(state: &AppState) -> String {
    let view = match state.purgatory_view {
        PurgatoryView::Active => "Active",
        PurgatoryView::Purgatory => "Purgatory",
        PurgatoryView::All => "All",
    };
    if state.search_query.is_empty() {
        view.to_string()
    } else {
        format!("{view} / {}", state.search_query)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A state with the aggregate cache populated — the event loop refreshes it
    /// on the first tick, so the tests must do the same.
    async fn state_with_aggregates() -> AppState {
        let mut state = crate::ops::profiles::test_support::test_state(Vec::new()).await;
        state.refresh_aggregates().await;
        state
    }

    /// Render the pane at `width` into a 120x24 `TestBackend` and flatten it.
    fn render_at(state: &AppState, width: u16) -> String {
        let mut terminal = ratatui::Terminal::new(ratatui::backend::TestBackend::new(width, 24))
            .expect("test backend");
        terminal
            .draw(|frame| render(frame, frame.area(), state))
            .expect("draw");
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

    /// The empty test DB has no selected row. All three section headers must
    /// still be present — the panel's shape must not change with the selection.
    #[tokio::test]
    async fn renders_three_section_headers_with_no_selection() {
        let state = state_with_aggregates().await;
        let out = render_at(&state, 120);
        let header = out.lines().next().expect("a first line");
        for label in ["Server", "Link", "DB "] {
            assert!(
                header.contains(label),
                "the {label:?} section must sit on the same header row: {header:?}"
            );
        }
        assert_eq!(
            header.matches('│').count(),
            2,
            "the header row carries both section rules: {header:?}"
        );
        assert!(
            out.contains("no server selected"),
            "the empty-selection hint is missing"
        );
    }

    /// Compact shows the GLOBAL bucket counts only (spec D16): no view total
    /// (the Profiles footer's `rows a-b of N` owns it) and no server identity
    /// (the footer's `Server:` line owns it).
    #[tokio::test]
    async fn compact_omits_the_view_total_and_server_identity() {
        let state = state_with_aggregates().await;
        let mut terminal = ratatui::Terminal::new(ratatui::backend::TestBackend::new(120, 24))
            .expect("test backend");
        terminal
            .draw(|frame| render_compact(frame, frame.area(), &state))
            .expect("draw");
        let buffer = terminal.backend().buffer();
        let mut out = String::new();
        for x in 0..buffer.area.width {
            out.push_str(buffer[(x, 0)].symbol());
        }
        assert!(
            out.contains("total"),
            "the global counts are missing: {out}"
        );
        assert!(
            out.contains("alive"),
            "the global counts are missing: {out}"
        );
        assert!(
            !out.contains("View:"),
            "compact must not repeat the view total"
        );
        assert!(
            !out.contains("Server:"),
            "compact must not repeat the footer's server identity"
        );
    }

    /// Below 100 cols the sections STACK: the facts first, the aggregate block
    /// after (spec D9).
    #[tokio::test]
    async fn stacked_below_100_cols() {
        let state = state_with_aggregates().await;
        let narrow = render_at(&state, 80);
        let wide = render_at(&state, 120);
        let db_row_wide = wide
            .lines()
            .position(|l| l.contains("DB "))
            .expect("the wide render has the aggregate block");
        let db_row_narrow = narrow
            .lines()
            .position(|l| l.contains("DB "))
            .expect("the narrow render has the aggregate block");
        assert!(
            db_row_narrow > db_row_wide,
            "below 100 cols the aggregate block must sit below the facts \
             (wide row {db_row_wide}, narrow row {db_row_narrow})"
        );
    }

    /// The Leas URL carries both identities the Real Test logs name.
    #[test]
    fn leas_url_names_endpoint_and_protocol() {
        assert_eq!(
            format!("leas://{:x}/{:x}", 0x1a2bi64, 0x3c4di64),
            "leas://1a2b/3c4d"
        );
    }
}
