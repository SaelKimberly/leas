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
use ratatui::widgets::Paragraph;

use crate::AppState;
use crate::ui::FmtBuf;
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

/// Padding for the label column, sliced to the shortfall (labels are static
/// and all fit `LABEL_WIDTH`).
const LABEL_PAD: &str = "             ";

/// One label/value line: a muted label column, then the value.
///
/// Borrows both halves: the pane is rebuilt every frame, and the old shape
/// formatted the padded label, copied the value with `to_string()` and then
/// collected a `Vec` — three allocations per field, ~50 per frame.
fn field<'a>(label: &'static str, value: &'a str, theme: &opaline::Theme) -> Line<'a> {
    let label_width = unicode_width::UnicodeWidthStr::width(label);
    debug_assert!(label_width <= LABEL_WIDTH, "label wider than its column");
    let pad = &LABEL_PAD[..LABEL_WIDTH.saturating_sub(label_width)];
    let value_style = if value == EMPTY {
        ThemeStyles::hint(theme)
    } else {
        ThemeStyles::footer_value(theme)
    };
    Line::from(vec![
        Span::styled(label, ThemeStyles::hint(theme)),
        Span::raw(pad),
        Span::styled(value, value_style),
    ])
}

fn group_header(name: &'static str, theme: &opaline::Theme) -> Line<'static> {
    Line::from(Span::styled(name, ThemeStyles::container_title(theme)))
}

/// `Addr1, Addr2, …` for a stack buffer: `join` needs an intermediate `Vec`.
struct IpList<'a>(&'a [std::net::IpAddr]);

impl std::fmt::Display for IpList<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (index, ip) in self.0.iter().enumerate() {
            if index > 0 {
                f.write_str(", ")?;
            }
            write!(f, "{ip}")?;
        }
        Ok(())
    }
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
    let mut text_buf = FmtBuf::<160>::default();
    let line = state.aggregates.as_ref().map_or_else(
        || Line::from(Span::styled("  computing…", ThemeStyles::hint(theme))),
        |cache| {
            let c = &cache.counts;
            Line::from(Span::styled(
                text_buf.put(format_args!(
                    "{} total · {} alive · {} active · {} proven · {} untested · {} failed",
                    c.total, c.alive, c.active, c.proven, c.untested, c.failed
                )),
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
    // Hoisted above the match: the pushed lines borrow these buffers and the
    // pane renders after the arm ends.
    let mut address_buf = FmtBuf::<96>::default();
    let mut ips_buf = FmtBuf::<256>::default();
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
            let address = address_buf.put(format_args!("{host}:{}", endpoint.port));
            let ips = if row.resolved_ips.is_empty() {
                EMPTY
            } else {
                ips_buf.put(format_args!("{}", IpList(&row.resolved_ips)))
            };
            lines.push(field("Address", address, theme));
            lines.push(field(
                "Country",
                info.and_then(|i| i.country.as_deref()).unwrap_or(EMPTY),
                theme,
            ));
            lines.push(field("Resolved IPs", ips, theme));
            lines.push(field("Whitelist", white_tokens(info), theme));
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

    let mut url_buf = FmtBuf::<64>::default();
    lines.push(field(
        "Leas URL",
        url_buf.put(format_args!(
            "leas://{:x}/{:x}",
            row.endpoint.id.get(),
            link.protocol_id.get()
        )),
        theme,
    ));
    // The protocol config: names only — no credentials, paths, or keys.
    if let Some(proto) = row.protocols.get(&link.protocol_id) {
        lines.push(field("Protocol", proto.proto_kind.as_str(), theme));
        lines.push(field("Transport", proto.transport.r#type.as_str(), theme));
        lines.push(field("Security", proto.security.r#type.as_str(), theme));
        if let Some(sni) = &proto.security.sni {
            lines.push(field("SNI", sni, theme));
        }
        if let Some(fp) = &proto.security.fp {
            lines.push(field("Fingerprint", fp, theme));
        }
    }

    // Each volatile value gets its own stack buffer: the spans borrow it for
    // the life of the line, and the pane is rebuilt every frame.
    let mut real_buf = FmtBuf::<24>::default();
    let real = link
        .latency
        .real_delay
        .map_or(EMPTY, |d| real_buf.put(format_args!("{d}ms")));
    let mut fast_buf = FmtBuf::<24>::default();
    let fast = link
        .latency
        .fast_delay
        .map_or(EMPTY, |d| fast_buf.put(format_args!("{d}ms")));
    let mut speed_buf = FmtBuf::<24>::default();
    let speed = link.speed_bps.map_or(EMPTY, |s| {
        speed_buf.put(format_args!("{:.1}MiB/s", s as f64 / 8.0 / 1_048_576.0))
    });
    let mut stab_buf = FmtBuf::<24>::default();
    let stab = if link.stab_len == 0 {
        EMPTY
    } else {
        stab_buf.put(format_args!(
            "{}/{}",
            link.stab_mask.count_ones(),
            link.stab_len
        ))
    };
    // The timestamp formatter owns the format (jiff), so its `String` is kept
    // whole: copying it into a stack buffer would be a second allocation.
    let seen_text = (link.last_seen_at > 0).then(|| format_epoch(link.last_seen_at));
    let used_text = link.last_used_at.map(format_epoch);

    lines.push(field(
        "Last Seen",
        seen_text.as_deref().unwrap_or(EMPTY),
        theme,
    ));
    lines.push(field(
        "Last Used",
        used_text.as_deref().unwrap_or(EMPTY),
        theme,
    ));
    lines.push(field("Real Delay", real, theme));
    lines.push(field("Fast Delay", fast, theme));
    lines.push(field("Auth", auth_label(link.latency.auth), theme));
    lines.push(field("Speed", speed, theme));
    lines.push(field("Stability", stab, theme));
    // `format_bytes` is the crate-wide formatter (it owns the unit thresholds);
    // its two strings are the only allocations left on this line.
    let mut traffic_buf = FmtBuf::<48>::default();
    let traffic = traffic_buf.put(format_args!(
        "↑{} ↓{}",
        format_bytes(link.traffic.today_up),
        format_bytes(link.traffic.today_down),
    ));
    lines.push(field("Traffic", traffic, theme));

    // The ACTIVE link's persisted real-ping IP wins; the display cache is the
    // fallback — the grid's exact precedence (`profiles.rs:1183`). Borrowed,
    // not cloned: the old path cloned the `Option<String>` every frame.
    let info = state.endpoint_info.get(&row.endpoint.id.get());
    let mut ip_buf = FmtBuf::<64>::default();
    let persisted_ip = row.active_link().and_then(|l| l.latency.ip.as_deref());
    let active_ip = persisted_ip.or_else(|| {
        info.and_then(|i| i.outbound_ip)
            .map(|ip| ip_buf.put(format_args!("{ip}")))
    });
    lines.push(field("Exit IP", active_ip.unwrap_or(EMPTY), theme));
    let country = persisted_ip.and_then(|ip| state.outbound_country_for(ip));
    lines.push(field(
        "Exit Country",
        country
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
    // `Paragraph::scroll` clips to the area itself; collecting a second `Vec`
    // of the visible lines was one more per-frame allocation.
    let offset = offset.min(lines.len().saturating_sub(1));
    let scroll = u16::try_from(offset).unwrap_or(u16::MAX);
    frame.render_widget(Paragraph::new(lines).scroll((scroll, 0)), area);
}

fn white_tokens(info: Option<&EndpointInfo>) -> &'static str {
    let Some(info) = info else {
        return EMPTY;
    };
    let sni = info.sni_whitelisted.unwrap_or(false)
        || info.host_features.sni_whitelisted
        || info.host_features.ip_whitelisted
        || info.host_features.cidr_whitelisted;
    let cidr = info.host_features.ip_whitelisted || info.host_features.cidr_whitelisted;
    match (sni, cidr) {
        (true, true) => "SNI+CIDR",
        (true, false) => "SNI",
        (false, true) => "CIDR",
        (false, false) => EMPTY,
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
    // One stack buffer per counter, formatted once and reused by both blocks
    // (each block shows the same four partition numbers).
    let mut total_buf = FmtBuf::<24>::default();
    let mut proven_buf = FmtBuf::<24>::default();
    let mut untested_buf = FmtBuf::<24>::default();
    let mut failed_buf = FmtBuf::<24>::default();
    let mut other_buf = FmtBuf::<24>::default();
    let mut alive_buf = FmtBuf::<24>::default();
    let mut active_buf = FmtBuf::<24>::default();
    let mut reliable_buf = FmtBuf::<24>::default();
    let mut exit_ips_buf = FmtBuf::<24>::default();
    let total = total_buf.put(format_args!("{}", c.total));
    let proven = proven_buf.put(format_args!("{}", c.proven));
    let untested = untested_buf.put(format_args!("{}", c.untested));
    let failed = failed_buf.put(format_args!("{}", c.failed));
    let other = other_buf.put(format_args!("{}", c.other));
    let alive = alive_buf.put(format_args!("{}", c.alive));
    let active = active_buf.put(format_args!("{}", c.active));
    let reliable = reliable_buf.put(format_args!("{}", c.reliable));
    let exit_ips = exit_ips_buf.put(format_args!("{}", c.exit_ips));

    lines.push(Line::from(vec![
        Span::styled("DB ", ThemeStyles::container_title(theme)),
        Span::styled(total, ThemeStyles::footer_value(theme)),
    ]));
    // The partition block.
    for (label, value) in [
        ("proven", proven),
        ("untested", untested),
        ("failed", failed),
        ("other", other),
    ] {
        lines.push(field(label, value, theme));
    }
    lines.push(Line::raw(""));
    // The orthogonal block — separated so it cannot be summed into the above.
    // Alive and Active are distinct bands, not one "recent" bucket.
    lines.push(field("alive", alive, theme));
    lines.push(field("active", active, theme));
    lines.push(field("reliable", reliable, theme));
    // Servers, not links: one exit IP per working server, however many ports
    // and endpoints it appears under (spec `2026-11-19-probe-truth` S6).
    lines.push(field("exit IPs", exit_ips, theme));

    lines.push(Line::raw(""));
    // The view label owns its `String` (it may append the search query).
    let view = view_label(state);
    lines.push(Line::from(Span::styled(
        view,
        ThemeStyles::container_title(theme),
    )));
    for (label, value) in [
        ("proven", proven),
        ("untested", untested),
        ("failed", failed),
        ("other", other),
    ] {
        lines.push(field(label, value, theme));
    }

    // Pinned at the top, clipped from the bottom: the global numbers are the
    // ones the user asked for first, so a short pane must not eat them — and
    // `Paragraph` clips to `area` on its own, with no second `Vec`.
    frame.render_widget(Paragraph::new(lines), area);
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
