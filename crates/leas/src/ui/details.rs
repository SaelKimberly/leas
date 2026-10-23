//! Pane-2 `Details` tab (spec §6).
//!
//! Two columns — the selected server's static facts (left) and the database's
//! own status (right) — that stack below ~100 cols. The facts column scrolls
//! with its own offset; the aggregate column is pinned and clipped from the
//! bottom, so the global numbers the user asked for first are never the ones
//! a short pane eats.
//!
//! The panel reads `state.endpoint_info` for country/whitelist/exit — a
//! DISPLAY cache that lags (spec D24) — and renders `—` when the entry is
//! absent. It never triggers a background fill.

use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::text::{Line, Span};
use leas_core::format_bytes;
use leas_db::models::PurgatoryView;

use crate::types::EndpointInfo;
use leas_db::models::ProfileStats;
use ratatui::widgets::Paragraph;

use crate::AppState;
use crate::ui::theme::ThemeStyles;

/// Below this width the two columns stack (facts first, aggregates after).
const TWO_COLUMN_MIN_WIDTH: u16 = 100;
/// The label column, xrat's shape (`xrat tui/theme.rs:13-16`).
const LABEL_WIDTH: usize = 13;
/// The empty-value glyph — one rule for the whole panel.
const EMPTY: &str = "—";

pub fn render(frame: &mut Frame, area: Rect, state: &AppState) {
    if area.height < 2 || area.width < 10 {
        return;
    }
    let theme = state.theme();
    if area.width >= TWO_COLUMN_MIN_WIDTH {
        let cols = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
            .split(area);
        render_facts(frame, cols[0], state, theme);
        render_aggregates(frame, cols[1], state, theme);
    } else {
        // Stacked: facts take what is left after the aggregate block.
        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(3), Constraint::Length(9)])
            .split(area);
        render_facts(frame, rows[0], state, theme);
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
                    "{} total · {} alive · {} proven · {} untested · {} failed",
                    c.total, c.alive, c.proven, c.untested, c.failed
                ),
                ThemeStyles::footer_value(theme),
            ))
        },
    );
    frame.render_widget(Paragraph::new(line), area);
}

/// The left column: the `Server` and `Link` groups.
fn render_facts(frame: &mut Frame, area: Rect, state: &AppState, theme: &opaline::Theme) {
    let row = state.filtered_profiles().nth(state.selected_index);
    let mut lines: Vec<Line> = Vec::new();

    lines.push(group_header("Server", theme));
    match row {
        None => {
            lines.push(Line::from(Span::styled(
                "  no server selected",
                ThemeStyles::hint(theme),
            )));
            // Both groups are always present, so the panel's shape does not
            // change with the selection.
            lines.push(group_header("Link", theme));
            lines.push(Line::from(Span::styled(
                "  no link",
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
            lines.push(field("Address", &format!("{host}:{}", endpoint.port), theme));

            // The representative link's protocol — the same link the grid's
            // Test/Stab cells describe.
            if let Some((_, protocol)) = row.active_protocol() {
                let p = &protocol;
                lines.push(field(
                    "Protocol",
                    &format!("{}/{}/{}", p.proto_kind, p.transport.r#type, p.security.r#type),
                    theme,
                ));
                if let Some(sni) = &p.security.sni {
                    lines.push(field("SNI", sni, theme));
                }
                if let Some(fp) = &p.security.fp {
                    lines.push(field("Fingerprint", fp, theme));
                }
            }

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
            lines.push(field(
                "Whitelist",
                &white_tokens(info),
                theme,
            ));

            // The ACTIVE link's persisted real-ping IP wins; the display cache
            // is the fallback — the grid's exact precedence (`profiles.rs:1183`).
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

            lines.push(group_header("Link", theme));
            // The representative link — one link, one rule, no drift from the
            // grid's Test/Stab cells.
            let dns_unresolved = crate::ops::profiles::endpoint_dns_unresolved(state, row);
            let link = row
                .representative_link_index(dns_unresolved)
                .and_then(|idx| row.links.get(idx));
            let Some(link) = link else {
                lines.push(Line::from(Span::styled(
                    "  no link",
                    ThemeStyles::hint(theme),
                )));
                return finish_facts(frame, area, state, lines);
            };
            lines.push(field("Last Seen", &format_epoch(link.last_seen_at), theme));
            lines.push(field(
                "Last Used",
                &link.last_used_at.map_or_else(|| EMPTY.to_string(), format_epoch),
                theme,
            ));
            lines.push(field(
                "Real Delay",
                &link.latency.real_delay.map_or_else(|| EMPTY.to_string(), |d| format!("{d}ms")),
                theme,
            ));
            lines.push(field(
                "Fast Delay",
                &link.latency.fast_delay.map_or_else(|| EMPTY.to_string(), |d| format!("{d}ms")),
                theme,
            ));
            lines.push(field("Auth", auth_label(link.latency.auth), theme));
            lines.push(field(
                "Speed",
                &link.speed_bps.map_or_else(|| EMPTY.to_string(), |s| format!("{s}bps")),
                theme,
            ));
            lines.push(field("Stability", &stability(link), theme));
            lines.push(field(
                "Error",
                &link
                    .error
                    .as_ref()
                    .map_or_else(|| EMPTY.to_string(), |e| format!("{:?}", e.kind)),
                theme,
            ));
            lines.push(field(
                "Traffic",
                &format!(
                    "↑{} ↓{}",
                    format_bytes(link.traffic.today_up),
                    format_bytes(link.traffic.today_down),
                ),
                theme,
            ));
        }
    }
    finish_facts(frame, area, state, lines);
}

/// Render the accumulated facts lines with the column's own scroll offset.
fn finish_facts(frame: &mut Frame, area: Rect, state: &AppState, lines: Vec<Line>) {
    // The facts column scrolls with its own offset.
    let offset = state.details_scroll.min(lines.len().saturating_sub(1));
    let visible: Vec<Line> = lines.into_iter().skip(offset).take(area.height as usize).collect();
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

const fn auth_label(auth: Option<i64>) -> &'static str {
    match auth {
        Some(1) => "ok",
        Some(2) => "failed",
        Some(3) => "n/a",
        _ => EMPTY,
    }
}

fn stability(link: &ProfileStats) -> String {
    if link.stab_len == 0 {
        return EMPTY.to_string();
    }
    let successes = link.stab_mask.count_ones();
    format!("{successes}/{}", link.stab_len)
}

fn format_epoch(secs: i64) -> String {
    if secs <= 0 {
        return EMPTY.to_string();
    }
    let dt = jiff::Timestamp::from_second(secs)
        .map_or_else(|_| EMPTY.to_string(), |t| t.to_string());
    // The panel shows a short form; the full timestamp is in the DB.
    dt.split('T').next().unwrap_or(EMPTY).to_string()
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
    lines.push(field("alive", &c.alive.to_string(), theme));
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
