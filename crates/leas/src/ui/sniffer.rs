//! Pane-1 `Sniffer` tab: per-host traffic for the live native session.
//!
//! The data comes from the in-process core's 1 s
//! [`CoreEvent::SnifferSample`](crate::CoreEvent::SnifferSample) snapshots,
//! collected by [`SnifferState`]. This module owns only presentation and the
//! table scroll offset (module-global, like `ui/native_activity.rs`).
//!
//! Layout (spec 2026-11-03 `sniffer-pane`):
//! - two header lines: current rates, then session summary;
//! - two mirrored sparklines (down above, up below) on a SHARED scale, so the
//!   two directions are visually comparable;
//! - the host table, sorted by total bytes by the native side.

use std::sync::atomic::{AtomicUsize, Ordering};

use crossterm::event::{KeyCode, KeyEvent};
use leas_core::format_bytes;
use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Table};

use crate::AppState;
use crate::types::{RateSample, SnifferState};
use crate::ui::theme::ThemeStyles;

/// Text rows per sparkline (each row is two half-cells).
const SPARK_ROWS: usize = 3;
/// Rows a `PageUp`/`PageDown` moves the host table.
const PAGE_ROWS: usize = 10;

/// Scroll offset in table rows from the top (0 = first host).
static SCROLL: AtomicUsize = AtomicUsize::new(0);

/// Drop the scroll offset: a new native session replaced the table.
pub fn reset_scroll() {
    SCROLL.store(0, Ordering::Relaxed);
}

/// The current offset, clamped to a table of `len` rows.
fn scroll_offset(len: usize) -> usize {
    let max = len.saturating_sub(1);
    SCROLL.fetch_min(max, Ordering::Relaxed).min(max)
}

/// Render the `Sniffer` tab into `area` (pane-1 inner rect).
pub fn render(frame: &mut Frame, area: Rect, state: &AppState) {
    let theme = state.theme();
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(ThemeStyles::container_border(theme));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    if !state.connected {
        render_hint(
            frame,
            inner,
            " No native session — per-host traffic requires the native core ",
            theme,
        );
        return;
    }
    let Some(snapshot) = &state.sniffer.latest else {
        render_hint(frame, inner, " Waiting for the first sample… ", theme);
        return;
    };

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2), // rates + summary
            Constraint::Length(u16::try_from(SPARK_ROWS * 2).unwrap_or(0)), // two mirrored sparklines
            Constraint::Min(0),                                             // host table
        ])
        .split(inner);

    let rates = state.sniffer.rates();
    let header = vec![
        Line::from(format!(
            " ↓ {:>10}/s   ↑ {:>10}/s",
            format_bytes(saturating_i64(rates.down)),
            format_bytes(saturating_i64(rates.up)),
        )),
        Line::from(format!(
            " hosts {} · failed {} · dropped {} datagrams ({})",
            snapshot.hosts.len(),
            snapshot.failed,
            snapshot.dropped_datagrams,
            format_bytes(saturating_i64(snapshot.dropped_bytes)),
        ))
        .style(ThemeStyles::hint(theme)),
    ];
    frame.render_widget(Paragraph::new(header), rows[0]);

    render_sparklines(frame, rows[1], &state.sniffer, theme);
    render_table(frame, rows[2], state, theme);
}

fn render_hint(frame: &mut Frame, area: Rect, text: &str, theme: &opaline::Theme) {
    frame.render_widget(
        Paragraph::new(text)
            .style(ThemeStyles::hint(theme))
            .alignment(Alignment::Center),
        area,
    );
}

/// Shared vertical scale: the larger of the two series' maxima, never zero.
fn shared_max(samples: &[RateSample]) -> u64 {
    samples
        .iter()
        .map(|sample| sample.down.max(sample.up))
        .max()
        .unwrap_or(0)
        .max(1)
}

/// Half-cell height of `value` on a scale of `max`; a non-zero value never
/// disappears (floor: one half-cell).
fn bars_for(value: u64, max: u64) -> usize {
    if value == 0 {
        return 0;
    }
    let full = u64::try_from(SPARK_ROWS * 2).unwrap_or(u64::MAX);
    let scaled = value.saturating_mul(full) / max.max(1);
    usize::try_from(scaled).unwrap_or(SPARK_ROWS * 2).max(1)
}

fn render_sparklines(frame: &mut Frame, area: Rect, state: &SnifferState, theme: &opaline::Theme) {
    let samples: Vec<RateSample> = state.samples_iter().copied().collect();
    let max = shared_max(&samples);
    let bars: Vec<(usize, usize)> = samples
        .iter()
        .map(|sample| (bars_for(sample.down, max), bars_for(sample.up, max)))
        .collect();
    let style = ThemeStyles::container_title(theme);

    for row in 0..SPARK_ROWS {
        // Down grows DOWN from the top half; up grows UP from the bottom half.
        let mut down_line = String::with_capacity(bars.len());
        let mut up_line = String::with_capacity(bars.len());
        let from_top = row * 2;
        let from_bottom = (SPARK_ROWS - 1 - row) * 2;
        for (down, up) in &bars {
            down_line.push(top_half(*down, from_top));
            up_line.push(bottom_half(*up, from_bottom));
        }
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(down_line, style))),
            Rect {
                x: area.x,
                y: area.y + u16::try_from(row).unwrap_or(0),
                width: area.width,
                height: 1,
            },
        );
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(up_line, style))),
            Rect {
                x: area.x,
                y: area.y + u16::try_from(SPARK_ROWS + row).unwrap_or(0),
                width: area.width,
                height: 1,
            },
        );
    }
}

/// Half-cell glyph for a bar growing downward, at half-cell offset `at`.
fn top_half(height: usize, at: usize) -> char {
    match height.saturating_sub(at).min(2) {
        0 => ' ',
        1 => '▀',
        _ => '█',
    }
}

/// Half-cell glyph for a bar growing upward, at half-cell offset `at`.
fn bottom_half(height: usize, at: usize) -> char {
    match height.saturating_sub(at).min(2) {
        0 => ' ',
        1 => '▄',
        _ => '█',
    }
}

fn render_table(frame: &mut Frame, area: Rect, state: &AppState, theme: &opaline::Theme) {
    let Some(snapshot) = &state.sniffer.latest else {
        return;
    };
    let header = Row::new([
        Cell::from("host"),
        Cell::from("via").style(ThemeStyles::hint(theme)),
        Cell::from("↓").style(ThemeStyles::hint(theme)),
        Cell::from("↑").style(ThemeStyles::hint(theme)),
        Cell::from("conns").style(ThemeStyles::hint(theme)),
        Cell::from("failed").style(ThemeStyles::hint(theme)),
    ])
    .style(ThemeStyles::table_header(theme));

    let rows: Vec<Row> = snapshot
        .hosts
        .iter()
        .map(|host| {
            Row::new([
                Cell::from(host.host.to_string()),
                outbound_cell(host.outbound.as_deref(), theme),
                Cell::from(format_bytes(saturating_i64(host.down))),
                Cell::from(format_bytes(saturating_i64(host.up))),
                Cell::from(host.conns.to_string()),
                Cell::from(host.failed.to_string()),
            ])
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Min(20),
            Constraint::Length(3),
            Constraint::Length(10),
            Constraint::Length(10),
            Constraint::Length(6),
            Constraint::Length(6),
        ],
    )
    .header(header)
    .column_spacing(1);

    let mut table_state =
        ratatui::widgets::TableState::default().with_offset(scroll_offset(snapshot.hosts.len()));
    frame.render_stateful_widget(table, area, &mut table_state);
}

/// Marker for the outbound the route chose for a host: `direct`, `proxy`,
/// `block`, or blank when routing named no outbound (a refused `Reject` /
/// `HijackDns` leg).
///
/// The three tags are the whole `leas_route::ir` route set, and the inbound
/// records `Outbound.tag` verbatim; an unknown tag therefore renders blank
/// rather than an unrecognised glyph.
fn outbound_cell(outbound: Option<&str>, theme: &opaline::Theme) -> Cell<'static> {
    use leas_route::ir::{BLOCK_TAG, DIRECT_TAG, PROXY_TAG};
    let (glyph, style) = match outbound {
        Some(DIRECT_TAG) => ("→", ThemeStyles::hint(theme)),
        Some(PROXY_TAG) => ("⇄", ThemeStyles::container_title(theme)),
        Some(BLOCK_TAG) => ("⊘", ThemeStyles::error(theme)),
        _ => ("", ThemeStyles::hint(theme)),
    };
    Cell::from(Line::from(glyph).alignment(Alignment::Center)).style(style)
}

/// Scroll keys for the host table; mirrors the Native Activity conventions.
pub fn handle_key(state: &mut AppState, key: &KeyEvent) {
    let len = state
        .sniffer
        .latest
        .as_ref()
        .map_or(0, |snapshot| snapshot.hosts.len());
    let current = scroll_offset(len);
    let next = match key.code {
        KeyCode::Up => current.saturating_sub(1),
        KeyCode::Down => current.saturating_add(1),
        KeyCode::PageUp => current.saturating_sub(PAGE_ROWS),
        KeyCode::PageDown => current.saturating_add(PAGE_ROWS),
        KeyCode::Home => 0,
        KeyCode::End => usize::MAX,
        _ => return,
    };
    SCROLL.store(next.min(len.saturating_sub(1)), Ordering::Relaxed);
}

/// `format_bytes` takes `i64`; a counter past `i64::MAX` clamps, never wraps.
fn saturating_i64(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_shared_scale_uses_the_larger_series_and_floors_non_zero() {
        let samples = [
            RateSample { down: 1_000, up: 1 },
            RateSample { down: 0, up: 0 },
        ];
        assert_eq!(shared_max(&samples), 1_000);
        assert_eq!(bars_for(1, shared_max(&samples)), 1, "uplink stays visible");
        assert_eq!(bars_for(1_000, shared_max(&samples)), SPARK_ROWS * 2);
        assert_eq!(bars_for(0, shared_max(&samples)), 0);
    }

    #[test]
    fn mirrored_glyphs_fill_from_their_own_edge() {
        // Full bar: both edges see solid cells at every offset.
        assert_eq!(top_half(6, 0), '█');
        assert_eq!(bottom_half(6, 0), '█');
        // One half-cell only: the very first half-row of each side.
        assert_eq!(top_half(1, 0), '▀');
        assert_eq!(top_half(1, 2), ' ');
        assert_eq!(bottom_half(1, 0), '▄');
        assert_eq!(bottom_half(1, 2), ' ');
    }

    /// Text of every cell, row by row (`TestBackend` has no text accessor).
    fn screen_text(terminal: &ratatui::Terminal<ratatui::backend::TestBackend>) -> String {
        let buffer = terminal.backend().buffer();
        let area = *buffer.area();
        (0..area.height)
            .map(|y| {
                (0..area.width)
                    .map(|x| {
                        buffer
                            .cell((x, y))
                            .map_or("?", ratatui::buffer::Cell::symbol)
                            .to_owned()
                    })
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn sample_snapshot() -> leas_native::telemetry::SnifferSnapshot {
        let mut snapshot = leas_native::telemetry::SnifferSnapshot::default();
        for (host, outbound, up, down, conns, failed) in [
            ("example.com", Some("proxy"), 1_024, 4_096, 2, 1),
            ("direct.example", Some("direct"), 512, 128, 1, 0),
            ("blocked.example", Some("block"), 0, 0, 0, 1),
        ] {
            snapshot.hosts.push(leas_native::telemetry::HostStat {
                host: compact_str::CompactString::new(host),
                up,
                down,
                conns,
                failed,
                outbound: outbound.map(compact_str::CompactString::new),
            });
        }
        snapshot.failed = 1;
        snapshot.dropped_datagrams = 3;
        snapshot
    }

    #[tokio::test]
    async fn the_pane_shows_the_empty_state_then_host_rows() {
        use ratatui::Terminal;
        use ratatui::backend::TestBackend;

        let mut state = crate::ops::profiles::test_support::test_state(Vec::new()).await;
        let mut terminal = Terminal::new(TestBackend::new(100, 20)).expect("terminal");

        terminal
            .draw(|frame| render(frame, frame.area(), &state))
            .expect("draw");
        assert!(
            screen_text(&terminal).contains("No native session"),
            "a non-native session must say why the pane is empty"
        );

        state.connected = true;
        state.sniffer.record(sample_snapshot());
        terminal
            .draw(|frame| render(frame, frame.area(), &state))
            .expect("draw");
        let text = screen_text(&terminal);
        for expected in ["conns", "failed", "dropped 3", "via"] {
            assert!(text.contains(expected), "missing {expected:?} in:\n{text}");
        }
        // The glyph must sit on ITS host's row: asserting mere presence would
        // stay green with the direct/proxy arms swapped.
        for (host, glyph) in [
            ("example.com", "⇄"),
            ("direct.example", "→"),
            ("blocked.example", "⊘"),
        ] {
            let row = text
                .lines()
                .find(|line| line.contains(host))
                .unwrap_or_else(|| panic!("missing {host:?} row in:\n{text}"));
            assert!(row.contains(glyph), "{host} row missing {glyph:?}: {row:?}");
        }
    }
}
