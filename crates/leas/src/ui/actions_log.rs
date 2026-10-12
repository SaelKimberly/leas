use leas_core::grpc_client::format_bytes;
use leas_proto::proto_spec::ProtocolKind;

use crate::AppState;
use crate::ui::theme::ThemeStyles;
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui_cheese::fieldset::{Fieldset, FieldsetStyles};

fn connection_icon(state: &AppState) -> (&'static str, Style) {
    let palette = state.current_palette();
    if state.connecting {
        ("⠋", ThemeStyles::spinner(&palette))
    } else if state.connected_core.is_some() {
        ("●", ThemeStyles::success(&palette))
    } else if state.connection_error.is_some() {
        ("⏹", ThemeStyles::error(&palette))
    } else if state.connected_protocol_id.is_some() {
        ("⏏", ThemeStyles::warning(&palette))
    } else {
        ("○", ThemeStyles::hint(&palette))
    }
}

fn server_summary(state: &AppState) -> (String, String, u16, String) {
    // Try the connected profile first
    let from_connected = state
        .connected_protocol_id
        .as_ref()
        .and_then(|id| state.endpoints.iter().find(|r| r.endpoint.id.get() == *id));

    // Fall back to selected profile
    let row = from_connected.or_else(|| {
        if state.filtered_len() == 0 {
            return None;
        }
        let idx = state.selected_index.min(state.filtered_len() - 1);
        state.filtered_profiles().nth(idx)
    });

    row.map_or_else(
        || ("-".to_string(), String::new(), 0u16, String::new()),
        |r| {
            let proto = r
                .active_protocol()
                .map_or(ProtocolKind::Custom, |(_, p)| p.proto_kind);
            let addr = r.endpoint.display_host(&r.resolved_ips);
            let port = r.endpoint.port;
            let core = state.resolved_core(r).to_string();
            (proto.to_string(), addr, port, core)
        },
    )
}
pub fn render(frame: &mut Frame, area: Rect, state: &AppState) {
    render_full(frame, area, state);
}

// ── Compact render (1-line bar) ────────────────────────────────────────

pub fn render_compact(frame: &mut Frame, area: Rect, state: &AppState) {
    let palette = state.current_palette();
    let (icon, icon_style) = connection_icon(state);
    let (proto, addr, port, core) = server_summary(state);

    // Server info segment
    let server_str = if addr.is_empty() {
        format!("{proto} [{core}]")
    } else {
        format!("{proto} {addr}:{port} [{core}]")
    };

    // Test results segment
    let mut test_parts = Vec::new();
    if let Some(tcp) = state.last_test_tcp {
        test_parts.push(format!("TCP:{tcp}ms"));
    }
    if let Some(rp) = state.last_test_real {
        test_parts.push(format!("RP:{rp}ms"));
    }
    if let Some(spd) = state.last_test_speed {
        let speed_str = if spd >= 1_000_000 {
            format!("{}Mbps", spd / 1_000_000)
        } else if spd >= 1_000 {
            format!("{}Kbps", spd / 1_000)
        } else {
            format!("{spd}bps")
        };
        test_parts.push(format!("SPD:{speed_str}"));
    }
    let test_str = if test_parts.is_empty() {
        String::new()
    } else {
        test_parts.join(" ")
    };

    // Traffic segment
    let traffic_up = format_bytes(state.current_traffic_up);
    let traffic_down = format_bytes(state.current_traffic_down);
    let traffic_str = format!("⬆{traffic_up} ⬇{traffic_down}");

    // Last core log segment (scan log_cache backwards for non-tui entry)
    let log_snippet = state
        .log_cache
        .iter()
        .rev()
        .find(|l| l.target != "tui")
        .map_or("", |l| l.message.as_str());

    // Build the line
    let mut spans = Vec::new();
    spans.push(Span::styled(format!("{icon} "), icon_style));
    spans.push(Span::styled(
        server_str,
        ThemeStyles::footer_value(&palette),
    ));

    if !test_str.is_empty() {
        spans.push(Span::raw(" | "));
        spans.push(Span::styled(test_str, ThemeStyles::footer_label(&palette)));
    }

    if state.current_traffic_up != 0 || state.current_traffic_down != 0 {
        spans.push(Span::raw(" | "));
        spans.push(Span::styled(
            traffic_str,
            ThemeStyles::footer_value(&palette),
        ));
    }

    if !log_snippet.is_empty() {
        spans.push(Span::raw(" | "));
        spans.push(Span::styled(
            log_snippet,
            ThemeStyles::footer_label(&palette),
        ));
    }

    let paragraph = Paragraph::new(Line::from(spans)).style(ThemeStyles::status_footer(&palette));
    frame.render_widget(paragraph, area);
}

// ── Full render (bordered panel) ───────────────────────────────────────

/// Columns rows 3-4 reserve for their statistics cells. The bars' separator
/// derives from it, so it and the padded formats below must agree — that fixed
/// block is what keeps the bars' column from moving as numbers change.
const STAT_BLOCK_W: u16 = 42;

pub fn render_full(frame: &mut Frame, area: Rect, state: &AppState) {
    let palette = state.current_palette();
    let (icon, icon_style) = connection_icon(state);
    let (proto, addr, port, core) = server_summary(state);

    // Row 1: Connection status
    let status_text = if state.connecting {
        format!("{icon} Connecting...")
    } else if let Some(core) = &state.connected_core {
        format!("{icon} Connected [{core}]")
    } else if let Some(err) = &state.connection_error {
        format!("{icon} Error: {err}")
    } else {
        format!("{icon} Disconnected")
    };
    let row1 = Line::from(Span::styled(status_text, icon_style));

    // Row 2: Server info
    let server_info = if addr.is_empty() {
        format!("{proto} [{core}]")
    } else {
        format!("{proto} {addr}:{port} [{core}]")
    };
    let row2 = Line::from(Span::styled(
        if server_info == "No server" || server_info == "- No server" {
            "- No server -".to_string()
        } else {
            format!("🖥 {server_info}")
        },
        ThemeStyles::footer_value(&palette),
    ));

    // Row 3: Test results — every value padded to a fixed width (the bar's
    // separator column is a constant, so a changing digit count must not move
    // it).
    let tcp_str = state
        .last_test_tcp
        .map_or_else(|| "-".to_string(), |v| format!("{v}ms"));
    let rp_str = state
        .last_test_real
        .map_or_else(|| "-".to_string(), |v| format!("{v}ms"));
    let spd_str = state.last_test_speed.map_or_else(
        || "-".to_string(),
        |v| {
            if v >= 1_000_000 {
                format!("{}Mbps", v / 1_000_000)
            } else if v >= 1_000 {
                format!("{}Kbps", v / 1_000)
            } else {
                format!("{v}bps")
            }
        },
    );
    let row3 = Line::from(Span::styled(
        format!("⏱ TCP:{tcp_str:>8}  RP:{rp_str:>8}  SPD:{spd_str:>9}"),
        ThemeStyles::footer_label(&palette),
    ));

    // Row 4: Traffic & memory
    let traffic_up = format_bytes(state.current_traffic_up);
    let traffic_down = format_bytes(state.current_traffic_down);
    let mem_mb = if state.current_memory > 0 {
        format!("{:.1}MB", state.current_memory as f64 / 1_048_576.0)
    } else {
        "-".to_string()
    };
    let row4 = Line::from(Span::styled(
        format!("📊 ⬆{traffic_up:>9}  ⬇{traffic_down:>9}  💾{mem_mb:>8}"),
        ThemeStyles::footer_value(&palette),
    ));
    // Row 5: Core log (scan log_cache backwards for non-tui entry)
    let core_log = state
        .log_cache
        .iter()
        .rev()
        .find(|l| l.target != "tui")
        .map(|l| format!("📋 Core: [{}] {}", l.level, l.message))
        .unwrap_or_default();
    let row5 = Line::from(Span::styled(core_log, ThemeStyles::footer_label(&palette)));

    // Row 6: TUI log (scan log_cache backwards for tui entry)
    let tui_log = state
        .log_cache
        .iter()
        .rev()
        .find(|l| l.target == "tui")
        .map(|l| format!("📋 TUI:  [{}] {} ({})", l.level, l.message, l.target))
        .unwrap_or_default();
    let row6 = Line::from(Span::styled(tui_log, ThemeStyles::footer_label(&palette)));

    let fieldset = Fieldset::new()
        .title(" ⚙ Actions Log ")
        .styles(FieldsetStyles::from_palette(&palette));
    let inner_area = fieldset.inner(area);
    frame.render_widget(fieldset, area);
    let available = inner_area.height as usize;

    // The batch's two levels share rows 3-4 with the statistics cells: the log
    // rows keep their full width, and the bars sit in space the short stat
    // values were already wasting. Below the ladder's minimum the rows render
    // full width (the status bar carries the numbers there).
    let bar_w = inner_area.width.saturating_sub(STAT_BLOCK_W + 1) as usize;
    let (real_bar, fast_bar) = if bar_w >= 18 {
        batch_bars(state, &palette, bar_w)
    } else {
        (None, None)
    };

    let mut panel_rows: Vec<(Line, Option<Line>)> = vec![
        (row1, None),
        (row2, None),
        (row3, real_bar),
        (row4, fast_bar),
        (row5, None),
        (row6, None),
    ];
    panel_rows.truncate(available);

    for (i, (left, right)) in panel_rows.into_iter().enumerate() {
        let y = inner_area.y + i as u16;
        if y >= inner_area.y + inner_area.height {
            break;
        }
        let Some(right) = right else {
            let r = Rect::new(inner_area.x, y, inner_area.width, 1);
            frame.render_widget(Paragraph::new(left), r);
            continue;
        };
        let left_rect = Rect::new(inner_area.x, y, STAT_BLOCK_W, 1);
        let sep_rect = Rect::new(inner_area.x + STAT_BLOCK_W, y, 1, 1);
        let right_rect = Rect::new(
            inner_area.x + STAT_BLOCK_W + 1,
            y,
            inner_area.width.saturating_sub(STAT_BLOCK_W + 1),
            1,
        );
        frame.render_widget(Paragraph::new(left), left_rect);
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                "│",
                ThemeStyles::container_border(&palette),
            ))),
            sep_rect,
        );
        frame.render_widget(Paragraph::new(right), right_rect);
    }
}

/// The two level bars for rows 3 (real) and 4 (fast).
///
/// A fast-only batch keeps its single bar on the first row and leaves the second
/// full width; the fast row shows the walk's page count while the plan is still
/// loading, because that is where the batch's own time goes before any probe
/// exists to report.
fn batch_bars(
    state: &AppState,
    palette: &ratatui_cheese::theme::Palette,
    width: usize,
) -> (Option<Line<'static>>, Option<Line<'static>>) {
    use std::sync::atomic::Ordering;

    use crate::ui::widgets::progress;

    let Some(meters) = &state.batch_progress else {
        return (None, None);
    };
    let fast = || {
        let (done, total) = (
            meters.fast.done.load(Ordering::Relaxed),
            meters.fast.total.load(Ordering::Relaxed),
        );
        progress::bar_line("Fast", done, total, meters.fast.eta_secs(), width, palette)
    };
    let pages = (
        meters.plan_pages_done.load(Ordering::Relaxed),
        meters.plan_pages_total.load(Ordering::Relaxed),
    );
    let fast_line = if pages.1 > 0 && pages.0 < pages.1 {
        Line::from(Span::styled(
            format!("planning {}/{} pages", pages.0, pages.1),
            ThemeStyles::footer_label(palette),
        ))
    } else {
        fast()
    };
    let real_total = meters.real.total.load(Ordering::Relaxed);
    if real_total == 0 {
        // Nothing real to report (a fast-only batch, or no candidate yet): the
        // single bar takes the first row.
        return (Some(fast_line), None);
    }
    let real = progress::bar_line(
        "Real",
        meters.real.done.load(Ordering::Relaxed),
        real_total,
        meters.real.eta_secs(),
        width,
        palette,
    );
    (Some(real), Some(fast_line))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::Ordering;

    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    use crate::AppState;
    use crate::types::BatchMeters;

    use super::render_full;

    /// The 6 content rows of the panel, plus the border lines, at a width wide
    /// enough for the full bar shape.
    fn render_panel(state: &AppState) -> Vec<String> {
        let mut terminal = Terminal::new(TestBackend::new(120, 8)).unwrap();
        terminal
            .draw(|frame| render_full(frame, frame.area(), state))
            .unwrap();
        let buffer = terminal.backend().buffer();
        (0..buffer.area.height)
            .map(|y| {
                (0..buffer.area.width)
                    .map(|x| buffer[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect()
    }

    async fn state_with_meters(meters: BatchMeters) -> AppState {
        let mut state = crate::ops::profiles::test_support::test_state(Vec::new()).await;
        state.batch_progress = Some(Arc::new(meters));
        state
    }

    #[tokio::test]
    async fn without_a_batch_the_statistics_rows_keep_the_full_width() {
        let state = crate::ops::profiles::test_support::test_state(Vec::new()).await;
        let lines = render_panel(&state);
        for line in &lines {
            assert!(
                !line.contains('│'),
                "no separator without a batch: {line:?}"
            );
        }
    }

    #[tokio::test]
    async fn a_fast_only_batch_puts_its_bar_on_the_first_row() {
        let meters = BatchMeters::default();
        meters.fast.total.store(100, Ordering::Relaxed);
        meters.fast.done.store(25, Ordering::Relaxed);
        let state = state_with_meters(meters).await;
        let lines = render_panel(&state);
        // The fieldset's top rule is line 0, so content row N is line N:
        // row 3 = line 3, row 4 = line 4.
        assert!(lines[3].contains("Fast"), "bar on row 3: {:?}", lines[3]);
        assert!(lines[3].contains("25/100"), "counters: {:?}", lines[3]);
        assert!(lines[3].contains('│'), "separator: {:?}", lines[3]);
        assert!(
            !lines[4].contains('│'),
            "the second bar row stays full width: {:?}",
            lines[4]
        );
    }

    #[tokio::test]
    async fn real_and_fast_bars_stack_with_real_first() {
        let meters = BatchMeters::default();
        meters.fast.total.store(34562, Ordering::Relaxed);
        meters.fast.done.store(8123, Ordering::Relaxed);
        meters.real.total.store(17051, Ordering::Relaxed);
        meters.real.done.store(1234, Ordering::Relaxed);
        let state = state_with_meters(meters).await;
        let lines = render_panel(&state);
        assert!(
            lines[3].contains("Real") && lines[3].contains("1234/17051"),
            "real bar on row 3: {:?}",
            lines[3]
        );
        assert!(
            lines[4].contains("Fast") && lines[4].contains("8123/34562"),
            "fast bar on row 4: {:?}",
            lines[4]
        );
        // The stat cells keep their own columns beside the bars.
        assert!(lines[3].contains("TCP:"), "stat cells kept: {:?}", lines[3]);
        assert!(lines[4].contains("📊"), "stat cells kept: {:?}", lines[4]);
    }

    #[tokio::test]
    async fn the_fast_row_reports_the_plan_walk_while_it_loads() {
        let meters = BatchMeters::default();
        meters.plan_pages_done.store(1, Ordering::Relaxed);
        meters.plan_pages_total.store(92, Ordering::Relaxed);
        meters.fast.total.store(200, Ordering::Relaxed);
        let state = state_with_meters(meters).await;
        let lines = render_panel(&state);
        assert!(
            lines[3].contains("planning 1/92 pages"),
            "the first bar row reports the walk: {:?}",
            lines[3]
        );
    }
}
